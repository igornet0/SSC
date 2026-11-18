//! Build sing-box client JSON with native VLESS / VMess / Trojan outbounds.

use crate::config_paths::singbox_run_path;
use crate::uri::{parse_share_uri, ParsedShare, Protocol};
use serde_json::{json, Value};
use ssc_policy::{compile_route_rules, PolicySnapshot};

fn tls_object(parsed: &ParsedShare) -> Option<Value> {
    if !parsed.tls.enabled && !parsed.reality.enabled {
        return None;
    }
    let mut tls = json!({
        "enabled": true,
    });
    if let Some(sni) = &parsed.tls.server_name {
        tls["server_name"] = json!(sni);
    }
    if !parsed.tls.alpn.is_empty() {
        tls["alpn"] = json!(parsed.tls.alpn);
    }
    if parsed.tls.insecure {
        tls["insecure"] = json!(true);
    }
    if let Some(fp) = &parsed.tls.fingerprint {
        tls["utls"] = json!({
            "enabled": true,
            "fingerprint": fp,
        });
    }
    if parsed.reality.enabled {
        let mut reality = json!({ "enabled": true });
        if let Some(pbk) = &parsed.reality.public_key {
            reality["public_key"] = json!(pbk);
        }
        if let Some(sid) = &parsed.reality.short_id {
            reality["short_id"] = json!(sid);
        }
        tls["reality"] = reality;
    }
    Some(tls)
}

fn transport_object(parsed: &ParsedShare) -> Option<Value> {
    let net = parsed.transport.network.to_lowercase();
    match net.as_str() {
        "ws" | "websocket" => {
            let mut t = json!({ "type": "ws" });
            if let Some(path) = &parsed.transport.path {
                t["path"] = json!(path);
            }
            if let Some(host) = &parsed.transport.host {
                t["headers"] = json!({ "Host": host });
            }
            Some(t)
        }
        "grpc" => {
            let mut t = json!({ "type": "grpc" });
            if let Some(sn) = &parsed.transport.service_name {
                t["service_name"] = json!(sn);
            }
            Some(t)
        }
        "http" | "h2" | "httpupgrade" => {
            let mut t = json!({ "type": if net == "h2" { "http" } else { net.as_str() } });
            if let Some(path) = &parsed.transport.path {
                t["path"] = json!(path);
            }
            if let Some(host) = &parsed.transport.host {
                t["host"] = json!([host]);
            }
            Some(t)
        }
        "tcp" | "" => None,
        other => Some(json!({ "type": other })),
    }
}

fn build_proxy_outbound(parsed: &ParsedShare) -> Result<Value, String> {
    let mut ob = match parsed.protocol {
        Protocol::Vless => {
            let uuid = parsed
                .uuid
                .as_ref()
                .ok_or_else(|| "vless uuid missing".to_string())?;
            let mut o = json!({
                "type": "vless",
                "tag": "proxy",
                "server": parsed.server,
                "server_port": parsed.server_port,
                "uuid": uuid,
            });
            if let Some(flow) = &parsed.flow {
                if !flow.is_empty() {
                    o["flow"] = json!(flow);
                }
            }
            if let Some(pe) = &parsed.packet_encoding {
                o["packet_encoding"] = json!(pe);
            }
            o
        }
        Protocol::Vmess => {
            let uuid = parsed
                .uuid
                .as_ref()
                .ok_or_else(|| "vmess uuid missing".to_string())?;
            let mut o = json!({
                "type": "vmess",
                "tag": "proxy",
                "server": parsed.server,
                "server_port": parsed.server_port,
                "uuid": uuid,
                "alter_id": parsed.alter_id,
                "security": parsed.encryption.as_deref().unwrap_or("auto"),
            });
            if let Some(pe) = &parsed.packet_encoding {
                o["packet_encoding"] = json!(pe);
            }
            o
        }
        Protocol::Trojan => {
            let password = parsed
                .password
                .as_ref()
                .ok_or_else(|| "trojan password missing".to_string())?;
            json!({
                "type": "trojan",
                "tag": "proxy",
                "server": parsed.server,
                "server_port": parsed.server_port,
                "password": password,
            })
        }
    };

    if let Some(tls) = tls_object(parsed) {
        ob["tls"] = tls;
    }
    if let Some(transport) = transport_object(parsed) {
        ob["transport"] = transport;
    }
    Ok(ob)
}

/// Build a full sing-box TUN config for the given share URI (default Full VPN policy).
pub fn build_singbox_config(uri: &str) -> Result<Value, String> {
    let parsed = parse_share_uri(uri).map_err(|e| e.to_string())?;
    // Preserve historical default: full tunnel (final = proxy) when no policy passed.
    let mut policy = PolicySnapshot::default();
    policy.settings.mode = ssc_policy::PolicyMode::Full;
    build_singbox_config_from_parsed(&parsed, &policy)
}

pub fn build_singbox_config_from_parsed(
    parsed: &ParsedShare,
    policy: &PolicySnapshot,
) -> Result<Value, String> {
    let proxy = build_proxy_outbound(parsed)?;
    let compiled = compile_route_rules(policy);

    let mut route_rules = vec![
        json!({ "action": "sniff" }),
        json!({ "protocol": "dns", "action": "hijack-dns" }),
        json!({ "ip_is_private": true, "outbound": "direct" }),
    ];

    // Dynamic LAN / gateway / link-local exclusions (after private rule).
    let exclusions = crate::netinfo::local_exclusions();
    if !exclusions.is_empty() {
        route_rules.push(json!({
            "ip_cidr": exclusions.clone(),
            "outbound": "direct"
        }));
    }

    // Critical: VPN server must remain DIRECT to avoid routing loops.
    push_vpn_server_exclusion(&mut route_rules, parsed);

    // User policy rules (domain / IP / CIDR → direct|proxy|block)
    route_rules.extend(compiled.route_rules);

    let outbounds = vec![proxy, json!({ "type": "direct", "tag": "direct" })];
    let _ = compiled.need_block_outbound; // reserved for kill-switch helpers

    Ok(json!({
        "log": { "level": "warn", "timestamp": true },
        "dns": {
            "servers": [
                { "type": "udp", "tag": "dns-remote", "server": "1.1.1.1" },
                { "type": "local", "tag": "dns-local" }
            ],
            "final": "dns-remote",
            // Avoid half-broken AAAA paths when TUN is IPv4-only (Electron/Cursor).
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.19.0.1/30"],
                "mtu": 1500,
                "auto_route": true,
                "strict_route": true,
                "stack": "system",
                // Keep loopback/LAN off the TUN stack entirely (not just DIRECT outbound).
                "route_exclude_address": exclusions
            }
        ],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": true,
            "default_domain_resolver": "dns-local",
            "rules": route_rules,
            "final": compiled.final_outbound
        },
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "secret": ""
            }
        }
    }))
}

fn push_vpn_server_exclusion(route_rules: &mut Vec<Value>, parsed: &ParsedShare) {
    let server = parsed.server.trim();
    if server.is_empty() {
        return;
    }
    if server.parse::<std::net::IpAddr>().is_ok() {
        let cidr = if server.contains(':') {
            format!("{server}/128")
        } else {
            format!("{server}/32")
        };
        route_rules.push(json!({
            "ip_cidr": [cidr],
            "outbound": "direct"
        }));
    } else {
        // Hostname server: exclude by domain so DNS→IP still goes DIRECT via sniff,
        // and also rely on default_domain_resolver for dialing the proxy outbound
        // on the physical interface (auto_detect_interface).
        route_rules.push(json!({
            "domain": [server.to_ascii_lowercase()],
            "outbound": "direct"
        }));
    }
}

pub fn write_singbox_config(uri: &str) -> Result<std::path::PathBuf, String> {
    write_singbox_config_with_policy(uri, &{
        let mut p = PolicySnapshot::default();
        p.settings.mode = ssc_policy::PolicyMode::Full;
        p
    })
}

/// Write sing-box config to an **ephemeral** runtime file (0600).
/// Credentials never persist in `singbox-run.json`.
/// A redacted meta file is written for diagnostics.
pub fn write_singbox_config_with_policy(
    uri: &str,
    policy: &PolicySnapshot,
) -> Result<std::path::PathBuf, String> {
    let parsed = parse_share_uri(uri).map_err(|e| e.to_string())?;
    let cfg = build_singbox_config_from_parsed(&parsed, policy)?;
    let path = crate::config_paths::ephemeral_singbox_path()?;
    let text = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
    std::fs::write(&path, &text).map_err(|e| format!("write ephemeral singbox config: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    // Pointer for cleanup / reload
    let ptr = crate::config_paths::ephemeral_pointer_path()?;
    std::fs::write(&ptr, path.to_string_lossy().as_bytes())
        .map_err(|e| format!("write ephemeral pointer: {e}"))?;

    // Redacted meta for diagnostics (no uuid/password)
    write_redacted_meta(&cfg)?;

    // Scrub legacy persistent credential file if present
    scrub_legacy_singbox_run()?;

    Ok(path)
}

/// Remove secrets from outbound objects for any on-disk meta snapshot.
pub fn redact_singbox_config(cfg: &Value) -> Value {
    let mut out = cfg.clone();
    if let Some(arr) = out.get_mut("outbounds").and_then(|v| v.as_array_mut()) {
        for ob in arr.iter_mut() {
            if ob.get("uuid").is_some() {
                ob["uuid"] = json!("********");
            }
            if ob.get("password").is_some() {
                ob["password"] = json!("********");
            }
            if ob.get("alter_id").is_some() {
                // keep alter_id (not a secret) 
            }
        }
    }
    out
}

fn write_redacted_meta(cfg: &Value) -> Result<(), String> {
    let meta = redact_singbox_config(cfg);
    let path = crate::config_paths::singbox_meta_path()?;
    let text = serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| format!("write singbox meta: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn scrub_legacy_singbox_run() -> Result<(), String> {
    let path = singbox_run_path()?;
    if path.is_file() {
        // Overwrite then delete so remnants are not recoverable easily.
        let _ = std::fs::write(&path, b"{}\n");
        let _ = std::fs::remove_file(&path);
    }
    Ok(())
}

/// Delete ephemeral runtime config (call on disconnect / reset-network).
pub fn cleanup_ephemeral_config() -> Result<(), String> {
    let eph = crate::config_paths::ephemeral_singbox_path()?;
    if eph.is_file() {
        let _ = std::fs::write(&eph, b"{}\n");
        let _ = std::fs::remove_file(&eph);
    }
    let ptr = crate::config_paths::ephemeral_pointer_path()?;
    let _ = std::fs::remove_file(&ptr);
    scrub_legacy_singbox_run()?;
    Ok(())
}

/// True if legacy persistent `singbox-run.json` still contains raw credentials.
pub fn persistent_config_has_secrets() -> Result<bool, String> {
    let path = singbox_run_path()?;
    if !path.is_file() {
        return Ok(false);
    }
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    Ok(has_raw_uuid_or_password(&text))
}

fn has_raw_uuid_or_password(text: &str) -> bool {
    if let Some(idx) = text.find("\"uuid\"") {
        let rest = &text[idx..];
        if let Some(q1) = rest.find(':') {
            let after = rest[q1 + 1..].trim_start();
            if after.starts_with('"') {
                let after = &after[1..];
                if let Some(end) = after.find('"') {
                    let val = &after[..end];
                    if val != "********" && val.len() >= 8 {
                        return true;
                    }
                }
            }
        }
    }
    if let Some(idx) = text.find("\"password\"") {
        let rest = &text[idx..];
        if let Some(start) = rest.find(':') {
            let after = rest[start + 1..].trim_start();
            if after.starts_with('"') && !after.starts_with("\"********\"") {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ssc_policy::{Action, MatchKind, PolicyMode, PolicyRule, Settings};

    #[test]
    fn vless_reality_outbound() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@ingress.example.com:443?encryption=none&type=tcp&security=reality&sni=www.oracle.com&fp=chrome&pbk=PUBLICKEY&sid=abcd1234#n";
        let cfg = build_singbox_config(uri).unwrap();
        let ob = &cfg["outbounds"][0];
        assert_eq!(ob["type"], "vless");
        assert_eq!(ob["uuid"], "11111111-1111-1111-1111-111111111111");
        assert_eq!(ob["tls"]["reality"]["enabled"], true);
        assert_eq!(ob["tls"]["reality"]["public_key"], "PUBLICKEY");
        assert_eq!(ob["tls"]["server_name"], "www.oracle.com");
        assert_eq!(ob["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(cfg["route"]["final"], "proxy");
        assert_eq!(cfg["inbounds"][0]["type"], "tun");
    }

    #[test]
    fn trojan_outbound() {
        let uri = "trojan://pass@1.2.3.4:443?security=tls&sni=1.2.3.4";
        let cfg = build_singbox_config(uri).unwrap();
        let ob = &cfg["outbounds"][0];
        assert_eq!(ob["type"], "trojan");
        assert_eq!(ob["password"], "pass");
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r.get("ip_cidr").is_some()));
    }

    #[test]
    fn vmess_outbound() {
        let json = r#"{"v":"2","ps":"n","add":"10.0.0.1","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"ws","path":"/v","host":"h.example","tls":"tls","sni":"h.example"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        let cfg = build_singbox_config(&format!("vmess://{b64}")).unwrap();
        let ob = &cfg["outbounds"][0];
        assert_eq!(ob["type"], "vmess");
        assert_eq!(ob["transport"]["type"], "ws");
        assert_eq!(ob["transport"]["path"], "/v");
        assert!(ob["tls"]["enabled"].as_bool().unwrap());
    }

    #[test]
    fn selective_policy_final_direct_and_domain_rule() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443?security=tls&sni=vpn.example.com#n";
        let parsed = parse_share_uri(uri).unwrap();
        let policy = PolicySnapshot {
            settings: Settings {
                mode: PolicyMode::Selective,
                ..Settings::default()
            },
            groups: vec![],
            rules: vec![PolicyRule::new(
                MatchKind::Domain,
                "google.com",
                Action::Vpn,
            )],
        };
        let cfg = build_singbox_config_from_parsed(&parsed, &policy).unwrap();
        assert_eq!(cfg["route"]["final"], "direct");
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| {
            r.get("domain") == Some(&json!(["google.com"])) && r["outbound"] == "proxy"
        }));
        // VPN server exclusion
        assert!(rules.iter().any(|r| {
            r.get("domain") == Some(&json!(["vpn.example.com"])) && r["outbound"] == "direct"
        }));
    }

    #[test]
    fn vpn_server_ip_exclusion_when_default_vpn() {
        let uri = "trojan://pass@203.0.113.10:443?security=tls&sni=x";
        let parsed = parse_share_uri(uri).unwrap();
        let policy = PolicySnapshot {
            settings: Settings {
                mode: PolicyMode::Full,
                ..Settings::default()
            },
            groups: vec![],
            rules: vec![],
        };
        let cfg = build_singbox_config_from_parsed(&parsed, &policy).unwrap();
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(
            rules.iter().any(|r| {
                r.get("ip_cidr") == Some(&json!(["203.0.113.10/32"])) && r["outbound"] == "direct"
            }),
            "VPN server must remain reachable (DIRECT) under full VPN routing"
        );
        assert_eq!(cfg["route"]["final"], "proxy");
    }

    #[test]
    fn local_exclusions_rule_present() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443?security=tls&sni=vpn.example.com#n";
        let parsed = parse_share_uri(uri).unwrap();
        let policy = PolicySnapshot::default();
        let cfg = build_singbox_config_from_parsed(&parsed, &policy).unwrap();
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(
            rules.iter().any(|r| {
                r.get("ip_cidr")
                    .and_then(|c| c.as_array())
                    .is_some_and(|arr| {
                        arr.iter().any(|v| v.as_str() == Some("127.0.0.0/8"))
                    })
                    && r["outbound"] == "direct"
            }),
            "expected local exclusion CIDRs after private rule"
        );
        let exclude = cfg["inbounds"][0]["route_exclude_address"]
            .as_array()
            .expect("tun must set route_exclude_address");
        assert!(
            exclude.iter().any(|v| v.as_str() == Some("127.0.0.0/8")),
            "loopback must be excluded from TUN for Electron/Cursor IPC"
        );
        assert!(
            exclude.iter().any(|v| v.as_str() == Some("::1/128")),
            "IPv6 loopback must be excluded from TUN"
        );
        assert_eq!(cfg["dns"]["strategy"], "ipv4_only");
    }

    #[test]
    fn ephemeral_config_keeps_secrets_out_of_persistent_path() {
        let dir = std::env::temp_dir().join(format!(
            "ssc-eph-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("SSC_CONFIG_DIR", &dir);

        let uri = "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443?security=tls&sni=vpn.example.com#n";
        let path = write_singbox_config_with_policy(uri, &PolicySnapshot::default()).unwrap();
        assert!(path.ends_with("singbox-ephemeral.json"));
        let eph = std::fs::read_to_string(&path).unwrap();
        assert!(eph.contains("11111111-1111-1111-1111-111111111111"));

        let legacy = crate::config_paths::singbox_run_path().unwrap();
        assert!(!legacy.is_file(), "legacy singbox-run.json must not exist");
        assert!(!persistent_config_has_secrets().unwrap());

        let meta = std::fs::read_to_string(crate::config_paths::singbox_meta_path().unwrap()).unwrap();
        assert!(meta.contains("********"));
        assert!(!meta.contains("11111111-1111-1111-1111-111111111111"));

        cleanup_ephemeral_config().unwrap();
        assert!(!path.is_file(), "ephemeral must be deleted after cleanup");

        // Simulate leftover legacy credential file and scrub
        std::fs::write(&legacy, eph).unwrap();
        assert!(persistent_config_has_secrets().unwrap());
        cleanup_ephemeral_config().unwrap();
        assert!(!persistent_config_has_secrets().unwrap());
        assert!(!legacy.is_file());

        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("SSC_CONFIG_DIR");
    }

    #[test]
    fn redact_hides_uuid_and_password() {
        let uri = "trojan://super-secret@1.2.3.4:443?security=tls&sni=x";
        let cfg = build_singbox_config(uri).unwrap();
        let red = redact_singbox_config(&cfg);
        assert_eq!(red["outbounds"][0]["password"], "********");
        assert_ne!(cfg["outbounds"][0]["password"], "********");
    }
}