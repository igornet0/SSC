//! Share URI parsing: `vless://`, `vmess://`, `trojan://`.

use base64::Engine;
use serde_json::Value as Json;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UriError {
    #[error("{0}")]
    Parse(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Vless,
    Vmess,
    Trojan,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Vless => "vless",
            Protocol::Vmess => "vmess",
            Protocol::Trojan => "trojan",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsOpts {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub fingerprint: Option<String>,
    pub alpn: Vec<String>,
    pub insecure: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RealityOpts {
    pub enabled: bool,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransportOpts {
    /// tcp | ws | grpc | http | httpupgrade | h2 | quic
    pub network: String,
    pub path: Option<String>,
    pub host: Option<String>,
    pub service_name: Option<String>,
    pub header_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedShare {
    pub protocol: Protocol,
    pub name: String,
    pub server: String,
    pub server_port: u16,
    pub uuid: Option<String>,
    pub password: Option<String>,
    pub alter_id: u16,
    pub encryption: Option<String>,
    pub flow: Option<String>,
    pub security: String,
    pub tls: TlsOpts,
    pub reality: RealityOpts,
    pub transport: TransportOpts,
    pub packet_encoding: Option<String>,
}

/// Parse a share URI (`vless://` / `vmess://` / `trojan://`).
pub fn parse_share_uri(uri: &str) -> Result<ParsedShare, UriError> {
    let t = uri.trim();
    if t.starts_with("vless://") {
        return parse_vless(t);
    }
    if t.starts_with("vmess://") {
        return parse_vmess(t);
    }
    if t.starts_with("trojan://") {
        return parse_trojan(t);
    }
    Err(UriError::Parse(
        "unsupported URI scheme (use vless://, vmess://, trojan://)".into(),
    ))
}

fn decode_component(s: &str) -> String {
    urlencoding::decode(s)
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| s.to_string())
}

fn parse_query(q: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(decode_component(k), decode_component(v));
    }
    out
}

fn parse_host_port(rest: &str) -> Result<(String, u16), UriError> {
    let (host, port_s) = if rest.starts_with('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| UriError::Parse("bad IPv6 host".into()))?;
        let host = rest[1..end].to_string();
        let after = &rest[end + 1..];
        let port_s = after
            .strip_prefix(':')
            .ok_or_else(|| UriError::Parse("missing port after IPv6".into()))?;
        (host, port_s)
    } else {
        rest.rsplit_once(':')
            .map(|(h, p)| (h.to_string(), p))
            .ok_or_else(|| UriError::Parse("bad host:port".into()))?
    };
    let port: u16 = port_s
        .parse()
        .map_err(|_| UriError::Parse(format!("bad port: {port_s}")))?;
    Ok((host, port))
}

fn split_authority_and_meta(after_scheme: &str) -> (String, Option<String>, Option<String>) {
    let (main, fragment) = after_scheme
        .split_once('#')
        .map(|(a, b)| (a, Some(b)))
        .unwrap_or((after_scheme, None));
    let (authority, query) = main
        .split_once('?')
        .map(|(a, b)| (a.to_string(), Some(b.to_string())))
        .unwrap_or((main.to_string(), None));
    (authority, query, fragment.map(|s| s.to_string()))
}

fn apply_security_from_query(q: &HashMap<String, String>, parsed: &mut ParsedShare) {
    let security = q
        .get("security")
        .map(|s| s.as_str())
        .unwrap_or("none")
        .to_lowercase();
    parsed.security = security.clone();

    let sni = q.get("sni").cloned().filter(|s| !s.is_empty());
    let fp = q.get("fp").cloned().filter(|s| !s.is_empty());
    let alpn = q
        .get("alpn")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let insecure = matches!(
        q.get("allowInsecure").map(|s| s.as_str()),
        Some("1" | "true" | "True" | "yes")
    ) || matches!(
        q.get("insecure").map(|s| s.as_str()),
        Some("1" | "true" | "True" | "yes")
    );

    match security.as_str() {
        "tls" => {
            parsed.tls = TlsOpts {
                enabled: true,
                server_name: sni.or_else(|| Some(parsed.server.clone())),
                fingerprint: fp,
                alpn,
                insecure,
            };
        }
        "reality" => {
            parsed.tls = TlsOpts {
                enabled: true,
                server_name: sni.or_else(|| Some(parsed.server.clone())),
                fingerprint: fp.or_else(|| Some("chrome".into())),
                alpn,
                insecure: false,
            };
            parsed.reality = RealityOpts {
                enabled: true,
                public_key: q.get("pbk").cloned().filter(|s| !s.is_empty()),
                short_id: q.get("sid").cloned().filter(|s| !s.is_empty()),
                spider_x: q.get("spx").cloned().filter(|s| !s.is_empty()),
            };
        }
        _ => {
            parsed.security = "none".into();
        }
    }

    let network = q
        .get("type")
        .or_else(|| q.get("net"))
        .map(|s| s.to_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "tcp".into());
    parsed.transport = TransportOpts {
        network,
        path: q.get("path").cloned().filter(|s| !s.is_empty()),
        host: q
            .get("host")
            .or_else(|| q.get("authority"))
            .cloned()
            .filter(|s| !s.is_empty()),
        service_name: q
            .get("serviceName")
            .or_else(|| q.get("service_name"))
            .cloned()
            .filter(|s| !s.is_empty()),
        header_type: q.get("headerType").cloned().filter(|s| !s.is_empty()),
    };

    if let Some(flow) = q.get("flow").cloned().filter(|s| !s.is_empty()) {
        parsed.flow = Some(flow);
    }
    if let Some(enc) = q.get("encryption").cloned().filter(|s| !s.is_empty()) {
        parsed.encryption = Some(enc);
    }
    if let Some(pe) = q
        .get("packetEncoding")
        .or_else(|| q.get("packet_encoding"))
        .cloned()
        .filter(|s| !s.is_empty())
    {
        parsed.packet_encoding = Some(pe);
    }
}

fn parse_vless(t: &str) -> Result<ParsedShare, UriError> {
    let rest = &t["vless://".len()..];
    let (authority, query, fragment) = split_authority_and_meta(rest);
    let (userinfo, hostport) = authority
        .split_once('@')
        .ok_or_else(|| UriError::Parse("vless: missing @".into()))?;
    let uuid = decode_component(userinfo.trim());
    if uuid.is_empty() {
        return Err(UriError::Parse("vless: empty uuid".into()));
    }
    let (server, server_port) = parse_host_port(hostport)?;
    let name = fragment
        .map(|f| decode_component(&f))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("vless@{server}:{server_port}"));

    let mut parsed = ParsedShare {
        protocol: Protocol::Vless,
        name,
        server,
        server_port,
        uuid: Some(uuid),
        password: None,
        alter_id: 0,
        encryption: Some("none".into()),
        flow: None,
        security: "none".into(),
        tls: TlsOpts::default(),
        reality: RealityOpts::default(),
        transport: TransportOpts {
            network: "tcp".into(),
            ..Default::default()
        },
        packet_encoding: Some("xudp".into()),
    };
    if let Some(q) = query {
        apply_security_from_query(&parse_query(&q), &mut parsed);
    }
    Ok(parsed)
}

fn parse_trojan(t: &str) -> Result<ParsedShare, UriError> {
    let rest = &t["trojan://".len()..];
    let (authority, query, fragment) = split_authority_and_meta(rest);
    let (userinfo, hostport) = authority
        .split_once('@')
        .ok_or_else(|| UriError::Parse("trojan: missing @".into()))?;
    let password = decode_component(userinfo.trim());
    if password.is_empty() {
        return Err(UriError::Parse("trojan: empty password".into()));
    }
    let (server, server_port) = parse_host_port(hostport)?;
    let name = fragment
        .map(|f| decode_component(&f))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("trojan@{server}:{server_port}"));

    let mut parsed = ParsedShare {
        protocol: Protocol::Trojan,
        name,
        server,
        server_port,
        uuid: None,
        password: Some(password),
        alter_id: 0,
        encryption: None,
        flow: None,
        security: "tls".into(),
        tls: TlsOpts {
            enabled: true,
            server_name: None,
            fingerprint: None,
            alpn: vec![],
            insecure: false,
        },
        reality: RealityOpts::default(),
        transport: TransportOpts {
            network: "tcp".into(),
            ..Default::default()
        },
        packet_encoding: None,
    };
    if let Some(q) = query {
        apply_security_from_query(&parse_query(&q), &mut parsed);
        if parsed.security == "none" {
            // Trojan almost always uses TLS; keep enabled if query omitted security.
            parsed.security = "tls".into();
            parsed.tls.enabled = true;
            if parsed.tls.server_name.is_none() {
                parsed.tls.server_name = Some(parsed.server.clone());
            }
        }
    } else if parsed.tls.server_name.is_none() {
        parsed.tls.server_name = Some(parsed.server.clone());
    }
    Ok(parsed)
}

fn parse_vmess(t: &str) -> Result<ParsedShare, UriError> {
    let b64 = t.trim_start_matches("vmess://");
    let pad = (4 - b64.len() % 4) % 4;
    let padded = format!("{b64}{}", "=".repeat(pad));
    let raw = base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .or_else(|_| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64.as_bytes())
        })
        .map_err(|e| UriError::Parse(format!("vmess base64: {e}")))?;
    let j: Json = serde_json::from_slice(&raw)
        .map_err(|e| UriError::Parse(format!("vmess json: {e}")))?;

    let server = j
        .get("add")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| UriError::Parse("vmess: missing add".into()))?
        .to_string();
    let server_port = match j.get("port") {
        Some(Json::Number(n)) => n.as_u64().unwrap_or(443) as u16,
        Some(Json::String(s)) => s.parse().unwrap_or(443),
        _ => 443,
    };
    let uuid = j
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| UriError::Parse("vmess: missing id".into()))?
        .to_string();
    let alter_id = match j.get("aid") {
        Some(Json::Number(n)) => n.as_u64().unwrap_or(0) as u16,
        Some(Json::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    };
    let name = j
        .get("ps")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("vmess@{server}:{server_port}"));
    let network = j
        .get("net")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp")
        .to_lowercase();
    let tls_flag = j
        .get("tls")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    let sni = j
        .get("sni")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let host = j
        .get("host")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let path = j
        .get("path")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let security = if tls_flag == "tls" || tls_flag == "reality" {
        tls_flag
    } else {
        "none".into()
    };

    let mut parsed = ParsedShare {
        protocol: Protocol::Vmess,
        name,
        server: server.clone(),
        server_port,
        uuid: Some(uuid),
        password: None,
        alter_id,
        encryption: j
            .get("scy")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        flow: None,
        security: security.clone(),
        tls: TlsOpts::default(),
        reality: RealityOpts::default(),
        transport: TransportOpts {
            network,
            path,
            host,
            service_name: None,
            header_type: j
                .get("type")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        },
        packet_encoding: None,
    };

    if security == "tls" {
        parsed.tls = TlsOpts {
            enabled: true,
            server_name: sni.or(Some(server)),
            fingerprint: j
                .get("fp")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            alpn: vec![],
            insecure: false,
        };
    } else if security == "reality" {
        parsed.tls = TlsOpts {
            enabled: true,
            server_name: sni.or(Some(server)),
            fingerprint: j
                .get("fp")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| Some("chrome".into())),
            alpn: vec![],
            insecure: false,
        };
        parsed.reality = RealityOpts {
            enabled: true,
            public_key: j
                .get("pbk")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            short_id: j
                .get("sid")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            spider_x: j
                .get("spx")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        };
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vless_reality() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@ingress.example.com:443?encryption=none&type=tcp&headerType=none&security=reality&sni=www.oracle.com&fp=chrome&pbk=PUBLICKEY&sid=abcd1234&spx=%2F#test-node";
        let p = parse_share_uri(uri).unwrap();
        assert_eq!(p.protocol, Protocol::Vless);
        assert_eq!(p.server, "ingress.example.com");
        assert_eq!(p.server_port, 443);
        assert_eq!(p.uuid.as_deref(), Some("11111111-1111-1111-1111-111111111111"));
        assert_eq!(p.security, "reality");
        assert!(p.reality.enabled);
        assert_eq!(p.reality.public_key.as_deref(), Some("PUBLICKEY"));
        assert_eq!(p.reality.short_id.as_deref(), Some("abcd1234"));
        assert_eq!(p.tls.server_name.as_deref(), Some("www.oracle.com"));
        assert_eq!(p.name, "test-node");
    }

    #[test]
    fn parse_vless_tls_ws() {
        let uri = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:8443?encryption=none&security=tls&sni=cdn.example.com&type=ws&path=%2Fray&host=cdn.example.com&fp=chrome#ws";
        let p = parse_share_uri(uri).unwrap();
        assert_eq!(p.transport.network, "ws");
        assert_eq!(p.transport.path.as_deref(), Some("/ray"));
        assert_eq!(p.transport.host.as_deref(), Some("cdn.example.com"));
        assert!(p.tls.enabled);
    }

    #[test]
    fn parse_trojan() {
        let uri = "trojan://secret-pass@host.example:443?security=tls&sni=host.example&fp=chrome&type=tcp#tj";
        let p = parse_share_uri(uri).unwrap();
        assert_eq!(p.protocol, Protocol::Trojan);
        assert_eq!(p.password.as_deref(), Some("secret-pass"));
        assert!(p.tls.enabled);
        assert_eq!(p.name, "tj");
    }

    #[test]
    fn parse_vmess_json() {
        let json = r#"{"v":"2","ps":"node","add":"10.0.0.1","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":"tls","sni":"sni.example"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        let uri = format!("vmess://{b64}");
        let p = parse_share_uri(&uri).unwrap();
        assert_eq!(p.protocol, Protocol::Vmess);
        assert_eq!(p.server, "10.0.0.1");
        assert_eq!(p.server_port, 443);
        assert_eq!(p.name, "node");
        assert!(p.tls.enabled);
        assert_eq!(p.tls.server_name.as_deref(), Some("sni.example"));
    }
}
