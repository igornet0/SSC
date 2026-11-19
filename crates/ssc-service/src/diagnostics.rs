//! Diagnostics for local VPN policy gateway.

use serde::{Deserialize, Serialize};
use ssc_policy::load_policy;
use ssc_runtime::{InstanceMode, InstancePaths, DEFAULT_INSTANCE_ID};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Machine-oriented check id (stable).
    pub name: String,
    /// Human-readable label for UI / CLI.
    #[serde(default)]
    pub label: String,
    pub ok: bool,
    /// Human-readable detail / suggestion.
    pub detail: String,
}

/// Per-instance diagnostic snapshot (no credentials).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstanceDiagnostic {
    pub id: String,
    pub name: String,
    pub mode: String,
    pub state: String,
    pub proxy_port: Option<u16>,
    pub clash_api_port: Option<u16>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsReport {
    /// Connected / disconnected / etc.
    pub vpn_state: String,
    /// Friendly one-line summary of VPN state.
    #[serde(default)]
    pub vpn_summary: String,
    pub tunnel_interface: Option<String>,
    pub vpn_server: Option<String>,
    pub dns_server: String,
    pub policy_mode: String,
    /// Friendly mode description.
    #[serde(default)]
    pub policy_summary: String,
    pub active_rules: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_error: Option<String>,
    pub routing_hint: String,
    pub checks: Vec<CheckResult>,
    /// Every VPN instance (default first).
    #[serde(default)]
    pub instances: Vec<InstanceDiagnostic>,
}

/// Minimal registry view for naming / mode of each instance.
#[derive(Debug, Deserialize)]
struct RegistryFile {
    #[serde(default)]
    instances: Vec<RegistryEntry>,
}

#[derive(Debug, Deserialize)]
struct RegistryEntry {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    mode: Option<ssc_runtime::InstanceMode>,
}

fn check(name: &str, label: &str, ok: bool, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.into(),
        label: label.into(),
        ok,
        detail: detail.into(),
    }
}

/// Best-effort port from profile metadata without Keychain (default 443).
fn profile_server_port(profile: &ssc_core::Profile) -> Option<u16> {
    // Legacy inline URI only (no keychain round-trip).
    if let Some(ref uri) = profile.uri {
        if let Ok(p) = ssc_core::parse_share_uri(uri) {
            return Some(p.server_port);
        }
    }
    Some(443)
}

/// Snapshot of a single instance from its on-disk state (no credentials, sync).
fn instance_diagnostic(id: &str, name: &str, mode: Option<InstanceMode>) -> InstanceDiagnostic {
    let mode = mode
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "tun".into());
    let Ok(paths) = InstancePaths::for_id(id) else {
        return InstanceDiagnostic {
            id: id.to_string(),
            name: name.to_string(),
            mode,
            state: "unknown".to_string(),
            ..Default::default()
        };
    };
    let status = ssc_runtime::read_status_at(&paths);
    let connected = ssc_runtime::is_instance_connected(&paths);
    let state = if connected {
        "connected"
    } else if status.last_error.is_some() {
        "error"
    } else {
        "disconnected"
    };
    InstanceDiagnostic {
        id: id.to_string(),
        name: name.to_string(),
        mode,
        state: state.to_string(),
        proxy_port: status.proxy_port,
        clash_api_port: status.clash_api_port,
        last_error: status.last_error,
    }
}

/// Every known instance: the reserved `default` first, then registry/dir ids.
fn collect_instances() -> Vec<InstanceDiagnostic> {
    let mut meta: BTreeMap<String, (String, Option<InstanceMode>)> = BTreeMap::new();
    if let Ok(path) = ssc_core::instances_registry_path() {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(file) = serde_json::from_str::<RegistryFile>(&text) {
                for entry in file.instances {
                    if ssc_core::validate_instance_id(&entry.id).is_err() {
                        continue;
                    }
                    let name = if entry.name.trim().is_empty() {
                        entry.id.clone()
                    } else {
                        entry.name
                    };
                    meta.insert(entry.id, (name, entry.mode));
                }
            }
        }
    }
    if let Ok(dir) = ssc_core::instances_dir() {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if !entry.path().is_dir() {
                    continue;
                }
                if let Some(id) = entry.file_name().to_str() {
                    if ssc_core::validate_instance_id(id).is_ok() {
                        meta.entry(id.to_string())
                            .or_insert_with(|| (id.to_string(), None));
                    }
                }
            }
        }
    }

    let mut out = Vec::with_capacity(meta.len() + 1);
    out.push(instance_diagnostic(
        DEFAULT_INSTANCE_ID,
        "Default VPN",
        Some(InstanceMode::Tun),
    ));
    for (id, (name, mode)) in meta {
        if id == DEFAULT_INSTANCE_ID {
            continue;
        }
        out.push(instance_diagnostic(&id, &name, mode));
    }
    out
}

pub fn run_diagnostics() -> DiagnosticsReport {
    let status = crate::VpnManager::global().status();
    let policy = load_policy().unwrap_or_default();
    let active_rules = policy.active_rules().count();

    let mut checks = Vec::new();

    let setup = ssc_runtime::check_setup();
    checks.push(check(
        "singbox_binary",
        "sing-box runtime",
        !setup.needs_setup,
        setup
            .singbox_path
            .clone()
            .unwrap_or_else(|| "sing-box not found — run `ssc setup`".into()),
    ));

    let connected = ssc_runtime::is_connected();
    checks.push(check(
        "vpn_process",
        "VPN tunnel process",
        connected,
        if connected {
            "sing-box is running"
        } else {
            "Not connected — use Connect or `ssc connect`"
        },
    ));

    match crate::netconflict::foreign_vpn_conflict() {
        Some(msg) => checks.push(check("foreign_vpn", "Other VPN conflict", false, msg)),
        None => checks.push(check(
            "foreign_vpn",
            "Other VPN conflict",
            true,
            "No other system VPN holding the default route",
        )),
    }

    let iface_ok = status.interface.is_some() || !connected;
    checks.push(check(
        "tunnel_interface",
        "Tunnel interface",
        iface_ok,
        status.interface.clone().unwrap_or_else(|| {
            if connected {
                "Connected but utun not detected yet".into()
            } else {
                "No tunnel (disconnected)".into()
            }
        }),
    ));

    let server_check = match (&status.server, ssc_core::active_profile()) {
        (Some(server), Ok(profile)) => {
            // Prefer metadata host:port — do NOT touch Keychain in diagnostics
            // (security(1) can hang on auth prompts and freeze the Web UI).
            let port = profile_server_port(&profile).unwrap_or(443);
            let addr = format!("{server}:{port}");
            let ok = std::net::ToSocketAddrs::to_socket_addrs(&addr)
                .ok()
                .and_then(|mut i| i.next())
                .map(|sa| {
                    std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(2))
                        .is_ok()
                })
                .unwrap_or(false);
            check(
                "vpn_server",
                "VPN server reachability",
                ok,
                if ok {
                    format!("{server}:{port} accepts TCP (no secret shown)")
                } else {
                    format!("{server}:{port} unreachable on direct path")
                },
            )
        }
        (_, Err(_)) => check(
            "vpn_server",
            "VPN server reachability",
            false,
            "No active profile — run `ssc add` or pick a profile",
        ),
        (None, Ok(_)) => check(
            "vpn_server",
            "VPN server reachability",
            false,
            "Active profile has no server host",
        ),
    };
    checks.push(server_check);

    let dns_ok = ssc_core::singbox_meta_path()
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .or_else(|| {
            ssc_core::ephemeral_singbox_path()
                .ok()
                .and_then(|p| std::fs::read_to_string(p).ok())
        })
        .map(|t| t.contains("dns-remote") && t.contains("hijack-dns"))
        .unwrap_or(false);
    checks.push(check(
        "dns_config",
        "DNS policy",
        dns_ok || !connected,
        if dns_ok {
            "DNS hijack + remote resolver configured in sing-box"
        } else if connected {
            "Generated config missing DNS markers — reconnect to rebuild"
        } else {
            "DNS config checked when connected"
        },
    ));

    let secrets_ok = !ssc_core::persistent_config_has_secrets().unwrap_or(true);
    checks.push(check(
        "no_persistent_secrets",
        "No credentials in persistent config",
        secrets_ok,
        if secrets_ok {
            "singbox-run.json has no raw credentials (ephemeral runtime only)"
        } else {
            "WARNING: persistent singbox-run.json still contains credentials — run reset-network"
        },
    ));

    let mode = policy.settings.mode.as_str();
    checks.push(check(
        "policy_engine",
        "Policy engine",
        true,
        format!(
            "{} mode with {active_rules} active rule{}",
            mode,
            if active_rules == 1 { "" } else { "s" }
        ),
    ));

    let exclusion_ok = ssc_core::singbox_meta_path()
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .or_else(|| {
            ssc_core::ephemeral_singbox_path()
                .ok()
                .and_then(|p| std::fs::read_to_string(p).ok())
        })
        .map(|t| t.contains("\"outbound\": \"direct\"") || t.contains("\"outbound\":\"direct\""))
        .unwrap_or(false);
    checks.push(check(
        "routing_direct",
        "Local / server exclusions",
        exclusion_ok || !connected,
        if exclusion_ok {
            "Direct rules present (LAN / private / VPN server)"
        } else if connected {
            "No direct rules found in config"
        } else {
            "Routing rules appear after connect"
        },
    ));

    let pwless = ssc_runtime::passwordless_tunnel_ok();
    checks.push(check(
        "passwordless_tun",
        "Passwordless TUN privileges",
        pwless,
        if pwless {
            ssc_runtime::privileges_status()
        } else {
            format!(
                "{} — run: sudo ssc privileges install",
                ssc_runtime::privileges_status()
            )
        },
    ));

    let vpn_summary = match status.state.as_str() {
        "connected" => format!(
            "Connected via {}",
            status.interface.as_deref().unwrap_or("utun")
        ),
        "connecting" => "Connecting…".into(),
        "disconnecting" => "Disconnecting…".into(),
        "error" => format!(
            "Error: {}",
            status
                .last_error
                .as_deref()
                .unwrap_or("unknown — see last_error")
        ),
        _ => "Disconnected".into(),
    };

    let policy_summary = match mode {
        "full" => format!("Full VPN — everything through tunnel except exclusions ({active_rules} rule overrides)"),
        _ => format!("Selective — only matched destinations use VPN ({active_rules} rules)"),
    };

    DiagnosticsReport {
        vpn_state: status.state.as_str().to_string(),
        vpn_summary,
        tunnel_interface: status.interface,
        vpn_server: status.server,
        dns_server: "1.1.1.1 via sing-box (dns-remote)".into(),
        policy_mode: mode.to_string(),
        policy_summary,
        active_rules,
        bytes_sent: status.bytes_sent,
        bytes_received: status.bytes_received,
        last_error: status.last_error,
        routing_hint:
            "Routes are managed by sing-box auto_route. Inspect with `route -n get default` or `ssc` route probe."
                .into(),
        checks,
        instances: collect_instances(),
    }
}

/// Human-readable multi-line diagnostics for CLI.
pub fn format_diagnostics_pretty(report: &DiagnosticsReport) -> String {
    let mut lines = Vec::new();
    lines.push("SSC diagnostics".into());
    lines.push(format!("  VPN:      {}", report.vpn_summary));
    lines.push(format!(
        "  Server:   {}",
        report.vpn_server.as_deref().unwrap_or("—")
    ));
    lines.push(format!(
        "  Tunnel:   {}",
        report.tunnel_interface.as_deref().unwrap_or("—")
    ));
    lines.push(format!("  DNS:      {}", report.dns_server));
    lines.push(format!("  Policy:   {}", report.policy_summary));
    lines.push(format!(
        "  Traffic:  ↑ {}  ↓ {}",
        report.bytes_sent, report.bytes_received
    ));
    if let Some(err) = &report.last_error {
        lines.push(format!("  Last error: {err}"));
    }
    lines.push(format!("  Hint:     {}", report.routing_hint));
    lines.push(String::new());
    lines.push("Instances:".into());
    if report.instances.is_empty() {
        lines.push("  (none)".into());
    } else {
        for inst in &report.instances {
            let port = inst
                .proxy_port
                .map(|p| format!(" :{p}"))
                .unwrap_or_default();
            let mut line = format!("  {} [{}] {}{}", inst.id, inst.mode, inst.state, port);
            if let Some(err) = &inst.last_error {
                line.push_str(&format!(" — {err}"));
            }
            lines.push(line);
        }
    }
    lines.push(String::new());
    lines.push("Checks:".into());
    for c in &report.checks {
        let mark = if c.ok { "ok" } else { "FAIL" };
        let label = if c.label.is_empty() {
            c.name.as_str()
        } else {
            c.label.as_str()
        };
        lines.push(format!("  [{mark}] {label}: {}", c.detail));
    }
    lines.join("\n")
}
