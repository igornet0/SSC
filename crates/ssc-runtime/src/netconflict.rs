//! Detect other system VPNs that fight SSC for the TUN default route.

use std::process::Command;
use std::time::Duration;

fn run_timed(program: &str, args: &[&str], _timeout: Duration) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Another macOS Network Extension / VPN is connected (e.g. Happ).
/// A single TUN can own the default route, so SSC refuses to start a second one.
#[cfg(target_os = "macos")]
pub fn foreign_vpn_conflict() -> Option<String> {
    let text = run_timed("scutil", &["--nc", "list"], Duration::from_secs(3))?;
    let mut names = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.contains("(Connected)") {
            continue;
        }
        if let Some(name) = parse_nc_display_name(trimmed) {
            names.push(name);
        } else {
            names.push("system VPN".into());
        }
    }
    if names.is_empty() {
        if default_route_looks_like_foreign_tun() {
            return Some(
                "Another VPN owns the default route (utun / 198.18.x). Turn it off, then connect in SSC."
                    .into(),
            );
        }
        return None;
    }
    names.sort();
    names.dedup();
    Some(format!(
        "Another VPN is connected ({}). Disconnect it first — only one TUN VPN can own routing.",
        names.join(", ")
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn foreign_vpn_conflict() -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
fn parse_nc_display_name(line: &str) -> Option<String> {
    if let Some(start) = line.rfind('"') {
        if let Some(open) = line[..start].rfind('"') {
            let name = line[open + 1..start].trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    if let Some(i) = line.find("VPN (") {
        let rest = &line[i + 5..];
        if let Some(end) = rest.find(')') {
            let bundle = rest[..end].trim();
            if !bundle.is_empty() {
                return Some(bundle.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn default_route_looks_like_foreign_tun() -> bool {
    let route = run_timed("route", &["-n", "get", "default"], Duration::from_secs(8));
    let Some(route) = route else {
        return false;
    };
    let iface = route
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("interface:")
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_default();
    if !iface.starts_with("utun") {
        return false;
    }
    let ifcfg = run_timed("ifconfig", &[&iface], Duration::from_secs(8));
    let Some(ifcfg) = ifcfg else {
        return false;
    };
    if ifcfg.contains("172.19.0.1") {
        return false;
    }
    ifcfg.contains("198.18.") || ifcfg.contains("198.19.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_happ_line() {
        let line = r#"* (Connected)      B2E4708A-3A2E-4DA0-858D-77CE1371034A VPN (su.ffg.happ)  "Happ"                           [VPN:su.ffg.happ]"#;
        assert_eq!(parse_nc_display_name(line).as_deref(), Some("Happ"));
    }
}
