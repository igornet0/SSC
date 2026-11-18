//! Detect other system VPNs that fight SSC for TUN / default route.

use crate::cmdutil::{run_timed_ok, DEFAULT_CMD_TIMEOUT};
use std::time::Duration;

/// Another macOS Network Extension / VPN is connected (e.g. Happ).
/// SSC TUN + auto_route cannot share the default route with it.
#[cfg(target_os = "macos")]
pub fn foreign_vpn_conflict() -> Option<String> {
    let text = run_timed_ok("scutil", &["--nc", "list"], Duration::from_secs(3)).ok()?;
    let mut names = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        // "* (Connected)  UUID  VPN (su.ffg.happ)  \"Happ\""
        if !trimmed.contains("(Connected)") {
            continue;
        }
        if let Some(name) = parse_nc_display_name(trimmed) {
            // SSC itself does not register via scutil --nc; any Connected entry is foreign.
            names.push(name);
        } else {
            names.push("system VPN".into());
        }
    }
    if names.is_empty() {
        // Happ-style fake-ip TUN without an scutil entry still owns the default route.
        if default_route_looks_like_foreign_tun() {
            return Some(
                "Another VPN owns the default route (utun / 198.18.x). Turn it off, then Connect in SSC."
                    .into(),
            );
        }
        return None;
    }
    names.sort();
    names.dedup();
    let list = names.join(", ");
    Some(format!(
        "Another VPN is connected ({list}). Disconnect it (e.g. Happ), then Connect in SSC — only one TUN VPN can own routing."
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn foreign_vpn_conflict() -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
fn parse_nc_display_name(line: &str) -> Option<String> {
    // Prefer quoted display name at end of line.
    if let Some(start) = line.rfind('"') {
        if let Some(open) = line[..start].rfind('"') {
            let name = line[open + 1..start].trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    // Fallback: VPN (bundle.id)
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
    let route = run_timed_ok("route", &["-n", "get", "default"], DEFAULT_CMD_TIMEOUT).ok();
    let Some(route) = route else {
        return false;
    };
    let iface = route
        .lines()
        .find_map(|l| {
            let l = l.trim();
            l.strip_prefix("interface:")
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_default();
    if !iface.starts_with("utun") {
        return false;
    }
    // SSC uses 172.19.0.1; Clash/Happ fake-ip commonly uses 198.18.0.1.
    let ifcfg = run_timed_ok("ifconfig", &[&iface], DEFAULT_CMD_TIMEOUT).ok();
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

    #[test]
    fn parses_happ_line() {
        let line = r#"* (Connected)      B2E4708A-3A2E-4DA0-858D-77CE1371034A VPN (su.ffg.happ)  "Happ"                           [VPN:su.ffg.happ]"#;
        assert_eq!(parse_nc_display_name(line).as_deref(), Some("Happ"));
    }
}
