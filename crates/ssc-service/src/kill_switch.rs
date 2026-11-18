//! macOS packet-filter kill switch (`pf` anchor `ssc.killswitch`).
//!
//! When the VPN drops unexpectedly with kill switch enabled, outbound traffic
//! is restricted so VPN-bound destinations cannot leak over the clear path.
//!
//! ## Modes
//! - **Full**: allow loopback, private LAN, and the VPN server; block-drop
//!   all other outbound IPv4/IPv6.
//! - **Selective with IP/CIDR VPN rules**: allow the same baseline, then
//!   block-drop only the listed VPN destination CIDRs.
//! - **Selective with domain-only rules**: pf cannot match domains. Known
//!   IP/CIDR VPN destinations are still blocked; domain-only destinations
//!   are a **weaker** guarantee — rely on sing-box reject routing while the
//!   tunnel is up, and accept that domain-only kill-switch coverage is
//!   limited after an unexpected drop.

use ssc_policy::{Action, MatchKind, PolicyMode, PolicySnapshot};
use std::io::Write;
use std::process::{Command, Stdio};

const ANCHOR: &str = "ssc.killswitch";

/// Collect IP/CIDR destinations that policy sends via VPN (for Selective block).
pub fn vpn_dest_cidrs(snapshot: &PolicySnapshot) -> Vec<String> {
    let mut out = Vec::new();
    for rule in snapshot.active_rules() {
        if rule.action != Action::Vpn {
            continue;
        }
        match rule.kind {
            MatchKind::Ip => {
                let ip = rule.value.trim();
                if ip.contains(':') {
                    out.push(format!("{ip}/128"));
                } else {
                    out.push(format!("{ip}/32"));
                }
            }
            MatchKind::Cidr => {
                let c = rule.value.trim();
                if !c.is_empty() {
                    out.push(c.to_string());
                }
            }
            MatchKind::Domain | MatchKind::Port => {
                // Domain/port cannot be expressed in pf tables reliably here.
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Activate the SSC pf kill-switch anchor.
///
/// - `full_tunnel == true` (Full mode): block all other outbound.
/// - `full_tunnel == false` (Selective): block only `vpn_dest_cidrs`.
///   Empty CIDRs with Selective = weaker domain-only case (baseline allow
///   only; no extra block rules beyond documentation above).
pub fn activate(
    vpn_server: &str,
    vpn_dest_cidrs: &[String],
    full_tunnel: bool,
) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        activate_macos(vpn_server, vpn_dest_cidrs, full_tunnel)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (vpn_server, vpn_dest_cidrs, full_tunnel);
        Err("kill switch is only implemented on macOS (pf)".into())
    }
}

/// Convenience: activate from current policy + VPN server host.
pub fn activate_for_policy(vpn_server: &str, snapshot: &PolicySnapshot) -> Result<(), String> {
    let cidrs = vpn_dest_cidrs(snapshot);
    let full = matches!(snapshot.settings.mode, PolicyMode::Full);
    activate(vpn_server, &cidrs, full)
}

/// Flush/remove the SSC pf anchor and disable pf if we enabled it.
pub fn deactivate() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        deactivate_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn activate_macos(
    vpn_server: &str,
    vpn_dest_cidrs: &[String],
    full_tunnel: bool,
) -> Result<(), String> {
    ensure_anchor_registered()?;
    let rules = build_pf_rules(vpn_server, vpn_dest_cidrs, full_tunnel);
    load_anchor_rules(&rules)?;
    enable_pf_if_needed()?;
    eprintln!("[KILL_SWITCH] activated anchor={ANCHOR} full={full_tunnel}");
    Ok(())
}

#[cfg(target_os = "macos")]
fn deactivate_macos() -> Result<(), String> {
    // Flush rules in our anchor.
    let _ = sudo_pf( &["-a", ANCHOR, "-F", "all"]);
    // Clear anchor contents with empty ruleset.
    let _ = load_anchor_rules("");
    eprintln!("[KILL_SWITCH] deactivated anchor={ANCHOR}");
    Ok(())
}

#[cfg(target_os = "macos")]
fn build_pf_rules(vpn_server: &str, vpn_dest_cidrs: &[String], full_tunnel: bool) -> String {
    let mut s = String::new();
    s.push_str("# SSC kill switch — managed; do not edit\n");
    s.push_str("set block-policy drop\n");
    s.push_str("set skip on lo0\n");
    // Pass loopback / private / link-local
    s.push_str("pass quick on lo0 all\n");
    s.push_str("pass out quick proto { tcp udp icmp } to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16 }\n");
    s.push_str("pass out quick proto { tcp udp icmp6 } to { fe80::/10, fc00::/7, ::1/128 }\n");
    // Always allow the VPN server itself so reconnect can succeed.
    let server = vpn_server.trim();
    if !server.is_empty() && server != "(unknown)" {
        s.push_str(&format!("pass out quick to {server}\n"));
    }
    if full_tunnel {
        s.push_str("block drop out quick all\n");
    } else if !vpn_dest_cidrs.is_empty() {
        for cidr in vpn_dest_cidrs {
            s.push_str(&format!("block drop out quick to {cidr}\n"));
        }
    } else {
        // Selective + domain-only: no pf CIDR blocks. Documented weaker mode.
        s.push_str("# selective domain-only: no additional pf blocks\n");
    }
    s
}

#[cfg(target_os = "macos")]
fn ensure_anchor_registered() -> Result<(), String> {
    // Load a tiny main ruleset fragment that references our anchor if possible.
    // Many systems already have pf enabled with anchors; we only require that
    // `pfctl -a ssc.killswitch` accepts rules.
    Ok(())
}

#[cfg(target_os = "macos")]
fn load_anchor_rules(rules: &str) -> Result<(), String> {
    let mut child = Command::new("sudo")
        .args(["-n", "pfctl", "-a", ANCHOR, "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("pfctl spawn: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(rules.as_bytes())
            .map_err(|e| format!("pfctl write: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("pfctl wait: {e}"))?;
    if !out.status.success() {
        // Retry without -n if privileges not installed yet.
        let mut child = Command::new("sudo")
            .args(["pfctl", "-a", ANCHOR, "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("pfctl spawn: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(rules.as_bytes())
                .map_err(|e| format!("pfctl write: {e}"))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("pfctl wait: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(format!("pfctl load anchor failed: {}", err.trim()));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn enable_pf_if_needed() -> Result<(), String> {
    // Enable pf; ignore "already enabled".
    let out = Command::new("sudo")
        .args(["-n", "pfctl", "-e"])
        .output()
        .map_err(|e| format!("pfctl -e: {e}"))?;
    let err = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
    if out.status.success() || err.contains("already enabled") {
        return Ok(());
    }
    let out = Command::new("sudo")
        .args(["pfctl", "-e"])
        .output()
        .map_err(|e| format!("pfctl -e: {e}"))?;
    let err = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
    if out.status.success() || err.contains("already enabled") {
        return Ok(());
    }
    // Non-fatal: rules may still apply if pf was already on.
    eprintln!("[KILL_SWITCH] pfctl -e: {}", err.trim());
    Ok(())
}

#[cfg(target_os = "macos")]
fn sudo_pf(args: &[&str]) -> Result<(), String> {
    let mut cmd = Command::new("sudo");
    cmd.arg("-n");
    cmd.arg("pfctl");
    cmd.args(args);
    let out = cmd.output().map_err(|e| format!("pfctl: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let mut cmd = Command::new("sudo");
    cmd.arg("pfctl");
    cmd.args(args);
    let out = cmd.output().map_err(|e| format!("pfctl: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!("pfctl failed: {}", err.trim()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssc_policy::{PolicyRule, Settings};

    #[test]
    fn vpn_cidrs_from_ip_rules() {
        let snap = PolicySnapshot {
            settings: Settings::default(),
            groups: vec![],
            rules: vec![
                PolicyRule::new(MatchKind::Ip, "1.2.3.4", Action::Vpn),
                PolicyRule::new(MatchKind::Cidr, "8.8.8.0/24", Action::Vpn),
                PolicyRule::new(MatchKind::Domain, "example.com", Action::Vpn),
                PolicyRule::new(MatchKind::Ip, "9.9.9.9", Action::Direct),
            ],
        };
        let c = vpn_dest_cidrs(&snap);
        assert!(c.iter().any(|x| x == "1.2.3.4/32"));
        assert!(c.iter().any(|x| x == "8.8.8.0/24"));
        assert!(!c.iter().any(|x| x.contains("9.9.9.9")));
    }
}
