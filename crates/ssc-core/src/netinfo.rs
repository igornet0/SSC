//! Detect primary interface, gateway, and local CIDRs (macOS-focused).

use std::net::Ipv4Addr;
use std::process::Command;

/// Snapshot of the primary network path used for LAN exclusions / route probe.
#[derive(Debug, Clone, Default)]
pub struct NetInfo {
    pub primary_iface: Option<String>,
    pub gateway: Option<String>,
    pub local_cidrs: Vec<String>,
}

/// CIDRs that must never enter TUN (`route_exclude_address`) and stay DIRECT:
/// loopback (IPv4+IPv6), link-local, detected LAN, gateway /32.
///
/// Excluding `127.0.0.0/8` / `::1` is required for Electron apps (e.g. Cursor):
/// TUN capture of loopback breaks their localhost IPC / extension host.
pub fn local_exclusions() -> Vec<String> {
    let mut out: Vec<String> = vec![
        "127.0.0.0/8".into(),
        "::1/128".into(),
        "169.254.0.0/16".into(),
        "fe80::/10".into(),
    ];
    let info = detect_netinfo();
    for cidr in info.local_cidrs {
        push_unique(&mut out, cidr);
    }
    if let Some(gw) = info.gateway {
        if gw.parse::<std::net::IpAddr>().is_ok() {
            let cidr = if gw.contains(':') {
                format!("{gw}/128")
            } else {
                format!("{gw}/32")
            };
            push_unique(&mut out, cidr);
        }
    }
    out
}

/// Best-effort primary interface name (e.g. `en0`).
pub fn primary_interface() -> Option<String> {
    detect_netinfo().primary_iface
}

/// Best-effort default gateway IP.
pub fn gateway_ip() -> Option<String> {
    detect_netinfo().gateway
}

pub fn detect_netinfo() -> NetInfo {
    #[cfg(target_os = "macos")]
    {
        detect_netinfo_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        NetInfo::default()
    }
}

#[cfg(target_os = "macos")]
fn detect_netinfo_macos() -> NetInfo {
    let mut info = NetInfo::default();
    let route = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok();
    if let Some(out) = route {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("gateway:") {
                let gw = rest.trim();
                if !gw.is_empty() && gw != "link#" {
                    info.gateway = Some(gw.to_string());
                }
            }
            if let Some(rest) = line.strip_prefix("interface:") {
                let iface = rest.trim();
                if !iface.is_empty() {
                    info.primary_iface = Some(iface.to_string());
                }
            }
        }
    }

    if let Some(ref iface) = info.primary_iface {
        if let Some(cidrs) = ifconfig_cidrs(iface) {
            info.local_cidrs = cidrs;
        }
    }
    info
}

#[cfg(target_os = "macos")]
fn ifconfig_cidrs(iface: &str) -> Option<Vec<String>> {
    let out = Command::new("ifconfig").arg(iface).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut cidrs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // inet 192.168.1.10 netmask 0xffffff00 broadcast ...
        if !line.starts_with("inet ") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let ip = parts[1];
        if ip == "127.0.0.1" {
            continue;
        }
        let Some(mask_idx) = parts.iter().position(|p| *p == "netmask") else {
            continue;
        };
        let mask = parts.get(mask_idx + 1)?;
        if let Some(cidr) = ipv4_cidr(ip, mask) {
            cidrs.push(cidr);
        }
    }
    if cidrs.is_empty() {
        None
    } else {
        Some(cidrs)
    }
}

fn ipv4_cidr(ip: &str, netmask: &str) -> Option<String> {
    let addr: Ipv4Addr = ip.parse().ok()?;
    let prefix = parse_netmask_prefix(netmask)?;
    let octets = addr.octets();
    let ip_u32 = u32::from_be_bytes(octets);
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    let network = Ipv4Addr::from(ip_u32 & mask);
    Some(format!("{network}/{prefix}"))
}

fn parse_netmask_prefix(netmask: &str) -> Option<u8> {
    let m = netmask.trim();
    if let Some(hex) = m.strip_prefix("0x").or_else(|| m.strip_prefix("0X")) {
        let val = u32::from_str_radix(hex, 16).ok()?;
        return Some(val.count_ones() as u8);
    }
    if let Ok(addr) = m.parse::<Ipv4Addr>() {
        return Some(u32::from(addr).count_ones() as u8);
    }
    None
}

fn push_unique(out: &mut Vec<String>, value: String) {
    if !out.iter().any(|x| x == &value) {
        out.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_exclusions_always_include_loopback_and_link_local() {
        let ex = local_exclusions();
        assert!(ex.iter().any(|c| c == "127.0.0.0/8"));
        assert!(ex.iter().any(|c| c == "::1/128"));
        assert!(ex.iter().any(|c| c == "169.254.0.0/16"));
    }

    #[test]
    fn ipv4_cidr_from_hex_mask() {
        let c = ipv4_cidr("192.168.1.42", "0xffffff00").unwrap();
        assert_eq!(c, "192.168.1.0/24");
    }
}
