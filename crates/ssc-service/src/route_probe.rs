//! Destination route probe: resolve + PolicyEngine decide + interface heuristic.

use serde::{Deserialize, Serialize};
use ssc_policy::{load_policy, Action, PolicyEngine, PolicyRule, RuleMatch};
use std::net::{IpAddr, ToSocketAddrs};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRuleView {
    pub id: String,
    pub kind: String,
    pub value: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteProbeResult {
    pub destination: String,
    pub resolved_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<MatchedRuleView>,
    /// vpn / direct / block
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    pub policy_mode: String,
    pub explanation: String,
}

impl From<&PolicyRule> for MatchedRuleView {
    fn from(r: &PolicyRule) -> Self {
        Self {
            id: r.id.clone(),
            kind: r.kind.as_str().to_string(),
            value: r.value.clone(),
            action: r.action.as_str().to_string(),
        }
    }
}

/// Probe how a destination would be routed under the active policy.
pub fn probe_destination(dest: &str) -> RouteProbeResult {
    let dest = dest.trim();
    let policy = load_policy().unwrap_or_default();
    let engine = PolicyEngine::new(policy.clone());
    let mode = policy.settings.mode.as_str().to_string();

    let (domain, ips) = resolve_destination(dest);
    let mut resolved_ips: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
    resolved_ips.sort();
    resolved_ips.dedup();

    // Prefer domain match; also try first resolved IP if no domain rule wins.
    let mut matched_rule: Option<PolicyRule> = None;
    let mut action = engine.mode().default_action();

    if let Some(ref d) = domain {
        let (a, rule) = engine.decide_with_rule(&RuleMatch::domain(d.clone()));
        action = a;
        matched_rule = rule;
    }

    if matched_rule.is_none() {
        if let Some(ip) = ips.first().copied() {
            let (a, rule) = engine.decide_with_rule(&RuleMatch::ip(ip));
            // If we already have a domain-based default and no IP rule, keep domain result.
            if rule.is_some() || domain.is_none() {
                action = a;
                matched_rule = rule;
            }
        }
    }

    // Literal IP destination with no domain.
    if domain.is_none() {
        if let Ok(ip) = dest.parse::<IpAddr>() {
            let (a, rule) = engine.decide_with_rule(&RuleMatch::ip(ip));
            action = a;
            matched_rule = rule;
            if resolved_ips.is_empty() {
                resolved_ips.push(ip.to_string());
            }
        }
    }

    let connected = ssc_runtime::is_connected();
    let interface = match action {
        Action::Vpn if connected => Some(guess_utun_iface().unwrap_or_else(|| "utun".into())),
        Action::Vpn => Some("utun (when connected)".into()),
        Action::Direct => ssc_core::primary_interface(),
        Action::Block => None,
    };

    let explanation = match (&matched_rule, action) {
        (Some(r), _) => format!(
            "Matched rule {} ({} {} → {})",
            r.id,
            r.kind.as_str(),
            r.value,
            r.action.as_str()
        ),
        (None, Action::Vpn) => format!("No rule matched; mode `{mode}` defaults to VPN"),
        (None, Action::Direct) => format!("No rule matched; mode `{mode}` defaults to DIRECT"),
        (None, Action::Block) => "Blocked by policy".into(),
    };

    RouteProbeResult {
        destination: dest.to_string(),
        resolved_ips,
        matched_rule: matched_rule.as_ref().map(MatchedRuleView::from),
        action: action.as_str().to_string(),
        interface,
        policy_mode: mode,
        explanation,
    }
}

fn resolve_destination(dest: &str) -> (Option<String>, Vec<IpAddr>) {
    let dest = dest.trim();
    if dest.is_empty() {
        return (None, vec![]);
    }
    if let Ok(ip) = dest.parse::<IpAddr>() {
        return (None, vec![ip]);
    }
    // Strip optional port for domain resolution.
    let host = if let Some((h, port)) = dest.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') {
            h
        } else {
            dest
        }
    } else {
        dest
    };
    let domain = Some(host.trim_end_matches('.').to_ascii_lowercase());
    let mut ips = Vec::new();
    let probe = format!("{host}:0");
    if let Ok(iter) = probe.to_socket_addrs() {
        for sa in iter {
            ips.push(sa.ip());
        }
    }
    (domain, ips)
}

fn guess_utun_iface() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let text = crate::cmdutil::run_timed_ok(
            "ifconfig",
            &[],
            crate::cmdutil::DEFAULT_CMD_TIMEOUT,
        )
        .ok()?;
        let mut current = None::<String>;
        for line in text.lines() {
            if !line.starts_with('\t') && !line.starts_with(' ') {
                current = line.split(':').next().map(|s| s.trim().to_string());
            } else if line.contains("172.19.0.1") {
                return current;
            }
        }
        None
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some("tun0".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssc_policy::{
        save_policy, Action, MatchKind, PolicyMode, PolicyRule, PolicySnapshot, Settings,
    };

    #[test]
    fn probe_ip_literal() {
        let _g = crate::test_env_lock();
        let dir = std::env::temp_dir().join(format!("ssc-probe-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("SSC_CONFIG_DIR", &dir);
        std::env::remove_var("SSC_ACTIVE_PROFILE");
        let snap = PolicySnapshot {
            settings: Settings {
                mode: PolicyMode::Selective,
                ..Settings::default()
            },
            groups: vec![],
            rules: vec![PolicyRule::new(MatchKind::Ip, "8.8.8.8", Action::Vpn)],
        };
        save_policy(&snap).unwrap();
        let r = probe_destination("8.8.8.8");
        assert_eq!(r.action, "vpn");
        assert!(r.matched_rule.is_some());
        std::env::remove_var("SSC_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
