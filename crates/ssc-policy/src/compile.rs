//! Compile PolicySnapshot into sing-box route rule fragments.

use crate::model::{Action, MatchKind, PolicyMode, PolicyRule, PolicySnapshot};
use serde_json::{json, Value};

/// Result of compiling policy for sing-box config generation.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    /// Rules inserted after sniff / dns / private / server-bypass.
    pub route_rules: Vec<Value>,
    /// Final outbound tag: `direct` or `proxy`.
    pub final_outbound: String,
    /// Optional block outbound needed.
    pub need_block_outbound: bool,
}

pub fn compile_route_rules(snapshot: &PolicySnapshot) -> CompiledPolicy {
    let mut route_rules = Vec::new();
    let mut need_block = false;

    for rule in snapshot.active_rules() {
        match rule.action {
            Action::Block => {
                if let Some(mut obj) = rule_to_singbox(rule) {
                    // sing-box 1.11+: reject action (no block outbound)
                    obj["action"] = json!("reject");
                    need_block = true;
                    route_rules.push(obj);
                }
            }
            Action::Direct | Action::Vpn => {
                if let Some(mut obj) = rule_to_singbox(rule) {
                    let outbound = match rule.action {
                        Action::Direct => "direct",
                        Action::Vpn => "proxy",
                        Action::Block => unreachable!(),
                    };
                    obj["outbound"] = json!(outbound);
                    route_rules.push(obj);
                }
            }
        }
    }

    // Kill switch (architectural): when enabled under selective mode with VPN rules,
    // we still rely on reconnect; block outbound is prepared for future use.
    if snapshot.settings.kill_switch {
        need_block = true;
    }

    let final_outbound = match snapshot.settings.mode {
        PolicyMode::Selective => "direct",
        PolicyMode::Full => "proxy",
    }
    .to_string();

    CompiledPolicy {
        route_rules,
        final_outbound,
        need_block_outbound: need_block,
    }
}

fn rule_to_singbox(rule: &PolicyRule) -> Option<Value> {
    match rule.kind {
        MatchKind::Domain => {
            let v = rule.value.trim();
            if let Some(suffix) = v.strip_prefix("*.") {
                Some(json!({ "domain_suffix": [normalize_domain(suffix)] }))
            } else if let Some(suffix) = v.strip_prefix('.') {
                Some(json!({ "domain_suffix": [normalize_domain(suffix)] }))
            } else {
                Some(json!({ "domain": [normalize_domain(v)] }))
            }
        }
        MatchKind::Ip => {
            let ip = rule.value.trim();
            // sing-box wants CIDR form
            let cidr = if ip.contains(':') {
                format!("{ip}/128")
            } else {
                format!("{ip}/32")
            };
            Some(json!({ "ip_cidr": [cidr] }))
        }
        MatchKind::Cidr => Some(json!({ "ip_cidr": [rule.value.trim()] })),
        MatchKind::Port => {
            // e.g. tcp:443 — deferred classification; emit port-only if parseable
            let v = rule.value.trim().to_ascii_lowercase();
            if let Some((proto, port)) = v.split_once(':') {
                if let Ok(p) = port.parse::<u16>() {
                    let mut o = json!({ "port": p });
                    if proto == "tcp" || proto == "udp" {
                        o["network"] = json!(proto);
                    }
                    return Some(o);
                }
            }
            None
        }
    }
}

fn normalize_domain(d: &str) -> String {
    d.trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PolicyRule, Settings};

    #[test]
    fn selective_compiles_final_direct() {
        let snap = PolicySnapshot {
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
        let c = compile_route_rules(&snap);
        assert_eq!(c.final_outbound, "direct");
        assert_eq!(c.route_rules.len(), 1);
        assert_eq!(c.route_rules[0]["outbound"], "proxy");
        assert_eq!(c.route_rules[0]["domain"], json!(["google.com"]));
    }

    #[test]
    fn wildcard_becomes_domain_suffix() {
        let snap = PolicySnapshot {
            settings: Settings::default(),
            groups: vec![],
            rules: vec![PolicyRule::new(
                MatchKind::Domain,
                "*.youtube.com",
                Action::Vpn,
            )],
        };
        let c = compile_route_rules(&snap);
        assert_eq!(
            c.route_rules[0]["domain_suffix"],
            json!(["youtube.com"])
        );
    }

    #[test]
    fn full_mode_final_proxy() {
        let snap = PolicySnapshot {
            settings: Settings {
                mode: PolicyMode::Full,
                ..Settings::default()
            },
            groups: vec![],
            rules: vec![PolicyRule::new(
                MatchKind::Domain,
                "github.com",
                Action::Direct,
            )],
        };
        let c = compile_route_rules(&snap);
        assert_eq!(c.final_outbound, "proxy");
        assert_eq!(c.route_rules[0]["outbound"], "direct");
    }
}
