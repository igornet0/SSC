//! Deterministic rule matching with precedence.

use crate::model::{Action, MatchKind, PolicyMode, PolicyRule, PolicySnapshot, RuleMatch};
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

/// Evaluate destinations against a policy snapshot.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    snapshot: PolicySnapshot,
}

impl PolicyEngine {
    pub fn new(snapshot: PolicySnapshot) -> Self {
        Self { snapshot }
    }

    pub fn snapshot(&self) -> &PolicySnapshot {
        &self.snapshot
    }

    pub fn mode(&self) -> PolicyMode {
        self.snapshot.settings.mode
    }

    pub fn decide(&self, dest: &RuleMatch) -> Action {
        self.decide_with_rule(dest).0
    }

    /// Decide action and return the matched rule when one applied (else mode default).
    pub fn decide_with_rule(&self, dest: &RuleMatch) -> (Action, Option<PolicyRule>) {
        if let Some(rule) = self.match_rule(dest) {
            return (rule.action, Some(rule.clone()));
        }
        (self.snapshot.settings.mode.default_action(), None)
    }

    fn enabled_rules(&self) -> impl Iterator<Item = &PolicyRule> {
        self.snapshot.active_rules()
    }

    fn match_rule(&self, dest: &RuleMatch) -> Option<&PolicyRule> {
        // 1. Exact domain
        if let Some(domain) = dest.domain.as_deref() {
            let host = normalize_domain(domain);
            for r in self.enabled_rules() {
                if r.kind == MatchKind::Domain && is_exact_domain(&r.value) {
                    if normalize_domain(&r.value) == host {
                        return Some(r);
                    }
                }
            }
            // 2. Domain wildcard — longest suffix wins
            let mut best: Option<(&PolicyRule, usize)> = None;
            for r in self.enabled_rules() {
                if r.kind != MatchKind::Domain {
                    continue;
                }
                if let Some(suffix) = wildcard_suffix(&r.value) {
                    let suf = normalize_domain(suffix);
                    if domain_matches_suffix(&host, &suf) {
                        let score = suf.len();
                        if best.map(|(_, s)| score > s).unwrap_or(true) {
                            best = Some((r, score));
                        }
                    }
                }
            }
            if let Some((r, _)) = best {
                return Some(r);
            }
        }

        // 3. Exact IP
        if let Some(ip) = dest.ip {
            for r in self.enabled_rules() {
                if r.kind == MatchKind::Ip {
                    if let Ok(rule_ip) = IpAddr::from_str(r.value.trim()) {
                        if rule_ip == ip {
                            return Some(r);
                        }
                    }
                }
            }
            // 4. CIDR — most specific prefix wins
            let mut best: Option<(&PolicyRule, u8)> = None;
            for r in self.enabled_rules() {
                if r.kind != MatchKind::Cidr {
                    continue;
                }
                if let Ok(net) = IpNet::from_str(r.value.trim()) {
                    if net.contains(&ip) {
                        let prefix = net.prefix_len();
                        if best.map(|(_, p)| prefix > p).unwrap_or(true) {
                            best = Some((r, prefix));
                        }
                    }
                }
            }
            if let Some((r, _)) = best {
                return Some(r);
            }
        }

        // 5. Protocol/port (optional MVP)
        if let (Some(proto), Some(port)) = (dest.protocol.as_deref(), dest.port) {
            let needle = format!("{}:{}", proto.to_ascii_lowercase(), port);
            for r in self.enabled_rules() {
                if r.kind == MatchKind::Port && r.value.trim().eq_ignore_ascii_case(&needle) {
                    return Some(r);
                }
            }
        }

        None
    }
}

fn normalize_domain(d: &str) -> String {
    d.trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn is_exact_domain(value: &str) -> bool {
    let v = value.trim();
    !v.starts_with("*.") && !v.starts_with('.')
}

fn wildcard_suffix(value: &str) -> Option<&str> {
    let v = value.trim();
    if let Some(rest) = v.strip_prefix("*.") {
        return Some(rest);
    }
    if let Some(rest) = v.strip_prefix('.') {
        return Some(rest);
    }
    None
}

fn domain_matches_suffix(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MatchKind, PolicyRule, Settings};

    fn engine(mode: PolicyMode, rules: Vec<PolicyRule>) -> PolicyEngine {
        PolicyEngine::new(PolicySnapshot {
            settings: Settings {
                mode,
                ..Settings::default()
            },
            groups: vec![],
            rules,
        })
    }

    #[test]
    fn exact_domain() {
        let e = engine(
            PolicyMode::Selective,
            vec![PolicyRule::new(MatchKind::Domain, "google.com", Action::Vpn)],
        );
        assert_eq!(e.decide(&RuleMatch::domain("google.com")), Action::Vpn);
        assert_eq!(e.decide(&RuleMatch::domain("www.google.com")), Action::Direct);
    }

    #[test]
    fn wildcard_domain() {
        let e = engine(
            PolicyMode::Selective,
            vec![PolicyRule::new(
                MatchKind::Domain,
                "*.google.com",
                Action::Vpn,
            )],
        );
        assert_eq!(e.decide(&RuleMatch::domain("mail.google.com")), Action::Vpn);
        assert_eq!(
            e.decide(&RuleMatch::domain("youtube.google.com")),
            Action::Vpn
        );
        assert_eq!(e.decide(&RuleMatch::domain("google.com")), Action::Vpn);
        assert_eq!(e.decide(&RuleMatch::domain("example.com")), Action::Direct);
    }

    #[test]
    fn precedence_exact_over_wildcard() {
        let e = engine(
            PolicyMode::Selective,
            vec![
                PolicyRule::new(MatchKind::Domain, "*.google.com", Action::Vpn),
                PolicyRule::new(MatchKind::Domain, "mail.google.com", Action::Direct),
            ],
        );
        assert_eq!(
            e.decide(&RuleMatch::domain("mail.google.com")),
            Action::Direct
        );
        assert_eq!(
            e.decide(&RuleMatch::domain("youtube.google.com")),
            Action::Vpn
        );
    }

    #[test]
    fn exact_ip() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let e = engine(
            PolicyMode::Selective,
            vec![PolicyRule::new(MatchKind::Ip, "8.8.8.8", Action::Vpn)],
        );
        assert_eq!(e.decide(&RuleMatch::ip(ip)), Action::Vpn);
        assert_eq!(
            e.decide(&RuleMatch::ip("1.1.1.1".parse().unwrap())),
            Action::Direct
        );
    }

    #[test]
    fn cidr_most_specific() {
        let e = engine(
            PolicyMode::Selective,
            vec![
                PolicyRule::new(MatchKind::Cidr, "10.0.0.0/8", Action::Vpn),
                PolicyRule::new(MatchKind::Cidr, "10.1.0.0/16", Action::Direct),
            ],
        );
        assert_eq!(
            e.decide(&RuleMatch::ip("10.1.2.3".parse().unwrap())),
            Action::Direct
        );
        assert_eq!(
            e.decide(&RuleMatch::ip("10.2.0.1".parse().unwrap())),
            Action::Vpn
        );
    }

    #[test]
    fn default_selective_and_full() {
        let sel = engine(PolicyMode::Selective, vec![]);
        assert_eq!(sel.decide(&RuleMatch::domain("x.com")), Action::Direct);
        let full = engine(PolicyMode::Full, vec![]);
        assert_eq!(full.decide(&RuleMatch::domain("x.com")), Action::Vpn);
    }

    #[test]
    fn disabled_rules_skipped() {
        let mut r = PolicyRule::new(MatchKind::Domain, "google.com", Action::Vpn);
        r.enabled = false;
        let e = engine(PolicyMode::Selective, vec![r]);
        assert_eq!(e.decide(&RuleMatch::domain("google.com")), Action::Direct);
    }

    #[test]
    fn ip_before_cidr() {
        let e = engine(
            PolicyMode::Selective,
            vec![
                PolicyRule::new(MatchKind::Cidr, "8.8.8.0/24", Action::Direct),
                PolicyRule::new(MatchKind::Ip, "8.8.8.8", Action::Vpn),
            ],
        );
        assert_eq!(
            e.decide(&RuleMatch::ip("8.8.8.8".parse().unwrap())),
            Action::Vpn
        );
    }

    #[test]
    fn decide_with_rule_returns_match() {
        let e = engine(
            PolicyMode::Selective,
            vec![PolicyRule::new(MatchKind::Domain, "google.com", Action::Vpn)],
        );
        let (action, rule) = e.decide_with_rule(&RuleMatch::domain("google.com"));
        assert_eq!(action, Action::Vpn);
        assert_eq!(rule.unwrap().value, "google.com");
        let (action2, rule2) = e.decide_with_rule(&RuleMatch::domain("other.com"));
        assert_eq!(action2, Action::Direct);
        assert!(rule2.is_none());
    }
}
