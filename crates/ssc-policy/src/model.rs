//! Policy data model.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Direct,
    Vpn,
    Block,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Direct => "direct",
            Action::Vpn => "vpn",
            Action::Block => "block",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "direct" => Some(Action::Direct),
            "vpn" | "proxy" => Some(Action::Vpn),
            "block" => Some(Action::Block),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    /// Default DIRECT; selected destinations → VPN.
    Selective,
    /// Default VPN; exceptions → DIRECT.
    Full,
}

impl PolicyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyMode::Selective => "selective",
            PolicyMode::Full => "full",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "selective" | "select" => Some(PolicyMode::Selective),
            "full" => Some(PolicyMode::Full),
            _ => None,
        }
    }

    pub fn default_action(self) -> Action {
        match self {
            PolicyMode::Selective => Action::Direct,
            PolicyMode::Full => Action::Vpn,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchKind {
    Domain,
    Ip,
    Cidr,
    /// Architected for later: e.g. `tcp:443`
    Port,
}

impl MatchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MatchKind::Domain => "domain",
            MatchKind::Ip => "ip",
            MatchKind::Cidr => "cidr",
            MatchKind::Port => "port",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "domain" => Some(MatchKind::Domain),
            "ip" => Some(MatchKind::Ip),
            "cidr" => Some(MatchKind::Cidr),
            "port" => Some(MatchKind::Port),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub kind: MatchKind,
    /// Domain, IP, CIDR, or `tcp:443`-style port matcher.
    pub value: String,
    pub action: Action,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional rule group. If set, the group must also be enabled for the rule to apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    #[serde(default)]
    pub created_at_ms: i64,
}

fn default_true() -> bool {
    true
}

impl PolicyRule {
    pub fn new(kind: MatchKind, value: impl Into<String>, action: Action) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            kind,
            value: value.into(),
            action,
            enabled: true,
            group_id: None,
            created_at_ms: now_ms(),
        }
    }

    pub fn with_group(mut self, group_id: impl Into<String>) -> Self {
        self.group_id = Some(group_id.into());
        self
    }
}

/// Named set of rules that can be toggled on/off together (independent of VPN profile).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleGroup {
    pub id: String,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub created_at_ms: i64,
}

impl RuleGroup {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.into(),
            enabled: true,
            created_at_ms: now_ms(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_mode")]
    pub mode: PolicyMode,
    /// Kill switch: when VPN drops, block VPN-only destinations (architectural).
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,
    #[serde(default = "default_retry_ms")]
    pub reconnect_delay_ms: u64,
    #[serde(default = "default_max_retry_ms")]
    pub reconnect_max_delay_ms: u64,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    /// Install LaunchAgent so the local API starts at login.
    #[serde(default)]
    pub launch_at_login: bool,
    /// After the gateway starts, connect the active profile automatically.
    #[serde(default)]
    pub connect_automatically: bool,
}

fn default_mode() -> PolicyMode {
    PolicyMode::Selective
}

fn default_retry_ms() -> u64 {
    1000
}

fn default_max_retry_ms() -> u64 {
    30_000
}

fn default_api_port() -> u16 {
    8765
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: PolicyMode::Selective,
            kill_switch: false,
            auto_reconnect: true,
            reconnect_delay_ms: default_retry_ms(),
            reconnect_max_delay_ms: default_max_retry_ms(),
            api_port: default_api_port(),
            launch_at_login: false,
            connect_automatically: false,
        }
    }
}

/// Full persisted policy document (global — not per VPN profile).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicySnapshot {
    #[serde(default)]
    pub settings: Settings,
    /// Toggleable rule packs (YouTube, Work, …). Independent of the active VPN profile.
    #[serde(default)]
    pub groups: Vec<RuleGroup>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

impl PolicySnapshot {
    /// Rule applies when it is enabled and its group (if any) is enabled / missing.
    pub fn rule_is_active(&self, rule: &PolicyRule) -> bool {
        if !rule.enabled {
            return false;
        }
        match rule.group_id.as_deref() {
            None => true,
            Some(gid) => self
                .groups
                .iter()
                .find(|g| g.id == gid)
                .map(|g| g.enabled)
                // Orphan group_id: treat as active so rules are not silently dropped.
                .unwrap_or(true),
        }
    }

    pub fn active_rules(&self) -> impl Iterator<Item = &PolicyRule> {
        self.rules.iter().filter(|r| self.rule_is_active(r))
    }
}

/// Destination described for evaluation (tests + future port matching).
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub domain: Option<String>,
    pub ip: Option<std::net::IpAddr>,
    pub protocol: Option<String>,
    pub port: Option<u16>,
}

impl RuleMatch {
    pub fn domain(d: impl Into<String>) -> Self {
        Self {
            domain: Some(d.into()),
            ip: None,
            protocol: None,
            port: None,
        }
    }

    pub fn ip(ip: std::net::IpAddr) -> Self {
        Self {
            domain: None,
            ip: Some(ip),
            protocol: None,
            port: None,
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
