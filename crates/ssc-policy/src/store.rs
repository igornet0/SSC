//! Persist global policy under SSC config dir (`policy.json`).
//!
//! Rules and groups are **not** tied to the active VPN profile. Older
//! per-profile files under `policies/{id}.json` are merged once into
//! `policy.json` on load.

use crate::model::{
    Action, MatchKind, PolicyMode, PolicyRule, PolicySnapshot, RuleGroup, Settings,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyStoreError {
    #[error("{0}")]
    Message(String),
}

impl From<String> for PolicyStoreError {
    fn from(s: String) -> Self {
        PolicyStoreError::Message(s)
    }
}

impl From<&str> for PolicyStoreError {
    fn from(s: &str) -> Self {
        PolicyStoreError::Message(s.to_string())
    }
}

/// Global policy path (`policy.json`).
pub fn policy_path() -> Result<PathBuf, PolicyStoreError> {
    let dir = ssc_config_dir()?;
    Ok(dir.join("policy.json"))
}

/// Legacy per-profile path (read-only migration source).
pub fn policy_path_for(profile_id: &str) -> Result<PathBuf, PolicyStoreError> {
    let id = sanitize_profile_id(profile_id)?;
    Ok(ssc_config_dir()?
        .join("policies")
        .join(format!("{id}.json")))
}

fn ssc_config_dir() -> Result<PathBuf, PolicyStoreError> {
    if let Ok(v) = std::env::var("SSC_CONFIG_DIR") {
        let t = v.trim();
        if !t.is_empty() {
            let p = PathBuf::from(t);
            std::fs::create_dir_all(&p).map_err(|e| format!("create config dir: {e}"))?;
            return Ok(p);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let p = dirs_fallback_macos()?;
        std::fs::create_dir_all(&p).map_err(|e| format!("create config dir: {e}"))?;
        Ok(p)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let base = std::env::var("HOME")
            .ok()
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
            .ok_or_else(|| "cannot resolve home".to_string())?;
        let p = base.join(".config").join("ssc");
        std::fs::create_dir_all(&p).map_err(|e| format!("create config dir: {e}"))?;
        Ok(p)
    }
}

#[cfg(target_os = "macos")]
fn dirs_fallback_macos() -> Result<PathBuf, PolicyStoreError> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("ssc"))
}

/// Active profile id (still used elsewhere; policy itself is global).
pub fn active_profile_id() -> Option<String> {
    for key in ["SSC_ACTIVE_PROFILE", "SSC_PROFILE_ID"] {
        if let Ok(v) = std::env::var(key) {
            let t = v.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    let path = ssc_config_dir().ok()?.join("profiles.json");
    if !path.is_file() {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("active_id")
        .and_then(|x| x.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn sanitize_profile_id(profile_id: &str) -> Result<String, PolicyStoreError> {
    let id = profile_id.trim();
    if id.is_empty() {
        return Err("profile id empty".into());
    }
    if id.contains('/') || id.contains('\\') || id.contains("..") {
        return Err("invalid profile id".into());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("invalid profile id".into());
    }
    Ok(id.to_string())
}

fn load_from_path(path: &Path) -> Result<PolicySnapshot, PolicyStoreError> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read policy: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("parse policy: {e}").into())
}

/// Load a policy snapshot from an explicit file path.
///
/// Used by VPN instances, each of which owns an isolated policy file.
/// Missing files yield [`PolicySnapshot::default`].
pub fn load_policy_at(path: &Path) -> Result<PolicySnapshot, PolicyStoreError> {
    if !path.is_file() {
        return Ok(PolicySnapshot::default());
    }
    load_from_path(path)
}

/// Persist a policy snapshot to an explicit file path (created with mode 0600).
pub fn save_policy_at(path: &Path, snap: &PolicySnapshot) -> Result<(), PolicyStoreError> {
    write_policy_file(path, snap)
}

fn write_policy_file(path: &Path, snap: &PolicySnapshot) -> Result<(), PolicyStoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create policy dir: {e}"))?;
    }
    let text = serde_json::to_string_pretty(snap).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| format!("write policy: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn rule_fingerprint(r: &PolicyRule) -> String {
    format!(
        "{}|{}|{}",
        r.kind.as_str(),
        r.value.trim().to_ascii_lowercase(),
        r.action.as_str()
    )
}

/// Merge unique rules/groups from `other` into `base` (settings kept from base if present).
fn merge_snapshots(base: &mut PolicySnapshot, other: PolicySnapshot) {
    let mut seen_rules: HashSet<String> = base.rules.iter().map(rule_fingerprint).collect();
    let mut seen_groups: HashSet<String> = base
        .groups
        .iter()
        .map(|g| g.name.trim().to_ascii_lowercase())
        .collect();
    // Remap other group ids → existing groups with the same name.
    let mut id_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for g in other.groups {
        let key = g.name.trim().to_ascii_lowercase();
        if let Some(existing) = base
            .groups
            .iter()
            .find(|x| x.name.trim().to_ascii_lowercase() == key)
        {
            id_map.insert(g.id.clone(), existing.id.clone());
        } else if seen_groups.insert(key) {
            id_map.insert(g.id.clone(), g.id.clone());
            base.groups.push(g);
        }
    }
    for mut r in other.rules {
        if let Some(gid) = r.group_id.clone() {
            if let Some(mapped) = id_map.get(&gid) {
                r.group_id = Some(mapped.clone());
            }
        }
        let fp = rule_fingerprint(&r);
        if seen_rules.insert(fp) {
            base.rules.push(r);
        }
    }
}

fn collect_legacy_profile_policies(dir: &Path) -> Vec<PolicySnapshot> {
    let pol_dir = dir.join("policies");
    let Ok(rd) = std::fs::read_dir(&pol_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for ent in rd.flatten() {
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(snap) = load_from_path(&path) {
            out.push(snap);
        }
    }
    out
}

/// Load global policy. One-time merge of legacy per-profile `policies/*.json` into `policy.json`.
pub fn load_policy() -> Result<PolicySnapshot, PolicyStoreError> {
    let path = policy_path()?;
    let dir = ssc_config_dir()?;
    let mut snap = if path.is_file() {
        load_from_path(&path)?
    } else {
        PolicySnapshot::default()
    };

    let legacy = collect_legacy_profile_policies(&dir);
    if !legacy.is_empty() {
        let before = snap.rules.len() + snap.groups.len();
        for other in legacy {
            merge_snapshots(&mut snap, other);
        }
        let after = snap.rules.len() + snap.groups.len();
        if after != before || !path.is_file() {
            write_policy_file(&path, &snap)?;
        }
    } else if !path.is_file() {
        // Ensure file exists for subsequent saves.
        write_policy_file(&path, &snap)?;
    }
    Ok(snap)
}

/// Compatibility: same as global load (policy is no longer per-profile).
pub fn load_policy_for(_profile_id: &str) -> Result<PolicySnapshot, PolicyStoreError> {
    load_policy()
}

/// Save global policy to `policy.json` (never to per-profile paths).
pub fn save_policy(snap: &PolicySnapshot) -> Result<(), PolicyStoreError> {
    write_policy_file(&policy_path()?, snap)
}

/// Compatibility shim — writes global policy.
pub fn save_policy_for(_profile_id: &str, snap: &PolicySnapshot) -> Result<(), PolicyStoreError> {
    save_policy(snap)
}

pub fn export_policy() -> Result<String, PolicyStoreError> {
    let snap = load_policy()?;
    serde_json::to_string_pretty(&snap).map_err(|e| e.to_string().into())
}

pub fn import_policy(json: &str) -> Result<PolicySnapshot, PolicyStoreError> {
    let snap: PolicySnapshot =
        serde_json::from_str(json).map_err(|e| format!("parse policy: {e}"))?;
    save_policy(&snap)?;
    Ok(snap)
}

pub fn set_mode(mode: PolicyMode) -> Result<PolicySnapshot, PolicyStoreError> {
    let mut snap = load_policy()?;
    snap.settings.mode = mode;
    save_policy(&snap)?;
    Ok(snap)
}

pub fn add_rule(
    kind: MatchKind,
    value: &str,
    action: Action,
) -> Result<PolicyRule, PolicyStoreError> {
    add_rule_in_group(kind, value, action, None)
}

pub fn add_rule_in_group(
    kind: MatchKind,
    value: &str,
    action: Action,
    group_id: Option<&str>,
) -> Result<PolicyRule, PolicyStoreError> {
    validate_rule(kind, value)?;
    let mut snap = load_policy()?;
    if let Some(gid) = group_id {
        if !snap.groups.iter().any(|g| g.id == gid) {
            return Err(format!("group not found: {gid}").into());
        }
    }
    let mut rule = PolicyRule::new(kind, value.trim(), action);
    rule.group_id = group_id.map(|s| s.to_string());
    snap.rules.push(rule.clone());
    save_policy(&snap)?;
    Ok(rule)
}

pub fn update_rule(id: &str, patch: RulePatch) -> Result<PolicyRule, PolicyStoreError> {
    let mut snap = load_policy()?;
    if let Some(ref gid) = patch.group_id {
        if !gid.is_empty() && !snap.groups.iter().any(|g| g.id == *gid) {
            return Err(format!("group not found: {gid}").into());
        }
    }
    let rule = snap
        .rules
        .iter_mut()
        .find(|r| r.id == id)
        .ok_or_else(|| format!("rule not found: {id}"))?;
    if let Some(kind) = patch.kind {
        rule.kind = kind;
    }
    if let Some(value) = patch.value {
        validate_rule(rule.kind, &value)?;
        rule.value = value;
    }
    if let Some(action) = patch.action {
        rule.action = action;
    }
    if let Some(enabled) = patch.enabled {
        rule.enabled = enabled;
    }
    if let Some(gid) = patch.group_id {
        rule.group_id = if gid.is_empty() { None } else { Some(gid) };
    }
    let out = rule.clone();
    save_policy(&snap)?;
    Ok(out)
}

pub fn delete_rule(id_or_value: &str) -> Result<(), PolicyStoreError> {
    let mut snap = load_policy()?;
    let before = snap.rules.len();
    snap.rules
        .retain(|r| r.id != id_or_value && r.value != id_or_value);
    if snap.rules.len() == before {
        return Err(format!("rule not found: {id_or_value}").into());
    }
    save_policy(&snap)?;
    Ok(())
}

pub fn add_group(name: &str) -> Result<RuleGroup, PolicyStoreError> {
    let name = name.trim();
    if name.is_empty() {
        return Err("group name empty".into());
    }
    let mut snap = load_policy()?;
    if snap
        .groups
        .iter()
        .any(|g| g.name.eq_ignore_ascii_case(name))
    {
        return Err(format!("group already exists: {name}").into());
    }
    let g = RuleGroup::new(name);
    snap.groups.push(g.clone());
    save_policy(&snap)?;
    Ok(g)
}

pub fn ensure_group(name: &str) -> Result<RuleGroup, PolicyStoreError> {
    let mut snap = load_policy()?;
    if let Some(g) = snap
        .groups
        .iter()
        .find(|g| g.name.eq_ignore_ascii_case(name.trim()))
    {
        return Ok(g.clone());
    }
    let g = RuleGroup::new(name.trim());
    snap.groups.push(g.clone());
    save_policy(&snap)?;
    Ok(g)
}

pub fn update_group(id: &str, patch: GroupPatch) -> Result<RuleGroup, PolicyStoreError> {
    let mut snap = load_policy()?;
    let g = snap
        .groups
        .iter_mut()
        .find(|g| g.id == id)
        .ok_or_else(|| format!("group not found: {id}"))?;
    if let Some(name) = patch.name {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err("group name empty".into());
        }
        g.name = name;
    }
    if let Some(enabled) = patch.enabled {
        g.enabled = enabled;
    }
    let out = g.clone();
    save_policy(&snap)?;
    Ok(out)
}

pub fn delete_group(id: &str, delete_rules: bool) -> Result<(), PolicyStoreError> {
    let mut snap = load_policy()?;
    let before = snap.groups.len();
    snap.groups.retain(|g| g.id != id);
    if snap.groups.len() == before {
        return Err(format!("group not found: {id}").into());
    }
    if delete_rules {
        snap.rules.retain(|r| r.group_id.as_deref() != Some(id));
    } else {
        for r in snap.rules.iter_mut() {
            if r.group_id.as_deref() == Some(id) {
                r.group_id = None;
            }
        }
    }
    save_policy(&snap)?;
    Ok(())
}

#[derive(Debug, Default)]
pub struct RulePatch {
    pub kind: Option<MatchKind>,
    pub value: Option<String>,
    pub action: Option<Action>,
    pub enabled: Option<bool>,
    pub group_id: Option<String>,
}

#[derive(Debug, Default)]
pub struct GroupPatch {
    pub name: Option<String>,
    pub enabled: Option<bool>,
}

fn validate_rule(kind: MatchKind, value: &str) -> Result<(), PolicyStoreError> {
    let v = value.trim();
    if v.is_empty() {
        return Err("rule value empty".into());
    }
    match kind {
        MatchKind::Domain => {
            if v.contains(' ') || v.contains('/') {
                return Err("invalid domain".into());
            }
            // Allow exact, *.suffix, and .suffix forms.
            let bare = v
                .strip_prefix("*.")
                .or_else(|| v.strip_prefix('.'))
                .unwrap_or(v);
            if bare.is_empty() || bare.starts_with('.') || bare.contains('*') {
                return Err("invalid domain".into());
            }
        }
        MatchKind::Ip => {
            if v.parse::<std::net::IpAddr>().is_err() {
                return Err(format!("invalid IP: {v}").into());
            }
        }
        MatchKind::Cidr => {
            if v.parse::<ipnet::IpNet>().is_err() {
                return Err(format!("invalid CIDR: {v}").into());
            }
        }
        MatchKind::Port => {
            let lower = v.to_ascii_lowercase();
            let Some((proto, port)) = lower.split_once(':') else {
                return Err("port rule must be proto:port".into());
            };
            if proto != "tcp" && proto != "udp" {
                return Err("port protocol must be tcp or udp".into());
            }
            if port.parse::<u16>().is_err() {
                return Err("invalid port".into());
            }
        }
    }
    Ok(())
}

pub fn update_settings(settings: Settings) -> Result<PolicySnapshot, PolicyStoreError> {
    let mut snap = load_policy()?;
    snap.settings = settings;
    save_policy(&snap)?;
    Ok(snap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    fn with_temp_config<F: FnOnce(&std::path::Path)>(f: F) {
        let _g = LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("ssc-policy-test-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("SSC_CONFIG_DIR", &dir);
        std::env::remove_var("SSC_ACTIVE_PROFILE");
        std::env::remove_var("SSC_PROFILE_ID");
        f(&dir);
        std::env::remove_var("SSC_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn policy_path_for_layout() {
        with_temp_config(|dir| {
            let p = policy_path_for("abc-123").unwrap();
            assert_eq!(p, dir.join("policies").join("abc-123.json"));
        });
    }

    #[test]
    fn save_is_always_global_even_with_active_profile() {
        with_temp_config(|dir| {
            let snap = PolicySnapshot {
                settings: Settings {
                    mode: PolicyMode::Full,
                    ..Settings::default()
                },
                groups: vec![],
                rules: vec![PolicyRule::new(
                    MatchKind::Domain,
                    "*.googlevideo.com",
                    Action::Vpn,
                )],
            };
            std::fs::write(
                dir.join("profiles.json"),
                r#"{"profiles":[{"id":"p1","name":"n","uri":"x","protocol":"vless","created_at_ms":0}],"active_id":"p1"}"#,
            )
            .unwrap();
            save_policy(&snap).unwrap();
            assert!(dir.join("policy.json").is_file());
            assert!(!dir.join("policies").join("p1.json").is_file());
            let loaded = load_policy().unwrap();
            assert_eq!(loaded.rules[0].value, "*.googlevideo.com");
        });
    }

    #[test]
    fn merges_legacy_per_profile_into_global() {
        with_temp_config(|dir| {
            let per = PolicySnapshot {
                settings: Settings::default(),
                groups: vec![RuleGroup::new("YouTube")],
                rules: vec![
                    PolicyRule::new(MatchKind::Domain, "*.youtube.com", Action::Vpn)
                        .with_group("will-remap"),
                ],
            };
            // Fix group id link
            let mut per = per;
            let gid = per.groups[0].id.clone();
            per.rules[0].group_id = Some(gid);
            std::fs::create_dir_all(dir.join("policies")).unwrap();
            write_policy_file(&dir.join("policies").join("p1.json"), &per).unwrap();

            let loaded = load_policy().unwrap();
            assert!(loaded.rules.iter().any(|r| r.value == "*.youtube.com"));
            assert!(loaded.groups.iter().any(|g| g.name == "YouTube"));
            assert!(dir.join("policy.json").is_file());
        });
    }

    #[test]
    fn group_toggle_affects_active_rules() {
        with_temp_config(|_| {
            let g = add_group("Pack").unwrap();
            add_rule_in_group(MatchKind::Domain, "*.ytimg.com", Action::Vpn, Some(&g.id)).unwrap();
            let snap = load_policy().unwrap();
            assert_eq!(snap.active_rules().count(), 1);
            update_group(
                &g.id,
                GroupPatch {
                    enabled: Some(false),
                    ..Default::default()
                },
            )
            .unwrap();
            let snap = load_policy().unwrap();
            assert_eq!(snap.active_rules().count(), 0);
        });
    }

    #[test]
    fn export_import_roundtrip() {
        with_temp_config(|_| {
            let snap = PolicySnapshot {
                settings: Settings::default(),
                groups: vec![],
                rules: vec![PolicyRule::new(MatchKind::Ip, "1.1.1.1", Action::Vpn)],
            };
            save_policy(&snap).unwrap();
            let json = export_policy().unwrap();
            let mut empty = PolicySnapshot::default();
            empty.rules.clear();
            save_policy(&empty).unwrap();
            let imported = import_policy(&json).unwrap();
            assert_eq!(imported.rules.len(), 1);
            assert_eq!(imported.rules[0].value, "1.1.1.1");
        });
    }

    #[test]
    fn wildcard_domain_validates() {
        with_temp_config(|_| {
            add_rule(MatchKind::Domain, "*.googlevideo.com", Action::Vpn).unwrap();
            let snap = load_policy().unwrap();
            assert_eq!(snap.rules[0].value, "*.googlevideo.com");
        });
    }
}
