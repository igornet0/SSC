//! Profile store (`profiles.json`).
//!
//! Share URIs are stored in the Keychain (or `secrets/` fallback). Public
//! metadata (`id`, `name`, `protocol`, `server`, …) stays in JSON without
//! plaintext secrets. Legacy profiles with an inline `uri` field are migrated
//! on first `profile_uri` / update.

use crate::config_paths::profiles_path;
use crate::keychain::{account_for_profile, delete_secret, load_secret, store_secret};
use crate::uri::parse_share_uri;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub protocol: String,
    /// Public server host (no credentials).
    #[serde(default)]
    pub server: String,
    pub created_at_ms: i64,
    /// Legacy plaintext URI — migrated to keychain on read/update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Keychain / secrets account, typically `ssc-profile-{id}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keychain_account: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfilesFile {
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub active_id: Option<String>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Public server host for a profile (metadata, else parse URI).
pub fn server_of(profile: &Profile) -> String {
    if !profile.server.is_empty() {
        return profile.server.clone();
    }
    match profile_uri(profile) {
        Ok(uri) => parse_share_uri(&uri)
            .map(|p| p.server)
            .unwrap_or_else(|_| "(unknown)".into()),
        Err(_) => "(unknown)".into(),
    }
}

/// Load the share URI for `profile` from keychain or legacy `uri`.
/// If only legacy plaintext remains, migrate it into the keychain and clear
/// `uri` from `profiles.json`.
pub fn profile_uri(profile: &Profile) -> Result<String, String> {
    if let Some(ref account) = profile.keychain_account {
        match load_secret(account) {
            Ok(s) if !s.is_empty() => return Ok(s),
            Ok(_) => {}
            Err(_) => {}
        }
    }
    if let Some(ref uri) = profile.uri {
        let uri = uri.trim().to_string();
        if !uri.is_empty() {
            // Migrate legacy plaintext → keychain.
            let _ = migrate_profile_secret(&profile.id, &uri);
            return Ok(uri);
        }
    }
    // Retry account derived from id even if keychain_account unset.
    let account = account_for_profile(&profile.id);
    load_secret(&account).map_err(|e| {
        format!("no secret for profile {} ({e}) — re-import with `ssc add`", profile.id)
    })
}

fn migrate_profile_secret(id: &str, uri: &str) -> Result<(), String> {
    let account = account_for_profile(id);
    store_secret(&account, uri)?;
    let mut file = load_profiles()?;
    if let Some(p) = file.profiles.iter_mut().find(|p| p.id == id) {
        p.keychain_account = Some(account);
        p.uri = None;
        if p.server.is_empty() {
            if let Ok(parsed) = parse_share_uri(uri) {
                p.server = parsed.server;
            }
        }
        save_profiles(&file)?;
    }
    Ok(())
}

pub fn load_profiles() -> Result<ProfilesFile, String> {
    let path = profiles_path()?;
    if !path.is_file() {
        return Ok(ProfilesFile::default());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("read profiles: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("parse profiles: {e}"))
}

pub fn save_profiles(file: &ProfilesFile) -> Result<(), String> {
    let path = profiles_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create profiles dir: {e}"))?;
    }
    let text = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| format!("write profiles: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod profiles: {e}"))?;
    }
    Ok(())
}

pub fn list_profiles() -> Result<ProfilesFile, String> {
    load_profiles()
}

fn find_by_uri(file: &ProfilesFile, uri: &str) -> Option<usize> {
    let needle = uri.trim();
    for (i, p) in file.profiles.iter().enumerate() {
        if let Some(ref legacy) = p.uri {
            if legacy.trim() == needle {
                return Some(i);
            }
        }
        let account = p
            .keychain_account
            .clone()
            .unwrap_or_else(|| account_for_profile(&p.id));
        if let Ok(stored) = load_secret(&account) {
            if stored.trim() == needle {
                return Some(i);
            }
        }
    }
    None
}

/// Parse URI, store secret in keychain, save metadata without plaintext URI.
pub fn add_profile(uri: &str) -> Result<Profile, String> {
    let parsed = parse_share_uri(uri).map_err(|e| e.to_string())?;
    let uri = uri.trim();
    let mut file = load_profiles()?;

    if let Some(idx) = find_by_uri(&file, uri) {
        let id = file.profiles[idx].id.clone();
        let account = account_for_profile(&id);
        store_secret(&account, uri)?;
        let p = &mut file.profiles[idx];
        p.name = parsed.name.clone();
        p.protocol = parsed.protocol.as_str().to_string();
        p.server = parsed.server.clone();
        p.keychain_account = Some(account);
        p.uri = None;
        let out = p.clone();
        file.active_id = Some(out.id.clone());
        save_profiles(&file)?;
        return Ok(out);
    }

    let id = Uuid::new_v4().to_string();
    let account = account_for_profile(&id);
    store_secret(&account, uri)?;
    let profile = Profile {
        id: id.clone(),
        name: parsed.name,
        protocol: parsed.protocol.as_str().to_string(),
        server: parsed.server,
        created_at_ms: now_ms(),
        uri: None,
        keychain_account: Some(account),
    };
    file.active_id = Some(profile.id.clone());
    file.profiles.push(profile.clone());
    save_profiles(&file)?;
    Ok(profile)
}

/// Read share URIs from a file: one per line, blank lines and `#` comments skipped.
pub fn read_uri_file(path: &std::path::Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut uris: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !uris.iter().any(|u| u == line) {
            uris.push(line.to_string());
        }
    }
    if uris.is_empty() {
        return Err(format!("no share URIs in {}", path.display()));
    }
    Ok(uris)
}

/// Replace all saved profiles with `uris`. Every URI is parsed before anything
/// is deleted, so a bad line leaves the existing profiles untouched.
/// The first URI becomes active.
pub fn replace_profiles(uris: &[String]) -> Result<Vec<Profile>, String> {
    let mut parsed = Vec::with_capacity(uris.len());
    for (i, uri) in uris.iter().enumerate() {
        let p = parse_share_uri(uri).map_err(|e| format!("line {}: {e}", i + 1))?;
        parsed.push((uri.trim().to_string(), p));
    }

    let old = load_profiles()?;
    for p in &old.profiles {
        let account = p
            .keychain_account
            .clone()
            .unwrap_or_else(|| account_for_profile(&p.id));
        let _ = delete_secret(&account);
    }

    let mut file = ProfilesFile::default();
    for (uri, p) in parsed {
        let id = Uuid::new_v4().to_string();
        let account = account_for_profile(&id);
        store_secret(&account, &uri)?;
        file.profiles.push(Profile {
            id,
            name: p.name,
            protocol: p.protocol.as_str().to_string(),
            server: p.server,
            created_at_ms: now_ms(),
            uri: None,
            keychain_account: Some(account),
        });
    }
    file.active_id = file.profiles.first().map(|p| p.id.clone());
    save_profiles(&file)?;
    Ok(file.profiles)
}

pub fn set_active(id: &str) -> Result<Profile, String> {
    let mut file = load_profiles()?;
    let profile = file
        .profiles
        .iter()
        .find(|p| p.id == id || p.name == id)
        .cloned()
        .ok_or_else(|| format!("profile not found: {id}"))?;
    file.active_id = Some(profile.id.clone());
    save_profiles(&file)?;
    Ok(profile)
}

pub fn remove_profile(id: &str) -> Result<(), String> {
    let mut file = load_profiles()?;
    let removed = file
        .profiles
        .iter()
        .find(|p| p.id == id || p.name == id)
        .cloned();
    let Some(removed) = removed else {
        return Err(format!("profile not found: {id}"));
    };
    let account = removed
        .keychain_account
        .clone()
        .unwrap_or_else(|| account_for_profile(&removed.id));
    let _ = delete_secret(&account);

    file.profiles
        .retain(|p| p.id != removed.id && p.name != id);
    if file.active_id.as_deref() == Some(removed.id.as_str())
        || file
            .active_id
            .as_ref()
            .is_some_and(|a| !file.profiles.iter().any(|p| &p.id == a))
    {
        file.active_id = file.profiles.first().map(|p| p.id.clone());
    }
    save_profiles(&file)?;
    Ok(())
}

pub fn active_profile() -> Result<Profile, String> {
    let file = load_profiles()?;
    let id = file
        .active_id
        .as_ref()
        .ok_or_else(|| "no active profile — run `ssc add` or `ssc use`".to_string())?;
    file.profiles
        .iter()
        .find(|p| &p.id == id)
        .cloned()
        .ok_or_else(|| format!("active profile id missing: {id}"))
}
