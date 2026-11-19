//! Config directory layout for SSC.

use std::path::PathBuf;

/// Override with `SSC_CONFIG_DIR`. Default: macOS Application Support/ssc, else `dirs::config_dir()/ssc`.
pub fn config_dir() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("SSC_CONFIG_DIR") {
        let t = v.trim();
        if !t.is_empty() {
            return Some(PathBuf::from(t));
        }
    }
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|h| h.join("Library").join("Application Support").join("ssc"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::config_dir().map(|d| d.join("ssc"))
    }
}

pub fn ensure_config_dir() -> Result<PathBuf, String> {
    let dir = config_dir().ok_or_else(|| "cannot resolve SSC config directory".to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("create config dir: {e}"))?;
    Ok(dir)
}

pub fn profiles_path() -> Result<PathBuf, String> {
    Ok(ensure_config_dir()?.join("profiles.json"))
}

/// Legacy persistent path — must never hold credentials after P8.1.
pub fn singbox_run_path() -> Result<PathBuf, String> {
    Ok(ensure_config_dir()?.join("singbox-run.json"))
}

/// Redacted status snapshot (no secrets) for diagnostics.
pub fn singbox_meta_path() -> Result<PathBuf, String> {
    Ok(ensure_config_dir()?.join("singbox-run.meta.json"))
}

pub fn runtime_dir() -> Result<PathBuf, String> {
    let dir = ensure_config_dir()?.join("runtime");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create runtime dir: {e}"))?;
    Ok(dir)
}

/// Root directory containing one subdirectory per named VPN instance.
pub fn instances_dir() -> Result<PathBuf, String> {
    let dir = ensure_config_dir()?.join("instances");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create instances dir: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

/// Registry metadata for named instances (`instances.json`, no credentials).
pub fn instances_registry_path() -> Result<PathBuf, String> {
    Ok(ensure_config_dir()?.join("instances.json"))
}

/// Validate an instance id used as a directory name.
///
/// Only `[A-Za-z0-9._-]` is accepted, no path separators, no `..` and no
/// leading dot. This prevents path traversal and hidden runtime directories.
pub fn validate_instance_id(id: &str) -> Result<(), String> {
    let id = id.trim();
    if id.is_empty() {
        return Err("instance id empty".into());
    }
    if id.len() > 64 {
        return Err("instance id too long (max 64)".into());
    }
    if id.starts_with('.') || id.contains("..") {
        return Err("instance id must not start with '.' or contain '..'".into());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err("instance id may only contain letters, digits, '-', '_' and '.'".into());
    }
    Ok(())
}

/// Per-instance directory (`instances/{id}`), created with mode 0700.
pub fn instance_dir(id: &str) -> Result<PathBuf, String> {
    validate_instance_id(id)?;
    let dir = instances_dir()?.join(id);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create instance dir: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

/// Ephemeral sing-box config (credentials while connected only).
pub fn ephemeral_singbox_path() -> Result<PathBuf, String> {
    Ok(runtime_dir()?.join("singbox-ephemeral.json"))
}

/// Pointer file recording the active ephemeral config path.
pub fn ephemeral_pointer_path() -> Result<PathBuf, String> {
    Ok(runtime_dir()?.join("active.path"))
}
