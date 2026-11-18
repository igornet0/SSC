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
        return dirs::home_dir().map(|h| {
            h.join("Library")
                .join("Application Support")
                .join("ssc")
        });
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

/// Ephemeral sing-box config (credentials while connected only).
pub fn ephemeral_singbox_path() -> Result<PathBuf, String> {
    Ok(runtime_dir()?.join("singbox-ephemeral.json"))
}

/// Pointer file recording the active ephemeral config path.
pub fn ephemeral_pointer_path() -> Result<PathBuf, String> {
    Ok(runtime_dir()?.join("active.path"))
}
