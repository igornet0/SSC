//! Backwards-compatible single-instance tunnel API.
//!
//! This module is a thin façade over the isolated `default` instance. New code
//! should use [`crate::instance`] (and `ssc_service::VpnInstanceManager`) for
//! multiple concurrent VPN connections.

use crate::instance::{
    cleanup_instance_orphans, is_instance_connected, read_status_at, run_instance_worker,
    spawn_instance, stop_instance, InstanceMode, InstancePaths, InstanceStatus,
    DEFAULT_INSTANCE_ID,
};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

static WATCH_STOP: AtomicBool = AtomicBool::new(false);

/// Legacy status shape (now the per-instance status with extra optional fields).
pub type TunnelStatus = InstanceStatus;

fn default_paths() -> Result<InstancePaths, String> {
    InstancePaths::for_id(DEFAULT_INSTANCE_ID)
}

pub fn read_status() -> TunnelStatus {
    default_paths()
        .map(|p| read_status_at(&p))
        .unwrap_or_default()
}

pub fn is_connected() -> bool {
    default_paths()
        .map(|p| is_instance_connected(&p))
        .unwrap_or(false)
}

pub fn status_summary() -> String {
    let st = read_status();
    let alive = is_connected();
    let pid = st.pid;
    format!(
        "connected={alive}\npid={}\nprofile_id={}\nlast_error={}\nupdated_at_ms={}",
        pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
        st.profile_id.as_deref().unwrap_or("-"),
        st.last_error.as_deref().unwrap_or("-"),
        st.updated_at_ms
    )
}

/// Kill leftover sing-box processes belonging to the default instance only.
///
/// Unlike the old implementation this never adopts or kills processes that
/// reference another config path / another instance.
pub fn cleanup_orphans() -> Result<(), String> {
    cleanup_instance_orphans(&default_paths()?)
}

/// Internal worker: run sing-box foreground (TUN or elevated worker).
pub fn run_tunnel_worker(
    config: &Path,
    singbox: &Path,
    profile_id: Option<&str>,
) -> Result<(), String> {
    run_instance_worker(
        config,
        singbox,
        profile_id,
        None,
        Some(InstanceMode::Tun),
        None,
        None,
    )
}

/// Connect the default TUN instance.
pub fn connect(config: &Path, profile_id: Option<&str>) -> Result<(), String> {
    let paths = default_paths()?;
    spawn_instance(
        &paths,
        config,
        profile_id.unwrap_or("default"),
        InstanceMode::Tun,
        None,
        ssc_core::DEFAULT_CLASH_API_PORT,
    )?;
    eprintln!("tunnel started");
    Ok(())
}

pub fn disconnect() -> Result<(), String> {
    stop_instance(&default_paths()?)?;
    eprintln!("disconnected");
    Ok(())
}

/// Signal failover watcher / Ctrl+C path to exit.
pub fn request_stop() -> Result<(), String> {
    WATCH_STOP.store(true, Ordering::SeqCst);
    let path = default_paths()?.stop;
    std::fs::write(&path, b"1").map_err(|e| format!("write stop flag: {e}"))?;
    Ok(())
}

pub fn clear_stop() -> Result<(), String> {
    WATCH_STOP.store(false, Ordering::SeqCst);
    if let Ok(paths) = default_paths() {
        let _ = std::fs::remove_file(paths.stop);
    }
    Ok(())
}

pub fn stop_requested() -> bool {
    if WATCH_STOP.load(Ordering::SeqCst) {
        return true;
    }
    default_paths().map(|p| p.stop.is_file()).unwrap_or(false)
}

/// Reset all instance runtime artefacts (secrets and pids) without deleting
/// instance definitions. Called by `reset-network`.
pub fn reset_all_instances() -> Vec<String> {
    let mut details = Vec::new();
    if let Ok(dir) = ssc_core::instances_dir() {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if !entry.path().is_dir() {
                    continue;
                }
                let Some(id) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                match InstancePaths::for_id(&id) {
                    Ok(paths) => {
                        if let Err(e) = stop_instance(&paths) {
                            details.push(format!("{id}: stop failed: {e}"));
                        } else {
                            details.push(format!("{id}: stopped"));
                        }
                        paths.wipe_all();
                    }
                    Err(e) => details.push(format!("{id}: {e}")),
                }
            }
        }
    }
    if let Ok(paths) = default_paths() {
        let _ = stop_instance(&paths);
        let _ = std::fs::remove_file(&paths.pid);
        let _ = std::fs::remove_file(&paths.status);
        let _ = std::fs::remove_file(&paths.stop);
        paths.wipe_config();
    }
    details
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_status_defaults_to_stopped() {
        // Pure type-level guard: status must remain deserializable from the old
        // on-disk format (missing instance fields default cleanly).
        let st: TunnelStatus =
            serde_json::from_str(r#"{"running":false,"updated_at_ms":0}"#).unwrap();
        assert!(!st.running);
        assert!(st.instance_id.is_none());
    }
}
