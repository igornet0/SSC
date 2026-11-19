//! Startup reconciliation: clear stale tunnel state and deactivate leftover kill switch.

use serde::{Deserialize, Serialize};
use ssc_runtime::{InstancePaths, DEFAULT_INSTANCE_ID};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReconcileReport {
    pub tunnel_cleared: bool,
    pub kill_switch_deactivated: bool,
    /// Number of named instances whose stale pid/status/stop files were cleared.
    #[serde(default)]
    pub instances_cleared: usize,
    pub details: Vec<String>,
}

/// Minimal view of `instances.json` — only ids are needed here.
#[derive(Debug, Deserialize)]
struct RegistryFile {
    #[serde(default)]
    instances: Vec<RegistryEntry>,
}

#[derive(Debug, Deserialize)]
struct RegistryEntry {
    id: String,
}

fn registry_instance_ids() -> Vec<String> {
    let mut ids = Vec::new();
    if let Ok(path) = ssc_core::instances_registry_path() {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(file) = serde_json::from_str::<RegistryFile>(&text) {
                ids.extend(
                    file.instances
                        .into_iter()
                        .map(|e| e.id)
                        .filter(|id| ssc_core::validate_instance_id(id).is_ok()),
                );
            }
        }
    }
    // Also cover leftover directories not present in the registry (for example
    // after a crash between directory creation and registry persistence).
    if let Ok(dir) = ssc_core::instances_dir() {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if !entry.path().is_dir() {
                    continue;
                }
                if let Some(name) = entry.file_name().to_str() {
                    if ssc_core::validate_instance_id(name).is_ok() {
                        ids.push(name.to_string());
                    }
                }
            }
        }
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Clear stale pid/status/stop files for one instance without touching a live
/// process. The last error is preserved so crash evidence remains visible.
fn reconcile_instance(paths: &InstancePaths) -> bool {
    if ssc_runtime::is_instance_connected(paths) {
        return false;
    }
    let status = ssc_runtime::read_status_at(paths);
    let had_state =
        paths.pid.is_file() || paths.stop.is_file() || status.running || status.pid.is_some();
    if !had_state {
        return false;
    }

    let _ = std::fs::remove_file(&paths.pid);
    let _ = std::fs::remove_file(&paths.stop);
    if paths.status.is_file() {
        let mut status = status;
        status.running = false;
        status.pid = None;
        status.updated_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let _ = ssc_runtime::write_status_at(paths, &status);
    }
    true
}

/// Marker file written when kill switch is engaged (PF / block-on-drop).
fn killswitch_marker_path() -> Result<std::path::PathBuf, String> {
    Ok(ssc_core::ensure_config_dir()?.join("killswitch.active"))
}

/// True when a prior crash left kill-switch engagement state behind.
pub fn kill_switch_engaged() -> bool {
    killswitch_marker_path()
        .map(|p| p.is_file())
        .unwrap_or(false)
}

/// Engage marker (paired with pf activate).
pub fn engage_kill_switch_marker() -> Result<(), String> {
    let path = killswitch_marker_path()?;
    std::fs::write(&path, b"1").map_err(|e| format!("write killswitch marker: {e}"))?;
    Ok(())
}

/// Deactivate stale kill switch: remove marker and best-effort flush SSC pf anchor.
pub fn deactivate_kill_switch() -> Result<(), String> {
    let path = killswitch_marker_path()?;
    if path.is_file() {
        let _ = std::fs::remove_file(&path);
    }
    // Best-effort: pf flush may require sudo and can fail in tests/dev.
    if let Err(e) = crate::kill_switch::deactivate() {
        eprintln!("[RECONCILE] pf kill-switch flush: {e}");
    }
    Ok(())
}

/// Clear stale tunnel pid/status when the process is gone; deactivate leftover kill switch.
pub fn reconcile_on_startup() -> ReconcileReport {
    let mut report = ReconcileReport::default();

    // Default (compatibility) instance.
    if let Ok(paths) = InstancePaths::for_id(DEFAULT_INSTANCE_ID) {
        if ssc_runtime::is_instance_connected(&paths) {
            report
                .details
                .push("tunnel process alive — left status intact".into());
        } else if reconcile_instance(&paths) {
            report.tunnel_cleared = true;
            report
                .details
                .push("cleared stale tunnel.pid / tunnel.status.json (process not alive)".into());
            eprintln!("[RECONCILE] cleared stale tunnel state");
        } else {
            report.details.push("no tunnel pid present".into());
        }
    }

    // Named instances: clear stale state, never touch a live process.
    for id in registry_instance_ids() {
        if id == DEFAULT_INSTANCE_ID {
            continue;
        }
        let Ok(paths) = InstancePaths::for_id(&id) else {
            continue;
        };
        if reconcile_instance(&paths) {
            report.instances_cleared += 1;
            report
                .details
                .push(format!("cleared stale state for instance '{id}'"));
            eprintln!("[RECONCILE] cleared stale state for instance '{id}'");
        }
    }

    // Kill switch stale: marker present while VPN is not connected.
    let connected = ssc_runtime::is_connected();
    if kill_switch_engaged() && !connected {
        let _ = deactivate_kill_switch();
        report.kill_switch_deactivated = true;
        report
            .details
            .push("deactivated stale kill-switch marker".into());
        eprintln!("[RECONCILE] deactivated stale kill switch");
    } else if !kill_switch_engaged() {
        report.details.push("kill switch not engaged".into());
    } else {
        report
            .details
            .push("kill switch engaged while connected — left active".into());
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconcile_clears_dead_pid() {
        let _g = crate::test_env_lock();
        let dir = std::env::temp_dir().join(format!("ssc-reconcile-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("SSC_CONFIG_DIR", &dir);
        std::fs::write(dir.join("tunnel.pid"), "2147483646").unwrap();
        std::fs::write(
            dir.join("tunnel.status.json"),
            r#"{"running":true,"pid":2147483646,"updated_at_ms":0}"#,
        )
        .unwrap();
        let report = reconcile_on_startup();
        assert!(report.tunnel_cleared, "details={:?}", report.details);
        assert!(!dir.join("tunnel.pid").is_file());
        std::env::remove_var("SSC_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconcile_deactivates_stale_killswitch() {
        let _g = crate::test_env_lock();
        let dir = std::env::temp_dir().join(format!("ssc-reconcile-ks-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("SSC_CONFIG_DIR", &dir);
        engage_kill_switch_marker().unwrap();
        assert!(kill_switch_engaged());
        let report = reconcile_on_startup();
        assert!(
            report.kill_switch_deactivated,
            "details={:?} engaged={} connected={}",
            report.details,
            kill_switch_engaged(),
            ssc_runtime::is_connected()
        );
        assert!(!kill_switch_engaged());
        std::env::remove_var("SSC_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reconcile_clears_stale_named_instances() {
        let _g = crate::test_env_lock();
        let dir =
            std::env::temp_dir().join(format!("ssc-reconcile-named-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("SSC_CONFIG_DIR", &dir);

        // One stale instance (dead pid + stop flag), one live, one with no state.
        let stale = ssc_core::instance_dir("stale").unwrap();
        std::fs::write(stale.join("tunnel.pid"), "2147483646").unwrap();
        std::fs::write(stale.join("tunnel.stop"), b"1").unwrap();
        std::fs::write(
            stale.join("tunnel.status.json"),
            r#"{"running":true,"pid":2147483646,"last_error":"sing-box crashed","updated_at_ms":0}"#,
        )
        .unwrap();

        let clean = ssc_core::instance_dir("clean").unwrap();
        // no pid/status/stop — must be ignored.
        let _ = clean;

        let report = reconcile_on_startup();
        assert_eq!(report.instances_cleared, 1, "details={:?}", report.details);

        // Stale files cleared, last_error preserved for crash visibility.
        assert!(!stale.join("tunnel.pid").is_file());
        assert!(!stale.join("tunnel.stop").is_file());
        let status =
            ssc_runtime::read_status_at(&InstancePaths::for_id("stale").expect("stale paths"));
        assert!(!status.running);
        assert_eq!(status.pid, None);
        assert_eq!(status.last_error.as_deref(), Some("sing-box crashed"));

        std::env::remove_var("SSC_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
