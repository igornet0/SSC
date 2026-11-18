//! Startup reconciliation: clear stale tunnel state and deactivate leftover kill switch.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReconcileReport {
    pub tunnel_cleared: bool,
    pub kill_switch_deactivated: bool,
    pub details: Vec<String>,
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

fn pid_path() -> Result<std::path::PathBuf, String> {
    Ok(ssc_core::ensure_config_dir()?.join("tunnel.pid"))
}

fn status_path() -> Result<std::path::PathBuf, String> {
    Ok(ssc_core::ensure_config_dir()?.join("tunnel.status.json"))
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    unsafe {
        if libc::kill(pid as i32, 0) == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

#[cfg(not(unix))]
fn process_alive(pid: u32) -> bool {
    pid != 0 && ssc_runtime::is_connected()
}

fn read_pid_file() -> Option<u32> {
    let path = pid_path().ok()?;
    let text = std::fs::read_to_string(path).ok()?;
    text.trim().parse().ok()
}

/// Clear stale tunnel pid/status when the process is gone; deactivate leftover kill switch.
pub fn reconcile_on_startup() -> ReconcileReport {
    let mut report = ReconcileReport::default();

    let pid = read_pid_file();
    let dead = match pid {
        Some(p) if process_alive(p) => false,
        Some(_) => true,
        None => {
            let st = ssc_runtime::read_status();
            st.running && st.pid.map(process_alive) != Some(true)
        }
    };

    if dead {
        if let Ok(p) = pid_path() {
            let _ = std::fs::remove_file(&p);
        }
        if let Ok(p) = status_path() {
            let _ = std::fs::remove_file(&p);
        }
        if let Ok(dir) = ssc_core::ensure_config_dir() {
            let _ = std::fs::remove_file(dir.join("tunnel.stop"));
        }
        report.tunnel_cleared = true;
        report
            .details
            .push("cleared stale tunnel.pid / tunnel.status.json (process not alive)".into());
        eprintln!("[RECONCILE] cleared stale tunnel state");
    } else if pid.is_some() {
        report
            .details
            .push("tunnel process alive — left status intact".into());
    } else {
        report.details.push("no tunnel pid present".into());
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
}
