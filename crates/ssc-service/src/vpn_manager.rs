//! Backwards-compatible single-VPN manager.
//!
//! This is a thin, synchronous façade over [`VpnInstanceManager`]'s reserved
//! `default` instance, so existing CLI / API callers keep working while new
//! code can use independent instances directly.
//!
//! Prefer [`crate::VpnInstanceManager`] for concurrent VPN connections, Local
//! Proxy mode, and per-instance policy.

pub use crate::instance_manager::VpnState;
use crate::instance_manager::{reconnect_backoff, InstanceStatusView, VpnInstanceManager};
use serde::{Deserialize, Serialize};
use ssc_policy::PolicySnapshot;
use ssc_runtime::{InstanceMode, DEFAULT_INSTANCE_ID};
use std::future::Future;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::{Builder, Runtime};

/// Legacy status shape for the single-VPN commands / endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnStatusView {
    pub state: VpnState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_at: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub mode: String,
    pub kill_switch: bool,
    pub auto_reconnect: bool,
}

impl From<InstanceStatusView> for VpnStatusView {
    fn from(v: InstanceStatusView) -> Self {
        Self {
            state: v.state,
            server: v.server,
            interface: v.interface,
            profile_id: v.profile_id,
            profile_name: v.profile_name,
            connected_at: v.connected_at,
            bytes_sent: v.bytes_sent,
            bytes_received: v.bytes_received,
            latency_ms: v.latency_ms,
            last_error: v.last_error,
            mode: v.policy_mode,
            kill_switch: v.kill_switch,
            auto_reconnect: v.auto_reconnect,
        }
    }
}

/// Process-wide compatibility manager (shared by CLI and API).
pub struct VpnManager {
    manager: VpnInstanceManager,
    /// Only used by the legacy `next_reconnect_delay` helper.
    attempts: AtomicU32,
}

fn global() -> &'static VpnManager {
    static M: OnceLock<VpnManager> = OnceLock::new();
    M.get_or_init(VpnManager::new)
}

/// Dedicated runtime so supervisors spawned by the façade keep running for the
/// lifetime of the process (they must not be tied to a per-call runtime).
fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("ssc-vpn")
            .enable_all()
            .build()
            .expect("build ssc vpn runtime")
    })
}

fn block_on<F: Future>(future: F) -> F::Output {
    runtime().block_on(future)
}

/// Run a future on the shared VPN runtime.
///
/// Synchronous embedders (CLI, tests) use this to drive
/// [`VpnInstanceManager`](crate::VpnInstanceManager) without creating a
/// short-lived runtime that would kill background supervisors.
pub fn run_blocking<F: Future>(future: F) -> F::Output {
    block_on(future)
}

impl Default for VpnManager {
    fn default() -> Self {
        Self::new()
    }
}

impl VpnManager {
    /// Compatibility manager using the production sing-box / profile backend.
    pub fn new() -> Self {
        Self {
            manager: VpnInstanceManager::new(),
            attempts: AtomicU32::new(0),
        }
    }

    pub fn global() -> &'static Self {
        global()
    }

    /// Access the underlying multi-instance manager.
    pub fn instances(&self) -> &VpnInstanceManager {
        &self.manager
    }

    /// Connect the default instance as a system TUN VPN using the active profile.
    pub fn connect(&self) -> Result<VpnStatusView, String> {
        self.connect_mode(InstanceMode::Tun, None)
    }

    /// Connect the default instance as a local proxy (no root required).
    pub fn connect_proxy(&self, port: Option<u16>) -> Result<VpnStatusView, String> {
        self.connect_mode(InstanceMode::Proxy, port)
    }

    fn connect_mode(
        &self,
        mode: InstanceMode,
        listen_port: Option<u16>,
    ) -> Result<VpnStatusView, String> {
        let profile = ssc_core::active_profile()?;
        let profile_id = profile.id.clone();
        block_on(async {
            self.manager
                .configure_default(Some(profile_id), Some(mode), None, listen_port)
                .await?;
            self.manager.start(DEFAULT_INSTANCE_ID).await
        })
        .map(VpnStatusView::from)
    }

    pub fn disconnect(&self) -> Result<VpnStatusView, String> {
        let view = block_on(self.manager.stop(DEFAULT_INSTANCE_ID)).map(VpnStatusView::from);
        let _ = crate::reconcile::deactivate_kill_switch();
        let _ = ssc_core::cleanup_ephemeral_config();
        view
    }

    pub fn reconnect(&self) -> Result<VpnStatusView, String> {
        block_on(self.manager.restart(DEFAULT_INSTANCE_ID)).map(VpnStatusView::from)
    }

    /// Apply the global policy to the default instance.
    ///
    /// Tries a Clash API hot reload first and only restarts `default`.
    pub fn apply_policy(&self) -> Result<VpnStatusView, String> {
        block_on(self.manager.apply_policy(DEFAULT_INSTANCE_ID)).map(VpnStatusView::from)
    }

    pub fn status(&self) -> VpnStatusView {
        let view = block_on(async {
            let _ = self.manager.poll_traffic(DEFAULT_INSTANCE_ID).await;
            self.manager.status(DEFAULT_INSTANCE_ID).await
        });
        match view {
            Ok(view) => {
                let mut out = VpnStatusView::from(view);
                if out.profile_name.is_none() {
                    if let Ok(p) = ssc_core::active_profile() {
                        out.profile_id = Some(p.id.clone());
                        out.profile_name = Some(p.name.clone());
                        out.server = Some(ssc_core::server_of(&p));
                    }
                }
                out
            }
            Err(e) => self.legacy_status(&e),
        }
    }

    /// Best-effort fallback when the registry cannot be loaded.
    fn legacy_status(&self, error: &str) -> VpnStatusView {
        let st = ssc_runtime::read_status();
        let alive = ssc_runtime::is_connected();
        let policy = ssc_policy::load_policy().unwrap_or_default();
        VpnStatusView {
            state: if alive {
                VpnState::Connected
            } else if st.last_error.is_some() {
                VpnState::Error
            } else {
                VpnState::Disconnected
            },
            server: match ssc_core::active_profile() {
                Ok(p) => Some(ssc_core::server_of(&p)),
                Err(_) => None,
            },
            interface: if alive { Some("utun".into()) } else { None },
            profile_id: st.profile_id.clone(),
            profile_name: None,
            connected_at: None,
            bytes_sent: 0,
            bytes_received: 0,
            latency_ms: None,
            last_error: st.last_error.or_else(|| Some(error.to_string())),
            mode: policy.settings.mode.as_str().to_string(),
            kill_switch: policy.settings.kill_switch,
            auto_reconnect: policy.settings.auto_reconnect,
        }
    }

    /// Legacy helper retained for embedders; new code should use
    /// [`reconnect_backoff`].
    pub fn next_reconnect_delay(&self, policy: &PolicySnapshot) -> Duration {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
        reconnect_backoff(policy, attempt)
    }
}

/// Safe recovery: stop every SSC instance and clear runtime state.
///
/// Never touches foreign routes or another VPN app.
pub fn reset_network() -> Result<(), String> {
    log_event("RESET_NETWORK", "begin");
    let manager = VpnManager::global();
    block_on(manager.instances().shutdown());
    let _ = ssc_runtime::request_stop();
    let _ = ssc_runtime::disconnect();
    let _ = ssc_runtime::reset_all_instances();
    let _ = crate::reconcile::deactivate_kill_switch();
    let _ = ssc_core::cleanup_ephemeral_config();

    let dir = ssc_core::ensure_config_dir()?;
    for name in ["tunnel.pid", "tunnel.stop", "tunnel.status.json"] {
        let _ = std::fs::remove_file(dir.join(name));
    }
    let _ = block_on(manager.instances().reload());
    log_event("RESET_NETWORK", "done");
    Ok(())
}

fn log_event(kind: &str, detail: &str) {
    if detail.is_empty() {
        eprintln!("[{kind}]");
    } else {
        eprintln!("[{kind}] {detail}");
    }
}

/// Kept for API compatibility with older code that formatted timestamps.
#[allow(dead_code)]
fn format_rfc3339(t: SystemTime) -> String {
    let ms = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| ms.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssc_policy::Settings;

    #[test]
    fn backoff_caps_at_max() {
        let m = VpnManager::new();
        let policy = PolicySnapshot {
            settings: Settings {
                reconnect_delay_ms: 1000,
                reconnect_max_delay_ms: 30_000,
                ..Settings::default()
            },
            groups: vec![],
            rules: vec![],
        };
        let delays: Vec<_> = (0..10)
            .map(|_| m.next_reconnect_delay(&policy).as_millis())
            .collect();
        assert_eq!(delays[0], 1000);
        assert_eq!(delays[1], 2000);
        assert_eq!(delays[2], 4000);
        assert!(*delays.last().unwrap() <= 30_000);
    }

    #[test]
    fn status_view_is_credential_free() {
        let view = VpnStatusView {
            state: VpnState::Disconnected,
            server: Some("vpn.example.com".into()),
            interface: None,
            profile_id: Some("p1".into()),
            profile_name: Some("Work".into()),
            connected_at: None,
            bytes_sent: 0,
            bytes_received: 0,
            latency_ms: None,
            last_error: None,
            mode: "selective".into(),
            kill_switch: false,
            auto_reconnect: true,
        };
        let text = serde_json::to_string(&view).unwrap();
        assert!(!text.contains("vless://"));
        assert!(!text.contains("password"));
    }
}
