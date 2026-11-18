//! VpnManager: connect / disconnect / reconnect / status with explicit states.

use crate::kill_switch;
use serde::{Deserialize, Serialize};
use ssc_policy::{load_policy, PolicySnapshot};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}

impl VpnState {
    pub fn as_str(self) -> &'static str {
        match self {
            VpnState::Disconnected => "disconnected",
            VpnState::Connecting => "connecting",
            VpnState::Connected => "connected",
            VpnState::Disconnecting => "disconnecting",
            VpnState::Error => "error",
        }
    }
}

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

struct ManagerInner {
    state: VpnState,
    connected_at: Option<SystemTime>,
    last_error: Option<String>,
    bytes_sent: u64,
    bytes_received: u64,
    last_latency_ms: Option<u64>,
    reconnect_attempt: u32,
    /// Set while an intentional disconnect/reset is in progress (watchdog ignores).
    intentional_stop: bool,
    watchdog_server: Option<String>,
}

impl Default for ManagerInner {
    fn default() -> Self {
        Self {
            state: VpnState::Disconnected,
            connected_at: None,
            last_error: None,
            bytes_sent: 0,
            bytes_received: 0,
            last_latency_ms: None,
            reconnect_attempt: 0,
            intentional_stop: false,
            watchdog_server: None,
        }
    }
}

/// Process-wide VPN manager (shared by CLI and API).
pub struct VpnManager {
    inner: Mutex<ManagerInner>,
    watchdog_running: AtomicBool,
}

fn global() -> &'static VpnManager {
    static M: OnceLock<VpnManager> = OnceLock::new();
    M.get_or_init(|| VpnManager {
        inner: Mutex::new(ManagerInner::default()),
        watchdog_running: AtomicBool::new(false),
    })
}

impl VpnManager {
    pub fn global() -> &'static Self {
        global()
    }

    pub fn connect(&self) -> Result<VpnStatusView, String> {
        {
            let mut g = self.inner.lock().map_err(|e| e.to_string())?;
            // Idempotent: Connect / Retry while already up must not surface as an error.
            if ssc_runtime::is_connected() {
                g.state = VpnState::Connected;
                g.last_error = None;
                g.intentional_stop = false;
                if g.connected_at.is_none() {
                    g.connected_at = Some(SystemTime::now());
                }
                drop(g);
                return Ok(self.status());
            }
            g.state = VpnState::Connecting;
            g.last_error = None;
            g.intentional_stop = false;
        }

        let result = (|| {
            if let Some(msg) = crate::netconflict::foreign_vpn_conflict() {
                return Err(msg);
            }
            let profile = ssc_core::active_profile()?;
            let uri = ssc_core::profile_uri(&profile)?;
            ensure_singbox()?;
            let policy = load_policy().map_err(|e| e.to_string())?;
            // Clear any prior kill-switch blocks so connect can reach the server.
            let _ = crate::reconcile::deactivate_kill_switch();
            let config = ssc_core::write_singbox_config_with_policy(&uri, &policy)?;
            log_event("VPN_CONNECTING", &format!("profile={}", profile.id));
            ssc_runtime::connect(&config, Some(&profile.id))?;
            let latency = probe_latency(&uri);
            let server = ssc_core::server_of(&profile);
            Ok::<_, String>((profile, latency, server, policy))
        })();

        match result {
            Ok((_profile, latency, server, policy)) => {
                {
                    let mut g = self.inner.lock().map_err(|e| e.to_string())?;
                    g.state = VpnState::Connected;
                    g.connected_at = Some(SystemTime::now());
                    g.last_latency_ms = latency;
                    g.reconnect_attempt = 0;
                    g.last_error = None;
                    g.watchdog_server = Some(server.clone());
                }
                log_event("VPN_CONNECTED", &format!("server_host_only={server}"));
                log_event("TUNNEL_CREATED", "sing-box tun");
                if policy.settings.kill_switch {
                    self.spawn_kill_switch_watchdog();
                }
                Ok(self.status())
            }
            Err(e) => {
                let mut g = self.inner.lock().map_err(|err| err.to_string())?;
                g.state = VpnState::Error;
                g.last_error = Some(e.clone());
                Err(e)
            }
        }
    }

    pub fn disconnect(&self) -> Result<VpnStatusView, String> {
        {
            let mut g = self.inner.lock().map_err(|e| e.to_string())?;
            g.state = VpnState::Disconnecting;
            g.intentional_stop = true;
        }
        let _ = ssc_runtime::request_stop();
        ssc_runtime::disconnect()?;
        let _ = crate::reconcile::deactivate_kill_switch();
        let _ = ssc_core::cleanup_ephemeral_config();
        {
            let mut g = self.inner.lock().map_err(|e| e.to_string())?;
            g.state = VpnState::Disconnected;
            g.connected_at = None;
            g.last_error = None;
            g.watchdog_server = None;
            g.intentional_stop = false;
        }
        log_event("VPN_DISCONNECTED", "");
        log_event("TUNNEL_DESTROYED", "");
        Ok(self.status())
    }

    pub fn reconnect(&self) -> Result<VpnStatusView, String> {
        if ssc_runtime::is_connected() {
            let _ = self.disconnect();
        }
        self.connect()
    }

    /// Apply current policy: rewrite config, try Clash API hot reload, else reconnect.
    pub fn apply_policy(&self) -> Result<VpnStatusView, String> {
        if !ssc_runtime::is_connected() {
            return Ok(self.status());
        }
        let profile = ssc_core::active_profile()?;
        let uri = ssc_core::profile_uri(&profile)?;
        let policy = load_policy().map_err(|e| e.to_string())?;
        let config_path = ssc_core::write_singbox_config_with_policy(&uri, &policy)?;
        log_event(
            "RULE_APPLIED",
            &format!(
                "profile={} mode={} rules={}",
                profile.id,
                policy.settings.mode.as_str(),
                policy.active_rules().count()
            ),
        );

        let path_str = config_path.to_string_lossy().to_string();
        match clash_api_reload(&path_str) {
            Ok(()) => {
                log_event("POLICY_RELOADED", &format!("path={path_str}"));
                Ok(self.status())
            }
            Err(e) => {
                log_event("POLICY_RELOAD_FAILED", &e);
                self.reconnect()
            }
        }
    }

    pub fn status(&self) -> VpnStatusView {
        let alive = ssc_runtime::is_connected();
        let st = ssc_runtime::read_status();
        let policy = load_policy().unwrap_or_default();
        let (profile_id, profile_name, server) = match ssc_core::active_profile() {
            Ok(p) => {
                let host = ssc_core::server_of(&p);
                (Some(p.id), Some(p.name), Some(host))
            }
            Err(_) => (st.profile_id.clone(), None, None),
        };

        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if alive {
            g.state = VpnState::Connected;
            g.last_error = None;
            if g.connected_at.is_none() {
                g.connected_at = Some(SystemTime::now());
            }
        } else if matches!(g.state, VpnState::Connected | VpnState::Connecting) {
            g.state = if g.last_error.is_some() {
                VpnState::Error
            } else {
                VpnState::Disconnected
            };
            g.connected_at = None;
        }

        if let Some((up, down)) = fetch_clash_traffic() {
            g.bytes_sent = up;
            g.bytes_received = down;
        }

        VpnStatusView {
            state: g.state,
            server,
            interface: if alive {
                Some(guess_utun().unwrap_or_else(|| "utun".into()))
            } else {
                None
            },
            profile_id,
            profile_name,
            connected_at: g.connected_at.map(format_rfc3339),
            bytes_sent: g.bytes_sent,
            bytes_received: g.bytes_received,
            latency_ms: g.last_latency_ms,
            // Live tunnel wins: never re-surface a stale file-backed last_error while up.
            last_error: if alive {
                None
            } else {
                g.last_error.clone().or(st.last_error)
            },
            mode: policy.settings.mode.as_str().to_string(),
            kill_switch: policy.settings.kill_switch,
            auto_reconnect: policy.settings.auto_reconnect,
        }
    }

    pub fn next_reconnect_delay(&self, policy: &PolicySnapshot) -> Duration {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let attempt = g.reconnect_attempt;
        g.reconnect_attempt = g.reconnect_attempt.saturating_add(1);
        let base = policy.settings.reconnect_delay_ms.max(1);
        let max = policy.settings.reconnect_max_delay_ms.max(base);
        let shift = attempt.min(16);
        let delay = base.saturating_mul(1u64 << shift).min(max);
        Duration::from_millis(delay)
    }

    fn spawn_kill_switch_watchdog(&self) {
        if self
            .watchdog_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        let mgr: &'static VpnManager = VpnManager::global();
        std::thread::Builder::new()
            .name("ssc-kill-switch-watchdog".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(2));
                    let (watching, intentional, server) = {
                        let g = match mgr.inner.lock() {
                            Ok(g) => g,
                            Err(_) => break,
                        };
                        let watching = matches!(g.state, VpnState::Connected)
                            && g.watchdog_server.is_some();
                        (
                            watching,
                            g.intentional_stop,
                            g.watchdog_server.clone(),
                        )
                    };
                    if !watching {
                        // Stay alive briefly in case we reconnect with kill switch.
                        let policy = load_policy().unwrap_or_default();
                        if !policy.settings.kill_switch {
                            break;
                        }
                        continue;
                    }
                    if intentional {
                        continue;
                    }
                    if ssc_runtime::is_connected() {
                        continue;
                    }
                    // Unexpected drop — engage kill switch and mark Error.
                    let policy = load_policy().unwrap_or_default();
                    if !policy.settings.kill_switch {
                        break;
                    }
                    let server = server.unwrap_or_default();
                    log_event("KILL_SWITCH", "unexpected drop — activating pf");
                    let _ = crate::reconcile::engage_kill_switch_marker();
                    if let Err(e) = kill_switch::activate_for_policy(&server, &policy) {
                        log_event("KILL_SWITCH", &format!("activate failed: {e}"));
                    }
                    if let Ok(mut g) = mgr.inner.lock() {
                        g.state = VpnState::Error;
                        g.last_error =
                            Some("VPN dropped unexpectedly; kill switch engaged".into());
                        g.connected_at = None;
                        g.watchdog_server = None;
                    }
                    break;
                }
                mgr.watchdog_running.store(false, Ordering::SeqCst);
            })
            .ok();
    }
}

fn ensure_singbox() -> Result<(), String> {
    let check = ssc_runtime::check_setup();
    if check.needs_setup {
        ssc_runtime::run_setup()?;
    }
    Ok(())
}

fn probe_latency(uri: &str) -> Option<u64> {
    let parsed = ssc_core::parse_share_uri(uri).ok()?;
    let start = Instant::now();
    let addr = format!("{}:{}", parsed.server, parsed.server_port);
    let sa = std::net::ToSocketAddrs::to_socket_addrs(&addr)
        .ok()
        .and_then(|mut i| i.next())?;
    let ok = std::net::TcpStream::connect_timeout(&sa, Duration::from_secs(3)).is_ok();
    if ok {
        Some(start.elapsed().as_millis() as u64)
    } else {
        None
    }
}

fn format_rfc3339(t: SystemTime) -> String {
    let ms = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| ms.to_string())
}

fn fetch_clash_traffic() -> Option<(u64, u64)> {
    let body = crate::cmdutil::http_get_timed(
        "http://127.0.0.1:9090/connections",
        crate::cmdutil::DEFAULT_HTTP_TIMEOUT,
    )
    .ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let up = v.get("uploadTotal").and_then(|x| x.as_u64()).unwrap_or(0);
    let down = v
        .get("downloadTotal")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    Some((up, down))
}

/// PUT http://127.0.0.1:9090/configs?force=true with `{"path":"..."}`.
fn clash_api_reload(config_path: &str) -> Result<(), String> {
    let body = serde_json::json!({ "path": config_path }).to_string();
    let resp = crate::cmdutil::http_put_timed(
        "http://127.0.0.1:9090/configs?force=true",
        &body,
        crate::cmdutil::DEFAULT_HTTP_TIMEOUT,
    )
    .map_err(|e| format!("clash reload: {e}"))?;
    let status_line = resp.lines().next().unwrap_or("");
    if !(status_line.contains(" 200")
        || status_line.contains(" 204")
        || status_line.contains(" 201"))
    {
        return Err(format!("unexpected response: {status_line}"));
    }
    Ok(())
}

fn guess_utun() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let text = crate::cmdutil::run_timed_ok(
            "ifconfig",
            &[],
            crate::cmdutil::DEFAULT_CMD_TIMEOUT,
        )
        .ok()?;
        let mut current = None::<String>;
        for line in text.lines() {
            if !line.starts_with('\t') && !line.starts_with(' ') {
                current = line.split(':').next().map(|s| s.trim().to_string());
            } else if line.contains("172.19.0.1") {
                return current;
            }
        }
        None
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some("tun0".into())
    }
}

fn log_event(kind: &str, detail: &str) {
    if detail.is_empty() {
        eprintln!("[{kind}]");
    } else {
        eprintln!("[{kind}] {detail}");
    }
}

/// Safe recovery: disconnect, clear SSC tunnel state. Does not touch foreign routes.
pub fn reset_network() -> Result<(), String> {
    log_event("RESET_NETWORK", "begin");
    {
        let m = VpnManager::global();
        if let Ok(mut g) = m.inner.lock() {
            g.intentional_stop = true;
        }
    }
    let _ = ssc_runtime::request_stop();
    let _ = ssc_runtime::disconnect();
    let _ = crate::reconcile::deactivate_kill_switch();
    let _ = ssc_core::cleanup_ephemeral_config();
    let dir = ssc_core::ensure_config_dir()?;
    for name in ["tunnel.pid", "tunnel.stop", "tunnel.status.json"] {
        let p = dir.join(name);
        let _ = std::fs::remove_file(p);
    }
    {
        let m = VpnManager::global();
        let mut g = m.inner.lock().map_err(|e| e.to_string())?;
        *g = ManagerInner::default();
    }
    log_event("RESET_NETWORK", "done");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssc_policy::{PolicySnapshot, Settings};

    #[test]
    fn backoff_caps_at_max() {
        let m = VpnManager {
            inner: Mutex::new(ManagerInner::default()),
            watchdog_running: AtomicBool::new(false),
        };
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
}
