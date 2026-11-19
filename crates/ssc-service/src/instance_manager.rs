//! VpnInstanceManager: independent, concurrently running VPN instances.
//!
//! Architecture:
//! - each instance owns its own config, policy snapshot, runtime directory,
//!   ports, process handle and statistics;
//! - instances are independent Tokio tasks, not a single global tunnel;
//! - no lock is held across `.await`; each instance has its own operation
//!   mutex and state mutex;
//! - `default` is a compatibility alias for the legacy single-VPN CLI/API.

use crate::kill_switch;
use crate::traffic::{TrafficMonitor, TrafficSnapshot};
use serde::{Deserialize, Serialize};
use ssc_core::{InboundKind, SingboxOptions};
use ssc_policy::{load_policy, load_policy_at, save_policy_at, PolicySnapshot, Settings};
use ssc_runtime::{
    InstanceFileLock, InstanceMode, InstancePaths, InstanceProcessBackend, RunningProcess,
    SingBoxBackend, DEFAULT_INSTANCE_ID,
};
use std::collections::{HashMap, HashSet};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Connection state of one instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum VpnState {
    #[default]
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

/// Resolved profile data. `uri` is a secret and is never serialized/logged.
#[derive(Clone)]
pub struct ResolvedProfile {
    pub id: String,
    pub name: String,
    pub server: String,
    pub server_port: u16,
    pub uri: String,
}

impl std::fmt::Debug for ResolvedProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedProfile")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("server", &self.server)
            .field("server_port", &self.server_port)
            .field("uri", &"***redacted***")
            .finish()
    }
}

/// Credential provider. The default reads the SSC profile store / Keychain;
/// embedders can inject a custom provider.
pub trait ProfileResolver: Send + Sync {
    fn resolve(&self, id_or_name: &str) -> Result<ResolvedProfile, String>;
    fn active(&self) -> Result<ResolvedProfile, String>;
}

/// Production resolver backed by `ssc-core` profiles + Keychain.
#[derive(Debug, Default, Clone, Copy)]
pub struct StoreProfileResolver;

impl StoreProfileResolver {
    fn from_profile(profile: ssc_core::Profile) -> Result<ResolvedProfile, String> {
        let uri = ssc_core::profile_uri(&profile)?;
        let parsed = ssc_core::parse_share_uri(&uri).map_err(|e| e.to_string())?;
        let server = if profile.server.is_empty() {
            parsed.server.clone()
        } else {
            profile.server.clone()
        };
        Ok(ResolvedProfile {
            id: profile.id,
            name: profile.name,
            server,
            server_port: parsed.server_port,
            uri,
        })
    }
}

impl ProfileResolver for StoreProfileResolver {
    fn resolve(&self, id_or_name: &str) -> Result<ResolvedProfile, String> {
        let file = ssc_core::list_profiles()?;
        let profile = file
            .profiles
            .iter()
            .find(|p| p.id == id_or_name || p.name == id_or_name)
            .cloned()
            .ok_or_else(|| format!("profile not found: {id_or_name}"))?;
        Self::from_profile(profile)
    }

    fn active(&self) -> Result<ResolvedProfile, String> {
        Self::from_profile(ssc_core::active_profile()?)
    }
}

/// Persisted instance definition (no credentials).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceConfig {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default = "default_mode")]
    pub mode: InstanceMode,
    /// Proxy inbound kind: `mixed`, `http` or `socks` (ignored for TUN).
    #[serde(default = "default_proxy_kind")]
    pub proxy_kind: InboundKind,
    #[serde(default = "default_listen_host")]
    pub listen_host: String,
    /// Explicit local proxy port. `None` = allocate safely from policy range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    /// Explicit Clash/admin port. `None` = allocate safely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_api_port: Option<u16>,
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,
    /// Fail-closed: never fall back to DIRECT when the tunnel/proxy dies.
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default)]
    pub start_on_boot: bool,
    #[serde(default)]
    pub created_at_ms: i64,
}

fn default_mode() -> InstanceMode {
    InstanceMode::Tun
}

fn default_proxy_kind() -> InboundKind {
    InboundKind::Mixed
}

fn default_listen_host() -> String {
    "127.0.0.1".into()
}

fn default_true() -> bool {
    true
}

impl InstanceConfig {
    pub fn new(id: impl Into<String>, name: impl Into<String>, mode: InstanceMode) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            profile_id: None,
            mode,
            proxy_kind: InboundKind::Mixed,
            listen_host: "127.0.0.1".into(),
            listen_port: None,
            clash_api_port: None,
            auto_reconnect: true,
            fail_closed: true,
            kill_switch: false,
            start_on_boot: false,
            created_at_ms: now_ms(),
        }
    }

    fn validate(&self) -> Result<(), String> {
        ssc_core::validate_instance_id(&self.id)?;
        if self.name.trim().is_empty() {
            return Err("instance name empty".into());
        }
        if self.mode == InstanceMode::Proxy {
            if !matches!(
                self.proxy_kind,
                InboundKind::Mixed | InboundKind::Http | InboundKind::Socks
            ) {
                return Err("proxy instance requires mixed/http/socks inbound".into());
            }
            if self.listen_port == Some(0) {
                return Err("listen port must be non-zero".into());
            }
        }
        if let (Some(a), Some(b)) = (self.listen_port, self.clash_api_port) {
            if a == b {
                return Err("listen port and clash api port must differ".into());
            }
        }
        Ok(())
    }
}

/// Request used to create a new independent VPN instance.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CreateInstanceRequest {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub proxy_kind: Option<String>,
    #[serde(default)]
    pub listen_port: Option<u16>,
    #[serde(default)]
    pub clash_api_port: Option<u16>,
    #[serde(default)]
    pub auto_reconnect: Option<bool>,
    #[serde(default)]
    pub fail_closed: Option<bool>,
    #[serde(default)]
    pub kill_switch: Option<bool>,
    #[serde(default)]
    pub start_on_boot: Option<bool>,
    /// Optional isolated policy snapshot (otherwise the global policy is copied).
    #[serde(default)]
    pub policy: Option<PolicySnapshot>,
}

/// Patchable fields of an instance definition.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateInstanceRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub proxy_kind: Option<String>,
    #[serde(default)]
    pub listen_port: Option<u16>,
    #[serde(default)]
    pub clash_api_port: Option<u16>,
    #[serde(default)]
    pub clear_ports: bool,
    #[serde(default)]
    pub auto_reconnect: Option<bool>,
    #[serde(default)]
    pub fail_closed: Option<bool>,
    #[serde(default)]
    pub kill_switch: Option<bool>,
    #[serde(default)]
    pub start_on_boot: Option<bool>,
}

/// Status view for one instance. Contains no secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceStatusView {
    pub id: String,
    pub name: String,
    /// `tun` or `proxy`.
    pub mode: String,
    /// `mixed`, `http`, `socks` or `tun`.
    pub proxy_kind: String,
    pub state: VpnState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// `http://127.0.0.1:PORT` / `socks5://127.0.0.1:PORT` for proxy instances.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clash_api_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_at: Option<String>,
    pub uptime_secs: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub healthy: bool,
    pub fail_closed: bool,
    pub kill_switch: bool,
    pub auto_reconnect: bool,
    pub reconnect_attempt: u32,
    pub policy_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_health_check_ms: Option<i64>,
    pub created_at_ms: i64,
}

/// Manager event stream (bridged to WebSocket by `ssc-api`).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InstanceEvent {
    InstanceStatus { instance: Box<InstanceStatusView> },
    InstancesChanged,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy)]
struct AssignedPorts {
    listen: Option<u16>,
    clash: u16,
}

impl AssignedPorts {
    fn proxy_endpoint(&self, kind: InboundKind) -> Option<String> {
        let port = self.listen?;
        let scheme = match kind {
            InboundKind::Socks => "socks5",
            InboundKind::Http => "http",
            InboundKind::Mixed => "http",
            InboundKind::Tun => return None,
        };
        Some(format!("{scheme}://127.0.0.1:{port}"))
    }
}

struct LiveState {
    state: VpnState,
    running: Option<RunningProcess>,
    lock: Option<InstanceFileLock>,
    ports: Option<AssignedPorts>,
    connected_at: Option<SystemTime>,
    last_error: Option<String>,
    reconnect_attempt: u32,
    healthy: bool,
    last_health_check_ms: Option<i64>,
    profile_name: Option<String>,
    server: Option<String>,
    latency_ms: Option<u64>,
    kill_switch_engaged: bool,
    consecutive_unhealthy: u32,
}

impl Default for LiveState {
    fn default() -> Self {
        Self {
            state: VpnState::Disconnected,
            running: None,
            lock: None,
            ports: None,
            connected_at: None,
            last_error: None,
            reconnect_attempt: 0,
            healthy: false,
            last_health_check_ms: None,
            profile_name: None,
            server: None,
            latency_ms: None,
            kill_switch_engaged: false,
            consecutive_unhealthy: 0,
        }
    }
}

struct Supervisor {
    token: CancellationToken,
    join: JoinHandle<()>,
}

struct Entry {
    paths: InstancePaths,
    config: RwLock<InstanceConfig>,
    policy: RwLock<PolicySnapshot>,
    state: Mutex<LiveState>,
    traffic: TrafficMonitor,
    /// Serializes start/stop/reconnect/reload for this instance only.
    op: AsyncMutex<()>,
    supervisor: Mutex<Option<Supervisor>>,
    /// Set false by stop so an in-flight spawn cannot resurrect the instance.
    desired_running: AtomicBool,
}

impl Entry {
    fn view(&self) -> InstanceStatusView {
        let cfg = self
            .config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let policy = self
            .policy
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let traffic = self.traffic.snapshot();
        let ports = st.ports;
        let endpoint = ports.and_then(|p| p.proxy_endpoint(cfg.proxy_kind));
        let proxy_port = ports.and_then(|p| p.listen);
        let clash_api_port = ports.map(|p| p.clash);
        let uptime_secs = st
            .connected_at
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        InstanceStatusView {
            id: cfg.id.clone(),
            name: cfg.name.clone(),
            mode: cfg.mode.as_str().to_string(),
            proxy_kind: if cfg.mode == InstanceMode::Proxy {
                cfg.proxy_kind.as_str().to_string()
            } else {
                "tun".to_string()
            },
            state: st.state,
            profile_id: cfg.profile_id.clone(),
            profile_name: st.profile_name.clone(),
            server: st.server.clone(),
            pid: st.running.as_ref().map(|r| r.pid),
            interface: if st.state == VpnState::Connected && cfg.mode == InstanceMode::Tun {
                Some(guess_utun().unwrap_or_else(|| "utun".into()))
            } else {
                None
            },
            endpoint,
            proxy_port,
            clash_api_port,
            connected_at: st.connected_at.map(format_rfc3339),
            uptime_secs,
            bytes_sent: traffic.bytes_sent,
            bytes_received: traffic.bytes_received,
            latency_ms: st.latency_ms,
            last_error: st.last_error.clone(),
            healthy: st.healthy && st.state == VpnState::Connected,
            fail_closed: cfg.fail_closed,
            kill_switch: cfg.kill_switch || policy.settings.kill_switch,
            auto_reconnect: cfg.auto_reconnect && policy.settings.auto_reconnect,
            reconnect_attempt: st.reconnect_attempt,
            policy_mode: policy.settings.mode.as_str().to_string(),
            last_health_check_ms: st.last_health_check_ms,
            created_at_ms: cfg.created_at_ms,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct InstancesFile {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    instances: Vec<InstanceConfig>,
}

/// Shared manager internals (cheaply cloneable handle).
#[derive(Clone)]
pub struct VpnInstanceManager {
    shared: Arc<Shared>,
}

struct Shared {
    backend: Arc<dyn InstanceProcessBackend>,
    resolver: Arc<dyn ProfileResolver>,
    registry: RwLock<HashMap<String, Arc<Entry>>>,
    ports: Mutex<PortAllocator>,
    events: broadcast::Sender<InstanceEvent>,
    loaded: AtomicBool,
    /// Config directory the registry was loaded from. Allows tests and
    /// embedders to switch `SSC_CONFIG_DIR` without stale global state.
    loaded_dir: Mutex<Option<std::path::PathBuf>>,
    load_lock: AsyncMutex<()>,
}

impl std::fmt::Debug for VpnInstanceManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VpnInstanceManager")
            .field(
                "instances",
                &self.shared.registry.read().map(|r| r.len()).unwrap_or(0),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

impl Default for VpnInstanceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl VpnInstanceManager {
    /// Production manager using sing-box and the SSC profile store.
    pub fn new() -> Self {
        Self::with_backend_and_resolver(Arc::new(SingBoxBackend), Arc::new(StoreProfileResolver))
    }

    /// Embedder/test constructor with injected process backend + credentials.
    pub fn with_backend_and_resolver(
        backend: Arc<dyn InstanceProcessBackend>,
        resolver: Arc<dyn ProfileResolver>,
    ) -> Self {
        let (events, _) = broadcast::channel(512);
        Self {
            shared: Arc::new(Shared {
                backend,
                resolver,
                registry: RwLock::new(HashMap::new()),
                ports: Mutex::new(PortAllocator::default()),
                events,
                loaded: AtomicBool::new(false),
                loaded_dir: Mutex::new(None),
                load_lock: AsyncMutex::new(()),
            }),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<InstanceEvent> {
        self.shared.events.subscribe()
    }

    fn current_config_dir() -> std::path::PathBuf {
        ssc_core::config_dir().unwrap_or_default()
    }

    async fn ensure_loaded(&self) -> Result<(), String> {
        let dir = Self::current_config_dir();
        if self.shared.loaded.load(Ordering::Acquire) {
            let same = self
                .shared
                .loaded_dir
                .lock()
                .map(|d| d.as_deref() == Some(dir.as_path()))
                .unwrap_or(false);
            if same {
                return Ok(());
            }
        }
        let _guard = self.shared.load_lock.lock().await;
        let dir = Self::current_config_dir();
        if self.shared.loaded.load(Ordering::Acquire) {
            let same = self
                .shared
                .loaded_dir
                .lock()
                .map(|d| d.as_deref() == Some(dir.as_path()))
                .unwrap_or(false);
            if same {
                return Ok(());
            }
        }
        self.load_registry()?;
        if let Ok(mut loaded_dir) = self.shared.loaded_dir.lock() {
            *loaded_dir = Some(dir);
        }
        self.shared.loaded.store(true, Ordering::Release);
        Ok(())
    }

    fn load_registry(&self) -> Result<(), String> {
        let path = ssc_core::instances_registry_path()?;
        let mut file = if path.is_file() {
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("read instances: {e}"))?;
            serde_json::from_str::<InstancesFile>(&text)
                .map_err(|e| format!("parse instances: {e}"))?
        } else {
            InstancesFile {
                version: 1,
                instances: Vec::new(),
            }
        };

        let global_policy = load_policy().unwrap_or_default();
        let mut map = HashMap::new();

        // Always provide the compatibility instance.
        if !file.instances.iter().any(|c| c.id == DEFAULT_INSTANCE_ID) {
            let mut cfg =
                InstanceConfig::new(DEFAULT_INSTANCE_ID, "Default VPN", InstanceMode::Tun);
            cfg.auto_reconnect = global_policy.settings.auto_reconnect;
            file.instances.push(cfg);
        }

        for cfg in file.instances {
            if cfg.validate().is_err() {
                continue;
            }
            let paths = InstancePaths::for_id(&cfg.id)?;
            let policy = if cfg.id == DEFAULT_INSTANCE_ID {
                global_policy.clone()
            } else {
                load_policy_at(&paths.policy).unwrap_or_else(|_| global_policy.clone())
            };
            let st = ssc_runtime::read_status_at(&paths);
            let alive = ssc_runtime::is_instance_connected(&paths);
            let mut live = LiveState::default();
            if alive {
                if let Some(pid) = st.pid {
                    live.state = VpnState::Connected;
                    live.running = Some(RunningProcess {
                        pid,
                        instance_id: cfg.id.clone(),
                        config_path: paths.config.clone(),
                    });
                    live.connected_at = st
                        .started_at_ms
                        .and_then(|ms| UNIX_EPOCH.checked_add(Duration::from_millis(ms as u64)));
                    live.healthy = true;
                    live.ports = match (st.proxy_port, st.clash_api_port) {
                        (_, Some(clash)) => Some(AssignedPorts {
                            listen: st.proxy_port,
                            clash,
                        }),
                        _ => None,
                    };
                }
            } else if st.last_error.is_some() {
                live.last_error = st.last_error;
                live.state = VpnState::Disconnected;
            }
            let entry = Arc::new(Entry {
                paths,
                config: RwLock::new(cfg.clone()),
                policy: RwLock::new(policy),
                state: Mutex::new(live),
                traffic: TrafficMonitor::new(),
                op: AsyncMutex::new(()),
                supervisor: Mutex::new(None),
                desired_running: AtomicBool::new(false),
            });
            if let Some(ports) = entry.state.lock().map(|s| s.ports).unwrap_or(None) {
                self.shared
                    .ports
                    .lock()
                    .map(|mut p| p.reserve(ports.clash))
                    .ok();
                if let Some(l) = ports.listen {
                    self.shared.ports.lock().map(|mut p| p.reserve(l)).ok();
                }
            }
            map.insert(cfg.id, entry);
        }
        *self.shared.registry.write().map_err(|e| e.to_string())? = map;
        Ok(())
    }

    fn persist_registry(&self) -> Result<(), String> {
        let mut configs: Vec<InstanceConfig> = self
            .shared
            .registry
            .read()
            .map_err(|e| e.to_string())?
            .values()
            .map(|e| e.config.read().unwrap_or_else(|x| x.into_inner()).clone())
            .collect();
        configs.sort_by(|a, b| a.id.cmp(&b.id));
        let path = ssc_core::instances_registry_path()?;
        let text = serde_json::to_string_pretty(&InstancesFile {
            version: 1,
            instances: configs,
        })
        .map_err(|e| e.to_string())?;
        write_private(&path, &text)
    }

    fn entry(&self, id: &str) -> Result<Arc<Entry>, String> {
        let registry = self.shared.registry.read().map_err(|e| e.to_string())?;
        registry
            .get(id)
            .cloned()
            .ok_or_else(|| format!("instance not found: {id}"))
    }

    fn emit(&self, event: InstanceEvent) {
        let _ = self.shared.events.send(event);
    }

    fn emit_status(&self, entry: &Entry) {
        self.emit(InstanceEvent::InstanceStatus {
            instance: Box::new(entry.view()),
        });
    }

    /// Create a new independent instance. Does not start it.
    pub async fn create(&self, req: CreateInstanceRequest) -> Result<InstanceStatusView, String> {
        self.ensure_loaded().await?;
        let mode = req
            .mode
            .as_deref()
            .and_then(InstanceMode::parse)
            .unwrap_or(InstanceMode::Proxy);
        let id = match req.id.as_deref() {
            Some(id) => id.trim().to_string(),
            None => {
                let slug = slugify(req.name.as_deref().unwrap_or("vpn"));
                format!("{slug}-{}", short_id())
            }
        };
        ssc_core::validate_instance_id(&id)?;
        if self
            .shared
            .registry
            .read()
            .map_err(|e| e.to_string())?
            .contains_key(&id)
        {
            return Err(format!("instance already exists: {id}"));
        }
        let name = req
            .name
            .unwrap_or_else(|| format!("VPN {id}"))
            .trim()
            .to_string();
        let mut cfg = InstanceConfig::new(id.clone(), name, mode);
        cfg.profile_id = req.profile_id;
        if let Some(kind) = req.proxy_kind.as_deref().and_then(InboundKind::parse) {
            cfg.proxy_kind = kind;
        }
        cfg.listen_port = req.listen_port;
        cfg.clash_api_port = req.clash_api_port;
        if let Some(v) = req.auto_reconnect {
            cfg.auto_reconnect = v;
        }
        if let Some(v) = req.fail_closed {
            cfg.fail_closed = v;
        }
        if let Some(v) = req.kill_switch {
            cfg.kill_switch = v;
        }
        if let Some(v) = req.start_on_boot {
            cfg.start_on_boot = v;
        }
        cfg.validate()?;

        let paths = InstancePaths::for_id(&id)?;
        paths.ensure()?;
        let policy = match req.policy {
            Some(p) => p,
            None => load_policy().unwrap_or_default(),
        };
        save_policy_at(&paths.policy, &policy).map_err(|e| e.to_string())?;

        let entry = Arc::new(Entry {
            paths,
            config: RwLock::new(cfg),
            policy: RwLock::new(policy),
            state: Mutex::new(LiveState::default()),
            traffic: TrafficMonitor::new(),
            op: AsyncMutex::new(()),
            supervisor: Mutex::new(None),
            desired_running: AtomicBool::new(false),
        });
        let view = entry.view();
        self.shared
            .registry
            .write()
            .map_err(|e| e.to_string())?
            .insert(id, entry);
        self.persist_registry()?;
        self.emit(InstanceEvent::InstancesChanged);
        self.emit_status_by_id(&view.id);
        Ok(view)
    }

    /// Ensure the compatibility `default` instance exists and sync its profile.
    pub async fn configure_default(
        &self,
        profile_id: Option<String>,
        mode: Option<InstanceMode>,
        proxy_kind: Option<InboundKind>,
        listen_port: Option<u16>,
    ) -> Result<(), String> {
        self.ensure_loaded().await?;
        let entry = self.entry(DEFAULT_INSTANCE_ID)?;
        {
            let mut cfg = entry.config.write().map_err(|e| e.to_string())?;
            if let Some(p) = profile_id {
                cfg.profile_id = Some(p);
            }
            if let Some(m) = mode {
                cfg.mode = m;
            }
            if let Some(k) = proxy_kind {
                cfg.proxy_kind = k;
            }
            if listen_port.is_some() {
                cfg.listen_port = listen_port;
            }
            cfg.validate()?;
        }
        self.persist_registry()
    }

    pub async fn get_config(&self, id: &str) -> Result<InstanceConfig, String> {
        self.ensure_loaded().await?;
        let entry = self.entry(id)?;
        let cfg = entry.config.read().map_err(|e| e.to_string())?.clone();
        Ok(cfg)
    }

    /// Update a definition. A running instance is restarted atomically.
    pub async fn update(
        &self,
        id: &str,
        patch: UpdateInstanceRequest,
    ) -> Result<InstanceStatusView, String> {
        self.ensure_loaded().await?;
        let entry = self.entry(id)?;
        let was_running = {
            let st = entry.state.lock().map_err(|e| e.to_string())?;
            matches!(st.state, VpnState::Connected | VpnState::Connecting)
        };
        if was_running {
            self.stop(id).await?;
        }
        {
            let mut cfg = entry.config.write().map_err(|e| e.to_string())?;
            if let Some(name) = patch.name {
                if name.trim().is_empty() {
                    return Err("instance name empty".into());
                }
                cfg.name = name.trim().to_string();
            }
            if let Some(p) = patch.profile_id {
                cfg.profile_id = Some(p);
            }
            if let Some(mode) = patch.mode.as_deref().and_then(InstanceMode::parse) {
                cfg.mode = mode;
            }
            if let Some(kind) = patch.proxy_kind.as_deref().and_then(InboundKind::parse) {
                cfg.proxy_kind = kind;
            }
            if patch.clear_ports {
                cfg.listen_port = None;
                cfg.clash_api_port = None;
            } else {
                if patch.listen_port.is_some() {
                    cfg.listen_port = patch.listen_port;
                }
                if patch.clash_api_port.is_some() {
                    cfg.clash_api_port = patch.clash_api_port;
                }
            }
            if let Some(v) = patch.auto_reconnect {
                cfg.auto_reconnect = v;
            }
            if let Some(v) = patch.fail_closed {
                cfg.fail_closed = v;
            }
            if let Some(v) = patch.kill_switch {
                cfg.kill_switch = v;
            }
            if let Some(v) = patch.start_on_boot {
                cfg.start_on_boot = v;
            }
            cfg.validate()?;
        }
        self.persist_registry()?;
        self.emit(InstanceEvent::InstancesChanged);
        if was_running {
            self.start(id).await?;
        }
        self.status(id).await
    }

    /// Start one instance. Other instances are untouched.
    pub async fn start(&self, id: &str) -> Result<InstanceStatusView, String> {
        self.ensure_loaded().await?;
        let entry = self.entry(id)?;
        let _op = entry.op.lock().await;
        entry.desired_running.store(true, Ordering::SeqCst);
        let result = self.connect_entry(&entry).await;
        match result {
            Ok(()) => {
                self.install_supervisor(&entry);
                self.emit_status(&entry);
                Ok(entry.view())
            }
            Err(e) => {
                let cfg = entry
                    .config
                    .read()
                    .unwrap_or_else(|x| x.into_inner())
                    .clone();
                let policy = entry
                    .policy
                    .read()
                    .unwrap_or_else(|x| x.into_inner())
                    .clone();
                let auto = cfg.auto_reconnect && policy.settings.auto_reconnect;
                if auto {
                    // Keep retrying in the background (fail-closed state).
                    self.install_supervisor(&entry);
                } else {
                    entry.desired_running.store(false, Ordering::SeqCst);
                    self.release_ports(&entry);
                    if let Ok(mut st) = entry.state.lock() {
                        st.lock = None;
                    }
                }
                self.emit_status(&entry);
                Err(e)
            }
        }
    }

    async fn connect_entry(&self, entry: &Arc<Entry>) -> Result<(), String> {
        if !entry.desired_running.load(Ordering::SeqCst) {
            return Err("start cancelled".into());
        }
        {
            let st = entry.state.lock().map_err(|e| e.to_string())?;
            if st.state == VpnState::Connected {
                if let Some(run) = &st.running {
                    if self.shared.backend.is_alive(run) {
                        return Ok(());
                    }
                }
            }
        }
        let cfg = entry.config.read().map_err(|e| e.to_string())?.clone();
        cfg.validate()?;
        self.ensure_tun_exclusive(entry, cfg.mode)?;

        // Acquire the per-instance file lock once; keep it across reconnects.
        {
            let has_lock = entry
                .state
                .lock()
                .map_err(|e| e.to_string())?
                .lock
                .is_some();
            if !has_lock {
                let lock = InstanceFileLock::acquire(&entry.paths)?;
                entry.state.lock().map_err(|e| e.to_string())?.lock = Some(lock);
            }
        }

        let ports = self.assign_ports(&cfg)?;
        {
            let mut st = entry.state.lock().map_err(|e| e.to_string())?;
            st.state = VpnState::Connecting;
            st.ports = Some(ports);
            st.last_error = None;
            st.healthy = false;
            st.consecutive_unhealthy = 0;
        }
        self.emit_status(entry);

        let backend = self.shared.backend.clone();
        let resolver = self.shared.resolver.clone();
        let paths = entry.paths.clone();
        let profile_ref = cfg.profile_id.clone();
        let is_default = entry.paths.id == DEFAULT_INSTANCE_ID;

        let prepared = tokio::task::spawn_blocking(move || {
            backend.preflight(cfg.mode)?;
            let binding = match profile_ref.as_deref() {
                Some(id) => resolver.resolve(id)?,
                None => resolver.active()?,
            };
            let policy = if is_default {
                load_policy().map_err(|e| e.to_string())?
            } else {
                load_policy_at(&paths.policy).map_err(|e| e.to_string())?
            };
            let options = match cfg.mode {
                InstanceMode::Tun => SingboxOptions {
                    inbound: InboundKind::Tun,
                    listen_host: cfg.listen_host.clone(),
                    listen_port: None,
                    clash_api_port: ports.clash,
                    tun_address: ssc_core::DEFAULT_TUN_ADDRESS.into(),
                },
                InstanceMode::Proxy => SingboxOptions::proxy(
                    cfg.proxy_kind,
                    ports
                        .listen
                        .ok_or_else(|| "proxy instance has no listen port".to_string())?,
                    ports.clash,
                ),
            };
            if is_default {
                ssc_core::write_legacy_singbox_config(&binding.uri, &policy, &options)?;
            } else {
                ssc_core::write_singbox_config_at(
                    &binding.uri,
                    &policy,
                    &options,
                    &paths.config,
                    Some(&paths.meta),
                )?;
            }
            let running = backend.spawn(
                &paths,
                &paths.config,
                &binding.id,
                cfg.mode,
                ports.listen,
                ports.clash,
            )?;
            let latency = ssc_runtime::probe_tcp(
                &binding.server,
                binding.server_port,
                Duration::from_secs(2),
            )
            .ok()
            .map(|d| d.as_millis().max(1) as u64);
            Ok::<_, String>((running, binding, policy, latency))
        })
        .await
        .map_err(|e| format!("instance spawn task: {e}"))?;

        let (running, binding, policy, latency) = match prepared {
            Ok(v) => v,
            Err(e) => {
                self.fail_entry(entry, e.clone(), false);
                return Err(e);
            }
        };

        if !entry.desired_running.load(Ordering::SeqCst) {
            let _ = self.stop_running(&running);
            self.fail_entry(entry, "start cancelled".into(), false);
            return Err("start cancelled".into());
        }

        {
            let mut st = entry.state.lock().map_err(|e| e.to_string())?;
            st.state = VpnState::Connected;
            st.running = Some(running);
            st.connected_at = Some(SystemTime::now());
            st.last_error = None;
            st.healthy = true;
            st.last_health_check_ms = Some(now_ms());
            st.reconnect_attempt = 0;
            st.profile_name = Some(binding.name.clone());
            st.server = Some(binding.server.clone());
            st.latency_ms = latency;
            st.consecutive_unhealthy = 0;
            if st.kill_switch_engaged {
                let _ = kill_switch::deactivate();
                st.kill_switch_engaged = false;
            }
        }
        *entry.policy.write().map_err(|e| e.to_string())? = policy.clone();
        if let Some(server) = entry.state.lock().ok().and_then(|s| s.server.clone()) {
            eprintln!(
                "[VPN_INSTANCE] id={} state=connected mode={} server={}",
                entry.paths.id,
                cfg.mode.as_str(),
                server
            );
        }
        self.emit_status(entry);
        Ok(())
    }

    fn fail_entry(&self, entry: &Entry, error: String, unexpected: bool) {
        let cfg = entry
            .config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let policy = entry
            .policy
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        {
            let Ok(mut st) = entry.state.lock() else {
                return;
            };
            st.state = VpnState::Error;
            st.running = None;
            st.connected_at = None;
            st.healthy = false;
            st.last_error = Some(error.clone());
            st.reconnect_attempt = st.reconnect_attempt.saturating_add(1);
            if unexpected && cfg.fail_closed && cfg.mode == InstanceMode::Tun && cfg.kill_switch {
                let server = st.server.clone().unwrap_or_default();
                if kill_switch::activate_for_policy(&server, &policy).is_ok() {
                    st.kill_switch_engaged = true;
                    let _ = crate::reconcile::engage_kill_switch_marker();
                }
            }
            // Persist the failure so a restarting API/CLI still reports Error
            // (fail-closed) instead of silently appearing disconnected.
            let _ = ssc_runtime::write_status_at(
                &entry.paths,
                &ssc_runtime::InstanceStatus {
                    running: false,
                    pid: None,
                    profile_id: cfg.profile_id.clone(),
                    last_error: Some(error.clone()),
                    updated_at_ms: now_ms(),
                    instance_id: Some(entry.paths.id.clone()),
                    mode: Some(cfg.mode.as_str().to_string()),
                    proxy_port: st.ports.and_then(|p| p.listen),
                    clash_api_port: st.ports.map(|p| p.clash),
                    started_at_ms: None,
                    exit_code: None,
                },
            );
        }
        self.release_ports(entry);
        entry.paths.wipe_config();
        eprintln!(
            "[VPN_INSTANCE] id={} state=error error={error}",
            entry.paths.id
        );
        self.emit_status(entry);
    }

    /// Stop one instance. Never affects other instances or foreign processes.
    pub async fn stop(&self, id: &str) -> Result<InstanceStatusView, String> {
        self.ensure_loaded().await?;
        let entry = self.entry(id)?;
        let _op = entry.op.lock().await;
        self.stop_entry(&entry).await?;
        Ok(entry.view())
    }

    async fn stop_entry(&self, entry: &Arc<Entry>) -> Result<(), String> {
        entry.desired_running.store(false, Ordering::SeqCst);
        self.cancel_supervisor(entry);
        {
            let mut st = entry.state.lock().map_err(|e| e.to_string())?;
            st.state = VpnState::Disconnecting;
        }
        self.emit_status(entry);

        let (running, engaged) = {
            let mut st = entry.state.lock().map_err(|e| e.to_string())?;
            (st.running.take(), st.kill_switch_engaged)
        };
        let backend = self.shared.backend.clone();
        let paths = entry.paths.clone();
        tokio::task::spawn_blocking(move || {
            if let Some(run) = running {
                let _ = backend.stop(&run);
            } else {
                let _ = ssc_runtime::stop_instance(&paths);
            }
        })
        .await
        .map_err(|e| format!("stop task: {e}"))?;

        if engaged {
            let _ = kill_switch::deactivate();
            let _ = crate::reconcile::deactivate_kill_switch();
        }
        {
            let mut st = entry.state.lock().map_err(|e| e.to_string())?;
            st.running = None;
            st.ports = None;
            st.connected_at = None;
            st.last_error = None;
            st.healthy = false;
            st.kill_switch_engaged = false;
            st.reconnect_attempt = 0;
            st.consecutive_unhealthy = 0;
            st.state = VpnState::Disconnected;
            st.lock = None;
        }
        let cfg = entry
            .config
            .read()
            .map(|c| c.clone())
            .unwrap_or_else(|e| e.into_inner().clone());
        let _ = ssc_runtime::write_status_at(
            &entry.paths,
            &ssc_runtime::InstanceStatus {
                running: false,
                pid: None,
                profile_id: cfg.profile_id,
                last_error: None,
                updated_at_ms: now_ms(),
                instance_id: Some(entry.paths.id.clone()),
                mode: Some(cfg.mode.as_str().to_string()),
                proxy_port: None,
                clash_api_port: None,
                started_at_ms: None,
                exit_code: Some(0),
            },
        );
        self.release_ports(entry);
        entry.paths.wipe_config();
        eprintln!("[VPN_INSTANCE] id={} state=disconnected", entry.paths.id);
        self.emit_status(entry);
        Ok(())
    }

    /// Restart one instance using its current profile + policy.
    pub async fn restart(&self, id: &str) -> Result<InstanceStatusView, String> {
        self.stop(id).await?;
        self.start(id).await
    }

    /// Remove an instance definition and all its runtime files.
    pub async fn remove(&self, id: &str) -> Result<(), String> {
        self.ensure_loaded().await?;
        if id == DEFAULT_INSTANCE_ID {
            return Err("default instance cannot be removed — use `ssc reset-network`".into());
        }
        let entry = self.entry(id)?;
        let _ = self.stop(id).await;
        self.cancel_supervisor(&entry);
        self.shared
            .registry
            .write()
            .map_err(|e| e.to_string())?
            .remove(id);
        entry.paths.wipe_all();
        let root = entry.paths.root.clone();
        let _ = std::fs::remove_dir_all(root);
        self.persist_registry()?;
        self.emit(InstanceEvent::InstancesChanged);
        Ok(())
    }

    /// Status of one instance.
    pub async fn status(&self, id: &str) -> Result<InstanceStatusView, String> {
        self.ensure_loaded().await?;
        let entry = self.entry(id)?;
        Ok(entry.view())
    }

    /// Status of all instances (compatibility instance first).
    pub async fn list(&self) -> Result<Vec<InstanceStatusView>, String> {
        self.ensure_loaded().await?;
        let entries: Vec<Arc<Entry>> = self
            .shared
            .registry
            .read()
            .map_err(|e| e.to_string())?
            .values()
            .cloned()
            .collect();
        let mut views: Vec<_> = entries.iter().map(|e| e.view()).collect();
        views.sort_by(|a, b| {
            let da = a.id != DEFAULT_INSTANCE_ID;
            let db = b.id != DEFAULT_INSTANCE_ID;
            da.cmp(&db).then_with(|| a.name.cmp(&b.name))
        });
        Ok(views)
    }

    /// Load the policy snapshot owned by this instance.
    pub async fn policy(&self, id: &str) -> Result<PolicySnapshot, String> {
        self.ensure_loaded().await?;
        let entry = self.entry(id)?;
        let policy = if id == DEFAULT_INSTANCE_ID {
            load_policy().map_err(|e| e.to_string())?
        } else {
            load_policy_at(&entry.paths.policy).map_err(|e| e.to_string())?
        };
        *entry.policy.write().map_err(|e| e.to_string())? = policy.clone();
        Ok(policy)
    }

    /// Persist an isolated policy snapshot and apply it to a running instance.
    pub async fn set_policy(
        &self,
        id: &str,
        snapshot: &PolicySnapshot,
    ) -> Result<InstanceStatusView, String> {
        self.ensure_loaded().await?;
        let entry = self.entry(id)?;
        save_policy_at(&entry.paths.policy, snapshot).map_err(|e| e.to_string())?;
        *entry.policy.write().map_err(|e| e.to_string())? = snapshot.clone();
        self.apply_policy(id).await
    }

    /// Recompile the current policy into this instance's sing-box config.
    ///
    /// Prefers a Clash API hot reload; falls back to restarting only this
    /// instance. Other instances are never touched.
    pub async fn apply_policy(&self, id: &str) -> Result<InstanceStatusView, String> {
        self.ensure_loaded().await?;
        let entry = self.entry(id)?;
        let _op = entry.op.lock().await;
        let policy = if id == DEFAULT_INSTANCE_ID {
            load_policy().map_err(|e| e.to_string())?
        } else {
            load_policy_at(&entry.paths.policy).map_err(|e| e.to_string())?
        };
        *entry.policy.write().map_err(|e| e.to_string())? = policy.clone();
        let connected = {
            let st = entry.state.lock().map_err(|e| e.to_string())?;
            st.state == VpnState::Connected && st.running.is_some()
        };
        if !connected {
            // Drop the state guard before building the view (view re-locks it).
            return Ok(entry.view());
        }
        let cfg = entry.config.read().map_err(|e| e.to_string())?.clone();
        let ports = entry
            .state
            .lock()
            .map_err(|e| e.to_string())?
            .ports
            .ok_or_else(|| "instance has no assigned ports".to_string())?;
        let resolver = self.shared.resolver.clone();
        let paths = entry.paths.clone();
        let profile_ref = cfg.profile_id.clone();
        let is_default = id == DEFAULT_INSTANCE_ID;
        let rewrite_policy = policy.clone();

        let rewrite = tokio::task::spawn_blocking(move || {
            let binding = match profile_ref.as_deref() {
                Some(p) => resolver.resolve(p)?,
                None => resolver.active()?,
            };
            let options = match cfg.mode {
                InstanceMode::Tun => SingboxOptions {
                    inbound: InboundKind::Tun,
                    listen_host: cfg.listen_host.clone(),
                    listen_port: None,
                    clash_api_port: ports.clash,
                    tun_address: ssc_core::DEFAULT_TUN_ADDRESS.into(),
                },
                InstanceMode::Proxy => SingboxOptions::proxy(
                    cfg.proxy_kind,
                    ports
                        .listen
                        .ok_or_else(|| "proxy instance has no listen port".to_string())?,
                    ports.clash,
                ),
            };
            if is_default {
                ssc_core::write_legacy_singbox_config(&binding.uri, &rewrite_policy, &options)?;
            } else {
                ssc_core::write_singbox_config_at(
                    &binding.uri,
                    &rewrite_policy,
                    &options,
                    &paths.config,
                    Some(&paths.meta),
                )?;
            }
            Ok::<_, String>(())
        })
        .await
        .map_err(|e| format!("policy rewrite task: {e}"))?;
        if let Err(e) = rewrite {
            self.fail_entry(entry.as_ref(), e.clone(), false);
            return Ok(entry.view());
        }

        let path = entry.paths.config.to_string_lossy().to_string();
        let clash_port = ports.clash;
        let reload = tokio::task::spawn_blocking(move || clash_api_reload(clash_port, &path))
            .await
            .map_err(|e| format!("reload task: {e}"))?;
        match reload {
            Ok(()) => {
                eprintln!(
                    "[POLICY_RELOADED] instance={id} mode={} rules={}",
                    policy.settings.mode.as_str(),
                    policy.active_rules().count()
                );
                self.emit_status(&entry);
                Ok(entry.view())
            }
            Err(e) => {
                eprintln!("[POLICY_RELOAD_FAILED] instance={id}: {e}");
                // Fall back to restarting this instance only. `entry.op` is
                // already held by this call, so do not re-lock it (deadlock).
                self.stop_entry(&entry).await?;
                entry.desired_running.store(true, Ordering::SeqCst);
                self.connect_entry(&entry).await?;
                self.install_supervisor(&entry);
                self.emit_status(&entry);
                Ok(entry.view())
            }
        }
    }

    /// Poll Clash API for traffic/connection metadata of one instance.
    pub async fn poll_traffic(&self, id: &str) -> Result<TrafficSnapshot, String> {
        self.ensure_loaded().await?;
        let entry = self.entry(id)?;
        let port = entry
            .state
            .lock()
            .map_err(|e| e.to_string())?
            .ports
            .map(|p| p.clash);
        if let Some(port) = port {
            entry.traffic.poll_clash_on(port);
        }
        Ok(entry.traffic.snapshot())
    }

    pub async fn traffic(&self, id: &str) -> Result<TrafficSnapshot, String> {
        self.ensure_loaded().await?;
        let entry = self.entry(id)?;
        Ok(entry.traffic.snapshot())
    }

    /// Poll every connected instance; returns aggregate bytes.
    pub async fn poll_all_traffic(&self) -> (u64, u64) {
        if self.ensure_loaded().await.is_err() {
            return (0, 0);
        }
        let entries: Vec<Arc<Entry>> = self
            .shared
            .registry
            .read()
            .map(|r| r.values().cloned().collect())
            .unwrap_or_default();
        let mut sent = 0;
        let mut received = 0;
        for entry in entries {
            let port = match entry.state.lock() {
                Ok(st) => st.ports.map(|p| p.clash),
                Err(_) => None,
            };
            if let Some(port) = port {
                entry.traffic.poll_clash_on(port);
            }
            let snap = entry.traffic.snapshot();
            sent += snap.bytes_sent;
            received += snap.bytes_received;
        }
        (sent, received)
    }

    /// Bounded, redacted per-instance log tail.
    pub async fn log_tail(&self, id: &str, max_bytes: usize) -> Result<String, String> {
        self.ensure_loaded().await?;
        let entry = self.entry(id)?;
        Ok(ssc_runtime::read_instance_log(&entry.paths, max_bytes))
    }

    /// Re-read the on-disk registry after an external reset.
    pub async fn reload(&self) -> Result<(), String> {
        self.shutdown().await;
        self.shared
            .registry
            .write()
            .map_err(|e| e.to_string())?
            .clear();
        self.shared
            .ports
            .lock()
            .map(|mut p| *p = PortAllocator::default())
            .ok();
        self.shared.loaded.store(false, Ordering::Release);
        self.ensure_loaded().await
    }

    /// Stop and clean every instance (used by `reset-network`).
    pub async fn shutdown(&self) {
        if self.ensure_loaded().await.is_err() {
            return;
        }
        let ids: Vec<String> = self
            .shared
            .registry
            .read()
            .map(|r| r.keys().cloned().collect())
            .unwrap_or_default();
        for id in ids {
            let _ = self.stop(&id).await;
        }
    }

    /// Launch instances marked `start_on_boot` (called by the API service).
    pub async fn start_on_boot(&self) -> Vec<(String, Result<(), String>)> {
        if self.ensure_loaded().await.is_err() {
            return Vec::new();
        }
        let ids: Vec<String> = self
            .shared
            .registry
            .read()
            .map(|r| {
                r.values()
                    .filter(|e| e.config.read().map(|c| c.start_on_boot).unwrap_or(false))
                    .map(|e| e.paths.id.clone())
                    .collect()
            })
            .unwrap_or_default();
        let mut out = Vec::new();
        for id in ids {
            let res = self.start(&id).await.map(|_| ());
            out.push((id, res));
        }
        out
    }

    // -- internals ---------------------------------------------------------

    fn emit_status_by_id(&self, id: &str) {
        if let Ok(entry) = self.entry(id) {
            self.emit_status(&entry);
        }
    }

    fn ensure_tun_exclusive(&self, entry: &Entry, mode: InstanceMode) -> Result<(), String> {
        if mode != InstanceMode::Tun {
            return Ok(());
        }
        let registry = self.shared.registry.read().map_err(|e| e.to_string())?;
        for (id, other) in registry.iter() {
            if id == &entry.paths.id {
                continue;
            }
            let other_mode = other
                .config
                .read()
                .map(|c| c.mode)
                .unwrap_or(InstanceMode::Proxy);
            if other_mode != InstanceMode::Tun {
                continue;
            }
            let active = other
                .state
                .lock()
                .map(|s| {
                    matches!(
                        s.state,
                        VpnState::Connected | VpnState::Connecting | VpnState::Disconnecting
                    )
                })
                .unwrap_or(false);
            if active {
                return Err(format!(
                    "tun_in_use: instance '{id}' already owns the system TUN — use Local Proxy instances for parallel connections"
                ));
            }
        }
        Ok(())
    }

    fn assign_ports(&self, cfg: &InstanceConfig) -> Result<AssignedPorts, String> {
        let policy = load_policy().unwrap_or_default();
        let settings = &policy.settings;
        let mut alloc = self.shared.ports.lock().map_err(|e| e.to_string())?;
        let clash = alloc.allocate(
            cfg.clash_api_port,
            if cfg.id == DEFAULT_INSTANCE_ID {
                Some(ssc_core::DEFAULT_CLASH_API_PORT)
            } else {
                None
            },
            settings.clash_port_start,
            settings.clash_port_end,
            "127.0.0.1",
        )?;
        let listen = if cfg.mode == InstanceMode::Proxy {
            match alloc.allocate(
                cfg.listen_port,
                None,
                settings.proxy_port_start,
                settings.proxy_port_end,
                &cfg.listen_host,
            ) {
                Ok(port) => Some(port),
                Err(e) => {
                    alloc.release(clash);
                    return Err(e);
                }
            }
        } else {
            None
        };
        if listen == Some(clash) {
            alloc.release(clash);
            if let Some(l) = listen {
                alloc.release(l);
            }
            return Err("proxy and clash ports collide".into());
        }
        Ok(AssignedPorts { listen, clash })
    }

    fn release_ports(&self, entry: &Entry) {
        let ports = entry.state.lock().ok().and_then(|mut s| s.ports.take());
        if let (Some(ports), Ok(mut alloc)) = (ports, self.shared.ports.lock()) {
            alloc.release(ports.clash);
            if let Some(l) = ports.listen {
                alloc.release(l);
            }
        }
    }

    fn install_supervisor(&self, entry: &Arc<Entry>) {
        self.cancel_supervisor(entry);
        let token = CancellationToken::new();
        let manager = self.clone();
        let e = entry.clone();
        let t = token.clone();
        let join = tokio::spawn(async move {
            manager.supervise(e, t).await;
        });
        if let Ok(mut slot) = entry.supervisor.lock() {
            *slot = Some(Supervisor { token, join });
        }
    }

    fn cancel_supervisor(&self, entry: &Entry) {
        if let Ok(mut slot) = entry.supervisor.lock() {
            if let Some(sup) = slot.take() {
                sup.token.cancel();
                sup.join.abort();
            }
        }
    }

    async fn supervise(&self, entry: Arc<Entry>, token: CancellationToken) {
        loop {
            let cfg = entry
                .config
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let policy = entry
                .policy
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let interval = Duration::from_secs(policy.settings.health_check_interval_s.max(1));
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(interval) => {}
            }
            if !entry.desired_running.load(Ordering::SeqCst) {
                break;
            }
            let (running, ports, mode) = {
                let Ok(st) = entry.state.lock() else { break };
                (st.running.clone(), st.ports, cfg.mode)
            };
            let Some(running) = running else {
                // Initial connect failed; retry with backoff if enabled.
                if cfg.auto_reconnect && policy.settings.auto_reconnect {
                    if !self.retry_connect(&entry, &policy, &token).await {
                        break;
                    }
                    continue;
                }
                break;
            };
            let Some(ports) = ports else { break };

            let backend = self.shared.backend.clone();
            let run = running.clone();
            let health = tokio::task::spawn_blocking(move || {
                backend.health(&run, mode, ports.listen, ports.clash)
            })
            .await
            .unwrap_or_default();

            let now = now_ms();
            {
                let Ok(mut st) = entry.state.lock() else {
                    break;
                };
                st.last_health_check_ms = Some(now);
                if health.is_healthy(mode) {
                    st.healthy = true;
                    st.consecutive_unhealthy = 0;
                    if st.state != VpnState::Connected {
                        st.state = VpnState::Connected;
                        st.connected_at.get_or_insert(SystemTime::now());
                        st.last_error = None;
                        st.reconnect_attempt = 0;
                    }
                } else if health.process_alive && st.state == VpnState::Connecting {
                    // Startup grace: process is up but ports not bound yet.
                    continue;
                } else {
                    st.consecutive_unhealthy = st.consecutive_unhealthy.saturating_add(1);
                    st.healthy = false;
                    if st.consecutive_unhealthy < 3 {
                        continue;
                    }
                }
            }
            let healthy = entry.state.lock().map(|s| s.healthy).unwrap_or(false);
            if healthy {
                self.emit_status(&entry);
                continue;
            }

            // Unexpected failure: fail closed, then optional reconnect.
            let was_unexpected = entry.desired_running.load(Ordering::SeqCst);
            self.fail_entry(
                entry.as_ref(),
                if health.process_alive {
                    "instance health check failed (ports not answering)".into()
                } else {
                    "sing-box exited unexpectedly; connection failed closed".into()
                },
                was_unexpected,
            );
            if !cfg.auto_reconnect || !policy.settings.auto_reconnect {
                break;
            }
            if !self.retry_connect(&entry, &policy, &token).await {
                break;
            }
        }
    }

    /// Backoff + reconnect loop. Returns false when cancelled/disabled.
    async fn retry_connect(
        &self,
        entry: &Arc<Entry>,
        policy: &PolicySnapshot,
        token: &CancellationToken,
    ) -> bool {
        loop {
            if token.is_cancelled() || !entry.desired_running.load(Ordering::SeqCst) {
                return false;
            }
            let attempt = entry.state.lock().map(|s| s.reconnect_attempt).unwrap_or(0);
            let delay = reconnect_backoff(policy, attempt);
            eprintln!(
                "[VPN_INSTANCE] id={} reconnect attempt={} delay={}ms",
                entry.paths.id,
                attempt + 1,
                delay.as_millis()
            );
            tokio::select! {
                _ = token.cancelled() => return false,
                _ = tokio::time::sleep(delay) => {}
            }
            if !entry.desired_running.load(Ordering::SeqCst) {
                return false;
            }
            let _op = entry.op.lock().await;
            if token.is_cancelled() || !entry.desired_running.load(Ordering::SeqCst) {
                return false;
            }
            match self.connect_entry(entry).await {
                Ok(()) => {
                    self.emit_status(entry);
                    return true;
                }
                Err(e) => {
                    self.fail_entry(entry.as_ref(), e, false);
                }
            }
        }
    }

    fn stop_running(&self, running: &RunningProcess) -> Result<(), String> {
        self.shared.backend.stop(running)
    }
}

/// Exponential backoff used by automatic reconnect (1s → 30s by default).
pub fn reconnect_backoff(policy: &PolicySnapshot, attempt: u32) -> Duration {
    let settings: &Settings = &policy.settings;
    let base = settings.reconnect_delay_ms.max(1);
    let max = settings.reconnect_max_delay_ms.max(base);
    let shift = attempt.min(16);
    Duration::from_millis(base.saturating_mul(1u64 << shift).min(max))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PortAllocator {
    reserved: HashSet<u16>,
}

impl PortAllocator {
    fn reserve(&mut self, port: u16) {
        self.reserved.insert(port);
    }

    fn release(&mut self, port: u16) {
        self.reserved.remove(&port);
    }

    fn allocate(
        &mut self,
        explicit: Option<u16>,
        preferred: Option<u16>,
        start: u16,
        end: u16,
        host: &str,
    ) -> Result<u16, String> {
        if let Some(port) = explicit {
            if port == 0 {
                return Err("port must be non-zero".into());
            }
            if self.reserved.contains(&port) || !port_free(host, port) {
                return Err(format!("port {port} is already in use"));
            }
            self.reserved.insert(port);
            return Ok(port);
        }
        if let Some(port) = preferred {
            if !self.reserved.contains(&port) && port_free(host, port) {
                self.reserved.insert(port);
                return Ok(port);
            }
        }
        let end = end.max(start);
        for port in start..=end {
            if !self.reserved.contains(&port) && port_free(host, port) {
                self.reserved.insert(port);
                return Ok(port);
            }
        }
        Err(format!("no free port in range {start}-{end} (host {host})"))
    }
}

fn port_free(host: &str, port: u16) -> bool {
    TcpListener::bind((host, port)).is_ok()
}

fn write_private(path: &std::path::Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create dir: {e}"))?;
    }
    std::fs::write(path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn slugify(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if (c == '-' || c == '_' || c.is_whitespace()) && !out.ends_with('-') {
            out.push('-');
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "vpn".into()
    } else {
        out.chars().take(32).collect()
    }
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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

fn guess_utun() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let text =
            crate::cmdutil::run_timed_ok("ifconfig", &[], crate::cmdutil::DEFAULT_CMD_TIMEOUT)
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

/// PUT `http://127.0.0.1:{port}/configs?force=true`.
fn clash_api_reload(port: u16, config_path: &str) -> Result<(), String> {
    let body = serde_json::json!({ "path": config_path }).to_string();
    let resp = crate::cmdutil::http_put_timed(
        &format!("http://127.0.0.1:{port}/configs?force=true"),
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

/// Poll traffic for all instances from a background task.
pub async fn poll_traffic_loop(manager: VpnInstanceManager) {
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        let _ = manager.poll_all_traffic().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const TEST_URI: &str = "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443?security=tls&sni=vpn.example.com#test";

    #[derive(Default)]
    struct MockInner {
        next_pid: u32,
        procs: HashMap<u32, std::path::PathBuf>,
        healthy: bool,
    }

    #[derive(Default)]
    struct MockBackend {
        inner: Mutex<MockInner>,
    }

    impl MockBackend {
        fn new(healthy: bool) -> Self {
            Self {
                inner: Mutex::new(MockInner {
                    next_pid: 40_000,
                    healthy,
                    ..Default::default()
                }),
            }
        }

        fn kill(&self, pid: u32) {
            self.inner.lock().unwrap().procs.remove(&pid);
        }

        fn live_count(&self) -> usize {
            self.inner.lock().unwrap().procs.len()
        }

        fn is_live(&self, pid: u32) -> bool {
            self.inner.lock().unwrap().procs.contains_key(&pid)
        }
    }

    impl InstanceProcessBackend for MockBackend {
        fn spawn(
            &self,
            paths: &InstancePaths,
            singbox_config: &Path,
            _profile_id: &str,
            _mode: InstanceMode,
            _proxy_port: Option<u16>,
            _clash_api_port: u16,
        ) -> Result<RunningProcess, String> {
            let mut g = self.inner.lock().unwrap();
            g.next_pid += 1;
            let pid = g.next_pid;
            g.procs.insert(pid, singbox_config.to_path_buf());
            Ok(RunningProcess {
                pid,
                instance_id: paths.id.clone(),
                config_path: paths.config.clone(),
            })
        }

        fn stop(&self, running: &RunningProcess) -> Result<(), String> {
            self.inner.lock().unwrap().procs.remove(&running.pid);
            Ok(())
        }

        fn is_alive(&self, running: &RunningProcess) -> bool {
            self.is_live(running.pid)
        }

        fn health(
            &self,
            running: &RunningProcess,
            _mode: InstanceMode,
            _proxy_port: Option<u16>,
            _clash_api_port: u16,
        ) -> ssc_runtime::InstanceHealth {
            let alive = self.is_live(running.pid);
            let healthy = alive && self.inner.lock().unwrap().healthy;
            ssc_runtime::InstanceHealth {
                process_alive: alive,
                proxy_reachable: healthy,
                admin_reachable: healthy,
            }
        }
    }

    struct MockResolver;

    impl ProfileResolver for MockResolver {
        fn resolve(&self, id_or_name: &str) -> Result<ResolvedProfile, String> {
            Ok(ResolvedProfile {
                id: id_or_name.to_string(),
                name: format!("Profile {id_or_name}"),
                server: "vpn.example.com".into(),
                server_port: 443,
                uri: TEST_URI.into(),
            })
        }

        fn active(&self) -> Result<ResolvedProfile, String> {
            self.resolve("active")
        }
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ssc-im-{tag}-{}-{}", std::process::id(), now_ms()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_manager(healthy: bool) -> (VpnInstanceManager, Arc<MockBackend>) {
        let backend: Arc<MockBackend> = Arc::new(MockBackend::new(healthy));
        let manager =
            VpnInstanceManager::with_backend_and_resolver(backend.clone(), Arc::new(MockResolver));
        (manager, backend)
    }

    fn fast_policy(auto_reconnect: bool) -> PolicySnapshot {
        PolicySnapshot {
            settings: Settings {
                auto_reconnect,
                health_check_interval_s: 1,
                reconnect_delay_ms: 50,
                reconnect_max_delay_ms: 200,
                ..Settings::default()
            },
            groups: vec![],
            rules: vec![],
        }
    }

    async fn create_proxy(
        manager: &VpnInstanceManager,
        id: &str,
        policy: PolicySnapshot,
    ) -> InstanceStatusView {
        manager
            .create(CreateInstanceRequest {
                id: Some(id.into()),
                name: Some(format!("Proxy {id}")),
                profile_id: Some("p1".into()),
                mode: Some("proxy".into()),
                proxy_kind: Some("mixed".into()),
                policy: Some(policy),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn ten_proxy_instances_run_independently() {
        let _guard = crate::test_env_lock_async().await;
        let dir = temp_dir("ten");
        std::env::set_var("SSC_CONFIG_DIR", &dir);

        let (manager, backend) = test_manager(true);
        for i in 0..10 {
            let view = create_proxy(&manager, &format!("proxy-{i}"), fast_policy(false)).await;
            assert_eq!(view.state, VpnState::Disconnected);
        }

        let mut ports = HashSet::new();
        let mut pids = HashSet::new();
        for i in 0..10 {
            let view = manager.start(&format!("proxy-{i}")).await.unwrap();
            assert_eq!(view.state, VpnState::Connected, "{}", view.id);
            assert_eq!(view.mode, "proxy");
            assert!(view.endpoint.is_some());
            assert!(
                ports.insert(view.proxy_port.unwrap()),
                "duplicate proxy port"
            );
            assert!(pids.insert(view.pid.unwrap()), "duplicate pid");
        }
        assert_eq!(backend.live_count(), 10);

        let all = manager.list().await.unwrap();
        let proxies: Vec<_> = all.iter().filter(|v| v.id.starts_with("proxy-")).collect();
        assert_eq!(proxies.len(), 10);
        assert!(proxies.iter().all(|v| v.state == VpnState::Connected));

        // Stopping one instance must not touch the other nine.
        let stopped = manager.stop("proxy-3").await.unwrap();
        assert_eq!(stopped.state, VpnState::Disconnected);
        assert!(!pids.is_empty());
        let all = manager.list().await.unwrap();
        for view in all.iter().filter(|v| v.id.starts_with("proxy-")) {
            if view.id == "proxy-3" {
                assert_eq!(view.state, VpnState::Disconnected);
                assert!(view.pid.is_none());
            } else {
                assert_eq!(view.state, VpnState::Connected, "{}", view.id);
                assert!(view.pid.is_some());
                assert!(backend.is_live(view.pid.unwrap()), "{} was killed", view.id);
            }
        }
        assert_eq!(backend.live_count(), 9);

        manager.shutdown().await;
        assert_eq!(backend.live_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("SSC_CONFIG_DIR");
    }

    #[tokio::test]
    async fn unexpected_exit_fails_closed_without_direct_fallback() {
        let _guard = crate::test_env_lock_async().await;
        let dir = temp_dir("failclosed");
        std::env::set_var("SSC_CONFIG_DIR", &dir);

        let (manager, backend) = test_manager(true);
        let view = create_proxy(&manager, "fail-close", fast_policy(false)).await;
        let view = manager.start(&view.id).await.unwrap();
        let pid = view.pid.unwrap();
        assert_eq!(view.state, VpnState::Connected);

        // Simulate sing-box dying behind our back.
        backend.kill(pid);

        let mut final_view = view;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            final_view = manager.status("fail-close").await.unwrap();
            if final_view.state == VpnState::Error {
                break;
            }
        }
        assert_eq!(final_view.state, VpnState::Error, "{final_view:?}");
        assert!(final_view.last_error.is_some());
        assert!(!final_view.healthy);
        assert!(final_view.pid.is_none());
        assert_eq!(backend.live_count(), 0);
        assert!(
            ssc_runtime::read_status_at(&InstancePaths::for_id("fail-close").unwrap())
                .last_error
                .is_some()
        );

        manager.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("SSC_CONFIG_DIR");
    }

    #[tokio::test]
    async fn tun_is_exclusive_but_proxy_is_not() {
        let _guard = crate::test_env_lock_async().await;
        let dir = temp_dir("tun");
        std::env::set_var("SSC_CONFIG_DIR", &dir);

        let (manager, _backend) = test_manager(true);
        for (id, mode) in [("tun-a", "tun"), ("tun-b", "tun"), ("px-a", "proxy")] {
            manager
                .create(CreateInstanceRequest {
                    id: Some(id.into()),
                    name: Some(id.into()),
                    profile_id: Some("p1".into()),
                    mode: Some(mode.into()),
                    policy: Some(fast_policy(false)),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let a = manager.start("tun-a").await.unwrap();
        assert_eq!(a.state, VpnState::Connected);
        let err = manager.start("tun-b").await.unwrap_err();
        assert!(err.contains("tun_in_use"), "{err}");

        // Proxy instances are unaffected by the TUN owner.
        let proxy = manager.start("px-a").await.unwrap();
        assert_eq!(proxy.state, VpnState::Connected);
        assert!(proxy.endpoint.is_some());

        manager.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("SSC_CONFIG_DIR");
    }

    #[tokio::test]
    async fn policies_are_isolated_per_instance() {
        let _guard = crate::test_env_lock_async().await;
        let dir = temp_dir("policy");
        std::env::set_var("SSC_CONFIG_DIR", &dir);

        let (manager, _backend) = test_manager(true);
        let mut a = fast_policy(false);
        a.settings.mode = ssc_policy::PolicyMode::Full;
        let mut b = fast_policy(false);
        b.settings.mode = ssc_policy::PolicyMode::Selective;
        create_proxy(&manager, "pol-a", a.clone()).await;
        create_proxy(&manager, "pol-b", b.clone()).await;

        let policy_a = manager.policy("pol-a").await.unwrap();
        let policy_b = manager.policy("pol-b").await.unwrap();
        assert_eq!(policy_a.settings.mode, ssc_policy::PolicyMode::Full);
        assert_eq!(policy_b.settings.mode, ssc_policy::PolicyMode::Selective);

        let mut updated = policy_a.clone();
        updated.settings.mode = ssc_policy::PolicyMode::Selective;
        manager.set_policy("pol-a", &updated).await.unwrap();
        assert_eq!(
            manager.policy("pol-a").await.unwrap().settings.mode,
            ssc_policy::PolicyMode::Selective
        );
        assert_eq!(
            manager.policy("pol-b").await.unwrap().settings.mode,
            ssc_policy::PolicyMode::Selective
        );
        assert_ne!(
            InstancePaths::for_id("pol-a").unwrap().policy,
            InstancePaths::for_id("pol-b").unwrap().policy
        );

        // Deleting one instance leaves the other intact.
        manager.remove("pol-a").await.unwrap();
        assert!(manager.status("pol-a").await.is_err());
        assert!(manager.status("pol-b").await.is_ok());

        manager.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("SSC_CONFIG_DIR");
    }
}
