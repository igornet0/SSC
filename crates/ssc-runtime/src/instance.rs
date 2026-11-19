//! Isolated sing-box instance runtime.
//!
//! Every VPN connection owns:
//! - a validated instance id and directory,
//! - its own sing-box config / meta snapshot,
//! - its own pid / status / stop / log files,
//! - its own policy snapshot path,
//! - its own ports (assigned by `ssc-service`).
//!
//! There is deliberately **no process-global tunnel state** here. The legacy
//! single-instance API in [`crate::tunnel`] maps to the reserved `default`
//! instance, which keeps old on-disk paths working for upgrades.

use crate::setup::{resolved_singbox_path, running_as_root_helper};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Reserved instance id used by the backwards-compatible single-VPN API.
pub const DEFAULT_INSTANCE_ID: &str = "default";

/// How an instance accepts user traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstanceMode {
    /// System VPN via a TUN interface. Requires elevation; one per host.
    Tun,
    /// Local loopback HTTP/SOCKS/mixed proxy. No root required.
    Proxy,
}

impl InstanceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            InstanceMode::Tun => "tun",
            InstanceMode::Proxy => "proxy",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tun" | "system" | "system-vpn" => Some(InstanceMode::Tun),
            "proxy" | "local" | "local-proxy" => Some(InstanceMode::Proxy),
            _ => None,
        }
    }
}

/// Kernel process handle owned by SSC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningProcess {
    pub pid: u32,
    pub instance_id: String,
    /// Exact config path used as the process ownership marker.
    pub config_path: PathBuf,
}

/// Result of a periodic health check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InstanceHealth {
    pub process_alive: bool,
    pub proxy_reachable: bool,
    pub admin_reachable: bool,
}

impl InstanceHealth {
    pub fn is_healthy(self, mode: InstanceMode) -> bool {
        match mode {
            InstanceMode::Tun => self.process_alive && self.admin_reachable,
            InstanceMode::Proxy => {
                self.process_alive && self.proxy_reachable && self.admin_reachable
            }
        }
    }
}

/// Low-level process backend used by the instance manager.
///
/// Production uses [`SingBoxBackend`]; tests and embedders can supply their
/// own implementation (container runtimes, remote sandboxes, fakes).
pub trait InstanceProcessBackend: Send + Sync {
    /// Platform / environment checks performed before every spawn.
    fn preflight(&self, _mode: InstanceMode) -> Result<(), String> {
        Ok(())
    }

    fn spawn(
        &self,
        paths: &InstancePaths,
        singbox_config: &Path,
        profile_id: &str,
        mode: InstanceMode,
        proxy_port: Option<u16>,
        clash_api_port: u16,
    ) -> Result<RunningProcess, String>;

    fn stop(&self, running: &RunningProcess) -> Result<(), String>;

    fn is_alive(&self, running: &RunningProcess) -> bool;

    fn health(
        &self,
        running: &RunningProcess,
        _mode: InstanceMode,
        proxy_port: Option<u16>,
        clash_api_port: u16,
    ) -> InstanceHealth {
        let process_alive = self.is_alive(running);
        InstanceHealth {
            process_alive,
            proxy_reachable: process_alive
                && proxy_port
                    .is_some_and(|p| tcp_reachable("127.0.0.1", p, Duration::from_millis(300))),
            admin_reachable: process_alive
                && tcp_reachable("127.0.0.1", clash_api_port, Duration::from_millis(300)),
        }
    }
}

/// Real sing-box process backend.
#[derive(Debug, Default, Clone, Copy)]
pub struct SingBoxBackend;

impl InstanceProcessBackend for SingBoxBackend {
    fn preflight(&self, mode: InstanceMode) -> Result<(), String> {
        if mode == InstanceMode::Tun {
            if let Some(msg) = crate::netconflict::foreign_vpn_conflict() {
                return Err(msg);
            }
        }
        Ok(())
    }

    fn spawn(
        &self,
        paths: &InstancePaths,
        singbox_config: &Path,
        profile_id: &str,
        mode: InstanceMode,
        proxy_port: Option<u16>,
        clash_api_port: u16,
    ) -> Result<RunningProcess, String> {
        let pid = spawn_instance(
            paths,
            singbox_config,
            profile_id,
            mode,
            proxy_port,
            clash_api_port,
        )?;
        Ok(RunningProcess {
            pid,
            instance_id: paths.id.clone(),
            config_path: paths.config.clone(),
        })
    }

    fn stop(&self, running: &RunningProcess) -> Result<(), String> {
        stop_process(running)
    }

    fn is_alive(&self, running: &RunningProcess) -> bool {
        process_alive(running.pid) && owned_by_config(running.pid, &running.config_path)
    }
}

fn tcp_reachable(host: &str, port: u16, timeout: Duration) -> bool {
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    for addr in addrs {
        let addr: SocketAddr = addr;
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return true;
        }
    }
    false
}

/// File layout for one instance.
#[derive(Debug, Clone)]
pub struct InstancePaths {
    pub id: String,
    pub root: PathBuf,
    pub runtime: PathBuf,
    pub config: PathBuf,
    pub meta: PathBuf,
    pub pid: PathBuf,
    pub status: PathBuf,
    pub log: PathBuf,
    pub stop: PathBuf,
    pub policy: PathBuf,
    pub lock: PathBuf,
}

impl InstancePaths {
    /// Resolve paths for `id`.
    ///
    /// `default` intentionally keeps the pre-multi-instance layout
    /// (`runtime/singbox-ephemeral.json`, `tunnel.pid`, …) so existing
    /// installations, scripts, and the public `ssc_runtime` API keep working.
    pub fn for_id(id: &str) -> Result<Self, String> {
        ssc_core::validate_instance_id(id)?;
        if id == DEFAULT_INSTANCE_ID {
            let root = ssc_core::ensure_config_dir()?;
            let runtime = ssc_core::runtime_dir()?;
            return Ok(Self {
                id: id.to_string(),
                root: root.clone(),
                runtime: runtime.clone(),
                config: ssc_core::ephemeral_singbox_path()?,
                meta: ssc_core::singbox_meta_path()?,
                pid: root.join("tunnel.pid"),
                status: root.join("tunnel.status.json"),
                log: root.join("tunnel.log"),
                stop: root.join("tunnel.stop"),
                policy: root.join("policy.json"),
                lock: runtime.join("tunnel.lock"),
            });
        }

        let root = ssc_core::instance_dir(id)?;
        let runtime = root.join("runtime");
        std::fs::create_dir_all(&runtime).map_err(|e| format!("create instance runtime: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self {
            id: id.to_string(),
            root: root.clone(),
            runtime,
            config: root.join("singbox.json"),
            meta: root.join("singbox.meta.json"),
            pid: root.join("tunnel.pid"),
            status: root.join("tunnel.status.json"),
            log: root.join("tunnel.log"),
            stop: root.join("tunnel.stop"),
            policy: root.join("policy.json"),
            lock: root.join("instance.lock"),
        })
    }

    pub fn ensure(&self) -> Result<(), String> {
        for dir in [&self.root, &self.runtime] {
            std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        Ok(())
    }

    /// Wipe the secret-bearing config and redacted meta after the process exits.
    pub fn wipe_config(&self) {
        wipe_file(&self.config);
        wipe_file(&self.meta);
    }

    /// Remove all runtime files (used when an instance is deleted or reset).
    pub fn wipe_all(&self) {
        self.wipe_config();
        for path in [&self.pid, &self.status, &self.stop, &self.lock] {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn wipe_file(path: &Path) {
    if path.is_file() {
        // Overwrite first so deleted credentials are not trivially recoverable.
        let _ = std::fs::write(path, b"{}\n");
        let _ = std::fs::remove_file(path);
    }
}

/// Per-instance status file. No credentials are ever stored here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceStatus {
    pub running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub updated_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_api_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

impl Default for InstanceStatus {
    fn default() -> Self {
        Self {
            running: false,
            pid: None,
            profile_id: None,
            last_error: None,
            updated_at_ms: now_ms(),
            instance_id: None,
            mode: None,
            proxy_port: None,
            clash_api_port: None,
            started_at_ms: None,
            exit_code: None,
        }
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn read_status_at(paths: &InstancePaths) -> InstanceStatus {
    std::fs::read_to_string(&paths.status)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn write_status_at(paths: &InstancePaths, status: &InstanceStatus) -> Result<(), String> {
    let text = serde_json::to_string_pretty(status).map_err(|e| e.to_string())?;
    let parent = paths.status.parent().ok_or("status path has no parent")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("create status dir: {e}"))?;
    std::fs::write(&paths.status, text).map_err(|e| format!("write status: {e}"))
}

fn read_pid_at(paths: &InstancePaths) -> Option<u32> {
    std::fs::read_to_string(&paths.pid)
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn write_pid_at(paths: &InstancePaths, pid: u32) -> Result<(), String> {
    paths.ensure()?;
    std::fs::write(&paths.pid, pid.to_string()).map_err(|e| format!("write pid: {e}"))
}

fn clear_pid_at(paths: &InstancePaths) {
    let _ = std::fs::remove_file(&paths.pid);
}

#[cfg(unix)]
pub fn process_alive(pid: u32) -> bool {
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

#[cfg(target_os = "windows")]
pub fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .map(|o| {
            o.status.success() && String::from_utf8_lossy(&o.stdout).contains(&pid.to_string())
        })
        .unwrap_or(false)
}

#[cfg(not(any(unix, target_os = "windows")))]
pub fn process_alive(_pid: u32) -> bool {
    false
}

/// Command line for a pid, used to verify process identity (PID-reuse guard).
fn process_command(pid: u32) -> Option<String> {
    #[cfg(unix)]
    {
        let out = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
    #[cfg(target_os = "windows")]
    {
        let ps =
            format!("(Get-CimInstance Win32_Process -Filter \"ProcessId = {pid}\").CommandLine");
        let out = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = pid;
        None
    }
}

/// True when `pid` is alive and its command line references exactly `config`.
///
/// This prevents killing or adopting an unrelated process after PID reuse and
/// prevents cross-instance interference (each config path is unique).
pub fn owned_by_config(pid: u32, config: &Path) -> bool {
    if !process_alive(pid) {
        return false;
    }
    let needle = config.to_string_lossy();
    match process_command(pid) {
        Some(cmd) => cmd.contains(needle.as_ref()),
        // Platforms where command inspection is unavailable: fall back to liveness.
        None => true,
    }
}

/// All live sing-box pids whose command line references exactly `config`.
pub fn find_owned_pids(config: &Path) -> Vec<u32> {
    #[cfg(unix)]
    {
        let needle = config.to_string_lossy().to_string();
        let out = match Command::new("ps")
            .args(["-ax", "-o", "pid=,command="])
            .output()
        {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                // Only the sing-box process, never the __tunnel-worker supervisor.
                if !line.contains(&needle)
                    || line.contains("__tunnel-worker")
                    || !line.to_ascii_lowercase().contains("sing-box")
                {
                    return None;
                }
                line.split_whitespace()
                    .next()
                    .and_then(|p| p.parse::<u32>().ok())
            })
            .collect()
    }
    #[cfg(target_os = "windows")]
    {
        let needle = config.to_string_lossy().to_string();
        let ps = format!(
            "Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -like '*sing-box*' -and $_.CommandLine -like '*{}*' }} | Select-Object -ExpandProperty ProcessId",
            needle.replace('\'', "''")
        );
        let out = match Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps])
            .output()
        {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = config;
        Vec::new()
    }
}

/// True when this instance has a live sing-box process.
pub fn is_instance_connected(paths: &InstancePaths) -> bool {
    if read_pid_at(paths).is_some_and(|p| owned_by_config(p, &paths.config)) {
        return true;
    }
    let st = read_status_at(paths);
    if let Some(pid) = st.pid.filter(|&p| owned_by_config(p, &paths.config)) {
        let _ = write_pid_at(paths, pid);
        return true;
    }
    let owned = find_owned_pids(&paths.config);
    if let Some(&pid) = owned.first() {
        let _ = write_pid_at(paths, pid);
        let mut status = st;
        status.running = true;
        status.pid = Some(pid);
        status.last_error = None;
        status.updated_at_ms = now_ms();
        status.instance_id = Some(paths.id.clone());
        let _ = write_status_at(paths, &status);
        return true;
    }
    false
}

/// Clean up only this instance's stale pids. Never scans other instances.
pub fn cleanup_instance_orphans(paths: &InstancePaths) -> Result<(), String> {
    let _ = std::fs::remove_file(&paths.stop);
    let mut pids = Vec::new();
    if let Some(pid) = read_pid_at(paths) {
        pids.push(pid);
    }
    if let Some(pid) = read_status_at(paths).pid {
        pids.push(pid);
    }
    pids.extend(find_owned_pids(&paths.config));
    pids.sort_unstable();
    pids.dedup();
    for pid in pids {
        if owned_by_config(pid, &paths.config) {
            let _ = kill_pid(pid);
            for _ in 0..20 {
                if !process_alive(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    clear_pid_at(paths);
    let mut st = read_status_at(paths);
    st.running = false;
    st.pid = None;
    st.last_error = None;
    st.updated_at_ms = now_ms();
    write_status_at(paths, &st)
}

fn check_config(singbox: &Path, config: &Path) -> Result<(), String> {
    let out = Command::new(singbox)
        .args(["check", "-c", &config.to_string_lossy()])
        .output()
        .map_err(|e| format!("sing-box check failed to start: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(format!("sing-box check failed:\n{stderr}{stdout}"));
    }
    Ok(())
}

fn sh_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// Foreground worker executed by the `ssc __tunnel-worker` CLI command.
///
/// It runs sing-box, records the real sing-box pid, and waits. It is started
/// detached both for TUN (via sudo) and for unprivileged Local Proxy instances.
#[allow(clippy::too_many_arguments)]
pub fn run_instance_worker(
    config: &Path,
    singbox: &Path,
    profile_id: Option<&str>,
    instance_id: Option<&str>,
    mode: Option<InstanceMode>,
    proxy_port: Option<u16>,
    clash_api_port: Option<u16>,
) -> Result<(), String> {
    let id = instance_id.unwrap_or(DEFAULT_INSTANCE_ID);
    let paths = InstancePaths::for_id(id)?;
    paths.ensure()?;
    check_config(singbox, config)?;
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log)
        .map_err(|e| format!("open tunnel log: {e}"))?;
    let log_err = log_file
        .try_clone()
        .map_err(|e| format!("clone log: {e}"))?;

    let mut child = Command::new(singbox)
        .args(["run", "-c", &config.to_string_lossy()])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|e| format!("spawn sing-box: {e}"))?;

    let pid = child.id();
    write_pid_at(&paths, pid)?;
    let started = now_ms();
    write_status_at(
        &paths,
        &InstanceStatus {
            running: true,
            pid: Some(pid),
            profile_id: profile_id.map(str::to_string),
            last_error: None,
            updated_at_ms: started,
            instance_id: Some(id.to_string()),
            mode: mode.map(|m| m.as_str().to_string()),
            proxy_port,
            clash_api_port,
            started_at_ms: Some(started),
            exit_code: None,
        },
    )?;

    let status = child.wait().map_err(|e| format!("wait sing-box: {e}"))?;
    clear_pid_at(&paths);
    let err = if status.success() {
        None
    } else {
        Some(format!("sing-box exited with {status}"))
    };
    write_status_at(
        &paths,
        &InstanceStatus {
            running: false,
            pid: None,
            profile_id: profile_id.map(str::to_string),
            last_error: err.clone(),
            updated_at_ms: now_ms(),
            instance_id: Some(id.to_string()),
            mode: mode.map(|m| m.as_str().to_string()),
            proxy_port,
            clash_api_port,
            started_at_ms: Some(started),
            exit_code: status.code(),
        },
    )?;
    if let Some(e) = err {
        return Err(e);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn worker_args(
    config: &Path,
    singbox: &Path,
    profile_id: Option<&str>,
    instance_id: &str,
    mode: InstanceMode,
    proxy_port: Option<u16>,
    clash_api_port: u16,
) -> Vec<String> {
    let mut args = vec![
        "__tunnel-worker".to_string(),
        "--config".into(),
        config.to_string_lossy().into_owned(),
        "--singbox".into(),
        singbox.to_string_lossy().into_owned(),
        "--instance-id".into(),
        instance_id.to_string(),
        "--mode".into(),
        mode.as_str().into(),
        "--clash-port".into(),
        clash_api_port.to_string(),
    ];
    if let Some(id) = profile_id {
        args.push("--profile-id".into());
        args.push(id.to_string());
    }
    if let Some(port) = proxy_port {
        args.push("--proxy-port".into());
        args.push(port.to_string());
    }
    args
}

fn spawn_detached_worker(args: &[String]) -> Result<u32, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // New process group: survive terminal signals / parent exit.
        cmd.process_group(0);
    }
    let child = cmd.spawn().map_err(|e| format!("spawn worker: {e}"))?;
    let pid = child.id();
    std::mem::forget(child);
    Ok(pid)
}

/// Spawn (or adopt) this instance's sing-box process.
#[allow(clippy::too_many_arguments)]
pub fn spawn_instance(
    paths: &InstancePaths,
    config: &Path,
    profile_id: &str,
    mode: InstanceMode,
    proxy_port: Option<u16>,
    clash_api_port: u16,
) -> Result<u32, String> {
    paths.ensure()?;
    let _ = std::fs::remove_file(&paths.stop);

    if is_instance_connected(paths) {
        let st = read_status_at(paths);
        if let Some(pid) = st.pid.or_else(|| read_pid_at(paths)) {
            return Ok(pid);
        }
    }
    cleanup_instance_orphans(paths)?;

    let singbox = resolved_singbox_path()?;
    check_config(&singbox, config)?;
    let args = worker_args(
        config,
        &singbox,
        Some(profile_id),
        &paths.id,
        mode,
        proxy_port,
        clash_api_port,
    );

    match mode {
        InstanceMode::Proxy => {
            // Never elevate a loopback proxy.
            spawn_detached_worker(&args)?;
            wait_for_instance(paths)
        }
        InstanceMode::Tun => {
            if running_as_root_helper() {
                spawn_detached_worker(&args)?;
                wait_for_instance(paths)
            } else {
                elevate_and_spawn(paths, &args)?;
                wait_for_instance(paths)
            }
        }
    }
}

fn wait_for_instance(paths: &InstancePaths) -> Result<u32, String> {
    let started = now_ms();
    for _ in 0..200 {
        std::thread::sleep(Duration::from_millis(100));
        let st = read_status_at(paths);
        if st.running {
            if let Some(pid) = st.pid.filter(|&p| process_alive(p)) {
                return Ok(pid);
            }
        }
        if st.updated_at_ms >= started {
            if let Some(err) = st.last_error {
                return Err(err);
            }
        }
    }
    Err("instance did not start (check per-instance tunnel.log)".into())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn elevate_and_spawn(paths: &InstancePaths, args: &[String]) -> Result<(), String> {
    let exe = crate::privileges::privileged_ssc_bin();
    // 1) Passwordless sudo installed by PKG / `ssc privileges install`.
    if try_passwordless_spawn(&exe, args)? {
        return Ok(());
    }

    let log = &paths.log;
    let cmd_line = format!(
        "nohup {} {} >> {} 2>&1 & echo $!",
        sh_single_quote(&exe.to_string_lossy()),
        args.iter()
            .map(|a| sh_single_quote(a))
            .collect::<Vec<_>>()
            .join(" "),
        sh_single_quote(&log.to_string_lossy())
    );

    let out = match Command::new("sudo")
        .args(["-n", "/bin/bash", "-c", &cmd_line])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => {
            #[cfg(target_os = "macos")]
            {
                eprintln!(
                    "Elevated privileges required for TUN. Showing macOS password prompt…\n\
                     Tip: install once with PKG, or run `sudo ssc privileges install` to skip this."
                );
                elevate_via_osascript(&cmd_line)?
            }
            #[cfg(target_os = "linux")]
            {
                return Err(
                    "elevated privileges required for TUN — run `sudo ssc privileges install` once"
                        .into(),
                );
            }
        }
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(format!("failed to start elevated tunnel: {stderr}{stdout}"));
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn try_passwordless_spawn(exe: &Path, args: &[String]) -> Result<bool, String> {
    let mut cmd = Command::new("sudo");
    cmd.arg("-n").arg("-b").arg(exe);
    for a in args {
        cmd.arg(a);
    }
    match cmd.status() {
        Ok(st) if st.success() => Ok(true),
        Ok(_) | Err(_) => Ok(false),
    }
}

#[cfg(target_os = "macos")]
fn elevate_via_osascript(bash_cmd: &str) -> Result<std::process::Output, String> {
    let apple = format!(
        "do shell script {} with administrator privileges",
        sh_single_quote(bash_cmd)
    );
    let mut child = Command::new("osascript")
        .args(["-e", &apple])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("osascript elevate failed to start: {e}"))?;

    let start = Instant::now();
    let timeout = Duration::from_secs(120);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = child
                    .stdout
                    .take()
                    .map(|mut s| {
                        let mut b = Vec::new();
                        let _ = std::io::Read::read_to_end(&mut s, &mut b);
                        b
                    })
                    .unwrap_or_default();
                let stderr = child
                    .stderr
                    .take()
                    .map(|mut s| {
                        let mut b = Vec::new();
                        let _ = std::io::Read::read_to_end(&mut s, &mut b);
                        b
                    })
                    .unwrap_or_default();
                if !status.success() {
                    let err = String::from_utf8_lossy(&stderr);
                    if err.to_lowercase().contains("user canceled")
                        || err.to_lowercase().contains("(-128)")
                    {
                        return Err("elevated privileges cancelled — approve the password prompt to connect".into());
                    }
                    return Err(format!("administrator elevation failed: {err}"));
                }
                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(
                        "elevated privileges timed out — approve the macOS password prompt, or run `ssc connect` in Terminal"
                            .into(),
                    );
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("osascript elevate: {e}")),
        }
    }
}

#[cfg(target_os = "windows")]
fn elevate_and_spawn(_paths: &InstancePaths, args: &[String]) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let arg_list = args
        .iter()
        .map(|a| {
            if a.contains(' ') {
                format!("\"{a}\"")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let ps = format!(
        "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs -WindowStyle Hidden",
        exe.display(),
        arg_list.replace('\'', "''")
    );
    let status = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps])
        .status()
        .map_err(|e| format!("UAC elevate failed: {e}"))?;
    if !status.success() {
        return Err("UAC elevation failed or was cancelled".into());
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn elevate_and_spawn(_paths: &InstancePaths, _args: &[String]) -> Result<(), String> {
    Err("TUN elevation not supported on this platform".into())
}

/// Stop one instance. Other instances and foreign processes are never touched.
pub fn stop_instance(paths: &InstancePaths) -> Result<(), String> {
    paths.ensure()?;
    let _ = std::fs::write(&paths.stop, b"1");

    let mut pids = Vec::new();
    if let Some(pid) = read_pid_at(paths) {
        pids.push(pid);
    }
    if let Some(pid) = read_status_at(paths).pid {
        pids.push(pid);
    }
    pids.extend(find_owned_pids(&paths.config));
    pids.sort_unstable();
    pids.dedup();

    let mut had_process = false;
    for &pid in &pids {
        if process_alive(pid) {
            // Only kill a process we can prove owns this exact config.
            if !owned_by_config(pid, &paths.config) {
                continue;
            }
            had_process = true;
            let _ = kill_pid(pid);
        }
    }
    if had_process {
        for _ in 0..30 {
            if !pids
                .iter()
                .any(|&p| process_alive(p) && owned_by_config(p, &paths.config))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        for pid in pids {
            if process_alive(pid) && owned_by_config(pid, &paths.config) {
                let _ = kill_pid_force(pid);
            }
        }
    }

    clear_pid_at(paths);
    let mut st = read_status_at(paths);
    st.running = false;
    st.pid = None;
    st.updated_at_ms = now_ms();
    st.last_error = None;
    st.exit_code = st.exit_code.or(Some(0));
    st.instance_id = Some(paths.id.clone());
    write_status_at(paths, &st)?;
    let _ = std::fs::remove_file(&paths.stop);
    paths.wipe_config();
    Ok(())
}

/// Stop and remove only the process described by `running`.
pub fn stop_process(running: &RunningProcess) -> Result<(), String> {
    if !process_alive(running.pid) {
        return Ok(());
    }
    if !owned_by_config(running.pid, &running.config_path) {
        return Err(format!(
            "refusing to stop pid {} — it no longer owns {}",
            running.pid,
            running.config_path.display()
        ));
    }
    let _ = kill_pid(running.pid);
    for _ in 0..30 {
        if !process_alive(running.pid) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    kill_pid_force(running.pid)
}

#[cfg(unix)]
fn kill_pid(pid: u32) -> Result<(), String> {
    kill_unix(pid, libc::SIGTERM)
}

#[cfg(unix)]
fn kill_pid_force(pid: u32) -> Result<(), String> {
    kill_unix(pid, libc::SIGKILL)
}

#[cfg(unix)]
fn kill_unix(pid: u32, signal: libc::c_int) -> Result<(), String> {
    unsafe {
        if libc::kill(pid as i32, signal) != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                let sig = if signal == libc::SIGKILL {
                    "-KILL"
                } else {
                    "-TERM"
                };
                let status = Command::new("sudo")
                    .args(["-n", "kill", sig, &pid.to_string()])
                    .status()
                    .map_err(|e| format!("sudo kill: {e}"))?;
                if !status.success() {
                    return Err(format!("failed to kill pid {pid}"));
                }
                return Ok(());
            }
            if err.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(format!("kill {pid}: {err}"));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn kill_pid(pid: u32) -> Result<(), String> {
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .status()
        .map_err(|e| format!("taskkill: {e}"))?;
    if !status.success() {
        let ps = format!("Start-Process taskkill -ArgumentList '/PID {pid} /F' -Verb RunAs -Wait");
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps])
            .status();
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn kill_pid_force(pid: u32) -> Result<(), String> {
    kill_pid(pid)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn kill_pid(_pid: u32) -> Result<(), String> {
    Err("process control not supported".into())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn kill_pid_force(pid: u32) -> Result<(), String> {
    kill_pid(pid)
}

/// RAII lock preventing two managers from controlling the same instance.
pub struct InstanceFileLock {
    path: PathBuf,
    #[allow(dead_code)]
    file: std::fs::File,
}

impl InstanceFileLock {
    pub fn acquire(paths: &InstancePaths) -> Result<Self, String> {
        paths.ensure()?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&paths.lock)
            .map_err(|e| format!("open instance lock: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
                return Err(format!(
                    "instance '{}' is already controlled by another SSC process",
                    paths.id
                ));
            }
        }
        use std::io::Write;
        let mut f = &file;
        let _ = writeln!(f, "{}", std::process::id());
        Ok(Self {
            path: paths.lock.clone(),
            file,
        })
    }
}

impl Drop for InstanceFileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Read a bounded, redacted tail of an instance log.
pub fn read_instance_log(paths: &InstancePaths, max_bytes: usize) -> String {
    let Ok(bytes) = std::fs::read(&paths.log) else {
        return String::new();
    };
    let start = bytes.len().saturating_sub(max_bytes);
    let text = String::from_utf8_lossy(&bytes[start..]).to_string();
    ssc_core::redact_log_text(&text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ssc-instance-{tag}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn default_instance_keeps_legacy_paths() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir("legacy");
        std::env::set_var("SSC_CONFIG_DIR", &dir);
        let p = InstancePaths::for_id(DEFAULT_INSTANCE_ID).unwrap();
        assert_eq!(p.pid, dir.join("tunnel.pid"));
        assert_eq!(p.status, dir.join("tunnel.status.json"));
        assert_eq!(p.policy, dir.join("policy.json"));
        assert!(p.config.ends_with("singbox-ephemeral.json"));
        std::env::remove_var("SSC_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn named_instances_are_fully_isolated() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir("isolation");
        std::env::set_var("SSC_CONFIG_DIR", &dir);
        let a = InstancePaths::for_id("alpha").unwrap();
        let b = InstancePaths::for_id("beta").unwrap();
        assert_ne!(a.root, b.root);
        assert_ne!(a.config, b.config);
        assert_ne!(a.pid, b.pid);
        assert_ne!(a.policy, b.policy);
        assert_ne!(a.lock, b.lock);
        assert!(a.root.starts_with(dir.join("instances")));
        std::env::remove_var("SSC_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_path_traversal() {
        for bad in ["../evil", "a/b", "..", ".hidden", "a b", ""] {
            assert!(InstancePaths::for_id(bad).is_err(), "{bad}");
        }
        for good in ["default", "work", "vpn-us-1", "a.b_c"] {
            assert!(ssc_core::validate_instance_id(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn status_roundtrip_is_credential_free() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir("status");
        std::env::set_var("SSC_CONFIG_DIR", &dir);
        let p = InstancePaths::for_id("stateful").unwrap();
        let st = InstanceStatus {
            running: true,
            pid: Some(42),
            profile_id: Some("p1".into()),
            last_error: None,
            updated_at_ms: 1,
            instance_id: Some("stateful".into()),
            mode: Some("proxy".into()),
            proxy_port: Some(19001),
            clash_api_port: Some(9091),
            started_at_ms: Some(1),
            exit_code: None,
        };
        write_status_at(&p, &st).unwrap();
        let back = read_status_at(&p);
        assert_eq!(back.proxy_port, Some(19001));
        let text = std::fs::read_to_string(&p.status).unwrap();
        assert!(!text.contains("vless://"));
        assert!(!text.contains("uuid"));
        std::env::remove_var("SSC_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_is_exclusive() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir("lock");
        std::env::set_var("SSC_CONFIG_DIR", &dir);
        let p = InstancePaths::for_id("locked").unwrap();
        let first = InstanceFileLock::acquire(&p).unwrap();
        assert!(InstanceFileLock::acquire(&p).is_err());
        drop(first);
        assert!(InstanceFileLock::acquire(&p).is_ok());
        std::env::remove_var("SSC_CONFIG_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
