//! Spawn / stop sing-box TUN process.

use crate::setup::{resolved_singbox_path, running_as_root_helper};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static WATCH_STOP: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub updated_at_ms: i64,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn pid_path() -> Result<PathBuf, String> {
    Ok(ssc_core::ensure_config_dir()?.join("tunnel.pid"))
}

fn status_path() -> Result<PathBuf, String> {
    Ok(ssc_core::ensure_config_dir()?.join("tunnel.status.json"))
}

fn log_path() -> Result<PathBuf, String> {
    Ok(ssc_core::ensure_config_dir()?.join("tunnel.log"))
}

fn write_status(status: &TunnelStatus) -> Result<(), String> {
    let path = status_path()?;
    let text = serde_json::to_string_pretty(status).map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| format!("write status: {e}"))
}

pub fn read_status() -> TunnelStatus {
    let Ok(path) = status_path() else {
        return TunnelStatus {
            running: false,
            pid: None,
            profile_id: None,
            last_error: None,
            updated_at_ms: now_ms(),
        };
    };
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(TunnelStatus {
            running: false,
            pid: None,
            profile_id: None,
            last_error: None,
            updated_at_ms: now_ms(),
        })
}

fn write_pid(pid: u32) -> Result<(), String> {
    let path = pid_path()?;
    std::fs::write(&path, pid.to_string()).map_err(|e| format!("write pid: {e}"))
}

fn read_pid() -> Option<u32> {
    let path = pid_path().ok()?;
    let text = std::fs::read_to_string(&path).ok()?;
    text.trim().parse().ok()
}

fn clear_pid() {
    if let Ok(path) = pid_path() {
        let _ = std::fs::remove_file(path);
    }
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

#[cfg(target_os = "windows")]
fn process_alive(pid: u32) -> bool {
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
fn process_alive(_pid: u32) -> bool {
    false
}

/// PIDs of SSC-managed sing-box processes (matched by our ephemeral config path).
fn find_ssc_singbox_pids() -> Vec<u32> {
    #[cfg(unix)]
    {
        let marker = "singbox-ephemeral.json";
        let out = Command::new("ps")
            .args(["-ax", "-o", "pid=,command="])
            .output()
            .ok();
        let Some(out) = out else {
            return Vec::new();
        };
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if !(line.contains("sing-box") && line.contains(marker)) {
                    return None;
                }
                line.split_whitespace()
                    .next()
                    .and_then(|p| p.parse::<u32>().ok())
            })
            .collect()
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}

/// Kill leftover sing-box / stale pid files so a new connect can bind TUN + Clash API.
pub fn cleanup_orphans() -> Result<(), String> {
    let _ = clear_stop();
    let mut pids: Vec<u32> = Vec::new();
    if let Some(pid) = read_pid() {
        pids.push(pid);
    }
    if let Some(pid) = read_status().pid {
        pids.push(pid);
    }
    pids.extend(find_ssc_singbox_pids());
    pids.sort_unstable();
    pids.dedup();
    for pid in pids {
        if process_alive(pid) {
            let _ = kill_pid(pid);
            for _ in 0..20 {
                if !process_alive(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    clear_pid();
    let _ = write_status(&TunnelStatus {
        running: false,
        pid: None,
        profile_id: read_status().profile_id,
        last_error: None,
        updated_at_ms: now_ms(),
    });
    Ok(())
}

pub fn is_connected() -> bool {
    if let Some(pid) = read_pid() {
        if process_alive(pid) {
            return true;
        }
        clear_pid();
    }
    let st = read_status();
    if st.running && st.pid.is_some_and(process_alive) {
        return true;
    }
    // Recover tracking if an elevated worker left a live process but stale status.
    let orphans = find_ssc_singbox_pids();
    if let Some(&pid) = orphans.first() {
        let _ = write_pid(pid);
        let _ = write_status(&TunnelStatus {
            running: true,
            pid: Some(pid),
            profile_id: st.profile_id.clone(),
            last_error: None,
            updated_at_ms: now_ms(),
        });
        return true;
    }
    false
}

pub fn status_summary() -> String {
    let st = read_status();
    let alive = is_connected();
    let pid = read_pid().or(st.pid);
    format!(
        "connected={alive}\npid={}\nprofile_id={}\nlast_error={}\nupdated_at_ms={}",
        pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
        st.profile_id.as_deref().unwrap_or("-"),
        st.last_error.as_deref().unwrap_or("-"),
        st.updated_at_ms
    )
}

fn check_config(singbox: &Path, config: &Path) -> Result<(), String> {
    let out = Command::new(singbox)
        .args(["check", "-c", &config.to_string_lossy()])
        .output()
        .map_err(|e| format!("sing-box check failed to start: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(format!(
            "sing-box check failed:\n{stderr}{stdout}"
        ));
    }
    Ok(())
}

fn sh_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// Internal worker: run sing-box in foreground (expected under root / elevated).
pub fn run_tunnel_worker(
    config: &Path,
    singbox: &Path,
    profile_id: Option<&str>,
) -> Result<(), String> {
    check_config(singbox, config)?;
    let log = log_path()?;
    if let Some(parent) = log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
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
    write_pid(pid)?;
    write_status(&TunnelStatus {
        running: true,
        pid: Some(pid),
        profile_id: profile_id.map(|s| s.to_string()),
        last_error: None,
        updated_at_ms: now_ms(),
    })?;

    let status = child
        .wait()
        .map_err(|e| format!("wait sing-box: {e}"))?;
    clear_pid();
    let err = if status.success() {
        None
    } else {
        Some(format!("sing-box exited with {status}"))
    };
    write_status(&TunnelStatus {
        running: false,
        pid: None,
        profile_id: profile_id.map(|s| s.to_string()),
        last_error: err.clone(),
        updated_at_ms: now_ms(),
    })?;
    if let Some(e) = err {
        return Err(e);
    }
    Ok(())
}

fn spawn_singbox_background(
    config: &Path,
    singbox: &Path,
    profile_id: Option<&str>,
) -> Result<u32, String> {
    check_config(singbox, config)?;
    let log = log_path()?;
    if let Some(parent) = log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .map_err(|e| format!("open tunnel log: {e}"))?;
    let log_err = log_file
        .try_clone()
        .map_err(|e| format!("clone log: {e}"))?;

    let child = Command::new(singbox)
        .args(["run", "-c", &config.to_string_lossy()])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_err))
        .spawn()
        .map_err(|e| format!("spawn sing-box: {e}"))?;
    let pid = child.id();
    // Detach: don't wait; leak Child intentionally so process keeps running.
    std::mem::forget(child);
    write_pid(pid)?;
    write_status(&TunnelStatus {
        running: true,
        pid: Some(pid),
        profile_id: profile_id.map(|s| s.to_string()),
        last_error: None,
        updated_at_ms: now_ms(),
    })?;
    Ok(pid)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn elevate_and_spawn(
    config: &Path,
    singbox: &Path,
    profile_id: Option<&str>,
) -> Result<(), String> {
    // Prefer the system binary so /etc/sudoers.d/ssc (PKG) matches.
    let exe = crate::privileges::privileged_ssc_bin();
    let mut args = vec![
        "__tunnel-worker".to_string(),
        "--config".into(),
        config.to_string_lossy().into_owned(),
        "--singbox".into(),
        singbox.to_string_lossy().into_owned(),
    ];
    if let Some(id) = profile_id {
        args.push("--profile-id".into());
        args.push(id.to_string());
    }

    // 1) Passwordless: sudo -n -b (no GUI password; installed by PKG / privileges install).
    if try_passwordless_spawn(&exe, &args)? {
        return wait_for_tunnel(profile_id);
    }

    // 2) Legacy: bash -c + sudo -n, then macOS admin dialog.
    let cmd_line = format!(
        "pkill -f 'sing-box.*singbox-ephemeral.json' 2>/dev/null || true; sleep 1; nohup {} {} >> {} 2>&1 & echo $!",
        sh_single_quote(&exe.to_string_lossy()),
        args.iter()
            .map(|a| sh_single_quote(a))
            .collect::<Vec<_>>()
            .join(" "),
        sh_single_quote(&log_path()?.to_string_lossy())
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
        return Err(format!(
            "failed to start elevated tunnel: {stderr}{stdout}"
        ));
    }

    if let Ok(()) = wait_for_tunnel(profile_id) {
        return Ok(());
    }
    // sudo echoed $! of nohup — try parse
    if let Ok(pid) = String::from_utf8_lossy(&out.stdout).trim().parse::<u32>() {
        write_pid(pid)?;
        write_status(&TunnelStatus {
            running: true,
            pid: Some(pid),
            profile_id: profile_id.map(|s| s.to_string()),
            last_error: None,
            updated_at_ms: now_ms(),
        })?;
        if process_alive(pid) {
            return Ok(());
        }
    }
    let st = read_status();
    Err(st
        .last_error
        .unwrap_or_else(|| "tunnel did not start (check tunnel.log)".into()))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn try_passwordless_spawn(exe: &Path, args: &[String]) -> Result<bool, String> {
    let mut cmd = Command::new("sudo");
    cmd.arg("-n").arg("-b").arg(exe);
    for a in args {
        cmd.arg(a);
    }
    match cmd.status() {
        Ok(st) if st.success() => {
            eprintln!("tunnel elevate: passwordless sudo (-n -b)");
            Ok(true)
        }
        Ok(_) | Err(_) => Ok(false),
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn wait_for_tunnel(profile_id: Option<&str>) -> Result<(), String> {
    let _ = profile_id;
    for _ in 0..150 {
        std::thread::sleep(Duration::from_millis(100));
        if is_connected() {
            return Ok(());
        }
    }
    Err("tunnel did not start (check tunnel.log)".into())
}

#[cfg(target_os = "macos")]
fn elevate_via_osascript(bash_cmd: &str) -> Result<std::process::Output, String> {
    // do shell script runs as root; echo PID for the caller.
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
                let stdout = child.stdout.take().map(|mut s| {
                    let mut b = Vec::new();
                    let _ = std::io::Read::read_to_end(&mut s, &mut b);
                    b
                }).unwrap_or_default();
                let stderr = child.stderr.take().map(|mut s| {
                    let mut b = Vec::new();
                    let _ = std::io::Read::read_to_end(&mut s, &mut b);
                    b
                }).unwrap_or_default();
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
fn elevate_and_spawn(
    config: &Path,
    singbox: &Path,
    profile_id: Option<&str>,
) -> Result<(), String> {
    let exe = current_exe()?;
    let mut arg_list = format!(
        "__tunnel-worker --config \"{}\" --singbox \"{}\"",
        config.display(),
        singbox.display()
    );
    if let Some(id) = profile_id {
        arg_list.push_str(&format!(" --profile-id \"{id}\""));
    }
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
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if is_connected() {
            return Ok(());
        }
    }
    Err("tunnel did not start after UAC (check tunnel.log)".into())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn elevate_and_spawn(
    _config: &Path,
    _singbox: &Path,
    _profile_id: Option<&str>,
) -> Result<(), String> {
    Err("TUN elevation not supported on this platform".into())
}

/// Connect using config path and optional profile id. Elevates if needed.
pub fn connect(config: &Path, profile_id: Option<&str>) -> Result<(), String> {
    let _ = clear_stop();
    // Idempotent: already-running tunnel is success (UI Connect/Retry must not error).
    if let Some(_pid) = read_pid().filter(|&p| process_alive(p)) {
        return Ok(());
    }
    if let Some(_pid) = read_status().pid.filter(|&p| process_alive(p)) {
        return Ok(());
    }
    // Drop stale stop flags / orphans (TUN busy, Clash :9090 in use) before spawn.
    let _ = cleanup_orphans();
    let singbox = resolved_singbox_path()?;
    check_config(&singbox, config)?;

    if running_as_root_helper() {
        let pid = spawn_singbox_background(config, &singbox, profile_id)?;
        eprintln!("sing-box started (pid {pid})");
        return Ok(());
    }
    match elevate_and_spawn(config, &singbox, profile_id) {
        Ok(()) => {
            eprintln!("tunnel started");
            Ok(())
        }
        Err(e) => {
            // Wait loop timed out but worker may still have come up.
            if is_connected() {
                eprintln!("tunnel started (late)");
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

#[cfg(unix)]
fn kill_pid(pid: u32) -> Result<(), String> {
    unsafe {
        if libc::kill(pid as i32, libc::SIGTERM) != 0 {
            let err = std::io::Error::last_os_error();
            // Try sudo if permission denied
            if err.raw_os_error() == Some(libc::EPERM) {
                let status = Command::new("sudo")
                    .args(["-n", "kill", "-TERM", &pid.to_string()])
                    .status()
                    .map_err(|e| format!("sudo kill: {e}"))?;
                if !status.success() {
                    // Fallback without -n (may prompt once if privileges missing).
                    let status = Command::new("sudo")
                        .args(["kill", "-TERM", &pid.to_string()])
                        .status()
                        .map_err(|e| format!("sudo kill: {e}"))?;
                    if !status.success() {
                        return Err(format!("failed to kill pid {pid}"));
                    }
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
        // try elevated
        let ps = format!("Start-Process taskkill -ArgumentList '/PID {pid} /F' -Verb RunAs -Wait");
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps])
            .status();
    }
    Ok(())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn kill_pid(_pid: u32) -> Result<(), String> {
    Err("disconnect not supported".into())
}

pub fn disconnect() -> Result<(), String> {
    cleanup_orphans()?;
    eprintln!("disconnected");
    Ok(())
}

fn stop_flag_path() -> Result<PathBuf, String> {
    Ok(ssc_core::ensure_config_dir()?.join("tunnel.stop"))
}

/// Signal failover watcher / Ctrl+C path to exit.
pub fn request_stop() -> Result<(), String> {
    WATCH_STOP.store(true, Ordering::SeqCst);
    let path = stop_flag_path()?;
    std::fs::write(&path, b"1").map_err(|e| format!("write stop flag: {e}"))?;
    Ok(())
}

pub fn clear_stop() -> Result<(), String> {
    WATCH_STOP.store(false, Ordering::SeqCst);
    if let Ok(path) = stop_flag_path() {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

pub fn stop_requested() -> bool {
    if WATCH_STOP.load(Ordering::SeqCst) {
        return true;
    }
    stop_flag_path()
        .ok()
        .map(|p| p.is_file())
        .unwrap_or(false)
}
