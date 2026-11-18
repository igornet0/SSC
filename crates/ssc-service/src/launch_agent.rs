//! LaunchAgent helper for starting the local SSC API at login.
//!
//! Label: `com.ssc.gateway`
//! Plist: `~/Library/LaunchAgents/com.ssc.gateway.plist`
//!
//! ProgramArguments carry only the binary path, `start`, and `--port` —
//! **never** secrets or share URIs.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const LABEL: &str = "com.ssc.gateway";

fn plist_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "cannot resolve home directory".to_string())?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

fn current_exe() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("current_exe: {e}"))
}

fn plist_body(exe: &str, port: u16) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>start</string>
        <string>--port</string>
        <string>{port}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/tmp/ssc-gateway.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/ssc-gateway.err</string>
</dict>
</plist>
"#
    )
}

/// Install / refresh the LaunchAgent and load it for the current user.
pub fn enable(port: u16) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let exe = current_exe()?;
        let exe_s = exe.to_string_lossy();
        let path = plist_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create LaunchAgents: {e}"))?;
        }
        let body = plist_body(&exe_s, port);
        fs::write(&path, body).map_err(|e| format!("write plist: {e}"))?;
        // Unload first so a refresh takes effect.
        let _ = Command::new("launchctl")
            .args(["unload", &path.to_string_lossy()])
            .status();
        let status = Command::new("launchctl")
            .args(["load", &path.to_string_lossy()])
            .status()
            .map_err(|e| format!("launchctl load: {e}"))?;
        if !status.success() {
            return Err(format!("launchctl load failed (exit {status})"));
        }
        eprintln!("[LAUNCH_AGENT] enabled {LABEL} port={port}");
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = port;
        Err("LaunchAgent is only supported on macOS".into())
    }
}

/// Unload and remove the LaunchAgent plist.
pub fn disable() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let path = plist_path()?;
        if path.is_file() {
            let _ = Command::new("launchctl")
                .args(["unload", &path.to_string_lossy()])
                .status();
            fs::remove_file(&path).map_err(|e| format!("remove plist: {e}"))?;
        }
        eprintln!("[LAUNCH_AGENT] disabled {LABEL}");
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

/// Whether the LaunchAgent plist is present.
pub fn is_enabled() -> bool {
    plist_path().map(|p| p.is_file()).unwrap_or(false)
}

/// Apply `settings.launch_at_login` — enable or disable the agent.
pub fn sync_from_settings(launch_at_login: bool, port: u16) -> Result<(), String> {
    if launch_at_login {
        enable(port)
    } else if is_enabled() {
        disable()
    } else {
        Ok(())
    }
}
