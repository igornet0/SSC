//! Passwordless TUN privileges via `/etc/sudoers.d/ssc`.
//! Also maps `ssc.lan` → `127.0.0.1` in `/etc/hosts` for the Web UI.
//!
//! Installed once by the macOS PKG (or `sudo ssc privileges install`).
//! After that, Connect / Disconnect / kill-switch use `sudo -n` and never
//! prompt for a password.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// System path for the installed CLI (matches PKG / `--system` install).
pub const SYSTEM_SSC_BIN: &str = "/usr/local/bin/ssc";

/// Drop-in sudoers file.
pub const SUDOERS_PATH: &str = "/etc/sudoers.d/ssc";

/// Absolute path used for passwordless elevation (prefer system install).
pub fn privileged_ssc_bin() -> PathBuf {
    let system = PathBuf::from(SYSTEM_SSC_BIN);
    if system.is_file() {
        return system;
    }
    std::env::current_exe().unwrap_or(system)
}

/// Whether `sudo -n` can run the tunnel worker without a password.
pub fn passwordless_tunnel_ok() -> bool {
    let out = Command::new("sudo")
        .args(["-n", "-l"])
        .output();
    let Ok(o) = out else {
        return false;
    };
    if !o.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&o.stdout);
    text.contains("__tunnel-worker") && text.contains("NOPASSWD")
}

/// Human-readable privilege status for CLI / diagnostics.
pub fn status_summary() -> String {
    let sudoers = Path::new(SUDOERS_PATH).is_file();
    let pwless = passwordless_tunnel_ok();
    match (sudoers, pwless) {
        (true, true) => {
            "passwordless TUN ready (/etc/sudoers.d/ssc) — Connect will not ask for a password"
                .into()
        }
        (true, false) => {
            "sudoers file present but sudo -n failed — re-run: sudo ssc privileges install".into()
        }
        (false, true) => "passwordless sudo works (custom sudoers)".into(),
        (false, false) => {
            "password required on Connect — install privileges: sudo ssc privileges install".into()
        }
    }
}

/// Sudoers body for the given `ssc` binary path (must be absolute, no spaces ideally).
pub fn sudoers_body(ssc_bin: &Path) -> String {
    let bin = ssc_bin.display();
    let mut s = String::new();
    s.push_str("# SSC — passwordless tunnel / kill-switch (managed; do not edit)\n");
    s.push_str("# Installed by SSC.pkg or `sudo ssc privileges install`\n");
    s.push_str(&format!("Defaults!{bin} !requiretty\n"));
    s.push('\n');
    // macOS admin group + common Linux sudo/wheel.
    for group in ["admin", "sudo", "wheel"] {
        s.push_str(&format!(
            "%{group} ALL=(root) NOPASSWD: {bin} __tunnel-worker *\n"
        ));
        #[cfg(target_os = "macos")]
        {
            s.push_str(&format!(
                "%{group} ALL=(root) NOPASSWD: /sbin/pfctl -a ssc.killswitch *\n"
            ));
            s.push_str(&format!("%{group} ALL=(root) NOPASSWD: /sbin/pfctl -e\n"));
        }
        s.push_str(&format!(
            "%{group} ALL=(root) NOPASSWD: /usr/bin/kill -TERM *, /usr/bin/kill -KILL *\n"
        ));
        s.push_str(&format!(
            "%{group} ALL=(root) NOPASSWD: /bin/kill -TERM *, /bin/kill -KILL *\n"
        ));
        s.push('\n');
    }
    s
}

/// Install `/etc/sudoers.d/ssc`. Must run as root.
pub fn install_privileges() -> Result<PathBuf, String> {
    ensure_root()?;
    let bin = PathBuf::from(SYSTEM_SSC_BIN);
    if !bin.is_file() {
        return Err(format!(
            "{SYSTEM_SSC_BIN} not found — install SSC first (PKG or `ssc install --system`)"
        ));
    }
    let body = sudoers_body(&bin);
    let tmp = PathBuf::from("/tmp/ssc-sudoers.new");
    fs::write(&tmp, &body).map_err(|e| format!("write temp sudoers: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp).map_err(|e| e.to_string())?.permissions();
        perms.set_mode(0o440);
        fs::set_permissions(&tmp, perms).map_err(|e| e.to_string())?;
    }
    // Validate before replacing live file.
    let check = Command::new("visudo")
        .args(["-cf", tmp.to_str().unwrap_or("/tmp/ssc-sudoers.new")])
        .output()
        .map_err(|e| format!("visudo: {e}"))?;
    if !check.status.success() {
        let err = String::from_utf8_lossy(&check.stderr);
        let _ = fs::remove_file(&tmp);
        return Err(format!("sudoers validation failed: {}", err.trim()));
    }
    fs::copy(&tmp, SUDOERS_PATH).map_err(|e| format!("install {SUDOERS_PATH}: {e}"))?;
    let _ = fs::remove_file(&tmp);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(SUDOERS_PATH)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o440);
        fs::set_permissions(SUDOERS_PATH, perms).map_err(|e| e.to_string())?;
    }
    eprintln!("installed {SUDOERS_PATH}");
    eprintln!("{}", status_summary());
    // Web UI at http://ssc.lan — non-fatal, TUN privileges are what matter here.
    if let Err(e) = crate::local_domain::install_hosts_entry() {
        eprintln!("warning: {} not added to hosts ({e})", crate::LOCAL_DOMAIN);
    }
    Ok(PathBuf::from(SUDOERS_PATH))
}

/// Remove `/etc/sudoers.d/ssc`. Must run as root.
pub fn remove_privileges() -> Result<(), String> {
    ensure_root()?;
    let path = Path::new(SUDOERS_PATH);
    if path.is_file() {
        fs::remove_file(path).map_err(|e| format!("remove {SUDOERS_PATH}: {e}"))?;
        eprintln!("removed {SUDOERS_PATH}");
    } else {
        eprintln!("not found: {SUDOERS_PATH}");
    }
    if let Err(e) = crate::local_domain::remove_hosts_entry() {
        eprintln!("warning: {} not removed from hosts ({e})", crate::LOCAL_DOMAIN);
    }
    Ok(())
}

fn ensure_root() -> Result<(), String> {
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } != 0 {
            return Err(
                "must run as root — use: sudo ssc privileges install".into(),
            );
        }
    }
    #[cfg(not(unix))]
    {
        return Err("privileges install is only supported on macOS/Linux".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn sudoers_mentions_tunnel_worker_and_bin() {
        let body = sudoers_body(Path::new("/usr/local/bin/ssc"));
        assert!(body.contains("/usr/local/bin/ssc __tunnel-worker *"));
        assert!(body.contains("%admin"));
        assert!(body.contains("NOPASSWD"));
    }
}
