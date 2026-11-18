//! Friendly Web UI hostname: `ssc.lan` → `127.0.0.1` via the system hosts file.
//!
//! Installed once alongside privileges (PKG postinstall or
//! `sudo ssc privileges install`) and removed with them. Only the line tagged
//! with [`HOSTS_MARKER`] is ever touched; user entries are left alone.

use std::fs;
use std::path::PathBuf;

/// Local hostname for the Web UI.
pub const LOCAL_DOMAIN: &str = "ssc.lan";

/// Trailing comment identifying the managed hosts line.
pub const HOSTS_MARKER: &str = "# ssc (managed)";

/// System hosts file path.
pub fn hosts_path() -> PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

/// Whether any active hosts line maps [`LOCAL_DOMAIN`] (managed or user-added).
pub fn hosts_maps_local_domain(content: &str) -> bool {
    content.lines().any(|line| {
        let active = line.split('#').next().unwrap_or("");
        active
            .split_whitespace()
            .skip(1)
            .any(|name| name.eq_ignore_ascii_case(LOCAL_DOMAIN))
    })
}

/// `content` with the managed line appended, or `None` if already mapped.
pub fn hosts_with_entry(content: &str) -> Option<String> {
    if hosts_maps_local_domain(content) {
        return None;
    }
    let mut out = content.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("127.0.0.1\t{LOCAL_DOMAIN}\t{HOSTS_MARKER}\n"));
    Some(out)
}

/// `content` without managed lines, or `None` if there were none.
pub fn hosts_without_entry(content: &str) -> Option<String> {
    if !content.lines().any(|l| l.trim_end().ends_with(HOSTS_MARKER)) {
        return None;
    }
    let mut out: String = content
        .lines()
        .filter(|l| !l.trim_end().ends_with(HOSTS_MARKER))
        .collect::<Vec<_>>()
        .join("\n");
    out.push('\n');
    Some(out)
}

/// Whether `http://ssc.lan` resolves locally via the hosts file.
pub fn local_domain_configured() -> bool {
    fs::read_to_string(hosts_path())
        .map(|c| hosts_maps_local_domain(&c))
        .unwrap_or(false)
}

/// Add `127.0.0.1 ssc.lan` to the hosts file. Needs root / Administrator.
/// Returns `true` if the file was changed.
pub fn install_hosts_entry() -> Result<bool, String> {
    let path = hosts_path();
    let content =
        fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let Some(updated) = hosts_with_entry(&content) else {
        return Ok(false);
    };
    // In-place write keeps the file's owner and mode.
    fs::write(&path, updated).map_err(|e| format!("write {}: {e}", path.display()))?;
    flush_dns_cache();
    eprintln!("added {LOCAL_DOMAIN} → 127.0.0.1 to {}", path.display());
    Ok(true)
}

/// Remove the managed `ssc.lan` line. Needs root / Administrator.
/// Returns `true` if the file was changed.
pub fn remove_hosts_entry() -> Result<bool, String> {
    let path = hosts_path();
    let content =
        fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let Some(updated) = hosts_without_entry(&content) else {
        return Ok(false);
    };
    fs::write(&path, updated).map_err(|e| format!("write {}: {e}", path.display()))?;
    flush_dns_cache();
    eprintln!("removed {LOCAL_DOMAIN} from {}", path.display());
    Ok(true)
}

fn flush_dns_cache() {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let _ = Command::new("dscacheutil").arg("-flushcache").status();
        let _ = Command::new("killall").args(["-HUP", "mDNSResponder"]).status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_entry_once() {
        let base = "127.0.0.1\tlocalhost\n::1 localhost";
        let added = hosts_with_entry(base).unwrap();
        assert!(added.starts_with("127.0.0.1\tlocalhost\n::1 localhost\n"));
        assert!(added.ends_with(&format!("127.0.0.1\tssc.lan\t{HOSTS_MARKER}\n")));
        assert!(hosts_maps_local_domain(&added));
        assert!(hosts_with_entry(&added).is_none());
    }

    #[test]
    fn respects_user_mapping_and_comments() {
        assert!(hosts_with_entry("10.0.0.5 nas SSC.LAN\n").is_none());
        assert!(hosts_with_entry("# 127.0.0.1 ssc.lan\n").is_some());
    }

    #[test]
    fn removes_only_managed_line() {
        let base = "127.0.0.1 localhost\n";
        let added = hosts_with_entry(base).unwrap();
        assert_eq!(hosts_without_entry(&added).unwrap(), base);
        assert!(hosts_without_entry(base).is_none());
    }
}
