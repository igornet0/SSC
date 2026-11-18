//! Secret storage for profile share URIs.
//!
//! On macOS, secrets live in the Keychain via the `security` CLI
//! (service `"SSC VPN"`, account `ssc-profile-{id}`).
//!
//! On other platforms, secrets are written under `secrets/` with mode `0600`.
//! That fallback is **limited**: file-based storage is weaker than a keychain
//! (no OS-level access prompts / encryption-at-rest guarantees).

use std::process::Command;

const SERVICE: &str = "SSC VPN";

/// Keychain / secrets account name for a profile id.
pub fn account_for_profile(id: &str) -> String {
    format!("ssc-profile-{id}")
}

/// Store a secret for `account` (creates or updates).
pub fn store_secret(account: &str, secret: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("security")
            .args([
                "add-generic-password",
                "-U",
                "-s",
                SERVICE,
                "-a",
                account,
                "-w",
                secret,
            ])
            .status()
            .map_err(|e| format!("keychain store: {e}"))?;
        if !status.success() {
            return Err(format!("keychain store failed (exit {status})"));
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        file_store(account, secret)
    }
}

/// Load secret for `account`.
pub fn load_secret(account: &str) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        // `security` can block forever on Keychain auth prompts — hard-timeout.
        let mut child = Command::new("security")
            .args(["find-generic-password", "-w", "-s", SERVICE, "-a", account])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("keychain load: {e}"))?;
        let timeout = std::time::Duration::from_secs(5);
        let start = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stdout = Vec::new();
                    let mut stderr = Vec::new();
                    if let Some(mut s) = child.stdout.take() {
                        let _ = std::io::Read::read_to_end(&mut s, &mut stdout);
                    }
                    if let Some(mut s) = child.stderr.take() {
                        let _ = std::io::Read::read_to_end(&mut s, &mut stderr);
                    }
                    if !status.success() {
                        let err = String::from_utf8_lossy(&stderr);
                        let msg = err.trim();
                        return Err(format!(
                            "keychain load failed: {}",
                            if msg.is_empty() { "not found" } else { msg }
                        ));
                    }
                    let mut s =
                        String::from_utf8(stdout).map_err(|e| format!("keychain utf8: {e}"))?;
                    while s.ends_with('\n') || s.ends_with('\r') {
                        s.pop();
                    }
                    return Ok(normalize_keychain_secret(&s));
                }
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(
                            "keychain load timed out (unlock Keychain / allow SSC access)"
                                .into(),
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(format!("keychain wait: {e}")),
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        file_load(account)
    }
}

/// `security … -w` hex-encodes the password when it contains non-ASCII
/// (e.g. emoji in a share-URI `#name` fragment). Decode when needed.
pub fn normalize_keychain_secret(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("vless://")
        || lower.starts_with("vmess://")
        || lower.starts_with("trojan://")
    {
        return trimmed.to_string();
    }
    if trimmed.len() >= 16
        && trimmed.len() % 2 == 0
        && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
    {
        if let Ok(bytes) = decode_hex(trimmed) {
            if let Ok(decoded) = String::from_utf8(bytes) {
                let d = decoded.trim();
                let dl = d.to_ascii_lowercase();
                if dl.starts_with("vless://")
                    || dl.starts_with("vmess://")
                    || dl.starts_with("trojan://")
                {
                    return d.to_string();
                }
            }
        }
    }
    trimmed.to_string()
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

/// Delete secret for `account` (ok if already absent).
pub fn delete_secret(account: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("security")
            .args([
                "delete-generic-password",
                "-s",
                SERVICE,
                "-a",
                account,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        file_delete(account)
    }
}

#[cfg(not(target_os = "macos"))]
fn secrets_dir() -> Result<std::path::PathBuf, String> {
    use crate::config_paths::ensure_config_dir;
    let dir = ensure_config_dir()?.join("secrets");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create secrets dir: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

#[cfg(not(target_os = "macos"))]
fn secret_path(account: &str) -> Result<std::path::PathBuf, String> {
    let safe: String = account
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Ok(secrets_dir()?.join(safe))
}

#[cfg(not(target_os = "macos"))]
fn file_store(account: &str, secret: &str) -> Result<(), String> {
    let path = secret_path(account)?;
    std::fs::write(&path, secret).map_err(|e| format!("write secret: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod secret: {e}"))?;
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn file_load(account: &str) -> Result<String, String> {
    let path = secret_path(account)?;
    std::fs::read_to_string(&path).map_err(|e| format!("read secret: {e}"))
}

#[cfg(not(target_os = "macos"))]
fn file_delete(account: &str) -> Result<(), String> {
    let path = secret_path(account)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("delete secret: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_passthrough_plain_uri() {
        let u = "vless://abc@host:443?security=tls#name";
        assert_eq!(normalize_keychain_secret(u), u);
    }

    #[test]
    fn normalize_decodes_hex_with_emoji_fragment() {
        let uri = "vless://11111111-1111-1111-1111-111111111111@host:443?security=tls#🇫🇮 Finland";
        let hex: String = uri.bytes().map(|b| format!("{b:02x}")).collect();
        let out = normalize_keychain_secret(&hex);
        assert!(out.starts_with("vless://"));
        assert!(out.contains("Finland"));
    }
}
