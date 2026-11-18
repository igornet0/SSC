//! Download and resolve sing-box binary.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const SINGBOX_VERSION: &str = "1.13.13";
const SETUP_MARKER: &str = "setup.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupCheck {
    pub needs_setup: bool,
    pub platform: String,
    pub singbox_ready: bool,
    pub singbox_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SetupMarker {
    version: u32,
    platform: String,
    completed_at_ms: i64,
    singbox_path: String,
}

pub fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    }
}

#[cfg(unix)]
pub fn running_as_root_helper() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "windows")]
pub fn running_as_root_helper() -> bool {
    Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(any(unix, target_os = "windows")))]
pub fn running_as_root_helper() -> bool {
    false
}

fn singbox_filename() -> &'static str {
    if cfg!(target_os = "windows") {
        "sing-box.exe"
    } else {
        "sing-box"
    }
}

fn user_bin_dir() -> Result<PathBuf, String> {
    Ok(ssc_core::ensure_config_dir()?.join("bin"))
}

pub fn user_singbox_path() -> Result<PathBuf, String> {
    Ok(user_bin_dir()?.join(singbox_filename()))
}

fn setup_marker_path() -> Result<PathBuf, String> {
    Ok(ssc_core::ensure_config_dir()?.join(SETUP_MARKER))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn save_marker(singbox_path: &Path) -> Result<(), String> {
    let marker = SetupMarker {
        version: 1,
        platform: platform_name().to_string(),
        completed_at_ms: now_ms(),
        singbox_path: singbox_path.to_string_lossy().into_owned(),
    };
    let path = setup_marker_path()?;
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&marker).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn detect_arch() -> Result<&'static str, String> {
    #[cfg(target_arch = "aarch64")]
    {
        Ok("arm64")
    }
    #[cfg(target_arch = "x86_64")]
    {
        Ok("amd64")
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        Err("unsupported CPU architecture".into())
    }
}

fn singbox_triple() -> Result<String, String> {
    let arch = detect_arch()?;
    Ok(match (platform_name(), arch) {
        ("macos", "arm64") => "darwin-arm64".to_string(),
        ("macos", "amd64") => "darwin-amd64".to_string(),
        ("linux", "arm64") => "linux-arm64".to_string(),
        ("linux", "amd64") => "linux-amd64".to_string(),
        ("windows", "arm64") => "windows-arm64".to_string(),
        ("windows", "amd64") => "windows-amd64".to_string(),
        (p, a) => return Err(format!("unsupported platform {p}/{a}")),
    })
}

fn download_url_archive() -> Result<(String, bool), String> {
    let triple = singbox_triple()?;
    #[cfg(target_os = "windows")]
    {
        return Ok((
            format!(
                "https://github.com/Sagernet/sing-box/releases/download/v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-{triple}.zip"
            ),
            true,
        ));
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok((
            format!(
                "https://github.com/Sagernet/sing-box/releases/download/v{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION}-{triple}.tar.gz"
            ),
            false,
        ))
    }
}

fn copy_executable(src: &Path, dest: &Path) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::copy(src, dest).map_err(|e| format!("copy sing-box: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dest)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(dest, perms).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn extract_singbox_from_tar_gz(archive: &Path, dest: &Path) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!("ssc-singbox-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let status = Command::new("tar")
        .args([
            "-xzf",
            &archive.to_string_lossy(),
            "-C",
            &tmp.to_string_lossy(),
        ])
        .status()
        .map_err(|e| format!("tar failed: {e}"))?;
    if !status.success() {
        return Err("failed to extract sing-box archive".into());
    }
    let mut found = None;
    for entry in std::fs::read_dir(&tmp).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let p = entry.path().join(singbox_filename());
        if p.is_file() {
            found = Some(p);
            break;
        }
    }
    let Some(src) = found else {
        return Err("sing-box binary not found in archive".into());
    };
    copy_executable(&src, dest)?;
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

#[cfg(target_os = "windows")]
fn extract_singbox_from_zip(archive: &Path, dest: &Path) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!("ssc-singbox-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let ps = format!(
        "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
        archive.display(),
        tmp.display()
    );
    let status = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps])
        .status()
        .map_err(|e| format!("powershell extract failed: {e}"))?;
    if !status.success() {
        return Err("failed to extract sing-box zip".into());
    }
    let mut found = None;
    fn walk(dir: &Path, found: &mut Option<PathBuf>) -> Result<(), String> {
        for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let p = entry.path();
            if p.is_dir() {
                walk(&p, found)?;
            } else if p.file_name().and_then(|n| n.to_str()) == Some(singbox_filename()) {
                *found = Some(p);
            }
            if found.is_some() {
                return Ok(());
            }
        }
        Ok(())
    }
    walk(&tmp, &mut found)?;
    let Some(src) = found else {
        return Err("sing-box.exe not found in archive".into());
    };
    copy_executable(&src, dest)?;
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

fn download_singbox(dest: &Path) -> Result<(), String> {
    let (url, is_zip) = download_url_archive()?;
    eprintln!("Downloading sing-box from {url}");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| e.to_string())?;
    let bytes = client
        .get(&url)
        .send()
        .map_err(|e| format!("download failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("download HTTP error: {e}"))?
        .bytes()
        .map_err(|e| e.to_string())?;
    let ext = if is_zip { "zip" } else { "tar.gz" };
    let archive = std::env::temp_dir().join(format!(
        "ssc-singbox-dl-{}.{}",
        std::process::id(),
        ext
    ));
    std::fs::write(&archive, &bytes).map_err(|e| e.to_string())?;
    eprintln!("Extracting sing-box…");
    #[cfg(target_os = "windows")]
    {
        let _ = is_zip;
        extract_singbox_from_zip(&archive, dest)?;
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = is_zip;
        extract_singbox_from_tar_gz(&archive, dest)?;
    }
    let _ = std::fs::remove_file(&archive);
    Ok(())
}

/// Find sing-box: env `SSC_SINGBOX_PATH`, user bin, or PATH.
pub fn find_singbox() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SSC_SINGBOX_PATH") {
        let path = PathBuf::from(p.trim());
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(user) = user_singbox_path() {
        if user.is_file() {
            return Some(user);
        }
    }
    which_singbox()
}

fn which_singbox() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        return Command::new("where")
            .arg("sing-box.exe")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .next()
                    .map(|l| PathBuf::from(l.trim()))
                    .filter(|p| p.is_file())
            });
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new("which")
            .arg("sing-box")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| {
                let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if p.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(p))
                }
            })
    }
}

pub fn resolved_singbox_path() -> Result<PathBuf, String> {
    find_singbox().ok_or_else(|| "sing-box not found — run `ssc setup` first".into())
}

pub fn check_setup() -> SetupCheck {
    let path = find_singbox();
    let singbox_ready = path.is_some();
    SetupCheck {
        needs_setup: !singbox_ready,
        platform: platform_name().to_string(),
        singbox_ready,
        singbox_path: path.map(|p| p.to_string_lossy().into_owned()),
    }
}

pub fn run_setup() -> Result<PathBuf, String> {
    eprintln!("Starting SSC setup ({})", platform_name());
    if let Some(existing) = find_singbox() {
        eprintln!("sing-box already available: {}", existing.display());
        // Prefer copying into user bin if found via PATH/env so status is stable.
        let dest = user_singbox_path()?;
        if existing != dest && !dest.is_file() {
            if let Err(e) = copy_executable(&existing, &dest) {
                eprintln!("note: could not copy to {}: {e}", dest.display());
                save_marker(&existing)?;
                return Ok(existing);
            }
            save_marker(&dest)?;
            return Ok(dest);
        }
        save_marker(&existing)?;
        return Ok(existing);
    }
    let dest = user_singbox_path()?;
    download_singbox(&dest)?;
    save_marker(&dest)?;
    eprintln!("SSC setup complete: {}", dest.display());
    Ok(dest)
}
