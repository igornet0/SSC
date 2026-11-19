//! Install / uninstall the `ssc` CLI into a PATH location and prepare sing-box.

use crate::setup::{platform_name, run_setup};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    /// Destination directory for the `ssc` binary. `None` → platform default.
    pub prefix_bin: Option<PathBuf>,
    /// Skip sing-box download/setup.
    pub skip_setup: bool,
    /// Prefer system-wide install (`/usr/local/bin`) when possible.
    pub system: bool,
}

#[derive(Debug, Clone)]
pub struct InstallResult {
    pub binary_path: PathBuf,
    pub singbox_path: Option<PathBuf>,
    pub path_hint: Option<String>,
}

fn binary_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "ssc.exe"
    } else {
        "ssc"
    }
}

/// Default install directory for the CLI binary.
pub fn default_bin_dir(system: bool) -> Result<PathBuf, String> {
    if let Some(custom) = env::var_os("SSC_INSTALL_BIN") {
        let p = PathBuf::from(custom);
        if !p.as_os_str().is_empty() {
            return Ok(p);
        }
    }

    #[cfg(target_os = "windows")]
    {
        let _ = system;
        let base =
            dirs::data_local_dir().ok_or_else(|| "cannot resolve LocalAppData".to_string())?;
        return Ok(base.join("Programs").join("ssc"));
    }

    #[cfg(not(target_os = "windows"))]
    {
        if system {
            return Ok(PathBuf::from("/usr/local/bin"));
        }
        if let Some(home) = dirs::home_dir() {
            let local = home.join(".local").join("bin");
            return Ok(local);
        }
        Err("cannot resolve home directory".into())
    }
}

fn current_exe() -> Result<PathBuf, String> {
    env::current_exe().map_err(|e| format!("resolve current executable: {e}"))
}

fn copy_self_to(dest: &Path) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create install dir: {e}"))?;
    }
    let src = current_exe()?;
    // Avoid copying onto ourselves.
    if same_file(&src, dest) {
        return Ok(());
    }
    let tmp = dest.with_extension("tmp");
    fs::copy(&src, &tmp).map_err(|e| format!("copy binary: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp).map_err(|e| e.to_string())?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&tmp, perms).map_err(|e| e.to_string())?;
    }
    if let Err(e) = fs::rename(&tmp, dest) {
        // Windows may block rename over an existing file — replace explicitly.
        let _ = fs::remove_file(dest);
        fs::copy(&tmp, dest).map_err(|e2| format!("install binary: {e}; fallback: {e2}"))?;
        let _ = fs::remove_file(&tmp);
    }
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

#[cfg(target_os = "windows")]
fn ensure_windows_user_path(bin_dir: &Path) -> Result<Option<String>, String> {
    let dir = bin_dir.to_string_lossy().replace('/', "\\");
    let script = format!(
        r#"
$dir = '{dir}'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ([string]::IsNullOrEmpty($userPath)) {{
  [Environment]::SetEnvironmentVariable('Path', $dir, 'User')
  Write-Output 'added'
}} elseif (($userPath -split ';' | ForEach-Object {{ $_.TrimEnd('\') }}) -notcontains $dir.TrimEnd('\')) {{
  [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $dir), 'User')
  Write-Output 'added'
}} else {{
  Write-Output 'exists'
}}
"#,
        dir = dir.replace('\'', "''")
    );
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map_err(|e| format!("update PATH failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "update PATH failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let status = String::from_utf8_lossy(&output.stdout);
    if status.contains("added") {
        Ok(Some(format!(
            "Added {dir} to your user PATH. Open a new terminal for `ssc` to be found."
        )))
    } else {
        Ok(None)
    }
}

#[cfg(not(target_os = "windows"))]
fn path_hint(bin_dir: &Path) -> Option<String> {
    let dir = bin_dir.display().to_string();
    let path = env::var("PATH").unwrap_or_default();
    let on_path = env::split_paths(&path).any(|p| p == bin_dir);
    if on_path {
        return None;
    }
    Some(format!(
        "Add to PATH (zsh/bash):\n  export PATH=\"{dir}:$PATH\"\n\
         Or append that line to ~/.zshrc / ~/.bashrc, then open a new terminal."
    ))
}

/// Install this executable as `ssc` and optionally run sing-box setup.
pub fn install(opts: InstallOptions) -> Result<InstallResult, String> {
    let bin_dir = match opts.prefix_bin {
        Some(p) => p,
        None => default_bin_dir(opts.system)?,
    };
    let dest = bin_dir.join(binary_name());
    eprintln!("Installing SSC ({}) → {}", platform_name(), dest.display());
    copy_self_to(&dest)?;

    #[cfg(target_os = "windows")]
    let path_hint = ensure_windows_user_path(&bin_dir)?;
    #[cfg(not(target_os = "windows"))]
    let path_hint = path_hint(&bin_dir);

    let singbox_path = if opts.skip_setup {
        None
    } else {
        eprintln!("Preparing VPN runtime (sing-box)…");
        Some(run_setup()?)
    };

    Ok(InstallResult {
        binary_path: dest,
        singbox_path,
        path_hint,
    })
}

/// Remove the installed `ssc` binary (does not delete profiles / sing-box cache).
pub fn uninstall(opts: InstallOptions) -> Result<PathBuf, String> {
    let bin_dir = match opts.prefix_bin {
        Some(p) => p,
        None => default_bin_dir(opts.system)?,
    };
    let dest = bin_dir.join(binary_name());
    if dest.is_file() {
        fs::remove_file(&dest).map_err(|e| format!("remove {}: {e}", dest.display()))?;
        eprintln!("removed {}", dest.display());
    } else {
        eprintln!("not found: {}", dest.display());
    }
    Ok(dest)
}

/// Print post-install usage.
pub fn print_usage_hint(result: &InstallResult) {
    println!("ssc installed: {}", result.binary_path.display());
    if let Some(sb) = &result.singbox_path {
        println!("sing-box ready: {}", sb.display());
    }
    if let Some(hint) = &result.path_hint {
        println!("{hint}");
    }
    println!();
    println!("Try:");
    println!("  ssc setup");
    println!("  ssc add 'vless://…'");
    println!("  ssc connect --best");
    println!("  ssc status");
    println!("  sudo ssc privileges install   # once — no password on Connect");
}
