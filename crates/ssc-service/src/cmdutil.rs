//! Timed process + HTTP helpers so diagnostics never hang forever.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

pub const DEFAULT_CMD_TIMEOUT: Duration = Duration::from_secs(8);
pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_millis(800);

#[derive(Debug)]
pub enum TimedError {
    Timeout,
    Spawn(String),
    Failed(String),
}

impl std::fmt::Display for TimedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimedError::Timeout => write!(f, "command timed out"),
            TimedError::Spawn(e) => write!(f, "{e}"),
            TimedError::Failed(e) => write!(f, "{e}"),
        }
    }
}

/// Run an external command with a hard timeout. On timeout the child is killed.
pub fn run_timed(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<std::process::Output, TimedError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| TimedError::Spawn(format!("spawn {program}: {e}")))?;

    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = child.stdout.take().map(|mut s| {
                    let mut b = Vec::new();
                    let _ = s.read_to_end(&mut b);
                    b
                }).unwrap_or_default();
                let stderr = child.stderr.take().map(|mut s| {
                    let mut b = Vec::new();
                    let _ = s.read_to_end(&mut b);
                    b
                }).unwrap_or_default();
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
                    return Err(TimedError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(TimedError::Failed(e.to_string())),
        }
    }
}

pub fn run_timed_ok(program: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    match run_timed(program, args, timeout) {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            if out.status.success() {
                Ok(stdout)
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(format!(
                    "{program} failed: {} {}",
                    out.status,
                    stderr.trim()
                ))
            }
        }
        Err(TimedError::Timeout) => Err(format!("{program}: command timed out")),
        Err(e) => Err(e.to_string()),
    }
}

/// Minimal HTTP GET with connect/read timeouts (localhost Clash API, etc.).
pub fn http_get_timed(url: &str, timeout: Duration) -> Result<String, String> {
    let url = url
        .strip_prefix("http://")
        .ok_or_else(|| "only http:// supported".to_string())?;
    let (host_port, path) = url
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((url, "/".into()));
    let (host, port): (&str, u16) = match host_port.split_once(':') {
        Some((h, p)) => (h, p.parse().map_err(|_| "bad port")?),
        None => (host_port, 80),
    };
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("parse addr: {e}"))?,
        timeout,
    )
    .map_err(|e| format!("connect: {e}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = String::new();
    stream
        .read_to_string(&mut buf)
        .map_err(|e| format!("read: {e}"))?;
    buf.split("\r\n\r\n")
        .nth(1)
        .map(|s| s.to_string())
        .ok_or_else(|| "empty HTTP body".into())
}

pub fn http_put_timed(url: &str, body: &str, timeout: Duration) -> Result<String, String> {
    let url = url
        .strip_prefix("http://")
        .ok_or_else(|| "only http:// supported".to_string())?;
    let (host_port, path) = url
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((url, "/".into()));
    let (host, port): (&str, u16) = match host_port.split_once(':') {
        Some((h, p)) => (h, p.parse().map_err(|_| "bad port")?),
        None => (host_port, 80),
    };
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("parse addr: {e}"))?,
        timeout,
    )
    .map_err(|e| format!("connect: {e}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req = format!(
        "PUT {path} HTTP/1.0\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = String::new();
    stream
        .read_to_string(&mut buf)
        .map_err(|e| format!("read: {e}"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_kills_long_sleep() {
        let err = run_timed("sleep", &["5"], Duration::from_millis(200)).unwrap_err();
        assert!(matches!(err, TimedError::Timeout));
    }

    #[test]
    fn echo_ok() {
        let out = run_timed_ok("echo", &["hi"], Duration::from_secs(2)).unwrap();
        assert!(out.contains("hi"));
    }
}
