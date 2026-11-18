//! TCP latency probe to profile server endpoints.

use ssc_core::{parse_share_uri, Profile};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub profile_id: String,
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub ok: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RaceOptions {
    /// Per-endpoint connect timeout.
    pub timeout: Duration,
}

impl Default for RaceOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
        }
    }
}

/// Measure TCP connect RTT (includes DNS resolve).
pub fn probe_tcp(host: &str, port: u16, timeout: Duration) -> Result<Duration, String> {
    let start = Instant::now();
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("dns: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err("dns: no addresses".into());
    }
    let mut last_err = String::from("connect failed");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return Ok(start.elapsed());
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(last_err)
}

#[derive(Debug, Clone)]
pub struct PingStats {
    pub profile_id: String,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub sent: u32,
    pub received: u32,
    pub samples_ms: Vec<u64>,
    pub last_error: Option<String>,
}

impl PingStats {
    pub fn min_ms(&self) -> Option<u64> {
        self.samples_ms.iter().copied().min()
    }
    pub fn max_ms(&self) -> Option<u64> {
        self.samples_ms.iter().copied().max()
    }
    pub fn avg_ms(&self) -> Option<u64> {
        if self.samples_ms.is_empty() {
            return None;
        }
        let sum: u64 = self.samples_ms.iter().sum();
        Some(sum / self.samples_ms.len() as u64)
    }
}

/// Ping a profile `count` times with `interval` between probes.
pub fn ping_profile(
    profile: &Profile,
    count: u32,
    timeout: Duration,
    interval: Duration,
) -> Result<PingStats, String> {
    let count = count.max(1);
    let uri = ssc_core::profile_uri(profile).map_err(|e| e.to_string())?;
    let parsed = parse_share_uri(&uri).map_err(|e| e.to_string())?;
    let mut stats = PingStats {
        profile_id: profile.id.clone(),
        name: profile.name.clone(),
        server: parsed.server.clone(),
        port: parsed.server_port,
        sent: 0,
        received: 0,
        samples_ms: Vec::new(),
        last_error: None,
    };
    for i in 0..count {
        stats.sent += 1;
        match probe_tcp(&parsed.server, parsed.server_port, timeout) {
            Ok(d) => {
                let ms = d.as_millis().max(1) as u64;
                stats.received += 1;
                stats.samples_ms.push(ms);
                println!(
                    "pong from {}:{}: time={} ms  seq={}",
                    parsed.server, parsed.server_port, ms, i + 1
                );
            }
            Err(e) => {
                stats.last_error = Some(e.clone());
                println!(
                    "timeout/fail {}:{}: {}  seq={}",
                    parsed.server, parsed.server_port, e, i + 1
                );
            }
        }
        if i + 1 < count && !interval.is_zero() {
            std::thread::sleep(interval);
        }
    }
    Ok(stats)
}

pub fn probe_profile(profile: &Profile, opts: &RaceOptions) -> ProbeResult {
    let parsed = match ssc_core::profile_uri(profile).and_then(|uri| {
        parse_share_uri(&uri).map_err(|e| e.to_string())
    }) {
        Ok(p) => p,
        Err(e) => {
            return ProbeResult {
                profile_id: profile.id.clone(),
                name: profile.name.clone(),
                protocol: profile.protocol.clone(),
                server: String::new(),
                port: 0,
                ok: false,
                latency_ms: None,
                error: Some(e.to_string()),
            };
        }
    };
    match probe_tcp(&parsed.server, parsed.server_port, opts.timeout) {
        Ok(d) => ProbeResult {
            profile_id: profile.id.clone(),
            name: profile.name.clone(),
            protocol: profile.protocol.clone(),
            server: parsed.server,
            port: parsed.server_port,
            ok: true,
            latency_ms: Some(d.as_millis().max(1) as u64),
            error: None,
        },
        Err(e) => ProbeResult {
            profile_id: profile.id.clone(),
            name: profile.name.clone(),
            protocol: profile.protocol.clone(),
            server: parsed.server,
            port: parsed.server_port,
            ok: false,
            latency_ms: None,
            error: Some(e),
        },
    }
}

/// Probe all profiles; results sorted: ok first by latency asc, then failures.
pub fn race_profiles(profiles: &[Profile], opts: &RaceOptions) -> Vec<ProbeResult> {
    let mut results: Vec<ProbeResult> = profiles
        .iter()
        .map(|p| probe_profile(p, opts))
        .collect();
    results.sort_by(|a, b| match (a.ok, b.ok) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        (true, true) => a
            .latency_ms
            .unwrap_or(u64::MAX)
            .cmp(&b.latency_ms.unwrap_or(u64::MAX)),
        (false, false) => a.name.cmp(&b.name),
    });
    results
}

pub fn pick_best(results: &[ProbeResult]) -> Option<&ProbeResult> {
    results.iter().find(|r| r.ok)
}

/// Switch when current is down, or candidate is faster by at least `hysteresis_ms`.
pub fn should_switch(
    current_ok: bool,
    current_ms: Option<u64>,
    candidate_ok: bool,
    candidate_ms: Option<u64>,
    hysteresis_ms: u64,
) -> bool {
    if !candidate_ok {
        return false;
    }
    let Some(cand) = candidate_ms else {
        return false;
    };
    if !current_ok {
        return true;
    }
    let Some(cur) = current_ms else {
        return true;
    };
    cand + hysteresis_ms < cur
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_on_dead_current() {
        assert!(should_switch(false, None, true, Some(50), 40));
    }

    #[test]
    fn no_switch_within_hysteresis() {
        assert!(!should_switch(true, Some(100), true, Some(80), 40));
    }

    #[test]
    fn switch_when_clearly_faster() {
        assert!(should_switch(true, Some(120), true, Some(50), 40));
    }

    #[test]
    fn no_switch_to_dead_candidate() {
        assert!(!should_switch(true, Some(100), false, None, 40));
    }

    #[test]
    fn race_sorts_ok_before_fail() {
        let mut results = vec![
            ProbeResult {
                profile_id: "a".into(),
                name: "slow".into(),
                protocol: "vless".into(),
                server: "a".into(),
                port: 443,
                ok: true,
                latency_ms: Some(200),
                error: None,
            },
            ProbeResult {
                profile_id: "b".into(),
                name: "dead".into(),
                protocol: "vless".into(),
                server: "b".into(),
                port: 443,
                ok: false,
                latency_ms: None,
                error: Some("x".into()),
            },
            ProbeResult {
                profile_id: "c".into(),
                name: "fast".into(),
                protocol: "vless".into(),
                server: "c".into(),
                port: 443,
                ok: true,
                latency_ms: Some(40),
                error: None,
            },
        ];
        results.sort_by(|a, b| match (a.ok, b.ok) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (true, true) => a
                .latency_ms
                .unwrap_or(u64::MAX)
                .cmp(&b.latency_ms.unwrap_or(u64::MAX)),
            (false, false) => a.name.cmp(&b.name),
        });
        assert_eq!(results[0].profile_id, "c");
        assert_eq!(results[1].profile_id, "a");
        assert_eq!(results[2].profile_id, "b");
        assert_eq!(pick_best(&results).unwrap().profile_id, "c");
    }
}
