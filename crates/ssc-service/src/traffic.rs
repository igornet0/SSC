//! Ring-buffer traffic / connection monitor (metadata only).

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_EVENTS: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEvent {
    pub time: String,
    pub timestamp_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    pub route: String,
    #[serde(default)]
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrafficSnapshot {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connections: Vec<ConnectionEvent>,
}

pub struct TrafficMonitor {
    events: Mutex<VecDeque<ConnectionEvent>>,
    bytes_sent: Mutex<u64>,
    bytes_received: Mutex<u64>,
}

impl Default for TrafficMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficMonitor {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::with_capacity(MAX_EVENTS)),
            bytes_sent: Mutex::new(0),
            bytes_received: Mutex::new(0),
        }
    }

    pub fn push(&self, mut ev: ConnectionEvent) {
        if ev.timestamp_ms == 0 {
            ev.timestamp_ms = now_ms();
        }
        if ev.time.is_empty() {
            ev.time = format_clock(ev.timestamp_ms);
        }
        if let Ok(mut q) = self.events.lock() {
            if q.len() >= MAX_EVENTS {
                q.pop_front();
            }
            q.push_back(ev);
        }
    }

    pub fn set_bytes(&self, sent: u64, received: u64) {
        if let Ok(mut s) = self.bytes_sent.lock() {
            *s = sent;
        }
        if let Ok(mut r) = self.bytes_received.lock() {
            *r = received;
        }
    }

    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            bytes_sent: self.bytes_sent.lock().map(|g| *g).unwrap_or(0),
            bytes_received: self.bytes_received.lock().map(|g| *g).unwrap_or(0),
            connections: self
                .events
                .lock()
                .map(|q| q.iter().rev().cloned().collect())
                .unwrap_or_default(),
        }
    }

    /// Pull recent connections from sing-box Clash API (metadata only).
    pub fn poll_clash(&self) {
        let Some(body) = http_get("http://127.0.0.1:9090/connections") else {
            return;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
            return;
        };
        let up = v.get("uploadTotal").and_then(|x| x.as_u64()).unwrap_or(0);
        let down = v
            .get("downloadTotal")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        self.set_bytes(up, down);

        let Some(arr) = v.get("connections").and_then(|c| c.as_array()) else {
            return;
        };
        // Only ingest a few newest to avoid flooding the ring buffer each poll.
        for c in arr.iter().rev().take(20) {
            let meta = c.get("metadata");
            let host = meta
                .and_then(|m| m.get("host"))
                .and_then(|h| h.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let ip = meta
                .and_then(|m| m.get("destinationIP"))
                .and_then(|h| h.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let port = meta
                .and_then(|m| m.get("destinationPort"))
                .and_then(|p| p.as_str().and_then(|s| s.parse().ok()).or_else(|| p.as_u64().map(|n| n as u16)));
            let protocol = meta
                .and_then(|m| m.get("network"))
                .and_then(|h| h.as_str())
                .map(|s| s.to_ascii_uppercase());
            let chain = c
                .get("chains")
                .and_then(|ch| ch.as_array())
                .and_then(|a| a.first())
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let route = if chain.eq_ignore_ascii_case("proxy") {
                "vpn"
            } else if chain.eq_ignore_ascii_case("direct") {
                "direct"
            } else if chain.is_empty() {
                "unknown"
            } else {
                chain
            }
            .to_string();
            let bytes = c.get("upload").and_then(|x| x.as_u64()).unwrap_or(0)
                + c.get("download").and_then(|x| x.as_u64()).unwrap_or(0);

            let dest = host.clone().or(ip.clone()).unwrap_or_else(|| "-".into());
            // Dedup roughly: skip if last event same dest+route within buffer head
            let skip = self
                .events
                .lock()
                .ok()
                .and_then(|q| q.back().cloned())
                .is_some_and(|last| {
                    last.route == route
                        && (last.domain.as_deref() == host.as_deref()
                            || last.ip.as_deref() == ip.as_deref()
                            || last.domain.as_deref() == Some(dest.as_str()))
                });
            if skip {
                continue;
            }
            eprintln!(
                "[CONNECTION_ROUTED] dest={} route={}",
                dest, &route
            );
            self.push(ConnectionEvent {
                time: String::new(),
                timestamp_ms: now_ms(),
                domain: host,
                ip,
                port,
                protocol,
                route,
                bytes,
            });
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn format_clock(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|d| d.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| ms.to_string())
}

fn http_get(url: &str) -> Option<String> {
    crate::cmdutil::http_get_timed(url, crate::cmdutil::DEFAULT_HTTP_TIMEOUT).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_caps_at_1000() {
        let m = TrafficMonitor::new();
        for i in 0..1100 {
            m.push(ConnectionEvent {
                time: String::new(),
                timestamp_ms: i,
                domain: Some(format!("h{i}.com")),
                ip: None,
                port: Some(443),
                protocol: Some("TCP".into()),
                route: "vpn".into(),
                bytes: 1,
            });
        }
        let snap = m.snapshot();
        assert_eq!(snap.connections.len(), 1000);
    }
}
