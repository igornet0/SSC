//! Shared API state.

use crate::ws::WsEvent;
use serde_json::json;
use ssc_policy::load_policy;
use ssc_service::{TrafficMonitor, VpnManager, VpnStatusView};
use std::sync::Arc;
use tokio::sync::broadcast;

pub struct AppState {
    pub vpn: &'static VpnManager,
    pub traffic: Arc<TrafficMonitor>,
    pub events: broadcast::Sender<String>,
}

impl AppState {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            vpn: VpnManager::global(),
            traffic: Arc::new(TrafficMonitor::new()),
            events: tx,
        }
    }

    pub fn initial_state_json(&self) -> String {
        let vpn = self.vpn.status();
        let policy = load_policy().unwrap_or_default();
        let traffic = self.traffic.snapshot();
        json!({
            "type": "state",
            "vpn": vpn,
            "policy": policy,
            "traffic": {
                "bytes_sent": traffic.bytes_sent,
                "bytes_received": traffic.bytes_received,
                "connections": traffic.connections,
            }
        })
        .to_string()
    }

    pub fn broadcast_status(&self, status: &VpnStatusView) {
        let _ = self.events.send(
            json!({
                "type": "vpn_status",
                "state": status.state.as_str(),
                "server": status.server,
                "interface": status.interface,
                "bytes_sent": status.bytes_sent,
                "bytes_received": status.bytes_received,
                "latency_ms": status.latency_ms,
                "mode": status.mode,
                "kill_switch": status.kill_switch,
                "last_error": status.last_error,
            })
            .to_string(),
        );
        let _ = self.events.send(
            json!({
                "type": "traffic",
                "bytes_sent": status.bytes_sent,
                "bytes_received": status.bytes_received,
            })
            .to_string(),
        );
    }

    pub fn broadcast_policy_changed(&self) {
        let policy = load_policy().unwrap_or_default();
        let _ = self.events.send(
            json!({
                "type": "policy_changed",
                "mode": policy.settings.mode.as_str(),
                "rules_count": policy.active_rules().count(),
                "kill_switch": policy.settings.kill_switch,
                "applied": true,
            })
            .to_string(),
        );
    }

    pub fn broadcast_event(&self, event: WsEvent) {
        if let Ok(s) = serde_json::to_string(&event) {
            let _ = self.events.send(s);
        }
    }

    pub fn broadcast_error(&self, message: &str) {
        let _ = self.events.send(
            json!({
                "type": "error",
                "message": message,
            })
            .to_string(),
        );
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
