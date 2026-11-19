//! Shared API state.

use crate::ws::WsEvent;
use serde_json::json;
use ssc_policy::load_policy;
use ssc_service::{
    InstanceEvent, InstanceStatusView, TrafficMonitor, VpnInstanceManager, VpnManager,
    VpnStatusView,
};
use std::sync::Arc;
use tokio::sync::broadcast;

pub struct AppState {
    /// Multi-instance manager (shared with the compatibility `VpnManager`).
    pub instances: VpnInstanceManager,
    pub traffic: Arc<TrafficMonitor>,
    pub events: broadcast::Sender<String>,
}

impl AppState {
    pub fn new() -> Self {
        Self::with_manager(VpnManager::global().instances().clone())
    }

    /// Test / embedder constructor with an injected manager.
    pub fn with_manager(instances: VpnInstanceManager) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            instances,
            traffic: Arc::new(TrafficMonitor::new()),
            events: tx,
        }
    }

    /// Compatibility status of the reserved `default` instance.
    pub async fn vpn_status(&self) -> Result<VpnStatusView, String> {
        let _ = self
            .instances
            .poll_traffic(ssc_service::DEFAULT_INSTANCE_ID)
            .await;
        let view = self
            .instances
            .status(ssc_service::DEFAULT_INSTANCE_ID)
            .await?;
        let mut out = VpnStatusView::from(view);
        if out.profile_name.is_none() {
            if let Ok(p) = ssc_core::active_profile() {
                out.profile_id = Some(p.id.clone());
                out.profile_name = Some(p.name.clone());
                out.server = Some(ssc_core::server_of(&p));
            }
        }
        Ok(out)
    }

    pub async fn initial_state_json(&self) -> String {
        let vpn = self.vpn_status().await.unwrap_or_else(|e| VpnStatusView {
            state: ssc_service::VpnState::Error,
            server: None,
            interface: None,
            profile_id: None,
            profile_name: None,
            connected_at: None,
            bytes_sent: 0,
            bytes_received: 0,
            latency_ms: None,
            last_error: Some(e),
            mode: "selective".into(),
            kill_switch: false,
            auto_reconnect: false,
        });
        let policy = load_policy().unwrap_or_default();
        let traffic = self.traffic.snapshot();
        let instances = self.instances.list().await.unwrap_or_default();
        json!({
            "type": "state",
            "vpn": vpn,
            "instances": instances,
            "policy": policy,
            "traffic": {
                "bytes_sent": traffic.bytes_sent,
                "bytes_received": traffic.bytes_received,
                "connections": traffic.connections,
            }
        })
        .to_string()
    }

    pub fn broadcast_instance_status(&self, status: &InstanceStatusView) {
        let _ = self.events.send(
            json!({
                "type": "vpn_instance_status",
                "instance": status,
            })
            .to_string(),
        );
        if status.id == ssc_service::DEFAULT_INSTANCE_ID {
            let _ = self.events.send(
                json!({
                    "type": "vpn_status",
                    "state": status.state.as_str(),
                    "server": status.server,
                    "interface": status.interface,
                    "bytes_sent": status.bytes_sent,
                    "bytes_received": status.bytes_received,
                    "latency_ms": status.latency_ms,
                    "mode": status.policy_mode,
                    "kill_switch": status.kill_switch,
                    "last_error": status.last_error,
                })
                .to_string(),
            );
        }
        let _ = self.events.send(
            json!({
                "type": "traffic",
                "bytes_sent": status.bytes_sent,
                "bytes_received": status.bytes_received,
            })
            .to_string(),
        );
    }

    /// Bridge manager events into the WebSocket broadcast channel.
    pub fn spawn_event_forwarder(&self) {
        let mut rx = self.instances.subscribe();
        let tx = self.events.clone();
        tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                let payload = match event {
                    InstanceEvent::InstanceStatus { instance } => json!({
                        "type": "vpn_instance_status",
                        "instance": instance.as_ref(),
                    }),
                    InstanceEvent::InstancesChanged => json!({
                        "type": "instances_changed",
                    }),
                };
                let _ = tx.send(payload.to_string());
            }
        });
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
