//! Local VPN service layer shared by CLI and Web API.

mod cmdutil;
mod diagnostics;
mod kill_switch;
mod launch_agent;
mod netconflict;
mod reconcile;
mod route_probe;
mod traffic;
mod vpn_manager;

pub use cmdutil::{
    http_get_timed, http_put_timed, run_timed, run_timed_ok, DEFAULT_CMD_TIMEOUT,
    DEFAULT_HTTP_TIMEOUT,
};
pub use diagnostics::{format_diagnostics_pretty, run_diagnostics, CheckResult, DiagnosticsReport};
pub use kill_switch::{
    activate as kill_switch_activate, activate_for_policy, deactivate as kill_switch_deactivate,
    vpn_dest_cidrs,
};
pub use launch_agent::{
    disable as launch_agent_disable, enable as launch_agent_enable,
    is_enabled as launch_agent_is_enabled, sync_from_settings as launch_agent_sync,
};
pub use netconflict::foreign_vpn_conflict;
pub use reconcile::{
    deactivate_kill_switch, engage_kill_switch_marker, kill_switch_engaged, reconcile_on_startup,
    ReconcileReport,
};
pub use route_probe::{probe_destination, MatchedRuleView, RouteProbeResult};
pub use traffic::{ConnectionEvent, TrafficMonitor, TrafficSnapshot};
pub use vpn_manager::{reset_network, VpnManager, VpnState, VpnStatusView};

/// Serialize tests that mutate `SSC_CONFIG_DIR` (parallel cargo tests race otherwise).
#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
