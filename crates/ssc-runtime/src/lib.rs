//! SSC runtime: sing-box setup, isolated instance lifecycle, race / failover.

mod best;
mod install;
mod instance;
mod local_domain;
mod netconflict;
mod privileges;
mod probe;
mod setup;
mod tunnel;

pub use best::{connect_best, format_race_table, run_race, BestConnectOptions};
pub use install::{
    default_bin_dir, install, print_usage_hint, uninstall, InstallOptions, InstallResult,
};
pub use instance::{
    cleanup_instance_orphans, find_owned_pids, is_instance_connected, owned_by_config,
    process_alive, read_instance_log, read_status_at, run_instance_worker, spawn_instance,
    stop_instance, stop_process, write_status_at, InstanceFileLock, InstanceHealth, InstanceMode,
    InstancePaths, InstanceProcessBackend, InstanceStatus, RunningProcess, SingBoxBackend,
    DEFAULT_INSTANCE_ID,
};
pub use local_domain::{
    hosts_path, install_hosts_entry, local_domain_configured, remove_hosts_entry, LOCAL_DOMAIN,
};
pub use netconflict::foreign_vpn_conflict;
pub use privileges::{
    install_privileges, passwordless_tunnel_ok, privileged_ssc_bin, remove_privileges,
    status_summary as privileges_status, SUDOERS_PATH, SYSTEM_SSC_BIN,
};
pub use probe::{
    pick_best, ping_profile, probe_profile, probe_tcp, race_profiles, should_switch, PingStats,
    ProbeResult, RaceOptions,
};
pub use setup::{
    check_setup, find_singbox, platform_name, resolved_singbox_path, run_setup, SetupCheck,
    SINGBOX_VERSION,
};
pub use tunnel::{
    cleanup_orphans, clear_stop, connect, disconnect, is_connected, read_status, request_stop,
    reset_all_instances, run_tunnel_worker, status_summary, stop_requested, TunnelStatus,
};
