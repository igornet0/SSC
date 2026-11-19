//! SSC core: share-URI parsing, profile store, sing-box client config.

mod config_paths;
mod keychain;
mod netinfo;
mod profiles;
mod singbox;
mod uri;

pub use config_paths::{
    config_dir, ensure_config_dir, ephemeral_pointer_path, ephemeral_singbox_path, instance_dir,
    instances_dir, instances_registry_path, profiles_path, runtime_dir, singbox_meta_path,
    singbox_run_path, validate_instance_id,
};
pub use keychain::{
    account_for_profile, delete_secret, load_secret, normalize_keychain_secret, store_secret,
};
pub use netinfo::{detect_netinfo, gateway_ip, local_exclusions, primary_interface, NetInfo};
pub use profiles::{
    active_profile, add_profile, list_profiles, load_profiles, profile_uri, read_uri_file,
    remove_profile, replace_profiles, save_profiles, server_of, set_active, Profile, ProfilesFile,
};
pub use singbox::{
    build_singbox_config, build_singbox_config_from_parsed, build_singbox_config_with_options,
    cleanup_ephemeral_config, persistent_config_has_secrets, redact_log_text,
    redact_singbox_config, write_legacy_singbox_config, write_singbox_config,
    write_singbox_config_at, write_singbox_config_with_policy, InboundKind, SingboxOptions,
    DEFAULT_CLASH_API_PORT, DEFAULT_TUN_ADDRESS,
};
pub use uri::{
    parse_share_uri, ParsedShare, Protocol, RealityOpts, TlsOpts, TransportOpts, UriError,
};
