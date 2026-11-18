//! SSC core: share-URI parsing, profile store, sing-box client config.

mod config_paths;
mod keychain;
mod netinfo;
mod profiles;
mod singbox;
mod uri;

pub use config_paths::{
    config_dir, ensure_config_dir, ephemeral_singbox_path, profiles_path, runtime_dir,
    singbox_meta_path, singbox_run_path,
};
pub use keychain::{
    account_for_profile, delete_secret, load_secret, normalize_keychain_secret, store_secret,
};
pub use netinfo::{
    detect_netinfo, gateway_ip, local_exclusions, primary_interface, NetInfo,
};
pub use profiles::{
    active_profile, add_profile, list_profiles, load_profiles, profile_uri, read_uri_file,
    remove_profile, replace_profiles, save_profiles, server_of, set_active, Profile, ProfilesFile,
};
pub use singbox::{
    build_singbox_config, build_singbox_config_from_parsed, cleanup_ephemeral_config,
    persistent_config_has_secrets, redact_singbox_config, write_singbox_config,
    write_singbox_config_with_policy,
};
pub use uri::{
    parse_share_uri, ParsedShare, Protocol, RealityOpts, TlsOpts, TransportOpts, UriError,
};
