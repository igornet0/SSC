//! Policy engine: domain / IP / CIDR → DIRECT | VPN | BLOCK.

mod compile;
mod engine;
mod model;
mod store;

pub use compile::{compile_route_rules, CompiledPolicy};
pub use engine::PolicyEngine;
pub use model::{
    Action, MatchKind, PolicyMode, PolicyRule, PolicySnapshot, RuleGroup, RuleMatch, Settings,
};
pub use store::{
    active_profile_id, add_group, add_rule, add_rule_in_group, delete_group, delete_rule,
    ensure_group, export_policy, import_policy, load_policy, load_policy_for, policy_path,
    policy_path_for, save_policy, save_policy_for, set_mode, update_group, update_rule,
    update_settings, GroupPatch, PolicyStoreError, RulePatch,
};
