//! REST API routes — localhost only, no secrets in responses.

use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use ssc_policy::{
    add_group, add_rule_in_group, delete_group, delete_rule, export_policy, import_policy,
    load_policy, save_policy, update_group, update_rule, Action, GroupPatch, MatchKind, PolicyMode,
    RulePatch, Settings,
};
use ssc_service::{
    probe_destination, run_diagnostics, CreateInstanceRequest, InstanceMode, UpdateInstanceRequest,
    DEFAULT_INSTANCE_ID,
};
use std::sync::Arc;

pub fn api_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/status", get(aggregate_status))
        .route("/api/v1/vpn/status", get(vpn_status))
        .route("/api/v1/vpn/connect", post(vpn_connect))
        .route("/api/v1/vpn/disconnect", post(vpn_disconnect))
        .route("/api/v1/vpn/reconnect", post(vpn_reconnect))
        .route("/api/v1/policy", get(get_policy).put(put_policy))
        .route("/api/v1/policy/export", get(policy_export))
        .route("/api/v1/policy/import", post(policy_import))
        .route("/api/v1/rules", get(list_rules).post(create_rule))
        .route("/api/v1/rules/{id}", put(patch_rule).delete(remove_rule))
        .route("/api/v1/groups", get(list_groups).post(create_group))
        .route("/api/v1/groups/{id}", put(patch_group).delete(remove_group))
        .route("/api/v1/traffic", get(get_traffic))
        .route("/api/v1/profiles", get(list_profiles).post(create_profile))
        .route(
            "/api/v1/profiles/{id}",
            put(update_profile).delete(remove_profile),
        )
        .route("/api/v1/diagnostics", get(diagnostics).post(diagnostics))
        .route(
            "/api/v1/route/probe",
            get(route_probe).post(route_probe_post),
        )
        // Independent VPN instances (TUN or Local Proxy).
        .route(
            "/api/v1/instances",
            get(list_instances).post(create_instance),
        )
        .route(
            "/api/v1/instances/{id}",
            get(get_instance)
                .put(update_instance)
                .delete(remove_instance),
        )
        .route("/api/v1/instances/{id}/start", post(start_instance))
        .route("/api/v1/instances/{id}/stop", post(stop_instance))
        .route("/api/v1/instances/{id}/restart", post(restart_instance))
        .route(
            "/api/v1/instances/{id}/policy",
            get(get_instance_policy).put(put_instance_policy),
        )
        .route("/api/v1/instances/{id}/traffic", get(instance_traffic))
        .route("/api/v1/instances/{id}/logs", get(instance_logs))
}

fn localhost_only(headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    // Soft CSRF: reject non-local Origin if present.
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        if !is_local_origin(origin) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "remote origin not allowed" })),
            ));
        }
    }
    Ok(())
}

/// Exact host match (port optional), so `http://localhost.evil.com` is rejected.
fn is_local_origin(origin: &str) -> bool {
    if origin == "null" {
        return true;
    }
    let Some(authority) = origin.strip_prefix("http://") else {
        return false;
    };
    let host = authority.split(':').next().unwrap_or("");
    host == "127.0.0.1"
        || host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case(ssc_runtime::LOCAL_DOMAIN)
}

fn friendly_err(e: String) -> (StatusCode, Json<Value>) {
    let lower = e.to_lowercase();
    let reason = if lower.contains("another vpn")
        || lower.contains("foreign vpn")
        || lower.contains("owns the default route")
    {
        "Another VPN is connected (e.g. Happ) — turn it off, then Connect"
    } else if lower.contains("timed out") || lower.contains("timeout") {
        "Unable to reach VPN server (timeout)"
    } else if lower.contains("connection refused") || lower.contains("unreachable") {
        "Unable to reach VPN server"
    } else if lower.contains("no active profile") || lower.contains("no secret") {
        "No VPN profile configured — import a share URI first"
    } else if lower.contains("sudo")
        || lower.contains("elevat")
        || lower.contains("permission")
        || lower.contains("administrator")
    {
        "Elevated privileges required for TUN — approve the macOS password prompt"
    } else if lower.contains("sing-box check") {
        "VPN configuration invalid — run Diagnostics"
    } else if lower.contains("resource busy") || lower.contains("address already in use") {
        "Tunnel busy — disconnect other VPN apps, then Retry"
    } else {
        "VPN connection failed"
    };
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": reason,
            "detail": e,
            "actions": ["retry", "diagnostics"],
        })),
    )
}

fn err_map(e: String) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": e })))
}

/// Recompile the global policy into the default instance only.
async fn apply_default_policy(state: &AppState) {
    if let Err(e) = state.instances.apply_policy(DEFAULT_INSTANCE_ID).await {
        eprintln!("[POLICY_APPLY_FAILED] instance={DEFAULT_INSTANCE_ID}: {e}");
    }
}

async fn aggregate_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let vpn = state.vpn_status().await.ok();
    let instances = state.instances.list().await.unwrap_or_default();
    let policy = load_policy().unwrap_or_default();
    Json(json!({
        "vpn": vpn,
        "instances": instances,
        "mode": policy.settings.mode.as_str(),
        "rules_count": policy.active_rules().count(),
        "kill_switch": policy.settings.kill_switch,
    }))
}

async fn vpn_status(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let status = state.vpn_status().await.map_err(err_map)?;
    Ok(Json(status))
}

async fn vpn_connect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let profile = ssc_core::active_profile().map_err(err_map)?;
    state
        .instances
        .configure_default(Some(profile.id), Some(InstanceMode::Tun), None, None)
        .await
        .map_err(err_map)?;
    match state.instances.start(DEFAULT_INSTANCE_ID).await {
        Ok(instance) => {
            state.broadcast_instance_status(&instance);
            let status = state.vpn_status().await.map_err(err_map)?;
            Ok(Json(status))
        }
        Err(e) => {
            // Race: the tunnel may already be up even if the request failed.
            if let Ok(instance) = state.instances.status(DEFAULT_INSTANCE_ID).await {
                if instance.state == ssc_service::VpnState::Connected {
                    state.broadcast_instance_status(&instance);
                    let status = state.vpn_status().await.map_err(err_map)?;
                    return Ok(Json(status));
                }
            }
            state.broadcast_error(&e);
            Err(friendly_err(e))
        }
    }
}

async fn vpn_disconnect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let instance = state
        .instances
        .stop(DEFAULT_INSTANCE_ID)
        .await
        .map_err(err_map)?;
    state.broadcast_instance_status(&instance);
    let status = state.vpn_status().await.map_err(err_map)?;
    Ok(Json(status))
}

async fn vpn_reconnect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let profile = ssc_core::active_profile().map_err(err_map)?;
    state
        .instances
        .configure_default(Some(profile.id), Some(InstanceMode::Tun), None, None)
        .await
        .map_err(err_map)?;
    match state.instances.restart(DEFAULT_INSTANCE_ID).await {
        Ok(instance) => {
            state.broadcast_instance_status(&instance);
            let status = state.vpn_status().await.map_err(err_map)?;
            Ok(Json(status))
        }
        Err(e) => {
            if let Ok(instance) = state.instances.status(DEFAULT_INSTANCE_ID).await {
                if instance.state == ssc_service::VpnState::Connected {
                    state.broadcast_instance_status(&instance);
                    let status = state.vpn_status().await.map_err(err_map)?;
                    return Ok(Json(status));
                }
            }
            state.broadcast_error(&e);
            Err(friendly_err(e))
        }
    }
}

async fn get_policy() -> impl IntoResponse {
    let snap = load_policy().unwrap_or_default();
    Json(snap)
}

#[derive(Debug, Deserialize)]
struct PolicyPut {
    mode: Option<String>,
    kill_switch: Option<bool>,
    auto_reconnect: Option<bool>,
    launch_at_login: Option<bool>,
    connect_automatically: Option<bool>,
    settings: Option<Settings>,
}

async fn put_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<PolicyPut>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let mut snap = load_policy().map_err(|e| err_map(e.to_string()))?;
    if let Some(settings) = body.settings {
        snap.settings = settings;
    }
    if let Some(mode) = body.mode {
        snap.settings.mode =
            PolicyMode::parse(&mode).ok_or_else(|| err_map("invalid mode".into()))?;
    }
    if let Some(ks) = body.kill_switch {
        snap.settings.kill_switch = ks;
    }
    if let Some(ar) = body.auto_reconnect {
        snap.settings.auto_reconnect = ar;
    }
    if let Some(v) = body.launch_at_login {
        snap.settings.launch_at_login = v;
    }
    if let Some(v) = body.connect_automatically {
        snap.settings.connect_automatically = v;
    }
    save_policy(&snap).map_err(|e| err_map(e.to_string()))?;
    let port = snap.settings.api_port;
    let _ = ssc_service::launch_agent_sync(snap.settings.launch_at_login, port);
    apply_default_policy(&state).await;
    state.broadcast_policy_changed();
    Ok(Json(json!({ "applied": true, "policy": snap })))
}

async fn list_rules() -> impl IntoResponse {
    let snap = load_policy().unwrap_or_default();
    Json(snap.rules)
}

async fn list_groups() -> impl IntoResponse {
    let snap = load_policy().unwrap_or_default();
    Json(snap.groups)
}

#[derive(Debug, Deserialize)]
struct NewGroup {
    name: String,
    enabled: Option<bool>,
}

async fn create_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<NewGroup>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let mut g = add_group(&body.name).map_err(|e| err_map(e.to_string()))?;
    if let Some(false) = body.enabled {
        g = update_group(
            &g.id,
            GroupPatch {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .map_err(|e| err_map(e.to_string()))?;
    }
    apply_default_policy(&state).await;
    state.broadcast_policy_changed();
    Ok((
        StatusCode::CREATED,
        Json(json!({ "applied": true, "group": g })),
    ))
}

#[derive(Debug, Deserialize)]
struct GroupUpdate {
    name: Option<String>,
    enabled: Option<bool>,
}

async fn patch_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<GroupUpdate>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let g = update_group(
        &id,
        GroupPatch {
            name: body.name,
            enabled: body.enabled,
        },
    )
    .map_err(|e| err_map(e.to_string()))?;
    apply_default_policy(&state).await;
    state.broadcast_policy_changed();
    Ok(Json(json!({ "applied": true, "group": g })))
}

#[derive(Debug, Deserialize)]
struct DeleteGroupQuery {
    /// When true, delete rules in the group; otherwise ungroup them.
    #[serde(default)]
    delete_rules: bool,
}

async fn remove_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<DeleteGroupQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    delete_group(&id, q.delete_rules).map_err(|e| err_map(e.to_string()))?;
    apply_default_policy(&state).await;
    state.broadcast_policy_changed();
    Ok(Json(json!({ "ok": true, "applied": true })))
}

#[derive(Debug, Deserialize)]
struct NewRule {
    kind: String,
    value: String,
    action: String,
    enabled: Option<bool>,
    group_id: Option<String>,
}

async fn create_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<NewRule>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let kind = MatchKind::parse(&body.kind).ok_or_else(|| err_map("invalid kind".into()))?;
    let action = Action::parse(&body.action).ok_or_else(|| err_map("invalid action".into()))?;
    let mut rule = add_rule_in_group(kind, &body.value, action, body.group_id.as_deref())
        .map_err(|e| err_map(e.to_string()))?;
    if let Some(en) = body.enabled {
        if !en {
            rule = update_rule(
                &rule.id,
                RulePatch {
                    enabled: Some(false),
                    ..Default::default()
                },
            )
            .map_err(|e| err_map(e.to_string()))?;
        }
    }
    eprintln!(
        "[RULE_ADDED] {} {} {} group={}",
        rule.kind.as_str(),
        rule.value,
        rule.action.as_str(),
        rule.group_id.as_deref().unwrap_or("-")
    );
    apply_default_policy(&state).await;
    state.broadcast_policy_changed();
    Ok((
        StatusCode::CREATED,
        Json(json!({ "applied": true, "rule": rule })),
    ))
}

#[derive(Debug, Deserialize)]
struct RuleUpdate {
    kind: Option<String>,
    value: Option<String>,
    action: Option<String>,
    enabled: Option<bool>,
    group_id: Option<String>,
}

async fn patch_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<RuleUpdate>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let patch = RulePatch {
        kind: body.kind.as_deref().and_then(MatchKind::parse),
        value: body.value,
        action: body.action.as_deref().and_then(Action::parse),
        enabled: body.enabled,
        group_id: body.group_id,
    };
    let rule = update_rule(&id, patch).map_err(|e| err_map(e.to_string()))?;
    apply_default_policy(&state).await;
    state.broadcast_policy_changed();
    Ok(Json(json!({ "applied": true, "rule": rule })))
}

async fn remove_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    delete_rule(&id).map_err(|e| err_map(e.to_string()))?;
    eprintln!("[RULE_REMOVED] {id}");
    apply_default_policy(&state).await;
    state.broadcast_policy_changed();
    Ok(Json(json!({ "ok": true, "applied": true })))
}

async fn get_traffic(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.traffic.poll_clash();
    Json(state.traffic.snapshot())
}

async fn list_profiles() -> impl IntoResponse {
    let file = ssc_core::list_profiles().unwrap_or_default();
    let list: Vec<Value> = file
        .profiles
        .iter()
        .map(|p| {
            let host = if !p.server.is_empty() {
                p.server.clone()
            } else {
                ssc_core::server_of(p)
            };
            json!({
                "id": p.id,
                "name": p.name,
                "protocol": p.protocol,
                "server": host,
                "active": file.active_id.as_deref() == Some(p.id.as_str()),
                "created_at_ms": p.created_at_ms,
            })
        })
        .collect();
    Json(json!({ "profiles": list, "active_id": file.active_id }))
}

#[derive(Debug, Deserialize)]
struct NewProfile {
    /// Share URI — accepted once, never returned.
    uri: String,
    name: Option<String>,
}

async fn create_profile(
    headers: HeaderMap,
    Json(body): Json<NewProfile>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let mut p = ssc_core::add_profile(&body.uri).map_err(err_map)?;
    if let Some(name) = body.name {
        // rename via reload
        let mut file = ssc_core::load_profiles().map_err(err_map)?;
        if let Some(existing) = file.profiles.iter_mut().find(|x| x.id == p.id) {
            existing.name = name.clone();
            p.name = name;
        }
        ssc_core::save_profiles(&file).map_err(err_map)?;
    }
    let host = if !p.server.is_empty() {
        p.server.clone()
    } else {
        ssc_core::server_of(&p)
    };
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": p.id,
            "name": p.name,
            "protocol": p.protocol,
            "server": host,
        })),
    ))
}

#[derive(Debug, Deserialize)]
struct ProfileUpdate {
    name: Option<String>,
    active: Option<bool>,
}

async fn update_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ProfileUpdate>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    if body.active == Some(true) {
        // Switch profile: disconnect → activate → connect with that profile.
        if let Ok(current) = state.instances.status(DEFAULT_INSTANCE_ID).await {
            if current.state == ssc_service::VpnState::Connected {
                let _ = state.instances.stop(DEFAULT_INSTANCE_ID).await;
            }
        }
        let p = ssc_core::set_active(&id).map_err(err_map)?;
        if let Err(e) = state
            .instances
            .configure_default(Some(p.id.clone()), Some(InstanceMode::Tun), None, None)
            .await
        {
            state.broadcast_error(&e);
            return Err(friendly_err(e));
        }
        match state.instances.start(DEFAULT_INSTANCE_ID).await {
            Ok(instance) => {
                state.broadcast_instance_status(&instance);
                state.broadcast_policy_changed();
                let status = state.vpn_status().await.map_err(err_map)?;
                return Ok(Json(json!({
                    "id": p.id,
                    "name": p.name,
                    "active": true,
                    "vpn": status,
                    "applied": true,
                })));
            }
            Err(e) => {
                state.broadcast_error(&e);
                return Err(friendly_err(e));
            }
        }
    }
    if let Some(name) = body.name {
        let mut file = ssc_core::load_profiles().map_err(err_map)?;
        let p = file
            .profiles
            .iter_mut()
            .find(|p| p.id == id || p.name == id)
            .ok_or_else(|| err_map(format!("profile not found: {id}")))?;
        p.name = name;
        let out = json!({ "id": p.id, "name": p.name });
        ssc_core::save_profiles(&file).map_err(err_map)?;
        return Ok(Json(out));
    }
    Err(err_map("nothing to update".into()))
}

async fn remove_profile(
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    ssc_core::remove_profile(&id).map_err(err_map)?;
    Ok(Json(json!({ "ok": true })))
}

async fn diagnostics() -> Response {
    // Never block the async runtime on Keychain / TCP / ifconfig.
    match tokio::task::spawn_blocking(run_diagnostics).await {
        Ok(report) => Json(report).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("diagnostics failed: {e}") })),
        )
            .into_response(),
    }
}

async fn policy_export() -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let json = export_policy().map_err(|e| err_map(e.to_string()))?;
    Ok(Json(
        json!({ "policy": serde_json::from_str::<Value>(&json).unwrap_or(Value::Null), "raw": json }),
    ))
}

#[derive(Debug, Deserialize)]
struct PolicyImportBody {
    /// Full policy JSON document (settings + rules).
    #[serde(default)]
    policy: Option<Value>,
    /// Or raw JSON string.
    #[serde(default)]
    raw: Option<String>,
}

async fn policy_import(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<PolicyImportBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let text = if let Some(raw) = body.raw {
        raw
    } else if let Some(policy) = body.policy {
        serde_json::to_string(&policy).map_err(|e| err_map(e.to_string()))?
    } else {
        return Err(err_map("provide policy or raw".into()));
    };
    let snap = import_policy(&text).map_err(|e| err_map(e.to_string()))?;
    apply_default_policy(&state).await;
    state.broadcast_policy_changed();
    Ok(Json(json!({ "applied": true, "policy": snap })))
}

#[derive(Debug, Deserialize)]
struct ProbeQuery {
    dest: String,
}

async fn route_probe(
    axum::extract::Query(q): axum::extract::Query<ProbeQuery>,
) -> impl IntoResponse {
    Json(probe_destination(&q.dest))
}

#[derive(Debug, Deserialize)]
struct ProbeBody {
    dest: String,
}

async fn route_probe_post(Json(body): Json<ProbeBody>) -> impl IntoResponse {
    Json(probe_destination(&body.dest))
}

// ---------------------------------------------------------------------------
// Independent VPN instances
// ---------------------------------------------------------------------------

fn instance_err(e: String) -> (StatusCode, Json<Value>) {
    let lower = e.to_lowercase();
    let code = if lower.contains("not found") {
        StatusCode::NOT_FOUND
    } else if lower.contains("already exists") {
        StatusCode::CONFLICT
    } else {
        StatusCode::BAD_REQUEST
    };
    (code, Json(json!({ "error": e })))
}

async fn list_instances(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let instances = state.instances.list().await.map_err(instance_err)?;
    Ok(Json(json!({ "instances": instances })))
}

async fn create_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateInstanceRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let view = state.instances.create(body).await.map_err(instance_err)?;
    state.broadcast_instance_status(&view);
    Ok((StatusCode::CREATED, Json(view)))
}

async fn get_instance(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let view = state.instances.status(&id).await.map_err(instance_err)?;
    Ok(Json(view))
}

async fn update_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateInstanceRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let view = state
        .instances
        .update(&id, body)
        .await
        .map_err(instance_err)?;
    state.broadcast_instance_status(&view);
    Ok(Json(view))
}

async fn remove_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    state.instances.remove(&id).await.map_err(instance_err)?;
    Ok(Json(json!({ "ok": true })))
}

async fn start_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    match state.instances.start(&id).await {
        Ok(view) => {
            state.broadcast_instance_status(&view);
            Ok(Json(view))
        }
        Err(e) => {
            state.broadcast_error(&e);
            Err(instance_err(e))
        }
    }
}

async fn stop_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let view = state.instances.stop(&id).await.map_err(instance_err)?;
    state.broadcast_instance_status(&view);
    Ok(Json(view))
}

async fn restart_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    match state.instances.restart(&id).await {
        Ok(view) => {
            state.broadcast_instance_status(&view);
            Ok(Json(view))
        }
        Err(e) => {
            state.broadcast_error(&e);
            Err(instance_err(e))
        }
    }
}

async fn get_instance_policy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let policy = state.instances.policy(&id).await.map_err(instance_err)?;
    Ok(Json(policy))
}

async fn put_instance_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(policy): Json<ssc_policy::PolicySnapshot>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    localhost_only(&headers)?;
    let view = state
        .instances
        .set_policy(&id, &policy)
        .await
        .map_err(instance_err)?;
    state.broadcast_instance_status(&view);
    state.broadcast_policy_changed();
    Ok(Json(
        json!({ "applied": true, "instance": view, "policy": policy }),
    ))
}

async fn instance_traffic(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let snapshot = state
        .instances
        .poll_traffic(&id)
        .await
        .map_err(instance_err)?;
    Ok(Json(snapshot))
}

#[derive(Debug, Deserialize)]
struct LogQuery {
    #[serde(default = "default_log_bytes")]
    max_bytes: usize,
}

fn default_log_bytes() -> usize {
    64 * 1024
}

async fn instance_logs(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<LogQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let max = q.max_bytes.clamp(1, 1024 * 1024);
    let text = state
        .instances
        .log_tail(&id, max)
        .await
        .map_err(instance_err)?;
    Ok(Json(json!({ "id": id, "log": text })))
}

#[cfg(test)]
mod tests {
    use super::is_local_origin;

    #[test]
    fn local_origins() {
        for ok in [
            "http://127.0.0.1:8765",
            "http://localhost:8765",
            "http://ssc.lan",
            "http://ssc.lan:8765",
            "null",
        ] {
            assert!(is_local_origin(ok), "{ok}");
        }
        for bad in [
            "http://localhost.evil.com",
            "http://ssc.lan.evil.com",
            "https://evil.com",
            "http://127.0.0.1.nip.io",
        ] {
            assert!(!is_local_origin(bad), "{bad}");
        }
    }
}
