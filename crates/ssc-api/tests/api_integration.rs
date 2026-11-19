//! API integration tests (localhost only; no live VPN required).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ssc_api::{app_router, AppState};
use ssc_service::{ProfileResolver, ResolvedProfile, VpnInstanceManager};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};
use tower::ServiceExt;

async fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    LOCK.lock().await
}

fn temp_config_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ssc-api-it-{}-{}",
        std::process::id(),
        uuid_simple()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn json_req(
    app: axum::Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("origin", "http://127.0.0.1:8765");
    let req = if let Some(b) = body {
        builder
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, v)
}

#[tokio::test]
async fn status_and_rules_crud() {
    let _guard = env_lock().await;
    let dir = temp_config_dir();
    std::env::set_var("SSC_CONFIG_DIR", &dir);

    let state = Arc::new(AppState::new());
    let app = app_router(state);

    let (st, body) = json_req(app.clone(), "GET", "/api/v1/status", None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.get("vpn").is_some());

    let (st, body) = json_req(
        app.clone(),
        "POST",
        "/api/v1/rules",
        Some(serde_json::json!({
            "kind": "domain",
            "value": "google.com",
            "action": "vpn"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    assert_eq!(body["applied"], true);
    let id = body["rule"]["id"].as_str().expect("rule id").to_string();

    let (st, rules) = json_req(app.clone(), "GET", "/api/v1/rules", None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(rules.as_array().unwrap().iter().any(|r| r["id"] == id));

    let (st, body) = json_req(
        app.clone(),
        "PUT",
        &format!("/api/v1/rules/{id}"),
        Some(serde_json::json!({ "action": "direct" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["applied"], true);
    assert_eq!(body["rule"]["action"], "direct");

    let (st, body) = json_req(
        app.clone(),
        "PUT",
        "/api/v1/policy",
        Some(serde_json::json!({ "mode": "selective" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["applied"], true);

    let (st, probe) = json_req(
        app.clone(),
        "POST",
        "/api/v1/route/probe",
        Some(serde_json::json!({ "dest": "127.0.0.1" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(probe.get("action").is_some());

    let (st, traffic) = json_req(app.clone(), "GET", "/api/v1/traffic", None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(traffic.get("connections").is_some());

    let (st, profiles) = json_req(app.clone(), "GET", "/api/v1/profiles", None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(profiles.get("profiles").is_some());

    let (st, body) = json_req(app.clone(), "DELETE", &format!("/api/v1/rules/{id}"), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["applied"], true);

    let (st, _) = json_req(app.clone(), "GET", "/api/v1/diagnostics", None).await;
    assert_eq!(st, StatusCode::OK);

    let (st, err) = json_req(
        app,
        "POST",
        "/api/v1/vpn/connect",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(err.get("error").is_some());

    let _ = std::fs::remove_dir_all(&dir);
    std::env::remove_var("SSC_CONFIG_DIR");
}

#[tokio::test]
async fn instances_crud_and_isolation() {
    let _guard = env_lock().await;
    let dir = temp_config_dir();
    std::env::set_var("SSC_CONFIG_DIR", &dir);

    let app = app_router(Arc::new(AppState::new()));

    let (st, body) = json_req(
        app.clone(),
        "POST",
        "/api/v1/instances",
        Some(serde_json::json!({
            "id": "work",
            "name": "Work VPN",
            "profile_id": "p1",
            "mode": "proxy",
            "proxy_kind": "mixed"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{body}");
    assert_eq!(body["id"], "work");
    assert_eq!(body["state"], "disconnected");
    assert_eq!(body["mode"], "proxy");

    // Duplicate ids are rejected.
    let (st, _) = json_req(
        app.clone(),
        "POST",
        "/api/v1/instances",
        Some(serde_json::json!({ "id": "work", "name": "dup", "mode": "proxy" })),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);

    let (st, list) = json_req(app.clone(), "GET", "/api/v1/instances", None).await;
    assert_eq!(st, StatusCode::OK);
    let instances = list["instances"].as_array().unwrap();
    assert!(instances.iter().any(|v| v["id"] == "work"));
    assert!(instances.iter().any(|v| v["id"] == "default"));

    let (st, body) = json_req(
        app.clone(),
        "PUT",
        "/api/v1/instances/work",
        Some(serde_json::json!({
            "name": "Work VPN 2",
            "listen_port": 19555
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "Work VPN 2");

    let (st, policy) = json_req(app.clone(), "GET", "/api/v1/instances/work/policy", None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(policy.get("settings").is_some());

    let (st, body) = json_req(
        app.clone(),
        "PUT",
        "/api/v1/instances/work/policy",
        Some(serde_json::json!({
            "settings": { "mode": "full", "auto_reconnect": false },
            "groups": [],
            "rules": []
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    assert_eq!(body["applied"], true);
    let (_, policy) = json_req(app.clone(), "GET", "/api/v1/instances/work/policy", None).await;
    assert_eq!(policy["settings"]["mode"], "full");

    // The default instance is permanent.
    let (st, _) = json_req(app.clone(), "DELETE", "/api/v1/instances/default", None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    let (st, missing) = json_req(app.clone(), "GET", "/api/v1/instances/nope", None).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{missing}");

    let (st, _) = json_req(app.clone(), "DELETE", "/api/v1/instances/work", None).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = json_req(app, "GET", "/api/v1/instances/work", None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let _ = std::fs::remove_dir_all(&dir);
    std::env::remove_var("SSC_CONFIG_DIR");
}

#[tokio::test]
async fn rejects_remote_origin() {
    let _guard = env_lock().await;
    let dir = temp_config_dir();
    std::env::set_var("SSC_CONFIG_DIR", &dir);
    let app = app_router(Arc::new(AppState::new()));
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/rules")
        .header("content-type", "application/json")
        .header("origin", "https://evil.example")
        .body(Body::from(
            serde_json::json!({"kind":"domain","value":"x.com","action":"vpn"}).to_string(),
        ))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let _ = std::fs::remove_dir_all(&dir);
    std::env::remove_var("SSC_CONFIG_DIR");
}

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_string()
}

// ---------------------------------------------------------------------------
// Fake backend / resolver so we can prove concurrent sessions are tracked
// through the API without a real sing-box binary or root privileges.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct FakeBackend {
    inner: Arc<std::sync::Mutex<FakeInner>>,
}

struct FakeInner {
    next_pid: u32,
    procs: std::collections::HashSet<u32>,
}

impl FakeBackend {
    fn new() -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(FakeInner {
                next_pid: 10_000,
                procs: std::collections::HashSet::new(),
            })),
        }
    }

    fn live_count(&self) -> usize {
        self.inner.lock().unwrap().procs.len()
    }
}

impl ssc_runtime::InstanceProcessBackend for FakeBackend {
    fn spawn(
        &self,
        paths: &ssc_runtime::InstancePaths,
        _config: &Path,
        _profile_id: &str,
        _mode: ssc_runtime::InstanceMode,
        _proxy_port: Option<u16>,
        _clash_api_port: u16,
    ) -> Result<ssc_runtime::RunningProcess, String> {
        let mut g = self.inner.lock().unwrap();
        g.next_pid += 1;
        let pid = g.next_pid;
        g.procs.insert(pid);
        Ok(ssc_runtime::RunningProcess {
            pid,
            instance_id: paths.id.clone(),
            config_path: paths.config.clone(),
        })
    }

    fn stop(&self, running: &ssc_runtime::RunningProcess) -> Result<(), String> {
        self.inner.lock().unwrap().procs.remove(&running.pid);
        Ok(())
    }

    fn is_alive(&self, running: &ssc_runtime::RunningProcess) -> bool {
        self.inner.lock().unwrap().procs.contains(&running.pid)
    }

    fn health(
        &self,
        running: &ssc_runtime::RunningProcess,
        _mode: ssc_runtime::InstanceMode,
        _proxy_port: Option<u16>,
        _clash_api_port: u16,
    ) -> ssc_runtime::InstanceHealth {
        let alive = self.is_alive(running);
        ssc_runtime::InstanceHealth {
            process_alive: alive,
            proxy_reachable: alive,
            admin_reachable: alive,
        }
    }
}

struct FakeResolver;

impl ProfileResolver for FakeResolver {
    fn resolve(&self, id_or_name: &str) -> Result<ResolvedProfile, String> {
        Ok(ResolvedProfile {
            id: id_or_name.to_string(),
            name: format!("Profile {id_or_name}"),
            server: "127.0.0.1".into(),
            server_port: 1,
            uri: format!(
                "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:1?security=none#{id_or_name}"
            ),
        })
    }

    fn active(&self) -> Result<ResolvedProfile, String> {
        self.resolve("active")
    }
}

#[tokio::test]
async fn parallel_sessions_tracked_via_api() {
    let _guard = env_lock().await;
    let dir = temp_config_dir();
    std::env::set_var("SSC_CONFIG_DIR", &dir);

    let backend = Arc::new(FakeBackend::new());
    let manager =
        VpnInstanceManager::with_backend_and_resolver(backend.clone(), Arc::new(FakeResolver));
    let state = Arc::new(AppState::with_manager(manager.clone()));
    let app = app_router(state.clone());

    // Split one VPN connection into three independent sessions.
    for id in ["work", "personal", "streaming"] {
        let (st, body) = json_req(
            app.clone(),
            "POST",
            "/api/v1/instances",
            Some(serde_json::json!({
                "id": id,
                "name": id,
                "profile_id": id,
                "mode": "proxy",
                "proxy_kind": "mixed"
            })),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "{body}");
    }

    // Start each session independently.
    for id in ["work", "personal", "streaming"] {
        let (st, body) = json_req(
            app.clone(),
            "POST",
            &format!("/api/v1/instances/{id}/start"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(body["state"], "connected", "{body}");
        assert!(body["endpoint"].as_str().is_some(), "{body}");
        assert!(body["proxy_port"].as_u64().is_some(), "{body}");
    }

    // Track every session through the API list endpoint.
    let (st, list) = json_req(app.clone(), "GET", "/api/v1/instances", None).await;
    assert_eq!(st, StatusCode::OK);
    let instances = list["instances"].as_array().unwrap();
    let proxies: Vec<_> = instances.iter().filter(|v| v["id"] != "default").collect();
    assert_eq!(proxies.len(), 3);

    let mut ports = std::collections::HashSet::new();
    let mut pids = std::collections::HashSet::new();
    for v in &proxies {
        assert_eq!(v["state"], "connected");
        let port = v["proxy_port"].as_u64().expect("proxy_port");
        let pid = v["pid"].as_u64().expect("pid");
        assert!(ports.insert(port), "duplicate proxy port {port}");
        assert!(pids.insert(pid), "duplicate pid {pid}");
    }
    assert_eq!(backend.live_count(), 3);

    // Per-session traffic + aggregate status.
    let (st, traffic) = json_req(app.clone(), "GET", "/api/v1/instances/work/traffic", None).await;
    assert_eq!(st, StatusCode::OK, "{traffic}");
    assert!(traffic.get("bytes_sent").is_some());

    let (st, agg) = json_req(app.clone(), "GET", "/api/v1/status", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(agg["instances"].as_array().unwrap().len(), 4); // default + 3

    // WebSocket initial state carries every session.
    let init: serde_json::Value = serde_json::from_str(&state.initial_state_json().await).unwrap();
    let ids: Vec<&str> = init["instances"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].as_str().unwrap())
        .collect();
    for id in ["work", "personal", "streaming"] {
        assert!(ids.contains(&id), "initial state missing {id}");
    }

    // Stopping one session must leave the other two connected.
    let (st, body) = json_req(app.clone(), "POST", "/api/v1/instances/personal/stop", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["state"], "disconnected");

    let (st, list) = json_req(app.clone(), "GET", "/api/v1/instances", None).await;
    assert_eq!(st, StatusCode::OK);
    for v in list["instances"].as_array().unwrap() {
        match v["id"].as_str().unwrap() {
            "personal" => assert_eq!(v["state"], "disconnected"),
            "default" => {}
            _ => assert_eq!(v["state"], "connected", "{} was affected", v["id"]),
        }
    }
    assert_eq!(backend.live_count(), 2);

    manager.shutdown().await;
    assert_eq!(backend.live_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
    std::env::remove_var("SSC_CONFIG_DIR");
}
