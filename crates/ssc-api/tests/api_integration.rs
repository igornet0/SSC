//! API integration tests (localhost only; no live VPN required).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ssc_api::{app_router, AppState};
use std::sync::{Arc, Mutex, OnceLock};
use tower::ServiceExt;

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
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
    let _guard = env_lock();
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
async fn rejects_remote_origin() {
    let _guard = env_lock();
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
