//! Local HTTP API bound to 127.0.0.1 only (`http://ssc.lan` via the hosts file).

mod routes;
mod state;
mod ws;

use axum::Router;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::services::ServeDir;

pub use state::AppState;

/// Default UI/API port.
pub const DEFAULT_PORT: u16 = 8765;

/// Build the axum router (API + static UI + websocket).
pub fn app_router(state: Arc<AppState>) -> Router {
    let ui_dir = ui_static_dir();
    let static_svc = ServeDir::new(&ui_dir).append_index_html_on_directories(true);

    Router::new()
        .merge(routes::api_routes())
        .route("/ws", axum::routing::get(ws::ws_handler))
        .fallback_service(static_svc)
        .with_state(state)
}

fn ui_static_dir() -> PathBuf {
    if let Ok(p) = std::env::var("SSC_UI_DIR") {
        return PathBuf::from(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest.join("../../web"),
        manifest.join("../../web/dist"),
        std::env::current_dir().unwrap_or_default().join("web"),
    ];
    for c in candidates {
        if c.join("index.html").is_file() {
            return c;
        }
    }
    manifest.join("../../web")
}

/// Bind exclusively to 127.0.0.1 and serve until Ctrl+C / signal.
pub async fn serve(port: u16) -> Result<(), String> {
    let report = ssc_service::reconcile_on_startup();
    if report.tunnel_cleared || report.kill_switch_deactivated {
        eprintln!(
            "[RECONCILE] tunnel_cleared={} kill_switch_deactivated={}",
            report.tunnel_cleared, report.kill_switch_deactivated
        );
    }

    let state = Arc::new(AppState::new());
    let poll_state = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            tick.tick().await;
            poll_state.traffic.poll_clash();
            let snap = poll_state.vpn.status();
            poll_state
                .traffic
                .set_bytes(snap.bytes_sent, snap.bytes_received);
            poll_state.broadcast_status(&snap);
        }
    });

    // Persist api_port + honor launch_at_login / connect_automatically.
    if let Ok(mut policy) = ssc_policy::load_policy() {
        if policy.settings.api_port != port {
            policy.settings.api_port = port;
            let _ = ssc_policy::save_policy(&policy);
        }
        let _ = ssc_service::launch_agent_sync(policy.settings.launch_at_login, port);
        if policy.settings.connect_automatically {
            let vpn = state.vpn;
            tokio::task::spawn_blocking(move || match vpn.connect() {
                Ok(s) => eprintln!("[AUTO_CONNECT] state={}", s.state.as_str()),
                Err(e) => eprintln!("[AUTO_CONNECT] failed: {e}"),
            });
        }
    }

    let app = app_router(state);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    eprintln!("SSC local UI listening on http://127.0.0.1:{port}");
    let domain = ssc_runtime::LOCAL_DOMAIN;
    if ssc_runtime::local_domain_configured() {
        eprintln!("SSC Web UI: http://{domain}:{port}");
    } else {
        eprintln!(
            "[UI] {domain} not in {} — enable with: sudo ssc privileges install",
            ssc_runtime::hosts_path().display()
        );
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("serve: {e}"))?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("shutting down local API…");
}

/// Blocking wrapper for CLI `ssc start`.
pub fn serve_blocking(port: u16) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(serve(port))
}
