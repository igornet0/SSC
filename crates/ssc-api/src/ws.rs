//! WebSocket live updates.

use crate::state::AppState;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsEvent {
    VpnStatus {
        state: String,
    },
    PolicyChanged {
        applied: bool,
    },
    Connection {
        domain: Option<String>,
        route: String,
    },
    Traffic {
        bytes_sent: u64,
        bytes_received: u64,
    },
    Diagnostics {
        ok: bool,
    },
    Error {
        message: String,
    },
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.events.subscribe();

    // Full initial state so UI does not depend on prior event order.
    let init = state.initial_state_json();
    let _ = sender.send(Message::Text(init.into())).await;

    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender
                .send(Message::Text(msg.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => { recv_task.abort(); }
        _ = &mut recv_task => { send_task.abort(); }
    }
}
