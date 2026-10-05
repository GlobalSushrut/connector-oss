//! UI-RPC — WebSocket JSON-RPC 2.0 gateway for the Dashboard UI.
//!
//! The Dashboard connects once via WebSocket; all subsequent UI operations
//! are multiplexed over that single connection as JSON-RPC 2.0 messages.
//!
//! Benefits over raw REST from the browser:
//!   - No CORS preflight on every call
//!   - Server can push unsolicited events (boot progress, agent alerts,
//!     audit entries) without the UI polling
//!   - All UI traffic is stamped source="dashboard-ui" in audit logs
//!   - Single auth handshake on WS upgrade — not per-request
//!
//! Protocol:
//!   Client → Server:  { "jsonrpc":"2.0", "id":1, "method":"agents.list",  "params":{} }
//!   Server → Client:  { "jsonrpc":"2.0", "id":1, "result": {...} }
//!   Server → Client:  { "jsonrpc":"2.0", "id":null, "method":"push.boot_progress", "params":{...} }
//!
//! Auth: Bearer token in `Sec-WebSocket-Protocol` header on upgrade:
//!   `Sec-WebSocket-Protocol: connector-rpc, bearer.<token>`
//!   The token is verified once; the session inherits its permissions.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::{Claims, PlatformRole};
use crate::state::SharedState;

// ── JSON-RPC 2.0 types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    pub const PARSE_ERROR: i32      = -32700;
    pub const INVALID_REQUEST: i32  = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32   = -32602;
    pub const INTERNAL: i32         = -32603;
    pub const UNAUTHORIZED: i32     = -32001;
    pub const RATE_LIMITED: i32     = -32002;
    pub const FORBIDDEN: i32        = -32003;

    pub fn parse_error() -> Self {
        Self { code: Self::PARSE_ERROR, message: "Parse error".into(), data: None }
    }
    pub fn method_not_found(m: &str) -> Self {
        Self { code: Self::METHOD_NOT_FOUND, message: format!("Method not found: {}", m), data: None }
    }
    pub fn internal(msg: &str) -> Self {
        Self { code: Self::INTERNAL, message: msg.into(), data: None }
    }
    pub fn unauthorized() -> Self {
        Self { code: Self::UNAUTHORIZED, message: "Authentication required".into(), data: None }
    }
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            code: Self::FORBIDDEN,
            message: msg.into(),
            data: None,
        }
    }
}

impl RpcResponse {
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Self { jsonrpc: "2.0", id, result: Some(result), error: None }
    }
    pub fn err(id: Option<Value>, error: RpcError) -> Self {
        Self { jsonrpc: "2.0", id, result: None, error: Some(error) }
    }
    pub fn push(method: &'static str, params: Value) -> Self {
        Self { jsonrpc: "2.0", id: None, result: Some(serde_json::json!({ "method": method, "params": params })), error: None }
    }
}

// ── Session context ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct UiSession {
    pub subject: String,
    pub session_id: String,
    pub connected_at_ms: u64,
    pub is_dev: bool,
    pub role: PlatformRole,
    pub permissions: Vec<String>,
}

impl UiSession {
    fn new_dev() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            subject: "dev".into(),
            session_id: uuid::Uuid::new_v4().to_string(),
            connected_at_ms: now,
            is_dev: true,
            role: PlatformRole::Operator,
            permissions: PlatformRole::Operator.permissions(),
        }
    }

    fn from_claims(claims: Claims) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let role = PlatformRole::from_str(&claims.role);
        Self {
            subject: claims.sub,
            session_id: uuid::Uuid::new_v4().to_string(),
            connected_at_ms: now,
            is_dev: false,
            role,
            permissions: claims.permissions,
        }
    }
}

// ── Method dispatch ───────────────────────────────────────────────────────────

async fn dispatch(
    method: &str,
    params: Value,
    state: &SharedState,
    session: &UiSession,
) -> Result<Value, RpcError> {
    if !crate::auth::rbac::rpc_method_allowed(session.role, method, session.is_dev) {
        return Err(RpcError::forbidden(format!(
            "UI-RPC method {} not allowed for role {}",
            method,
            session.role.to_str()
        )));
    }

    match method {
        // ── System ────────────────────────────────────────────────────────
        "system.ping" => Ok(serde_json::json!({
            "pong": true,
            "session_id": session.session_id,
            "subject": session.subject,
        })),

        "system.boot_progress" => {
            use std::sync::atomic::Ordering;
            use crate::boot::{BOOT_STAGES_COMPLETE, BOOT_STAGE_COUNT, BOOT_STAGE_NAMES, NODE_READY, BOOT_START_MS};
            let bits = BOOT_STAGES_COMPLETE.load(Ordering::SeqCst) as u32;
            let complete = bits.count_ones() as u16;
            let ready = NODE_READY.load(Ordering::SeqCst);
            let start_ms = BOOT_START_MS.load(Ordering::SeqCst);
            let elapsed_ms = if start_ms > 0 {
                SystemTime::now().duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64).unwrap_or(0)
                    .saturating_sub(start_ms)
            } else { 0 };
            let stages: Vec<Value> = (0..BOOT_STAGE_COUNT).map(|i| {
                serde_json::json!({
                    "index": i,
                    "name": BOOT_STAGE_NAMES.get(i as usize).unwrap_or(&""),
                    "complete": (bits & (1 << i)) != 0,
                })
            }).collect();
            Ok(serde_json::json!({
                "stages_complete": complete,
                "stages_total": BOOT_STAGE_COUNT,
                "progress_pct": (complete as u16 * 100) / BOOT_STAGE_COUNT,
                "ready": ready,
                "boot_time_ms": elapsed_ms,
                "stages": stages,
            }))
        }

        "system.dns" => {
            let entries = crate::internal_dns::dump_json();
            Ok(serde_json::to_value(entries).unwrap_or_default())
        }

        // ── Agents ────────────────────────────────────────────────────────
        "agents.list" => {
            let kernel = state.kernel.lock()
                .map_err(|_| RpcError::internal("kernel lock failed"))?;
            let agents: Vec<Value> = kernel.all_agents().iter().map(|a| serde_json::json!({
                "agent_pid": a.agent_pid,
                "name": a.agent_name,
                "namespace": a.namespace,
                "status": format!("{:?}", a.status),
            })).collect();
            let count = agents.len();
            Ok(serde_json::json!({ "agents": agents, "count": count }))
        }

        "agents.get" => {
            let pid = params.get("agent_pid").and_then(|v| v.as_str())
                .ok_or_else(|| RpcError { code: RpcError::INVALID_PARAMS, message: "agent_pid required".into(), data: None })?;
            let kernel = state.kernel.lock()
                .map_err(|_| RpcError::internal("kernel lock failed"))?;
            match kernel.get_agent(pid) {
                Some(a) => Ok(serde_json::json!({
                    "agent_pid": a.agent_pid,
                    "name": a.agent_name,
                    "namespace": a.namespace,
                    "status": format!("{:?}", a.status),
                    "priority": a.priority,
                    "total_tokens_consumed": a.total_tokens_consumed,
                    "total_cost_usd": a.total_cost_usd,
                })),
                None => Err(RpcError { code: RpcError::INVALID_PARAMS, message: format!("agent not found: {}", pid), data: None }),
            }
        }

        // ── Health ────────────────────────────────────────────────────────
        "health.status" => {
            use crate::boot::{boot_progress, NODE_READY};
            use std::sync::atomic::Ordering;
            let progress = boot_progress();
            let ready = NODE_READY.load(Ordering::SeqCst);
            Ok(serde_json::json!({
                "live": true,
                "ready": ready,
                "boot_progress_pct": progress,
            }))
        }

        // ── Audit ─────────────────────────────────────────────────────────────
        "audit.recent" => {
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
            let kernel = state.kernel.lock()
                .map_err(|_| RpcError::internal("kernel lock failed"))?;
            let entries: Vec<Value> = kernel.audit_log().iter().rev().take(limit).map(|e| serde_json::json!({
                "id": e.audit_id,
                "operation": format!("{:?}", e.operation),
                "agent_pid": e.agent_pid,
                "timestamp": e.timestamp,
                "outcome": format!("{:?}", e.outcome),
                "target": e.target,
            })).collect();
            let count = entries.len();
            Ok(serde_json::json!({ "entries": entries, "count": count }))
        }

        // ── Metrics ───────────────────────────────────────────────────────
        "metrics.summary" => {
            let uptime = crate::boot::uptime_secs();
            Ok(serde_json::json!({
                "uptime_secs": uptime,
                "source": "dashboard-ui",
                "session_id": session.session_id,
            }))
        }

        _ => Err(RpcError::method_not_found(method)),
    }
}

// ── WebSocket handler ─────────────────────────────────────────────────────────

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Extract and verify token from Sec-WebSocket-Protocol header
    // Format: "connector-rpc, bearer.<token>"
    let dev_mode = crate::services::runtime_control::dev_auth_bypass_allowed();

    let proto_header = headers
        .get("sec-websocket-protocol")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let token = proto_header
        .split(',')
        .map(|s| s.trim())
        .find(|s| s.starts_with("bearer."))
        .and_then(|s| s.strip_prefix("bearer."));

    let session_result = match token {
        Some(t) => match crate::auth::verify_token(t) {
            Ok(claims) => {
                if crate::auth::is_access_jti_revoked(&claims.jti) {
                    Err(StatusCode::UNAUTHORIZED)
                } else {
                    Ok(UiSession::from_claims(claims))
                }
            }
            Err(_) => Err(StatusCode::UNAUTHORIZED),
        },
        None if dev_mode && !crate::connector_profile::is_productionish_env() => {
            Ok(UiSession::new_dev())
        }
        None => Err(StatusCode::UNAUTHORIZED),
    };

    let session = match session_result {
        Ok(s) => s,
        Err(status) => return status.into_response(),
    };

    tracing::info!(
        subject = %session.subject,
        session_id = %session.session_id,
        "UI-RPC WebSocket connected"
    );

    // Negotiate sub-protocol header in response
    ws.protocols(["connector-rpc"])
        .on_upgrade(move |socket| handle_socket(socket, state, session))
}

async fn handle_socket(socket: WebSocket, state: SharedState, session: UiSession) {
    let (mut sender, mut receiver) = socket.split();

    // Send welcome push immediately on connect
    let welcome = RpcResponse::push("push.connected", serde_json::json!({
        "session_id": session.session_id,
        "subject": session.subject,
        "server_time_ms": SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
    }));
    if let Ok(txt) = serde_json::to_string(&welcome) {
        let _ = sender.send(Message::Text(txt)).await;
    }

    // Spawn a push task — sends boot progress updates every 2s until ready
    let mut push_interval = tokio::time::interval(Duration::from_secs(2));
    let (push_tx, mut push_rx) = tokio::sync::mpsc::channel::<String>(32);

    let push_task = {
        let push_tx = push_tx.clone();
        tokio::spawn(async move {
            use std::sync::atomic::Ordering;
            use crate::boot::{NODE_READY, BOOT_STAGES_COMPLETE, BOOT_STAGE_COUNT};
            loop {
                push_interval.tick().await;
                if NODE_READY.load(Ordering::SeqCst) {
                    break;
                }
                let bits = BOOT_STAGES_COMPLETE.load(Ordering::SeqCst) as u32;
                let complete = bits.count_ones() as u16;
                let msg = RpcResponse::push("push.boot_progress", serde_json::json!({
                    "stages_complete": complete,
                    "stages_total": BOOT_STAGE_COUNT,
                    "progress_pct": (complete * 100) / BOOT_STAGE_COUNT,
                    "ready": false,
                }));
                if let Ok(txt) = serde_json::to_string(&msg) {
                    if push_tx.send(txt).await.is_err() { break; }
                }
            }
        })
    };

    // Main message loop
    loop {
        tokio::select! {
            // Outbound push messages
            Some(txt) = push_rx.recv() => {
                if sender.send(Message::Text(txt)).await.is_err() { break; }
            }

            // Inbound RPC calls
            msg = receiver.next() => {
                match msg {
                    None => break,
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, "UI-RPC WS recv error");
                        break;
                    }
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(Message::Ping(d))) => {
                        let _ = sender.send(Message::Pong(d)).await;
                    }
                    Some(Ok(Message::Text(text))) => {
                        let response = handle_rpc_message(&text, state.clone(), &session).await;
                        if let Ok(txt) = serde_json::to_string(&response) {
                            if sender.send(Message::Text(txt)).await.is_err() { break; }
                        }
                    }
                    Some(Ok(Message::Binary(data))) => {
                        // Try to parse binary as UTF-8 JSON
                        if let Ok(text) = String::from_utf8(data.to_vec()) {
                            let response = handle_rpc_message(&text, state.clone(), &session).await;
                            if let Ok(txt) = serde_json::to_string(&response) {
                                if sender.send(Message::Text(txt)).await.is_err() { break; }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    push_task.abort();
    tracing::info!(
        subject = %session.subject,
        session_id = %session.session_id,
        "UI-RPC WebSocket disconnected"
    );
}

async fn handle_rpc_message(text: &str, state: SharedState, session: &UiSession) -> RpcResponse {
    let req: RpcRequest = match serde_json::from_str(text) {
        Ok(r) => r,
        Err(_) => return RpcResponse::err(None, RpcError::parse_error()),
    };

    if req.jsonrpc != "2.0" {
        return RpcResponse::err(req.id, RpcError {
            code: RpcError::INVALID_REQUEST,
            message: "jsonrpc must be \"2.0\"".into(),
            data: None,
        });
    }

    tracing::debug!(
        method = %req.method,
        subject = %session.subject,
        session_id = %session.session_id,
        source = "dashboard-ui",
        "UI-RPC call"
    );

    match dispatch(&req.method, req.params, &state, session).await {
        Ok(result) => RpcResponse::ok(req.id, result),
        Err(e) => RpcResponse::err(req.id, e),
    }
}

// ── Router builder ─────────────────────────────────────────────────────────────

pub fn build_ui_rpc_router(state: SharedState) -> Router {
    Router::new()
        .route("/ui-rpc", get(ws_handler))
        .route("/ui-rpc/health", get(|| async {
            Json(serde_json::json!({ "status": "ok", "gateway": "ui-rpc/1" }))
        }))
        .with_state(state)
}

// ── Spawn the UI-RPC listener ─────────────────────────────────────────────────

pub async fn spawn_ui_rpc(state: SharedState, addr: SocketAddr) {
    let router = build_ui_rpc_router(state);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => {
            tracing::info!(addr = %addr, "UI-RPC WebSocket gateway listening");
            crate::internal_dns::register(
                crate::internal_dns::SVC_UI_RPC,
                addr,
                "Dashboard UI WebSocket RPC gateway",
                &["ui", "websocket", "rpc", "internal"],
            );
            l
        }
        Err(e) => {
            tracing::warn!(
                addr = %addr,
                error = %e,
                "UI-RPC gateway could not bind — dashboard will use REST API"
            );
            return;
        }
    };

    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, router).await {
            tracing::error!(error = %e, "UI-RPC gateway exited unexpectedly");
        }
    });
}
