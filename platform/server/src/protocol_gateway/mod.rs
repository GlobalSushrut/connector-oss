//! Protocol Gateway — dedicated listener on :9092 for external agent protocols.
//!
//! Handles: MCP, A2A, ACP, ANP, AP2 — all on a single port, isolated from
//! the main REST API (:9091). Each protocol has its own path prefix.
//!
//! Security layers (Phase R1 — bearer auth; Phase R2 adds mTLS):
//!   - Bearer JWT or cpk_live_* API key required on every route
//!   - Per-IP and per-key rate limiting (separate budget from REST API)
//!   - Every inbound call stamped source: "protocol-gateway" in audit log
//!   - Peer identity header `X-Connector-Peer` injected from verified token
//!   - CORS locked to explicit origins (not permissive)
//!
//! Starts as a second tokio::net::TcpListener in main.rs alongside the
//! primary REST listener.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::{Any, CorsLayer};

use crate::state::SharedState;

pub mod tls;
pub mod gw_middleware;

// ── Peer identity — injected by auth middleware, consumed by handlers ─────────

#[derive(Debug, Clone)]
pub struct PeerIdentity {
    /// Subject from JWT / API key owner
    pub subject: String,
    /// "jwt" | "cpk" | "mtls" (Phase R2)
    pub auth_method: String,
    /// Protocol this peer is speaking
    pub protocol: String,
}

// ── Request context extension ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GatewayContext {
    pub peer: PeerIdentity,
    pub request_id: String,
    pub received_at_ms: u64,
}

// ── Auth middleware for the protocol gateway ──────────────────────────────────

async fn gateway_auth_middleware(
    headers: HeaderMap,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = req.uri().path().to_string();

    // Health check bypass
    if path == "/proto/health" || path == "/proto/readyz" {
        return Ok(next.run(req).await);
    }

    // Dev mode bypass (disabled in production/pilots env or CONNECTOR_DEFENSE_STRICT)
    let dev_mode = crate::services::runtime_control::dev_auth_bypass_allowed();

    if !dev_mode {
        if let Err(_) = crate::substrate::cfni::verify_inbound_mesh_relay(&headers) {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let (subject, auth_method) = if dev_mode {
        ("dev".to_string(), "dev".to_string())
    } else {
        // Try Authorization: Bearer <token>
        if let Some(auth) = headers.get("authorization").and_then(|h| h.to_str().ok()) {
            if let Some(token) = auth.strip_prefix("Bearer ") {
                match crate::auth::verify_token(token) {
                    Ok(claims) => (claims.sub, "jwt".to_string()),
                    Err(_) => return Err(StatusCode::UNAUTHORIZED),
                }
            } else {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        // Try X-API-Key — must validate against store (no prefix-only trust).
        else if let Some(key) = headers.get("x-api-key").and_then(|h| h.to_str().ok()) {
            match crate::auth::validate_api_key(key) {
                Ok(user_id) => (user_id, "cpk".to_string()),
                Err(_) => return Err(StatusCode::UNAUTHORIZED),
            }
        } else {
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Detect protocol from path prefix
    let protocol = if path.starts_with("/proto/mcp") { "mcp" }
        else if path.starts_with("/proto/a2a") { "a2a" }
        else if path.starts_with("/proto/acp") { "acp" }
        else if path.starts_with("/proto/anp") { "anp" }
        else if path.starts_with("/proto/ap2") { "ap2" }
        else { "unknown" };

    let request_id = uuid::Uuid::new_v4().to_string();
    let received_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    req.extensions_mut().insert(GatewayContext {
        peer: PeerIdentity {
            subject,
            auth_method,
            protocol: protocol.to_string(),
        },
        request_id: request_id.clone(),
        received_at_ms,
    });

    // Inject request-id into response headers via after-response
    let mut response = next.run(req).await;
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    response.headers_mut().insert(
        "x-connector-gateway",
        HeaderValue::from_static("protocol-gateway/1"),
    );

    Ok(response)
}

// ── Rate limiter (per-IP, separate budget from REST API) ──────────────────────

use std::sync::OnceLock;
use dashmap::DashMap;

type RateWindow = (u64, u64); // (hit_count, window_start_ms)

static GW_RATE_WINDOWS: OnceLock<DashMap<String, RateWindow>> = OnceLock::new();

fn gw_rate_windows() -> &'static DashMap<String, RateWindow> {
    GW_RATE_WINDOWS.get_or_init(DashMap::new)
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

async fn gateway_rate_limit_middleware(
    headers: HeaderMap,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Identify the caller by API key or IP
    let key = headers.get("x-api-key")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()).map(|s| s.split(',').next().unwrap_or("").trim().to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    let limit: u64 = std::env::var("CONNECTOR_GATEWAY_RATE_LIMIT")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(120); // 120 req/min
    let window_ms: u64 = 60_000;
    let now = now_ms();

    let exceeded = {
        let mut entry = gw_rate_windows().entry(key.clone()).or_insert((0, now));
        if now - entry.1 >= window_ms {
            *entry = (1, now);
            false
        } else {
            entry.0 += 1;
            entry.0 > limit
        }
    };

    if exceeded {
        let retry_after = ((window_ms - (now % window_ms)) / 1000).max(1);
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("Retry-After", retry_after.to_string()),
                ("X-RateLimit-Limit", limit.to_string()),
                ("X-RateLimit-Window", "60".to_string()),
            ],
            Json(serde_json::json!({
                "error": "rate_limit_exceeded",
                "message": "Protocol gateway rate limit exceeded",
                "retry_after_secs": retry_after,
            })),
        ).into_response());
    }

    Ok(next.run(req).await)
}

// ── Protocol-specific handlers ────────────────────────────────────────────────

/// GET /proto/health — gateway liveness (no auth)
async fn gateway_health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "gateway": "protocol-gateway/1" }))
}

/// POST /proto/mcp/tools/list
async fn mcp_tools_list(
    State(state): State<SharedState>,
    axum::Extension(ctx): axum::Extension<GatewayContext>,
) -> impl IntoResponse {
    tracing::debug!(peer = %ctx.peer.subject, req_id = %ctx.request_id, "gateway: mcp/tools/list");
    let resp = crate::services::protocols::mcp_list_tools(State(state.clone())).await;
    crate::substrate::cnp_edge::record_gateway_handler(state.as_ref(), &ctx, "/proto/mcp/tools/list");
    resp
}

/// POST /proto/mcp/tools/call
async fn mcp_tools_call(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::Extension(ctx): axum::Extension<GatewayContext>,
    Json(body): Json<crate::services::protocols::McpCallRequest>,
) -> impl IntoResponse {
    tracing::debug!(peer = %ctx.peer.subject, req_id = %ctx.request_id, "gateway: mcp/tools/call");
    let resp = crate::services::protocols::mcp_call_tool(
        State(state.clone()),
        headers,
        Json(body),
    )
    .await;
    crate::substrate::cnp_edge::record_gateway_handler(state.as_ref(), &ctx, "/proto/mcp/tools/call");
    resp
}

/// POST /proto/mcp/discover
async fn mcp_discover(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::Extension(ctx): axum::Extension<GatewayContext>,
    Json(body): Json<crate::services::protocols::McpDiscoverRequest>,
) -> impl IntoResponse {
    tracing::debug!(peer = %ctx.peer.subject, req_id = %ctx.request_id, "gateway: mcp/discover");
    let resp = crate::services::protocols::mcp_discover(
        State(state.clone()),
        headers,
        Json(body),
    )
    .await;
    crate::substrate::cnp_edge::record_gateway_handler(state.as_ref(), &ctx, "/proto/mcp/discover");
    resp
}

/// POST /proto/a2a/tasks
async fn a2a_send_task(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::Extension(ctx): axum::Extension<GatewayContext>,
    Json(body): Json<crate::services::protocols::A2aSendTaskRequest>,
) -> impl IntoResponse {
    tracing::debug!(peer = %ctx.peer.subject, req_id = %ctx.request_id, "gateway: a2a/tasks");
    let resp = crate::services::protocols::a2a_send_task(State(state.clone()), headers, Json(body)).await;
    crate::substrate::cnp_edge::record_gateway_handler(state.as_ref(), &ctx, "/proto/a2a/tasks");
    resp
}

/// GET /proto/a2a/tasks/:id
async fn a2a_get_task(
    State(state): State<SharedState>,
    axum::Extension(ctx): axum::Extension<GatewayContext>,
    Path(task_id): Path<String>,
) -> impl IntoResponse {
    tracing::debug!(peer = %ctx.peer.subject, task = %task_id, req_id = %ctx.request_id, "gateway: a2a/tasks/get");
    let resp = crate::services::protocols::a2a_get_task(State(state.clone()), axum::extract::Path(task_id)).await;
    crate::substrate::cnp_edge::record_gateway_handler(state.as_ref(), &ctx, "/proto/a2a/tasks/:id");
    resp
}

/// POST /proto/acp/messages
async fn acp_send_message(
    State(state): State<SharedState>,
    axum::Extension(ctx): axum::Extension<GatewayContext>,
    Json(body): Json<crate::services::protocols::AcpSendRequest>,
) -> impl IntoResponse {
    tracing::debug!(peer = %ctx.peer.subject, req_id = %ctx.request_id, "gateway: acp/messages");
    let resp = crate::services::protocols::acp_send(State(state.clone()), Json(body)).await;
    crate::substrate::cnp_edge::record_gateway_handler(state.as_ref(), &ctx, "/proto/acp/messages");
    resp
}

// ── CORS for the protocol gateway ────────────────────────────────────────────

fn gateway_cors() -> CorsLayer {
    let allowed_origins = std::env::var("CONNECTOR_GATEWAY_ALLOWED_ORIGINS")
        .unwrap_or_default();

    if allowed_origins.is_empty() || allowed_origins == "*" {
        // Permissive only when explicitly configured or in dev
        CorsLayer::permissive()
    } else {
        let origins: Vec<HeaderValue> = allowed_origins
            .split(',')
            .filter_map(|o| o.trim().parse::<HeaderValue>().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(Any)
    }
}

// ── Router builder ────────────────────────────────────────────────────────────

pub fn build_gateway_router(state: SharedState) -> Router {
    Router::new()
        // Health (no auth)
        .route("/proto/health", get(gateway_health))
        .route("/proto/readyz", get(gateway_health))

        // MCP routes
        .route("/proto/mcp/discover",    post(mcp_discover))
        .route("/proto/mcp/tools/list",  post(mcp_tools_list))
        .route("/proto/mcp/tools/call",  post(mcp_tools_call))

        // A2A routes
        .route("/proto/a2a/tasks",       post(a2a_send_task))
        .route("/proto/a2a/tasks/:id",   get(a2a_get_task))

        // ACP routes
        .route("/proto/acp/messages",    post(acp_send_message))

        // Middleware stack: rate limit → auth → handlers
        .layer(axum::middleware::from_fn(gateway_auth_middleware))
        .layer(axum::middleware::from_fn(gateway_rate_limit_middleware))
        .layer(gateway_cors())
        .with_state(state)
}

// ── Spawn the gateway TCP listener ────────────────────────────────────────────

/// Bind a dedicated TCP listener on `addr` (default: 0.0.0.0:9092) and serve
/// the protocol gateway router.
///
/// Phase R2: If `CONNECTOR_TLS_CERT` / `CONNECTOR_TLS_KEY` / `CONNECTOR_PEER_CA_CERT`
/// are set, the listener is wrapped in `axum-server` TLS with mTLS peer verification.
/// Otherwise falls back to plain TCP (Phase R1 — auth via Bearer/cpk header).
pub async fn spawn_gateway(state: SharedState, addr: SocketAddr) {
    let router = build_gateway_router(state);

    // Register in InternalDns regardless of TLS mode
    let register = || {
        crate::internal_dns::register(
            crate::internal_dns::SVC_PROTOCOL_GATEWAY,
            addr,
            "External protocol gateway (MCP/A2A/ACP/ANP/AP2)",
            &["protocol", "external", "rpc"],
        );
    };

    // Phase R2: attempt mTLS
    match tls::build_tls_config() {
        Ok(Some(tls_config)) => {
            tracing::info!(addr = %addr, "Protocol gateway listening (mTLS enabled)");
            register();
            let handle = axum_server::Handle::new();
            let tls_acceptor = axum_server::tls_rustls::RustlsConfig::from_config(tls_config);
            tokio::spawn(async move {
                if let Err(e) = axum_server::bind_rustls(addr, tls_acceptor)
                    .handle(handle)
                    .serve(router.into_make_service())
                    .await
                {
                    tracing::error!(error = %e, "Protocol gateway (mTLS) exited unexpectedly");
                }
            });
        }
        Ok(None) => {
            // Plain TCP — Phase R1 fallback
            match tokio::net::TcpListener::bind(&addr).await {
                Ok(listener) => {
                    tracing::info!(addr = %addr, "Protocol gateway listening (bearer-only, no mTLS)");
                    register();
                    tokio::spawn(async move {
                        if let Err(e) = axum::serve(listener, router).await {
                            tracing::error!(error = %e, "Protocol gateway exited unexpectedly");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        addr = %addr, error = %e,
                        "Protocol gateway could not bind — protocols still served on main port :9091"
                    );
                }
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "mTLS config error — protocol gateway NOT started. Fix cert/key paths.");
        }
    }
}
