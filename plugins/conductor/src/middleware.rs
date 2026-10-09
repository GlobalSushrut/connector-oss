//! Production middleware:
//! - X-Request-ID propagation (generate if absent, echo in response)
//! - API key authentication on all /api/* routes
//! - Request body size limit
//! - Structured per-request tracing

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use uuid::Uuid;

static REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
static CONDUCTOR_KEY_HEADER: HeaderName = HeaderName::from_static("x-conductor-api-key");

// ── Request ID ────────────────────────────────────────────────────────────────

/// Injects X-Request-ID into every request and response.
/// If the client sends one, it is reused. Otherwise a UUID v4 is generated.
pub async fn request_id(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    req.headers_mut().insert(
        REQUEST_ID_HEADER.clone(),
        HeaderValue::from_str(&id).unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );

    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        REQUEST_ID_HEADER.clone(),
        HeaderValue::from_str(&id).unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );
    resp
}

// ── API Key Auth ──────────────────────────────────────────────────────────────

/// Validates the X-Conductor-API-Key header (or Authorization: Bearer <key>).
/// Applied to all /api/* routes. Health endpoint is excluded at the router level.
pub async fn require_api_key(req: Request, next: Next) -> Response {
    let expected = match std::env::var("CONDUCTOR_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return next.run(req).await, // no key configured → open (dev mode)
    };

    // Accept X-Conductor-API-Key header
    let key_from_header = req
        .headers()
        .get(&CONDUCTOR_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Accept Authorization: Bearer <key>
    let key_from_bearer = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    let provided = key_from_header.or(key_from_bearer);

    match provided {
        Some(k) if k == expected => next.run(req).await,
        Some(_) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "UNAUTHORIZED", "message": "Invalid API key" })),
        ).into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "UNAUTHORIZED", "message": "Missing API key — provide X-Conductor-API-Key header or Authorization: Bearer <key>" })),
        ).into_response(),
    }
}

// ── Structured request tracing ────────────────────────────────────────────────

/// Logs method, path, status, and latency for every request as a structured span.
pub async fn trace_request(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path   = req.uri().path().to_string();
    let req_id = req
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    let start = std::time::Instant::now();
    let resp = next.run(req).await;
    let latency_ms = start.elapsed().as_millis();
    let status = resp.status().as_u16();

    tracing::info!(
        method = %method,
        path   = %path,
        status,
        latency_ms,
        request_id = %req_id,
        "request"
    );

    resp
}
