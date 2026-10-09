//! Enterprise middleware stack for LedgerLens.
//!
//! Layers (applied in main.rs):
//!   1. `request_id`      — assign/propagate X-Request-ID, echo in response
//!   2. `require_api_key` — LEDGERLENS_API_KEY gate, constant-time compare
//!   3. `trace_request`   — structured JSON log + Prometheus latency histogram

use std::time::Instant;

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use constant_time_eq::constant_time_eq;
use serde_json::json;
use uuid::Uuid;

static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
static X_API_KEY:    HeaderName = HeaderName::from_static("x-ledgerlens-api-key");

// ── Request ID ────────────────────────────────────────────────────────────────

pub async fn request_id(mut req: Request, next: Next) -> Response {
    let id = req.headers()
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    req.headers_mut().insert(
        X_REQUEST_ID.clone(),
        HeaderValue::from_str(&id).unwrap_or(HeaderValue::from_static("invalid")),
    );

    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        X_REQUEST_ID.clone(),
        HeaderValue::from_str(&id).unwrap_or(HeaderValue::from_static("invalid")),
    );
    resp
}

// ── API key auth (constant-time) ──────────────────────────────────────────────

pub async fn require_api_key(req: Request, next: Next) -> Response {
    let configured = std::env::var("LEDGERLENS_API_KEY").unwrap_or_default();
    if configured.is_empty() {
        return next.run(req).await;
    }

    let provided = req.headers()
        .get(&X_API_KEY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    // Pad to same length before constant-time compare
    let a = provided.as_bytes();
    let b = configured.as_bytes();
    let max_len = a.len().max(b.len()).max(1);
    let mut pa = vec![0u8; max_len];
    let mut pb = vec![0u8; max_len];
    pa[..a.len()].copy_from_slice(a);
    pb[..b.len()].copy_from_slice(b);

    if !constant_time_eq(&pa, &pb) || a.len() != b.len() {
        metrics::counter!("ledgerlens_auth_failures_total").increment(1);
        let body = json!({ "error": { "code": "UNAUTHORIZED", "message": "Invalid API key", "status": 401 } });
        return (StatusCode::UNAUTHORIZED, Json(body)).into_response();
    }

    next.run(req).await
}

// ── Request tracing + Prometheus histogram ────────────────────────────────────

pub async fn trace_request(req: Request, next: Next) -> Response {
    let method = req.method().to_string();
    let path   = normalize_path(req.uri().path());
    let req_id = req.headers()
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_owned();

    let start = Instant::now();

    tracing::info!(
        request_id = %req_id,
        method     = %method,
        path       = %path,
        "→ request"
    );

    let resp    = next.run(req).await;
    let latency = start.elapsed().as_millis() as f64;
    let status  = resp.status().as_u16();
    let status_class = match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _         => "5xx",
    };

    metrics::histogram!(
        "ledgerlens_request_duration_ms",
        "method"  => method.clone(),
        "path"    => path.clone(),
        "status"  => status_class,
    ).record(latency);

    metrics::counter!(
        "ledgerlens_requests_total",
        "method"  => method.clone(),
        "path"    => path.clone(),
        "status"  => status_class,
    ).increment(1);

    let log_level = if status >= 500 { "error" }
                   else if status >= 400 { "warn" }
                   else { "info" };

    match log_level {
        "error" => tracing::error!(request_id = %req_id, %method, %path, status, latency_ms = latency, "← response"),
        "warn"  => tracing::warn! (request_id = %req_id, %method, %path, status, latency_ms = latency, "← response"),
        _       => tracing::info! (request_id = %req_id, %method, %path, status, latency_ms = latency, "← response"),
    }

    resp
}

// ── Path normalisation (cardinality control) ──────────────────────────────────

fn normalize_path(path: &str) -> String {
    static UUID_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        ).unwrap()
    });
    static NUM_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"(?<=/)\d+(?=/|$)").unwrap()
    });

    let s = UUID_RE.replace_all(path, ":id");
    NUM_RE.replace_all(&s, ":id").into_owned()
}
