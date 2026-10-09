//! Enterprise-grade middleware stack for AgentLoop.
//!
//! Layers (applied in order in main.rs):
//!   1. `request_id`    — assign/propagate X-Request-ID, echo in response
//!   2. `require_api_key` — AGENTLOOP_API_KEY gate, constant-time compare
//!   3. `trace_request`  — structured JSON request log + Prometheus latency histogram
//!
//! Rate limiting lives in the `RateLimiter` extractor used in routes that need it.

use std::time::Instant;

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use uuid::Uuid;

static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
static X_API_KEY:    HeaderName = HeaderName::from_static("x-agentloop-api-key");

// ── 1. Request ID ─────────────────────────────────────────────────────────────

pub async fn request_id(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let hv = HeaderValue::from_str(&id).unwrap_or_else(|_| HeaderValue::from_static("unknown"));
    req.headers_mut().insert(X_REQUEST_ID.clone(), hv.clone());

    let mut resp = next.run(req).await;
    resp.headers_mut().insert(X_REQUEST_ID.clone(), hv);
    resp
}

// ── 2. API Key auth ───────────────────────────────────────────────────────────
//
// Constant-time compare to resist timing attacks.

pub async fn require_api_key(req: Request, next: Next) -> Response {
    let configured = std::env::var("AGENTLOOP_API_KEY").unwrap_or_default();
    if configured.is_empty() {
        return next.run(req).await;
    }

    let provided = req
        .headers()
        .get(&X_API_KEY)
        .or_else(|| req.headers().get("authorization"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").to_owned())
        .unwrap_or_default();

    if !constant_time_eq(provided.as_bytes(), configured.as_bytes()) {
        metrics::counter!("agentloop_auth_failures_total").increment(1);
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": {
                    "code":    "UNAUTHORIZED",
                    "message": "Invalid or missing API key",
                    "status":  401,
                }
            })),
        ).into_response();
    }

    next.run(req).await
}

/// Constant-time byte comparison (branchless XOR accumulate).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let diff: u8 = a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    diff == 0
}

// ── 3. Structured request tracing + Prometheus histogram ──────────────────────

pub async fn trace_request(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path   = req.uri().path().to_owned();
    let req_id = req
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_owned();

    let start = Instant::now();
    let resp  = next.run(req).await;
    let ms    = start.elapsed().as_millis() as f64;
    let status = resp.status().as_u16();

    // Prometheus histogram
    metrics::histogram!(
        "agentloop_request_duration_ms",
        "method" => method.to_string(),
        "path"   => normalise_path(&path),
        "status" => status_class(status),
    ).record(ms);

    // Request counter
    metrics::counter!(
        "agentloop_requests_total",
        "method" => method.to_string(),
        "path"   => normalise_path(&path),
        "status" => status.to_string(),
    ).increment(1);

    let level = if status >= 500 { "error" } else if status >= 400 { "warn" } else { "info" };
    match level {
        "error" => tracing::error!(method = %method, path = %path, status, latency_ms = ms as u64, request_id = %req_id, "request"),
        "warn"  => tracing::warn!(method  = %method, path = %path, status, latency_ms = ms as u64, request_id = %req_id, "request"),
        _       => tracing::info!(method  = %method, path = %path, status, latency_ms = ms as u64, request_id = %req_id, "request"),
    }

    resp
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Replace UUID path segments with `:id` to keep metric cardinality low.
fn normalise_path(path: &str) -> String {
    static UUID_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap()
    });
    UUID_RE.replace_all(path, ":id").into_owned()
}

fn status_class(status: u16) -> &'static str {
    match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _         => "other",
    }
}
