//! Axum middleware: constant-time API key auth, request tracing, Prometheus metrics.

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use constant_time_eq::constant_time_eq;
use serde_json::json;
use std::time::Instant;
use uuid::Uuid;

// ── API key authentication ─────────────────────────────────────────────────────
//
// Constant-time comparison — prevents timing-oracle attacks.
// The /api/v1/verify and /api/v1/crl endpoints are public (no auth needed).

pub async fn require_api_key(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();

    // Public endpoints — no auth
    if path == "/health"
        || path == "/readyz"
        || path == "/api/v1/verify"
        || path == "/api/v1/crl"
        || path.starts_with("/api/v1/sponsors/approve/")
    {
        return next.run(req).await;
    }

    let expected = match std::env::var("AGENTPASSPORT_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            tracing::warn!("AGENTPASSPORT_API_KEY not set — all non-public requests blocked");
            return auth_error("Server misconfiguration: API key not configured");
        }
    };

    let provided = req
        .headers()
        .get("X-API-Key")
        .or_else(|| req.headers().get(header::AUTHORIZATION))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").to_string())
        .unwrap_or_default();

    if provided.is_empty() || !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        metrics::counter!("agentpassport_auth_failures_total").increment(1);
        return auth_error("Invalid or missing API key");
    }

    next.run(req).await
}

fn auth_error(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": { "code": "UNAUTHORIZED", "message": msg, "status": 401 } })),
    ).into_response()
}

// ── Request tracing + Prometheus histogram ─────────────────────────────────────

pub async fn trace_request(req: Request, next: Next) -> Response {
    let method    = req.method().to_string();
    let path      = normalise_path(req.uri().path());
    let req_id    = Uuid::new_v4().to_string();
    let start     = Instant::now();

    tracing::info!(
        request_id = %req_id,
        method     = %method,
        path       = %path,
        "→ request"
    );

    let mut resp = next.run(req).await;

    let status  = resp.status().as_u16().to_string();
    let elapsed = start.elapsed().as_secs_f64();

    tracing::info!(
        request_id = %req_id,
        method     = %method,
        path       = %path,
        status     = %status,
        elapsed_s  = elapsed,
        "← response"
    );

    metrics::counter!("agentpassport_requests_total",
        "method" => method.clone(),
        "path"   => path.clone(),
        "status" => status.clone()
    ).increment(1);

    metrics::histogram!("agentpassport_request_duration_seconds",
        "method" => method,
        "path"   => path,
        "status" => status
    ).record(elapsed);

    resp.headers_mut().insert(
        "X-Request-ID",
        req_id.parse().unwrap(),
    );

    resp
}

// ── Path normalisation ─────────────────────────────────────────────────────────
//
// Replace UUID segments with `:id` to avoid metric label cardinality explosion.

fn normalise_path(path: &str) -> String {
    let uuid_re = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        ).unwrap()
    });
    let did_re = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"did:[a-z]+:[a-z]+:[a-zA-Z0-9]+").unwrap()
    });
    let s = uuid_re.replace_all(path, ":id");
    did_re.replace_all(&s, ":did").to_string()
}
