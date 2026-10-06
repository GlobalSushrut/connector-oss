//! Proxy TraceTramp **management plane** admin APIs through the Connector platform.
//!
//! The dashboard runs on the same origin as `/api/v1` and cannot reach `127.0.0.1:9742` with
//! TraceTramp's admin token without exposing secrets in the browser. These handlers forward
//! requests server-side using env configuration.
//!
//! ## Environment
//! - `CONNECTOR_TRACETRAMP_MANAGEMENT_URL` or `TRACETRAMP_MANAGEMENT_URL` — base URL (default `http://127.0.0.1:19742`, matching `lab/docker-compose.premium-lab.yml` host port for the management plane)
//! - `CONNECTOR_TRACETRAMP_ADMIN_TOKEN` or `TRACETRAMP_ADMIN_TOKEN` — bearer token for `require_admin` on TraceTramp

use axum::{
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::{json, Value};
use std::time::Duration;

use crate::state::SharedState;

/// Hosted playground sidecar listens on :9742; lab compose publishes :19742.
pub fn default_tt_base() -> String {
    if crate::services::playground::is_playground_mode() {
        "http://127.0.0.1:9742".into()
    } else {
        "http://127.0.0.1:19742".into()
    }
}

/// Whether TraceTramp management URL + admin token are set so the platform proxy can call upstream.
pub fn tracetramp_management_plane_configured() -> bool {
    tt_creds().is_ok()
}

/// True when management base URL was set explicitly (not only the default).
pub fn tracetramp_management_url_explicit() -> bool {
    std::env::var("CONNECTOR_TRACETRAMP_MANAGEMENT_URL")
        .or_else(|_| std::env::var("TRACETRAMP_MANAGEMENT_URL"))
        .is_ok()
        || crate::services::plugin_configure::overlay_string("tracetramp", "management_url")
            .is_some()
}

fn tt_creds() -> Result<(String, String), String> {
    // Env wins; else UI-saved configure overlay (POST /plugins/tracetramp/configure).
    let base = std::env::var("CONNECTOR_TRACETRAMP_MANAGEMENT_URL")
        .or_else(|_| std::env::var("TRACETRAMP_MANAGEMENT_URL"))
        .ok()
        .or_else(|| {
            crate::services::plugin_configure::overlay_string("tracetramp", "management_url")
        })
        .unwrap_or_else(|| default_tt_base());
    let base = base.trim_end_matches('/').to_string();
    let token = std::env::var("CONNECTOR_TRACETRAMP_ADMIN_TOKEN")
        .or_else(|_| std::env::var("TRACETRAMP_ADMIN_TOKEN"))
        .ok()
        .or_else(|| crate::services::plugin_configure::overlay_string("tracetramp", "admin_token"))
        .ok_or_else(|| {
            "set CONNECTOR_TRACETRAMP_ADMIN_TOKEN (or save admin_token via POST /plugins/tracetramp/configure)"
                .to_string()
        })?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err("TraceTramp admin token is empty".to_string());
    }
    Ok((base, token))
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .build()
        .expect("tracetramp proxy reqwest client")
}

/// Short probe: `GET {management}/admin/stats` with admin token. Used by `/plugins/status`.
/// Returns `None` if credentials are missing; `Some(false)` on transport/HTTP failure; `Some(true)` on 2xx.
pub async fn tracetramp_upstream_reachable() -> Option<bool> {
    let (base, token) = tt_creds().ok()?;
    let url = format!("{}/admin/stats", base.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .connect_timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let ok = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json")
        .send()
        .await
        .ok()
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    Some(ok)
}

async fn forward_admin(
    state: &crate::state::SharedState,
    headers: &axum::http::HeaderMap,
    method: reqwest::Method,
    admin_path: &str,
    query: Option<&str>,
    body: Option<Value>,
    tenant_id: Option<&str>,
) -> Result<Value, (StatusCode, Value)> {
    if let Err(resp) = crate::substrate::proxy_auth::require_management_proxy_auth(headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            json!({
                "error": "management_proxy_auth_required",
                "message": "Authenticated platform caller required",
            }),
        ));
    }
    if method != reqwest::Method::GET
        && crate::substrate::handoff_queue::handoff_backpressure_active(state.as_ref())
    {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "error": "handoff_backpressure",
                "message": "CONNECTOR_HANDOFF_REQUIRED: pending WitnessCtl handoffs exceed cap; TraceTramp mutating proxy blocked",
                "hint": "Deliver WC ingest/seal or raise CONNECTOR_HANDOFF_PENDING_MAX",
            }),
        ));
    }
    let tenant_id = tenant_id
        .map(str::to_string)
        .or_else(|| crate::substrate::outbound::verified_tenant_id(headers));
    let tenant_ref = tenant_id.as_deref();
    let (base, token) = tt_creds().map_err(|msg| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "error": "tracetramp_proxy_unconfigured",
                "message": msg,
                "hint": "Set CONNECTOR_TRACETRAMP_MANAGEMENT_URL and CONNECTOR_TRACETRAMP_ADMIN_TOKEN (or TRACETRAMP_* equivalents) on the platform process."
            }),
        )
    })?;

    let mut q_parts: Vec<String> = query.map(|s| s.to_string()).into_iter().collect();
    // Inject tenant_id into query string so TraceTramp can filter
    if let Some(tid) = tenant_ref {
        q_parts.push(format!("tenant_id={}", urlencoding::encode(tid)));
    }
    let q = if q_parts.is_empty() {
        String::new()
    } else {
        format!("?{}", q_parts.join("&"))
    };
    let path = admin_path.trim_start_matches('/');
    let url = format!("{base}/admin/{path}{q}");

    let method_label = method.as_str().to_string();
    let mut req = http_client()
        .request(method, &url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json");
    let req = crate::substrate::outbound::stamp_reqwest(req, headers);

    let resp = if let Some(b) = body {
        let req = req.header("Content-Type", "application/json");
        req.json(&b).send().await
    } else {
        req.send().await
    }
    .map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            json!({
                "error": "tracetramp_upstream_error",
                "message": e.to_string()
            }),
        )
    })?;

    let status = resp.status();
    let text = resp.text().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            json!({ "error": "tracetramp_read_body", "message": e.to_string() }),
        )
    })?;

    let body: Value = serde_json::from_str(&text).unwrap_or(json!({
        "upstream_status": status.as_u16(),
        "raw": text.chars().take(2000).collect::<String>()
    }));

    if !status.is_success() {
        return Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            json!({
                "error": "tracetramp_upstream_http",
                "upstream_status": status.as_u16(),
                "body": body
            }),
        ));
    }

    crate::substrate::projection::record_tracetramp_admin_forward(
        state.as_ref(),
        &method_label,
        admin_path,
        tenant_ref,
        headers,
    );

    Ok(body)
}

fn stamp_operator_approver(headers: &axum::http::HeaderMap, mut body: Value) -> Value {
    if !body.is_object() {
        body = json!({});
    }
    if let Some(claims) = crate::auth::extract_claims(headers) {
        let approver = if !claims.email.trim().is_empty() {
            claims.email.clone()
        } else {
            claims.sub.clone()
        };
        if let Some(obj) = body.as_object_mut() {
            // Verified claims overwrite any client-supplied approver_id.
            obj.insert("approver_id".into(), json!(approver));
            obj.insert("approver_sub".into(), json!(claims.sub));
            obj.insert("approver_role".into(), json!(claims.role));
            obj.insert("approver_source".into(), json!("platform_verified_claims"));
        }
    }
    body
}

fn json_err(status: StatusCode, body: Value) -> axum::response::Response {
    (status, Json(body)).into_response()
}

async fn require_live_pending_hold(
    state: &SharedState,
    headers: &axum::http::HeaderMap,
    id: &str,
) -> Result<Value, (StatusCode, Value)> {
    let v = forward_admin(
        state,
        headers,
        reqwest::Method::GET,
        "approvals",
        Some("status=pending"),
        None,
        extract_tenant(headers),
    )
    .await?;
    let found = v
        .get("approvals")
        .or_else(|| v.get("items"))
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
        .find(|row| row.get("id").and_then(|x| x.as_str()) == Some(id))
        .cloned();
    match found {
        Some(row) => Ok(row),
        None => Err((
            StatusCode::CONFLICT,
            json!({
                "ok": false,
                "error": "hold_not_pending",
                "message": format!("Cannot decide '{id}': it is not a live pending TraceTramp hold"),
                "honesty": "Approve/deny/quarantine only consume a pending row. Already decided or expired holds cannot be revived from this proxy.",
            }),
        )),
    }
}

fn tracetramp_control_status(configured: bool, upstream_reachable: Option<bool>) -> &'static str {
    if !configured {
        return "not_configured";
    }
    match upstream_reachable {
        Some(true) => "reachable",
        Some(false) => "unavailable",
        None => "unknown",
    }
}

/// Platform-visible enforce honesty (TT process may override via its own env).
fn tracetramp_enforce_posture() -> &'static str {
    if std::env::var("TRACETRAMP_FAIL_CLOSED")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
    {
        return "enforce";
    }
    if std::env::var("TRACETRAMP_ALLOW_FAIL_OPEN")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
    {
        return "fail_open_lab";
    }
    match std::env::var("CONNECTOR_ENV")
        .or_else(|_| std::env::var("TRACETRAMP_ENV"))
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "production" | "prod" | "pilots" | "pilot" | "staging" => "enforce",
        _ => "lab_default",
    }
}

pub async fn tracetramp_proxy_status(State(_s): State<SharedState>) -> impl IntoResponse {
    let configured = tracetramp_management_plane_configured();
    let mgmt_explicit = tracetramp_management_url_explicit();
    let upstream_reachable = if configured {
        tracetramp_upstream_reachable().await
    } else {
        None
    };
    let control_status = tracetramp_control_status(configured, upstream_reachable);
    let enforce_posture = tracetramp_enforce_posture();
    Json(json!({
        "ok": configured,
        "management_url_explicit": mgmt_explicit,
        "default_base": default_tt_base(),
        "upstream_reachable": upstream_reachable,
        "control_status": control_status,
        "enforce_posture": enforce_posture,
        "status_badge": control_status,
        "honesty": "unavailable ≠ healthy; green only when control_status=reachable. TT down must not look like enforce-ok.",
        "hint": "Platform forwards to TraceTramp management plane using CONNECTOR_TRACETRAMP_ADMIN_TOKEN or TRACETRAMP_ADMIN_TOKEN."
    }))
}

#[cfg(test)]
mod control_status_tests {
    use super::*;

    #[test]
    fn control_status_unavailable_when_upstream_down() {
        assert_eq!(tracetramp_control_status(true, Some(false)), "unavailable");
        assert_eq!(tracetramp_control_status(true, Some(true)), "reachable");
        assert_eq!(tracetramp_control_status(false, None), "not_configured");
    }
}

fn extract_tenant(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
}

pub async fn tt_get_stats(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::GET,
        "stats",
        None,
        None,
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_get_traces(
    State(state): State<SharedState>,
    RawQuery(q): RawQuery,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::GET,
        "traces",
        q.as_deref(),
        None,
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_get_approvals(
    State(state): State<SharedState>,
    RawQuery(q): RawQuery,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::GET,
        "approvals",
        q.as_deref(),
        None,
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_get_policies(
    State(state): State<SharedState>,
    RawQuery(q): RawQuery,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::GET,
        "policies",
        q.as_deref(),
        None,
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_get_operation_blocks(
    State(state): State<SharedState>,
    RawQuery(q): RawQuery,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::GET,
        "operation-blocks",
        q.as_deref(),
        None,
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_get_quarantines(
    State(state): State<SharedState>,
    RawQuery(q): RawQuery,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::GET,
        "quarantine",
        q.as_deref(),
        None,
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_get_quarantine_all(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::GET,
        "quarantine/all",
        None,
        None,
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_post_approve(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let path = format!("approvals/{id}/approve");
    let body = stamp_operator_approver(&headers, body);
    if let Err((st, b)) = require_live_pending_hold(&state, &headers, &id).await {
        return json_err(st, b);
    }
    let approved = match forward_admin(
        &state,
        &headers,
        reqwest::Method::POST,
        &path,
        None,
        Some(body),
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => v,
        Err((st, b)) => return json_err(st, b),
    };
    // Approve only flips the row. The held call stays blocked until the resume latch is armed.
    let latch_path = format!("approvals/{id}/execute");
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::POST,
        &latch_path,
        None,
        Some(json!({})),
        extract_tenant(&headers),
    )
    .await
    {
        Ok(latch) => Json(json!({
            "ok": true,
            "action": "approve",
            "id": id,
            "status": "approved",
            "result_ready": latch.get("result_ready").cloned().unwrap_or(json!(true)),
            "executed": false,
            "resume_headers": {
                "X-Approval-Resume": "approved",
                "X-Approval-Id": id,
            },
            "tracetramp": approved,
            "latch": latch,
            "honesty": "TraceTramp hold approved and the resume latch is armed. This is not a PATE ask. Connector did not run the held request. The original caller retries with X-Approval-Resume: approved and X-Approval-Id.",
        }))
        .into_response(),
        Err((st, b)) => (
            st,
            Json(json!({
                "ok": false,
                "action": "approve",
                "id": id,
                "status": "approved",
                "result_ready": false,
                "error": "tracetramp_latch_failed",
                "execute": b,
                "honesty": "The hold was marked approved, but the resume latch did not arm. A retry with X-Approval-Resume is refused until execute succeeds.",
            })),
        )
            .into_response(),
    }
}

pub async fn tt_post_reject(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let path = format!("approvals/{id}/reject");
    let body = stamp_operator_approver(&headers, body);
    if let Err((st, b)) = require_live_pending_hold(&state, &headers, &id).await {
        return json_err(st, b);
    }
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::POST,
        &path,
        None,
        Some(body),
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(json!({
            "ok": true,
            "action": "reject",
            "id": id,
            "status": "rejected",
            "executed": false,
            "tracetramp": v,
            "honesty": "TraceTramp hold rejected. Nothing is resumed. This is not a PATE denial.",
        }))
        .into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_post_quarantine_approval(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let path = format!("approvals/{id}/quarantine");
    let body = stamp_operator_approver(&headers, body);
    if let Err((st, b)) = require_live_pending_hold(&state, &headers, &id).await {
        return json_err(st, b);
    }
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::POST,
        &path,
        None,
        Some(body),
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_post_execute_approval(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let path = format!("approvals/{id}/execute");
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::POST,
        &path,
        None,
        Some(body),
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_post_quarantine_release(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::POST,
        "quarantine/release",
        None,
        Some(body),
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_post_create_quarantine(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::POST,
        "quarantine",
        None,
        Some(body),
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_post_operation_block(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::POST,
        "operation-blocks",
        None,
        Some(body),
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_post_operation_block_release(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::POST,
        "operation-blocks/release",
        None,
        Some(body),
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn tt_post_policy(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    match forward_admin(
        &state,
        &headers,
        reqwest::Method::POST,
        "policies",
        None,
        Some(body),
        extract_tenant(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}
