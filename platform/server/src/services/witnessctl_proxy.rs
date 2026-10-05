//! Proxy WitnessCtl **management** HTTP through the Connector platform (dashboard + hub).
//!
//! ## Environment
//! - `CONNECTOR_WITNESSCTL_MANAGEMENT_URL` or `WITNESSCTL_MANAGEMENT_URL` — WitnessCtl base (no trailing slash).
//! - `CONNECTOR_WITNESSCTL_ADMIN_TOKEN` or `WITNESSCTL_ADMIN_TOKEN` — Bearer token accepted as admin by WitnessCtl (`/api/v1/*`).
//!
//! `GET /health` is forwarded **without** a token when only the base URL is set. Authenticated routes require the admin token.

use axum::{
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::{json, Value};
use std::time::Duration;

use crate::auth;
use crate::state::SharedState;

fn wc_base() -> Option<String> {
    crate::services::plugin_upstream_probe::witnessctl_management_url()
}

fn wc_admin_token() -> Option<String> {
    std::env::var("CONNECTOR_WITNESSCTL_ADMIN_TOKEN")
        .or_else(|_| std::env::var("WITNESSCTL_ADMIN_TOKEN"))
        .ok()
        .or_else(|| crate::services::plugin_configure::overlay_string("witnessctl", "admin_token"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Base URL set (used for `/health` proxy and hub probe).
pub fn witnessctl_health_proxy_configured() -> bool {
    wc_base().is_some()
}

/// Base URL + admin token (required for `/api/v1/*` proxy).
pub fn witnessctl_api_proxy_configured() -> bool {
    wc_base().is_some() && wc_admin_token().is_some()
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("witnessctl proxy reqwest client")
}

fn query_suffix(query: Option<&str>) -> String {
    query
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| format!("?{s}"))
        .unwrap_or_default()
}

async fn read_json_response(resp: reqwest::Response) -> Result<Value, (StatusCode, Value)> {
    let status = resp.status();
    let text = resp.text().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            json!({ "error": "witnessctl_read_body", "message": e.to_string() }),
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
                "error": "witnessctl_upstream_http",
                "upstream_status": status.as_u16(),
                "body": body
            }),
        ));
    }
    Ok(body)
}

async fn forward_path_no_auth(
    path: &str,
    query: Option<&str>,
) -> Result<Value, (StatusCode, Value)> {
    let base = wc_base().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        json!({
            "error": "witnessctl_proxy_unconfigured",
            "message": "Set CONNECTOR_WITNESSCTL_MANAGEMENT_URL or WITNESSCTL_MANAGEMENT_URL on the platform process.",
        }),
    ))?;
    let path = path.trim_start_matches('/');
    let url = format!("{}/{}{}", base, path, query_suffix(query));
    let resp = http_client()
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                json!({ "error": "witnessctl_upstream_error", "message": e.to_string() }),
            )
        })?;
    read_json_response(resp).await
}

fn extract_tenant_wc(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
}

async fn forward_api_v1(
    state: &crate::state::SharedState,
    headers: &axum::http::HeaderMap,
    method: reqwest::Method,
    tail: &str,
    query: Option<&str>,
    body: Option<Value>,
    tenant_id: Option<&str>,
) -> Result<Value, (StatusCode, Value)> {
    if let Err(_resp) = crate::substrate::proxy_auth::require_management_proxy_auth(headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            json!({
                "error": "witnessctl_management_proxy_auth_required",
                "message": "Authenticated platform caller required",
            }),
        ));
    }
    let tenant_id = tenant_id
        .map(str::to_string)
        .or_else(|| crate::substrate::outbound::verified_tenant_id(headers));
    let tenant_ref = tenant_id.as_deref();
    let base = wc_base().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        json!({
            "error": "witnessctl_proxy_unconfigured",
            "message": "Set CONNECTOR_WITNESSCTL_MANAGEMENT_URL on the platform process.",
        }),
    ))?;
    let token = wc_admin_token().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        json!({
            "error": "witnessctl_proxy_missing_token",
            "message": "Set CONNECTOR_WITNESSCTL_ADMIN_TOKEN or WITNESSCTL_ADMIN_TOKEN for authenticated WitnessCtl API proxy.",
        }),
    ))?;
    let tail = tail.trim_start_matches('/');
    let method_label = method.as_str().to_string();
    let tail_owned = tail.to_string();
    // Inject tenant_id into query for tenant isolation
    let mut q_parts: Vec<String> = query.map(|s| s.to_string()).into_iter().collect();
    if let Some(tid) = tenant_ref {
        q_parts.push(format!("tenant_id={}", urlencoding::encode(tid)));
    }
    let q = if q_parts.is_empty() {
        String::new()
    } else {
        format!("?{}", q_parts.join("&"))
    };
    let url = format!("{}/api/v1/{}{}", base, tail, q);
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
            json!({ "error": "witnessctl_upstream_error", "message": e.to_string() }),
        )
    })?;
    match read_json_response(resp).await {
        Ok(body) => {
            crate::substrate::projection::record_witnessctl_forward(
                state.as_ref(),
                &method_label,
                &tail_owned,
                tenant_ref,
                headers,
            );
            Ok(body)
        }
        Err(e) => Err(e),
    }
}

fn json_err(status: StatusCode, body: Value) -> axum::response::Response {
    (status, Json(body)).into_response()
}

/// Verify session exists for caller tenant before evidence export (closes WC IDOR at platform proxy).
async fn wc_assert_session_access(
    state: &SharedState,
    session_id: &str,
    headers: &axum::http::HeaderMap,
) -> Result<(), axum::response::Response> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    if auth::extract_claims(headers).is_none() {
        return Err(json_err(
            StatusCode::UNAUTHORIZED,
            json!({"error": "authentication_required", "message": "Bearer token required for session export"}),
        ));
    }
    match forward_api_v1(
        state,
        headers,
        reqwest::Method::GET,
        &format!("sessions/{session_id}"),
        None,
        None,
        extract_tenant_wc(headers),
    )
    .await
    {
        Ok(_) => Ok(()),
        Err((StatusCode::NOT_FOUND, _)) => Err(json_err(
            StatusCode::FORBIDDEN,
            json!({
                "error": "session_access_denied",
                "message": "Session not found or not visible for this tenant",
            }),
        )),
        Err((st, body)) => Err(json_err(st, body)),
    }
}

pub async fn wc_proxy_status(State(_s): State<SharedState>) -> impl IntoResponse {
    let health_ok = witnessctl_health_proxy_configured();
    let api_ok = witnessctl_api_proxy_configured();
    let upstream_health = if health_ok {
        crate::services::plugin_upstream_probe::witnessctl_upstream_reachable().await
    } else {
        None
    };
    Json(json!({
        "ok": api_ok,
        "health_proxy_configured": health_ok,
        "api_proxy_configured": api_ok,
        "upstream_reachable": upstream_health,
        "hint": "Use CONNECTOR_WITNESSCTL_MANAGEMENT_URL + CONNECTOR_WITNESSCTL_ADMIN_TOKEN; dashboard calls GET /api/v1/plugins/witnessctl/*."
    }))
    .into_response()
}

pub async fn wc_get_health(
    State(_s): State<SharedState>,
    RawQuery(q): RawQuery,
) -> impl IntoResponse {
    match forward_path_no_auth("health", q.as_deref()).await {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn wc_get_sessions(
    State(state): State<SharedState>,
    RawQuery(q): RawQuery,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    match forward_api_v1(
        &state,
        &headers,
        reqwest::Method::GET,
        "sessions",
        q.as_deref(),
        None,
        extract_tenant_wc(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn wc_get_session(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if uuid::Uuid::parse_str(&id).is_err() {
        return json_err(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_session_id", "message": "Expected UUID session id" }),
        );
    }
    match forward_api_v1(
        &state,
        &headers,
        reqwest::Method::GET,
        &format!("sessions/{id}"),
        None,
        None,
        extract_tenant_wc(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn wc_post_session(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    match forward_api_v1(
        &state,
        &headers,
        reqwest::Method::POST,
        "sessions",
        None,
        Some(body),
        extract_tenant_wc(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn wc_post_session_seal(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if uuid::Uuid::parse_str(&id).is_err() {
        return json_err(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_session_id", "message": "Expected UUID session id" }),
        );
    }
    match forward_api_v1(
        &state,
        &headers,
        reqwest::Method::POST,
        &format!("sessions/{id}/seal"),
        None,
        Some(body),
        extract_tenant_wc(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn wc_post_ingest(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    match forward_api_v1(
        &state,
        &headers,
        reqwest::Method::POST,
        "ingest",
        None,
        Some(body),
        extract_tenant_wc(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn wc_get_compliance(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if uuid::Uuid::parse_str(&session_id).is_err() {
        return json_err(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_session_id", "message": "Expected UUID session id" }),
        );
    }
    match forward_api_v1(
        &state,
        &headers,
        reqwest::Method::GET,
        &format!("compliance/{session_id}"),
        None,
        None,
        extract_tenant_wc(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn wc_get_hitl(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if uuid::Uuid::parse_str(&session_id).is_err() {
        return json_err(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_session_id", "message": "Expected UUID session id" }),
        );
    }
    match forward_api_v1(
        &state,
        &headers,
        reqwest::Method::GET,
        &format!("compliance/{session_id}/hitl"),
        None,
        None,
        extract_tenant_wc(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

/// POST /plugins/witnessctl/compliance/:session_id/hitl — create HITL item.
pub async fn wc_post_hitl(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if uuid::Uuid::parse_str(&session_id).is_err() {
        return json_err(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_session_id", "message": "Expected UUID session id" }),
        );
    }
    match forward_api_v1(
        &state,
        &headers,
        reqwest::Method::POST,
        &format!("compliance/{session_id}/hitl"),
        None,
        Some(body),
        extract_tenant_wc(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

/// POST /plugins/witnessctl/compliance/:session_id/hitl/:item_id/resolve
pub async fn wc_post_hitl_resolve(
    State(state): State<SharedState>,
    Path((session_id, item_id)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if uuid::Uuid::parse_str(&session_id).is_err() {
        return json_err(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_session_id", "message": "Expected UUID session id" }),
        );
    }
    if item_id.trim().is_empty() {
        return json_err(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_item_id", "message": "HITL item id required" }),
        );
    }
    match forward_api_v1(
        &state,
        &headers,
        reqwest::Method::POST,
        &format!("compliance/{session_id}/hitl/{item_id}/resolve"),
        None,
        Some(body),
        extract_tenant_wc(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn wc_get_custody_status(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if uuid::Uuid::parse_str(&session_id).is_err() {
        return json_err(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_session_id", "message": "Expected UUID session id" }),
        );
    }
    match forward_api_v1(
        &state,
        &headers,
        reqwest::Method::GET,
        &format!("custody/{session_id}/status"),
        None,
        None,
        extract_tenant_wc(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn wc_get_pentest_decisions(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if uuid::Uuid::parse_str(&session_id).is_err() {
        return json_err(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_session_id", "message": "Expected UUID session id" }),
        );
    }
    match forward_api_v1(
        &state,
        &headers,
        reqwest::Method::GET,
        &format!("pentest/{session_id}/decisions"),
        None,
        None,
        extract_tenant_wc(&headers),
    )
    .await
    {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

// ── Binary-forwarding handlers (PDF / HTML evidence exports) ────────
//
// WitnessCtl's `/api/v1/export/:session_id` and `/api/v1/report/...`
// endpoints return binary or text bodies (`application/pdf`,
// `text/html`, `text/markdown`, `text/csv`, `application/json`), not
// the JSON envelope the other proxies forward. We forward those bytes
// through with their upstream `Content-Type` + `Content-Disposition`
// preserved so the browser's PDF viewer renders them inline and the
// `Download` button sees the right filename.

async fn forward_api_v1_bytes(
    headers: &axum::http::HeaderMap,
    tail: &str,
    query: Option<&str>,
    default_filename: &str,
    tenant_id: Option<&str>,
) -> axum::response::Response {
    let base = match wc_base() {
        Some(b) => b,
        None => {
            return json_err(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({
                    "error": "witnessctl_proxy_unconfigured",
                    "message": "Set CONNECTOR_WITNESSCTL_MANAGEMENT_URL on the platform process.",
                }),
            );
        }
    };
    let token = match wc_admin_token() {
        Some(t) => t,
        None => {
            return json_err(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({
                    "error": "witnessctl_proxy_missing_token",
                    "message": "Set CONNECTOR_WITNESSCTL_ADMIN_TOKEN to forward evidence exports.",
                }),
            );
        }
    };
    let tenant_id = tenant_id
        .map(str::to_string)
        .or_else(|| crate::substrate::outbound::verified_tenant_id(headers));
    let tail = tail.trim_start_matches('/');
    let mut q = query_suffix(query);
    if let Some(tid) = tenant_id.as_deref() {
        if q.is_empty() {
            q = format!("?tenant_id={}", urlencoding::encode(tid));
        } else {
            q = format!("{q}&tenant_id={}", urlencoding::encode(tid));
        }
    }
    let url = format!("{}/api/v1/{}{}", base, tail, q);
    let req = http_client()
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header(
            "Accept",
            "application/pdf, text/html, text/markdown, text/csv, application/json",
        );
    let req = crate::substrate::outbound::stamp_reqwest(req, headers);
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return json_err(
                StatusCode::BAD_GATEWAY,
                json!({ "error": "witnessctl_upstream_error", "message": e.to_string() }),
            );
        }
    };
    let status = resp.status();
    let upstream_ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let upstream_cd = resp
        .headers()
        .get(reqwest::header::CONTENT_DISPOSITION)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return json_err(
                StatusCode::BAD_GATEWAY,
                json!({ "error": "witnessctl_read_body", "message": e.to_string() }),
            );
        }
    };
    if !status.is_success() {
        // Try to surface a structured error envelope. The upstream
        // returns JSON for failures.
        let text = String::from_utf8_lossy(&bytes).to_string();
        let json_body: Value = serde_json::from_str(&text).unwrap_or(json!({
            "upstream_status": status.as_u16(),
            "raw": text.chars().take(2000).collect::<String>()
        }));
        return json_err(
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            json!({
                "error": "witnessctl_upstream_http",
                "upstream_status": status.as_u16(),
                "body": json_body,
            }),
        );
    }
    // If the upstream didn't supply a `Content-Disposition`, synthesise
    // one from the default filename so the browser's download tray gets
    // a sensible name.
    let disposition =
        upstream_cd.unwrap_or_else(|| format!("inline; filename=\"{default_filename}\""));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        upstream_ct
            .parse()
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        disposition
            .parse()
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("inline")),
    );
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    (StatusCode::OK, headers, bytes).into_response()
}

/// `GET /plugins/witnessctl/sessions/:session_id/iia-join`
///
/// Platform-side IIA join for a WitnessCtl session hint (or UUID): compliance
/// contract digests + universal envelope IDs. Does not require WitnessCtl upstream.
pub async fn wc_get_session_iia_join(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if crate::services::agents::caller(&headers).is_none()
        && headers.get(axum::http::header::AUTHORIZATION).is_none()
    {
        return json_err(
            StatusCode::UNAUTHORIZED,
            json!({ "error": "auth_required" }),
        );
    }
    let join = crate::kernel::forensic_rollups::witnessctl_export_join(state.as_ref(), &session_id);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "schema": "connector.witnessctl_iia_join.v2",
            "session_id": session_id,
            "join": join,
            "forensic_package_hint": "GET /api/v1/forensics/package?agent_pid=",
            "honesty": "IIA digests are court-tier when signing_tier=ed25519_court; WitnessCtl remains SoT for framework evaluation",
        })),
    )
        .into_response()
}

/// Forward `GET /api/v1/export/:session_id?format=pdf|html|md|csv|json`.
///
/// This is the WitnessCtl "session evidence" export — a full audit
/// dossier for one session in the requested format.
pub async fn wc_get_session_export(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
    RawQuery(q): RawQuery,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if uuid::Uuid::parse_str(&session_id).is_err() {
        return json_err(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_session_id", "message": "Expected UUID session id" }),
        );
    }
    if let Err(resp) = wc_assert_session_access(&state, &session_id, &headers).await {
        return resp;
    }
    let fmt = extract_format(q.as_deref()).unwrap_or_else(|| "pdf".to_string());
    let filename = format!("witnessctl-session-{}.{}", session_id, fmt);
    forward_api_v1_bytes(
        &headers,
        &format!("export/{session_id}"),
        q.as_deref(),
        &filename,
        extract_tenant_wc(&headers),
    )
    .await
}

/// Forward `GET /api/v1/report/:session_id?framework=...&format=pdf|html`.
///
/// The single-framework compliance report (HIPAA, SOC2, …) for a
/// witness session. Per-framework filename so saved files don't
/// collide.
pub async fn wc_get_session_report(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
    RawQuery(q): RawQuery,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if uuid::Uuid::parse_str(&session_id).is_err() {
        return json_err(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_session_id", "message": "Expected UUID session id" }),
        );
    }
    if let Err(resp) = wc_assert_session_access(&state, &session_id, &headers).await {
        return resp;
    }
    let fmt = extract_format(q.as_deref()).unwrap_or_else(|| "pdf".to_string());
    let fw = extract_param(q.as_deref(), "framework").unwrap_or_else(|| "all".to_string());
    let filename = format!("witnessctl-report-{session_id}-{fw}.{fmt}");
    forward_api_v1_bytes(
        &headers,
        &format!("report/{session_id}"),
        q.as_deref(),
        &filename,
        extract_tenant_wc(&headers),
    )
    .await
}

/// Forward `GET /api/v1/report/:session_id/batch?frameworks=...&format=pdf`.
///
/// Multi-framework manifest report. Same plumbing as the single-
/// framework variant — the path tail is the only difference.
pub async fn wc_get_session_report_batch(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
    RawQuery(q): RawQuery,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if uuid::Uuid::parse_str(&session_id).is_err() {
        return json_err(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_session_id", "message": "Expected UUID session id" }),
        );
    }
    if let Err(resp) = wc_assert_session_access(&state, &session_id, &headers).await {
        return resp;
    }
    let fmt = extract_format(q.as_deref()).unwrap_or_else(|| "pdf".to_string());
    let filename = format!("witnessctl-report-{session_id}-batch.{fmt}");
    forward_api_v1_bytes(
        &headers,
        &format!("report/{session_id}/batch"),
        q.as_deref(),
        &filename,
        extract_tenant_wc(&headers),
    )
    .await
}

/// Parse a single query parameter without pulling in a full URL crate.
/// Returns the first occurrence of `name=...` as a decoded String.
fn extract_param(query: Option<&str>, name: &str) -> Option<String> {
    let q = query?;
    for pair in q.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next()?;
        if k == name {
            let raw = it.next().unwrap_or("");
            return Some(percent_decode_simple(raw));
        }
    }
    None
}

fn extract_format(query: Option<&str>) -> Option<String> {
    extract_param(query, "format").map(|s| {
        s.trim()
            .trim_matches('"')
            .to_ascii_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect()
    })
}

/// Minimal percent-decoder for `+` and `%XX`. Covers the only two
/// query values we actually consume (`format=...`, `framework=...`).
fn percent_decode_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'+' {
            out.push(' ');
            i += 1;
        } else if b == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h * 16 + l) as u8) as char);
                i += 3;
                continue;
            }
            out.push(b as char);
            i += 1;
        } else {
            out.push(b as char);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_format_lowercases_and_strips_quotes() {
        assert_eq!(
            extract_format(Some("framework=hipaa&format=PDF")),
            Some("pdf".to_string())
        );
        assert_eq!(
            extract_format(Some("format=%22pdf%22")),
            Some("pdf".to_string())
        );
        assert_eq!(extract_format(None), None);
    }

    #[test]
    fn extract_param_returns_framework() {
        assert_eq!(
            extract_param(Some("framework=soc2&format=pdf"), "framework"),
            Some("soc2".to_string())
        );
        assert_eq!(
            extract_param(Some("framework=eu+ai+act"), "framework"),
            Some("eu ai act".to_string())
        );
    }

    #[test]
    fn percent_decode_handles_unicode_escapes() {
        assert_eq!(percent_decode_simple("a%20b%2bc"), "a b+c");
        assert_eq!(percent_decode_simple("plain"), "plain");
        assert_eq!(percent_decode_simple("a+b"), "a b");
    }
}
