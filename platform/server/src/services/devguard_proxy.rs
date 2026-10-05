//! Proxy DevGuard **extension status API** through the Connector platform.
//!
//! Workstations run `devguard status-api` (or equivalent) exposing `GET /devguard/status` and
//! `GET /devguard/audit/:session_id` without browser access to loopback.
//!
//! ## Environment
//! - `CONNECTOR_DEVGUARD_MANAGEMENT_URL` or `DEVGUARD_MANAGEMENT_URL` — base URL of the status API (no trailing slash).

use axum::{
    extract::{Path, RawQuery, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::{json, Value};
use std::time::Duration;

use crate::state::SharedState;

fn dg_base() -> Option<String> {
    crate::services::plugin_upstream_probe::devguard_management_url()
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .connect_timeout(Duration::from_secs(4))
        .build()
        .expect("devguard proxy reqwest client")
}

fn query_suffix(query: Option<&str>) -> String {
    query
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| format!("?{s}"))
        .unwrap_or_default()
}

async fn forward_get(path: &str, query: Option<&str>) -> Result<Value, (StatusCode, Value)> {
    let base = dg_base().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        json!({
            "error": "devguard_proxy_unconfigured",
            "message": "Set CONNECTOR_DEVGUARD_MANAGEMENT_URL or DEVGUARD_MANAGEMENT_URL on the platform process.",
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
                json!({ "error": "devguard_upstream_error", "message": e.to_string() }),
            )
        })?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            json!({ "error": "devguard_read_body", "message": e.to_string() }),
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
                "error": "devguard_upstream_http",
                "upstream_status": status.as_u16(),
                "body": body
            }),
        ));
    }
    Ok(body)
}

fn json_err(status: StatusCode, body: Value) -> axum::response::Response {
    (status, Json(body)).into_response()
}

pub async fn dg_extension_status(
    State(_s): State<SharedState>,
    RawQuery(q): RawQuery,
) -> impl IntoResponse {
    match forward_get("devguard/status", q.as_deref()).await {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn dg_extension_audit(
    State(_s): State<SharedState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let sid = session_id.trim();
    if sid.is_empty() || sid.len() > 256 {
        return json_err(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid_session_id", "message": "session_id required" }),
        );
    }
    match forward_get(&format!("devguard/audit/{sid}"), None).await {
        Ok(v) => Json(v).into_response(),
        Err((st, b)) => json_err(st, b),
    }
}

pub async fn dg_proxy_status(State(state): State<SharedState>) -> impl IntoResponse {
    let cfg = dg_base().is_some();
    let up = if cfg {
        crate::services::plugin_upstream_probe::devguard_upstream_reachable().await
    } else {
        None
    };
    let playground = crate::services::runtime_control::free_tier_open_auth_enabled();
    let local_profile_saved = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("devguard_local_profile", "singleton")
            .ok()
            .flatten()
            .is_some()
    };
    // DG-08: saved local-profile JSON must never alone produce ok/embedded/healthy.
    // Playground may still report embedded availability for trial UX.
    let embedded_ok = playground;
    let ok = cfg || embedded_ok;
    let mode = if cfg {
        "proxy"
    } else if embedded_ok {
        "embedded"
    } else {
        "unconfigured"
    };
    // Measured readiness: critical bind → attach → admit → guard paths present in the
    // shared contract (must stay aligned with router mounts; see contract↔router test).
    let kernel_contract = crate::services::devguard::devguard_http_contract();
    let required = [
        "/api/v1/devguard/connect",
        "/api/v1/devguard/sessions",
        "/api/v1/devguard/admit",
        "/api/v1/devguard/fs/check",
        "/api/v1/devguard/exec/check",
        "/api/v1/devguard/github/checks/evaluate",
    ];
    let kernel_routes_ready = required.iter().all(|need| {
        kernel_contract.iter().any(|(_, p)| *p == *need)
    });
    let github_app_publish = false;
    Json(json!({
        "ok": ok,
        "mode": mode,
        "extension_proxy_configured": cfg,
        "embedded_mode": embedded_ok,
        "local_profile_saved": local_profile_saved,
        "local_profile_enforces": false,
        "kernel_routes_ready": kernel_routes_ready,
        "kernel_routes_required": required,
        "kernel_contract_paths": kernel_contract.len(),
        "github_check_publish": github_app_publish,
        "upstream_reachable": up,
        "sessions_endpoint": "/api/v1/devguard/sessions",
        "connect_endpoint":  "/api/v1/devguard/connect",
        "github_status_endpoint": "/api/v1/devguard/github/status",
        "guardrails": {
            "honesty": "Guardrail labels below describe kernel capabilities when a cg_ session is active — not that a saved local-profile alone is enforcing.",
            "injection_protection": if ok { "available" } else { "unconfigured" },
            "hallucination_filter": if ok { "available" } else { "unconfigured" },
            "pii_scrub": if ok { "available" } else { "unconfigured" },
            "policy_engine": if ok { "available" } else { "unconfigured" }
        },
        "hint": if cfg {
            "External DevGuard management URL configured; extension proxy active when upstream is reachable."
        } else if embedded_ok {
            "Playground/embedded mode: kernel DevGuard routes are available. Bind a repo, attach an agent for a cg_ token. A saved local-profile alone is not enforcement."
        } else if local_profile_saved {
            "Local profile saved (onboarding config only). DevGuard is not healthy from that alone — attach an agent or configure CONNECTOR_DEVGUARD_MANAGEMENT_URL. Use POST /devguard/connect then /repos/:id/agents."
        } else {
            "Point CONNECTOR_DEVGUARD_MANAGEMENT_URL at the workstation status-api bind address for external proxy mode, or use kernel POST /devguard/connect."
        }
    }))
    .into_response()
}
