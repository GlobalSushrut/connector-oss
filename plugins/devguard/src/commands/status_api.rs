use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use std::{collections::{HashMap, HashSet}, sync::Arc};
use tokio::sync::Mutex;

use crate::connector_client::ConnectorClient;

#[derive(Clone)]
pub struct StatusApiState {
    client: ConnectorClient,
    session_hint: Option<String>,
    config_path: String,
    request_rate_limit: Arc<Mutex<HashMap<String, Vec<i64>>>>,
}

#[derive(Debug, Deserialize)]
struct StatusQuery {
    session: Option<String>,
}

pub async fn serve(
    client: ConnectorClient,
    session_hint: Option<String>,
    host: &str,
    port: u16,
    config_path: String,
) -> Result<()> {
    let state = Arc::new(StatusApiState {
        client,
        session_hint,
        config_path,
        request_rate_limit: Arc::new(Mutex::new(HashMap::new())),
    });
    let rl_state = state.clone();
    let app = Router::new()
        .route("/devguard/status", get(status_handler))
        .route("/devguard/audit/:session_id", get(audit_handler))
        .route_layer(middleware::from_fn_with_state(rl_state, rate_limit_middleware))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port)).await?;
    println!("DevGuard extension status API listening on http://{}:{}/devguard/status", host, port);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn rate_limit_middleware(
    State(state): State<Arc<StatusApiState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    if !path.starts_with("/devguard/status") && !path.starts_with("/devguard/audit") {
        return next.run(req).await;
    }
    let ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let now = chrono::Utc::now().timestamp();
    let mut limiter = state.request_rate_limit.lock().await;
    let window = limiter.entry(ip).or_default();
    window.retain(|ts| now - *ts <= 60);
    if window.len() >= 60 {
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "Too many requests",
                "message": "Rate limit exceeded: 60 requests per minute per IP"
            })),
        )
            .into_response();
        response
            .headers_mut()
            .insert("Retry-After", HeaderValue::from_static("60"));
        return response;
    }
    window.push(now);
    drop(limiter);
    next.run(req).await
}

async fn status_handler(
    State(state): State<Arc<StatusApiState>>,
    Query(query): Query<StatusQuery>,
) -> Json<serde_json::Value> {
    let session_filter = query.session.or_else(|| state.session_hint.clone());
    let mut current_session = serde_json::json!(null);
    let mut active_role = serde_json::json!(null);
    let mut pending_approvals = 0usize;
    let mut last_blocked_action: Option<String> = None;
    let mut budget_remaining = serde_json::json!(null);

    if let Ok(sessions) = state.client.session_list().await {
        let arr = sessions.get("sessions").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let selected = if let Some(ref sid) = session_filter {
            arr.iter().find(|s| s.get("session_id").and_then(|v| v.as_str()) == Some(sid))
        } else {
            arr.iter().find(|s| s.get("active").and_then(|v| v.as_bool()).unwrap_or(false))
        };
        if let Some(sess) = selected {
            current_session = sess.get("session_id").cloned().unwrap_or(serde_json::json!(null));
            active_role = sess.get("role").cloned().unwrap_or(serde_json::json!(null));
            if let Some(sid) = sess.get("session_id").and_then(|v| v.as_str()) {
                if let Ok(trail) = state.client.audit_trail(sid).await {
                    let entries = trail.get("entries").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                    let mut created = HashSet::new();
                    let mut resolved = HashSet::new();
                    for e in &entries {
                        let details = e.get("details").cloned().unwrap_or_default();
                        let typ = details.get("type").or_else(|| e.get("type")).and_then(|v| v.as_str()).unwrap_or("");
                        let aid = details.get("approval_id").or_else(|| e.get("approval_id")).and_then(|v| v.as_str()).unwrap_or("");
                        if typ == "approval.created" && !aid.is_empty() {
                            created.insert(aid.to_string());
                        }
                        if (typ == "approval.approved" || typ == "approval.rejected" || typ == "approval.expired")
                            && !aid.is_empty()
                        {
                            resolved.insert(aid.to_string());
                        }
                        let action = e.get("action").and_then(|v| v.as_str()).unwrap_or("");
                        if (action.contains("deny") || typ.contains("rejected"))
                            && last_blocked_action.is_none()
                        {
                            last_blocked_action = Some(action.to_string());
                        }
                    }
                    pending_approvals = created.into_iter().filter(|id| !resolved.contains(id)).count();
                }
            }

            // Budget remaining from local config role budget minus observed tokens.
            let tokens_used = sess
                .get("stats")
                .and_then(|s| s.get("tokens_consumed"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if let Some(role_name) = sess.get("role").and_then(|v| v.as_str()) {
                if let Ok(cfg) = crate::config::DevGuardConfig::load(&state.config_path) {
                    if let Some(role) = cfg.roles.get(role_name) {
                        if role.budget.max_tokens_per_task > 0 {
                            let rem = role.budget.max_tokens_per_task.saturating_sub(tokens_used);
                            budget_remaining = serde_json::json!({
                                "tokens_remaining": rem,
                                "max_tokens_per_task": role.budget.max_tokens_per_task
                            });
                        }
                    }
                }
            }
        }
    }

    let workspace = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| ".".into());
    let ws = std::path::Path::new(&workspace);
    let hooks = ws.join(".git/hooks/pre-commit").exists() || ws.join(".git/hooks/pre-push").exists();
    let watchdog = crate::commands::connect::watchdog_alive(ws);
    let heartbeat_fresh = crate::commands::connect::watchdog_heartbeat_fresh(ws, 10);
    let exec_wrapper = ws.join(".devguard/exec_wrapper.sh").exists();
    let file_perms = ws.join(".devguard/saved_perms.json").exists();
    let preload = std::env::var("LD_PRELOAD")
        .map(|v| v.contains("devguard") || v.contains("connector"))
        .unwrap_or(false);
    let cage_json = ws.join(".devguard/cage.json").exists();
    let enforcement_mode = crate::commands::connect::detect_enforcement_mode(&workspace);
    let bypass = std::env::var("DEVGUARD_BYPASS")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    let required_missing = !hooks || !watchdog || !heartbeat_fresh || !exec_wrapper;
    let degraded = bypass || (cage_json && required_missing) || (watchdog && !heartbeat_fresh);
    let last_heartbeat_age_secs = {
        let hb_path = ws.join(".devguard/watchdog.heartbeat");
        std::fs::read_to_string(hb_path)
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .map(|ts| (chrono::Utc::now().timestamp() - ts).max(0))
    };

    Json(serde_json::json!({
        "current_session": current_session,
        "active_role": active_role,
        "pending_approvals_count": pending_approvals,
        "budget_remaining": budget_remaining,
        "last_blocked_action": last_blocked_action,
        "cage": {
            "layers": {
                "hooks": hooks,
                "watchdog": watchdog,
                "exec_wrapper": exec_wrapper,
                "file_perms": file_perms,
                "preload": preload,
                "cage_json": cage_json,
            },
            "last_heartbeat_age_secs": last_heartbeat_age_secs,
            "bypass": bypass,
            "enforcement_mode": enforcement_mode,
            "degraded": degraded,
            "honesty": "Layer flags are live probes of this workstation — not a claim that every process is caged.",
        },
    }))
}

async fn audit_handler(
    State(state): State<Arc<StatusApiState>>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let payload = state
        .client
        .audit_trail(&session_id)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(Json(payload))
}
