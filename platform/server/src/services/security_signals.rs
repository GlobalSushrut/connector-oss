//! CONT-02 — Operator-visible security / control-plane signals.
//!
//! Aggregates auth-bypass flags, DLQ growth, revoked-token pressure, and
//! isolation downgrade hints. Does not page by itself — feeds alerts/dashboards.

use axum::{extract::State, http::HeaderMap, Json};
use serde_json::{json, Value};

use crate::auth::{verify_token, PlatformRole};
use crate::state::SharedState;

fn caller_admin(headers: &HeaderMap) -> bool {
    let auth = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(a) => a,
        None => return false,
    };
    let token = auth.strip_prefix("Bearer ").unwrap_or(auth).trim();
    verify_token(token)
        .ok()
        .map(|c| PlatformRole::from_str(&c.role).rank() >= PlatformRole::Admin.rank())
        .unwrap_or(false)
}

/// GET /api/v1/security/signals — admin+ control-plane signal board.
pub async fn get_security_signals(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<Value> {
    if !caller_admin(&headers) && !crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Json(json!({
            "ok": false,
            "error": "admin_required",
            "status": 403,
        }));
    }

    let bypass = json!({
        "dev_auth_bypass": crate::services::runtime_control::dev_auth_bypass_allowed(),
        "free_tier_open_auth": crate::services::runtime_control::free_tier_open_auth_enabled(),
        "playground": crate::services::playground::is_playground_mode(),
        "gateway_anon_ban": crate::services::gateway::gateway_anon_ban_enabled(),
        "severity": if crate::services::runtime_control::dev_auth_bypass_allowed()
            || crate::services::runtime_control::free_tier_open_auth_enabled()
        {
            "critical"
        } else {
            "info"
        },
        "signal": "auth_bypass_flags",
    });

    let (webhook_dlq, webhook_queued, revoked_token_hits, hitl_pending, plugin_quarantined) = {
        let es = match state.engine_store.lock() {
            Ok(g) => g,
            Err(_) => {
                return Json(json!({
                    "ok": false,
                    "error": "engine_store_lock_poisoned",
                    "status": 503,
                }));
            }
        };
        let mut dlq = 0usize;
        let mut queued = 0usize;
        for k in es.folder_keys("webhook_retry", None).unwrap_or_default() {
            if let Ok(Some(v)) = es.folder_get("webhook_retry", &k) {
                match v.get("status").and_then(|s| s.as_str()) {
                    Some("dead_letter") => dlq += 1,
                    Some("queued") => queued += 1,
                    _ => {}
                }
            }
        }
        let revoked_hits = es
            .folder_keys("security_signal_events", None)
            .unwrap_or_default()
            .iter()
            .filter_map(|k| es.folder_get("security_signal_events", k).ok().flatten())
            .filter(|v| v.get("signal").and_then(|s| s.as_str()) == Some("revoked_token_use"))
            .count();
        let hitl = es
            .folder_keys("iia_hitl_requests", None)
            .unwrap_or_default()
            .iter()
            .filter_map(|k| es.folder_get("iia_hitl_requests", k).ok().flatten())
            .filter(|v| v.get("status").and_then(|s| s.as_str()) == Some("pending"))
            .count();
        let quarantined = es
            .folder_keys("plugin_crash_recovery", None)
            .unwrap_or_default()
            .iter()
            .filter_map(|k| es.folder_get("plugin_crash_recovery", k).ok().flatten())
            .filter(|v| {
                v.get("quarantined")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false)
            })
            .count();
        (dlq, queued, revoked_hits, hitl, quarantined)
    };

    let isolation = json!({
        "signal": "isolation_downgrade",
        "microvm_tier_file": crate::services::plugin_tier_scheduler::microvm_tier_state_file_path_from_env(),
        "honesty": "Production microVM intent may downgrade — check plugin tier scheduler / substrate status",
        "severity": "warning",
    });

    let signals = vec![
        bypass,
        json!({
            "signal": "webhook_dlq_growth",
            "dead_letter": webhook_dlq,
            "queued": webhook_queued,
            "severity": if webhook_dlq > 0 { "high" } else { "info" },
        }),
        json!({
            "signal": "revoked_token_use",
            "count": revoked_token_hits,
            "severity": if revoked_token_hits > 0 { "high" } else { "info" },
        }),
        json!({
            "signal": "hitl_pending",
            "count": hitl_pending,
            "severity": if hitl_pending > 10 { "high" } else if hitl_pending > 0 { "medium" } else { "info" },
        }),
        json!({
            "signal": "plugin_quarantine",
            "quarantined_plugins": plugin_quarantined,
            "severity": if plugin_quarantined > 0 { "high" } else { "info" },
        }),
        isolation,
    ];

    let critical = signals
        .iter()
        .filter(|s| s.get("severity").and_then(|x| x.as_str()) == Some("critical"))
        .count();
    let high = signals
        .iter()
        .filter(|s| s.get("severity").and_then(|x| x.as_str()) == Some("high"))
        .count();

    Json(json!({
        "ok": true,
        "schema": "connector.security_signals.v1",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "summary": { "critical": critical, "high": high, "total": signals.len() },
        "signals": signals,
        "honesty": "CONT-02 — signal board for operators; wire to pager/alerting separately",
    }))
}

/// Record a security signal event (e.g. revoked token presentation).
pub fn record_signal(state: &SharedState, signal: &str, detail: Value) {
    let id = format!("{}_{}", signal, uuid::Uuid::new_v4().as_simple());
    let rec = json!({
        "signal": signal,
        "detail": detail,
        "at": chrono::Utc::now().to_rfc3339(),
    });
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put("security_signal_events", &id, &rec);
    }
}
