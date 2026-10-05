//! PROD-09 — Redacted diagnostic / support bundle for operators.
//!
//! Aggregates versions, readiness, policy fingerprints, queue health, and
//! recent signal IDs. Never includes secrets, API keys, or raw tokens.

use axum::{extract::State, http::HeaderMap, Json};
use serde_json::{json, Value};

use crate::auth::{verify_token, PlatformRole};
use crate::state::SharedState;

fn caller_role(headers: &HeaderMap) -> Option<PlatformRole> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ").unwrap_or(auth).trim();
    verify_token(token)
        .ok()
        .map(|c| PlatformRole::from_str(&c.role))
}

fn redact_host(url: &str) -> String {
    let trimmed = url.trim();
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    rest.split('/')
        .next()
        .unwrap_or("redacted")
        .split('@')
        .next_back()
        .unwrap_or("redacted")
        .split(':')
        .next()
        .unwrap_or("redacted")
        .to_string()
}

/// GET /api/v1/support/bundle — admin+ diagnostic snapshot (redacted).
pub async fn get_support_bundle(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<Value> {
    let role = match caller_role(&headers) {
        Some(r) if r.rank() >= PlatformRole::Admin.rank() => r,
        Some(_) => {
            return Json(json!({
                "ok": false,
                "error": "admin_required",
                "status": 403,
            }));
        }
        None => {
            return Json(json!({
                "ok": false,
                "error": "authentication_required",
                "status": 401,
            }));
        }
    };

    let deployment = crate::services::deployment::deployment_info_value(state.as_ref());

    let readiness = {
        let kernel_ok = state.kernel.lock().is_ok();
        let store_ok = state.engine_store.lock().is_ok();
        json!({
            "kernel_lock_ok": kernel_ok,
            "engine_store_lock_ok": store_ok,
            "llm_wired": state.llm_wired(),
            "playground": crate::services::runtime_control::free_tier_open_auth_enabled()
                || std::env::var("CONNECTOR_PLAYGROUND")
                    .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true"))
                    .unwrap_or(false),
        })
    };

    let (webhook_retry_queued, webhook_retry_dlq, hitl_pending, workflow_enabled) = {
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
        let retry_keys = es.folder_keys("webhook_retry", None).unwrap_or_default();
        let mut queued = 0usize;
        let mut dlq = 0usize;
        for k in &retry_keys {
            if let Ok(Some(v)) = es.folder_get("webhook_retry", k) {
                match v.get("status").and_then(|s| s.as_str()) {
                    Some("queued") => queued += 1,
                    Some("dead_letter") => dlq += 1,
                    _ => {}
                }
            }
        }
        let hitl_keys = es
            .folder_keys("iia_hitl_requests", None)
            .unwrap_or_default();
        let hitl_pending = hitl_keys
            .iter()
            .filter_map(|k| es.folder_get("iia_hitl_requests", k).ok().flatten())
            .filter(|v| v.get("status").and_then(|s| s.as_str()) == Some("pending"))
            .count();
        let wf_keys = es
            .folder_keys(crate::services::workflow_runtime::WORKFLOW_FOLDER, None)
            .unwrap_or_default();
        let workflow_enabled = wf_keys
            .iter()
            .filter_map(|k| {
                es.folder_get(crate::services::workflow_runtime::WORKFLOW_FOLDER, k)
                    .ok()
                    .flatten()
            })
            .filter(|v| v.get("state").and_then(|s| s.as_str()) == Some("ENABLED"))
            .count();
        (queued, dlq, hitl_pending, workflow_enabled)
    };

    let policy_fingerprints = {
        let es = state.engine_store.lock().ok();
        let mut fps = Vec::new();
        if let Some(es) = es {
            let keys = es
                .folder_keys("devguard_policies", None)
                .unwrap_or_default();
            for k in keys.into_iter().take(50) {
                if let Ok(Some(v)) = es.folder_get("devguard_policies", &k) {
                    if let Some(id) = v.get("policy_bundle_id").and_then(|x| x.as_str()) {
                        fps.push(json!({ "agent_pid": k, "policy_bundle_id": id }));
                    }
                }
            }
        }
        fps
    };

    let recent_error_ids: Vec<Value> = {
        let k = state.kernel.lock().ok();
        k.map(|kernel| {
            kernel
                .audit_log()
                .iter()
                .rev()
                .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
                .take(25)
                .map(|e| {
                    json!({
                        "audit_id": e.audit_id,
                        "agent_pid": e.agent_pid,
                        "operation": format!("{:?}", e.operation),
                        "reason": e.reason,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
    };

    let env_flags = json!({
        "CONNECTOR_ENV": std::env::var("CONNECTOR_ENV").unwrap_or_else(|_| "(unset)".into()),
        "CONNECTOR_LLM_STUB": std::env::var("CONNECTOR_LLM_STUB").ok().map(|v| {
            if matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on") {
                "set"
            } else {
                "other"
            }
        }),
        "CONNECTOR_PLAYGROUND": std::env::var("CONNECTOR_PLAYGROUND").ok().map(|_| "set"),
        "management_url_hosts": {
            "devguard": std::env::var("CONNECTOR_DEVGUARD_MANAGEMENT_URL")
                .ok()
                .map(|u| redact_host(&u)),
            "witnessctl": std::env::var("CONNECTOR_WITNESSCTL_MANAGEMENT_URL")
                .ok()
                .map(|u| redact_host(&u)),
            "tracetramp": std::env::var("CONNECTOR_TRACETRAMP_MANAGEMENT_URL")
                .ok()
                .map(|u| redact_host(&u)),
        },
    });

    Json(json!({
        "ok": true,
        "schema": "connector.support_bundle.v1",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "requested_by_role": format!("{:?}", role),
        "deployment": deployment,
        "readiness": readiness,
        "queues": {
            "webhook_retry_queued": webhook_retry_queued,
            "webhook_retry_dead_letter": webhook_retry_dlq,
            "hitl_pending": hitl_pending,
            "workflows_enabled_count": workflow_enabled,
        },
        "policy_fingerprints": policy_fingerprints,
        "recent_denied_audit_ids": recent_error_ids,
        "env_flags_redacted": env_flags,
        "honesty": "Bundle omits secrets, raw tokens, and full payloads. Use for support triage only.",
    }))
}

#[cfg(test)]
mod tests {
    use super::redact_host;

    #[test]
    fn redact_host_keeps_hostname_only() {
        assert_eq!(
            redact_host("https://tt.example.com:9742/admin"),
            "tt.example.com"
        );
    }
}
