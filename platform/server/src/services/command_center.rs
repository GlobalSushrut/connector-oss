//! Thin read aggregators for operator UIs (single round-trip optional).
//! Granular routes remain the source of truth for SOC / exports.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::auth::{verify_token, PlatformRole};
use crate::state::SharedState;
use vac_core::types::{MemoryKernelOp, OpOutcome};

fn caller(headers: &HeaderMap) -> Option<(String, PlatformRole)> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Some(("dev".to_string(), PlatformRole::SuperAdmin));
    }
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|h| h.to_str().ok()))?;
    let claims = verify_token(token).ok()?;
    Some((claims.sub, PlatformRole::from_str(&claims.role)))
}

/// GET /command-center/snapshot — authenticated; operator+ sees 24h policy denials slice.
pub async fn snapshot(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let Some((_sub, role)) = caller(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Authentication required", "status": 401})),
        )
            .into_response();
    };

    let agents = {
        let k = state.kernel.lock().unwrap();
        k.agents()
            .iter()
            .take(48)
            .map(|(pid, acb)| {
                json!({
                    "pid": pid,
                    "namespace": acb.namespace,
                    "status": format!("{:?}", acb.status),
                })
            })
            .collect::<Vec<_>>()
    };

    let violations = if role.rank() >= 4 {
        let k = state.kernel.lock().unwrap();
        let cutoff = chrono::Utc::now().timestamp_millis() - 86_400_000;
        let v: Vec<_> = k
            .audit_log()
            .iter()
            .filter(|e| e.timestamp >= cutoff && e.outcome == OpOutcome::Denied)
            .take(32)
            .map(|e| {
                json!({
                    "audit_id": e.audit_id,
                    "timestamp": e.timestamp,
                    "operation": format!("{:?}", e.operation),
                    "agent_pid": e.agent_pid,
                    "reason": e.reason,
                })
            })
            .collect();
        json!(v)
    } else {
        json!(null)
    };

    let pending_approvals = {
        let k = state.kernel.lock().unwrap();
        k.audit_log()
            .iter()
            .filter(|e| {
                e.operation == MemoryKernelOp::ToolDispatch && e.outcome == OpOutcome::Skipped
            })
            .take(24)
            .map(|e| {
                json!({
                    "audit_id": e.audit_id,
                    "agent_pid": e.agent_pid,
                    "tool": e.target,
                    "reason": e.reason,
                })
            })
            .collect::<Vec<_>>()
    };

    let recent_actions = {
        let aapi = state.aapi.lock().unwrap();
        aapi.list_actions(None)
            .iter()
            .take(25)
            .map(|a| {
                json!({
                    "agent_pid": a.agent_pid,
                    "action": a.action,
                    "timestamp": a.timestamp,
                })
            })
            .collect::<Vec<_>>()
    };

    Json(json!({
        "ok": true,
        "data": {
            "agents": agents,
            "violations": violations,
            "violations_gated": role.rank() < 4,
            "pending_approvals": pending_approvals,
            "recent_actions": recent_actions,
            "note": "Aggregated view; use GET /agents, /compliance/policy-violations, /tools/approvals/pending, /actionlog/actions for full contracts."
        }
    }))
    .into_response()
}
