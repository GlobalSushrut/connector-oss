//! AMA-5: PolicyCheck endpoint — access(2) syscall analog for agents.
//!
//! Agents can pre-check if an action is allowed before attempting it.
//! No audit entry is written on success (zero cost, like POSIX access(2)).
//!
//! Routes:
//!   POST /agents/{pid}/policy/check — body: { operation, resource } → { allowed, reason }

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;

use crate::state::SharedState;
use vac_core::kernel::{SyscallPayload, SyscallRequest, SyscallValue};
use vac_core::types::OpOutcome;

#[derive(Debug, Deserialize)]
pub struct PolicyCheckRequest {
    /// Operation name: ToolDispatch, MemRead, MemWrite, AccessGrant, etc.
    pub operation: String,
    /// Resource being accessed: namespace path, tool URI, agent PID, etc.
    pub resource: String,
}

/// POST /agents/{pid}/policy/check
///
/// Runs MAC + execution-policy dry-run. Returns allowed/denied + reason.
/// No audit entry created on allowed result (access(2) semantics).
pub async fn policy_check(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Json(req): Json<PolicyCheckRequest>,
) -> Json<serde_json::Value> {
    if req.operation.is_empty() {
        return Json(serde_json::json!({
            "ok": false,
            "error": {"code": "operation_required", "message": "operation field is required"}
        }));
    }

    // Parse operation into MemoryKernelOp
    let op: vac_core::MemoryKernelOp = match serde_json::from_value(serde_json::Value::String(
        req.operation.to_lowercase(),
    )) {
        Ok(o) => o,
        Err(_) => {
            return Json(serde_json::json!({
                "ok": false,
                "allowed": false,
                "reason": "unknown_operation",
                "detail": format!("'{}' is not a recognised MemoryKernelOp", req.operation),
                "valid_examples": ["tool_dispatch", "mem_read", "mem_write", "access_grant", "agent_register"],
            }));
        }
    };

    // Dispatch PolicyCheck syscall to kernel
    let result = {
        let mut kernel = state.kernel.lock().unwrap();
        kernel.dispatch(SyscallRequest {
            operation: vac_core::MemoryKernelOp::PolicyCheck,
            agent_pid: pid.clone(),
            payload: SyscallPayload::PolicyCheck {
                operation: op,
                resource: req.resource.clone(),
            },
            reason: Some("policy_check_api".to_string()),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        })
    };

    let allowed = result.outcome == OpOutcome::Success;
    let detail = match &result.value {
        SyscallValue::Json(v) => v.clone(),
        SyscallValue::Error(e) => serde_json::json!({"error": e}),
        _ => serde_json::json!({}),
    };

    Json(serde_json::json!({
        "ok": true,
        "agent_pid": pid,
        "operation": req.operation,
        "resource": req.resource,
        "allowed": allowed,
        "reason": result.audit_entry.reason,
        "detail": detail,
    }))
}
