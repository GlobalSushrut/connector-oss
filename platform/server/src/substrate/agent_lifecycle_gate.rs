//! Unified agent lifecycle gate — the **only** platform path to kernel lifecycle syscalls.
//!
//! Combines intelligence authority policy, audit, and short-lived capability grants.
//! All `AgentStart` / `AgentSuspend` / `AgentResume` / `AgentTerminate` from
//! `platform/server` must go through this module.

use connector_trust::CapabilityGrantV2;
use serde_json::json;
use vac_core::kernel::{SyscallPayload, SyscallRequest, SyscallValue};
use vac_core::types::{MemoryKernelOp, OpOutcome};

use crate::auth::PlatformRole;
use crate::services::intelligence_authority::{
    self, LifecycleOp, LifecycleOpts,
};
use crate::state::SharedState;

pub const GRANTS_FOLDER: &str = "lifecycle_grants";
pub const SCHEMA: &str = "agent_lifecycle_gate.v1";

/// Who initiated a lifecycle transition.
#[derive(Debug, Clone)]
pub struct LifecycleActor {
    pub principal_id: String,
    pub role: PlatformRole,
    /// e.g. `http`, `mcp`, `system:shutdown`, `system:reaper`, `system:admission`
    pub source: String,
}

impl LifecycleActor {
    pub fn system(source: &str) -> Self {
        Self {
            principal_id: format!("system:{source}"),
            role: PlatformRole::SuperAdmin,
            source: format!("system:{source}"),
        }
    }

    pub fn operator(principal_id: impl Into<String>, role: PlatformRole, source: &str) -> Self {
        Self {
            principal_id: principal_id.into(),
            role,
            source: source.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LifecycleReceipt {
    pub outcome: OpOutcome,
    pub kernel_pid: String,
    pub api_pid: String,
    pub op: LifecycleOp,
    pub grant_id: Option<String>,
}

#[derive(Debug)]
pub enum LifecycleGateError {
    PolicyDenied(String),
    KernelMissing,
    KernelFailed(String),
}

impl LifecycleGateError {
    pub fn message(&self) -> String {
        match self {
            Self::PolicyDenied(m) => m.clone(),
            Self::KernelMissing => "agent not found in kernel".into(),
            Self::KernelFailed(m) => m.clone(),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::PolicyDenied(m) => json!({
                "ok": false,
                "error": "lifecycle_denied",
                "status": 403,
                "decision": "DENY",
                "reason": m,
            }),
            Self::KernelMissing => json!({
                "ok": false,
                "error": "agent_not_found",
                "status": 404,
            }),
            Self::KernelFailed(m) => json!({
                "ok": false,
                "error": "kernel_lifecycle_failed",
                "status": 500,
                "detail": m,
            }),
        }
    }
}

fn resolve_pids(state: &SharedState, pid_hint: &str) -> (String, String) {
    crate::services::agents::resolve_kernel_pid(state, pid_hint)
}

fn op_to_action(op: LifecycleOp) -> &'static str {
    match op {
        LifecycleOp::Start => "agent:lifecycle:start",
        LifecycleOp::Stop => "agent:lifecycle:stop",
        LifecycleOp::Pause => "agent:lifecycle:pause",
        LifecycleOp::Resume => "agent:lifecycle:resume",
        LifecycleOp::Freeze => "agent:lifecycle:freeze",
        LifecycleOp::Thaw => "agent:lifecycle:thaw",
        LifecycleOp::Quarantine => "agent:lifecycle:quarantine",
        LifecycleOp::Unquarantine => "agent:lifecycle:unquarantine",
        LifecycleOp::SignalSuspend => "agent:lifecycle:signal_suspend",
        LifecycleOp::SignalResume => "agent:lifecycle:signal_resume",
        LifecycleOp::SignalTerminate => "agent:lifecycle:signal_terminate",
    }
}

fn mint_lifecycle_grant(
    state: &SharedState,
    actor: &LifecycleActor,
    api_pid: &str,
    op: LifecycleOp,
) -> Option<String> {
    let grant_id = format!("lcg_{}", uuid::Uuid::new_v4().simple());
    let now = chrono::Utc::now().timestamp();
    let grant = CapabilityGrantV2 {
        grant_id: grant_id.clone(),
        principal_id: actor.principal_id.clone(),
        tenant_id: None,
        workload_id: Some(api_pid.to_string()),
        action: op_to_action(op).to_string(),
        resource: format!("agent:{api_pid}"),
        audience: Some("connector-platform".into()),
        expires_at: now + 120,
        policy_revision: None,
        revoked: false,
        contract_version: 2,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        if es
            .folder_put(GRANTS_FOLDER, &grant_id, &serde_json::to_value(&grant).unwrap_or_default())
            .is_ok()
        {
            return Some(grant_id);
        }
    }
    None
}

/// Unified governed effect admission lives in `substrate::governed_effect`.
pub use crate::substrate::governed_effect::{
    evaluate_effect, evaluate_governed_effect, GovernedEffectResult,
};

/// Policy gate — all lifecycle ops except pure system containment.
pub fn authorize_lifecycle(
    state: &SharedState,
    api_pid: &str,
    op: LifecycleOp,
    actor: &LifecycleActor,
    opts: &LifecycleOpts,
) -> Result<(), LifecycleGateError> {
    if actor.source.starts_with("system:") {
        match op {
            LifecycleOp::Start
            | LifecycleOp::Resume
            | LifecycleOp::Thaw
            | LifecycleOp::SignalResume => {
                intelligence_authority::require_lifecycle_transition(
                    state,
                    api_pid,
                    op,
                    &actor.principal_id,
                    actor.role,
                    opts,
                )
                .map_err(|v| {
                    LifecycleGateError::PolicyDenied(
                        v.get("reason")
                            .and_then(|x| x.as_str())
                            .unwrap_or("lifecycle denied")
                            .to_string(),
                    )
                })?;
            }
            _ => {}
        }
        return Ok(());
    }

    intelligence_authority::require_lifecycle_transition(
        state,
        api_pid,
        op,
        &actor.principal_id,
        actor.role,
        opts,
    )
    .map_err(|v| {
        LifecycleGateError::PolicyDenied(
            v.get("reason")
                .and_then(|x| x.as_str())
                .or_else(|| v.get("error").and_then(|x| x.as_str()))
                .unwrap_or("lifecycle denied")
                .to_string(),
        )
    })
}

/// Dispatch a kernel lifecycle syscall after policy authorization.
pub fn dispatch_lifecycle(
    state: &SharedState,
    pid_hint: &str,
    op: LifecycleOp,
    actor: &LifecycleActor,
    opts: &LifecycleOpts,
    reason: &str,
) -> Result<LifecycleReceipt, LifecycleGateError> {
    let (kernel_pid, api_pid) = resolve_pids(state, pid_hint);
    authorize_lifecycle(state, &api_pid, op, actor, opts)?;

    let grant_id = mint_lifecycle_grant(state, actor, &api_pid, op);

    let (operation, payload) = match op {
        LifecycleOp::Start => (MemoryKernelOp::AgentStart, SyscallPayload::Empty),
        LifecycleOp::Pause | LifecycleOp::Freeze | LifecycleOp::SignalSuspend => {
            (MemoryKernelOp::AgentSuspend, SyscallPayload::Empty)
        }
        LifecycleOp::Resume | LifecycleOp::Thaw | LifecycleOp::SignalResume => {
            (MemoryKernelOp::AgentResume, SyscallPayload::Empty)
        }
        LifecycleOp::Stop | LifecycleOp::SignalTerminate => (
            MemoryKernelOp::AgentTerminate,
            SyscallPayload::AgentTerminate {
                target_pid: Some(kernel_pid.clone()),
                reason: reason.to_string(),
            },
        ),
        LifecycleOp::Quarantine | LifecycleOp::Unquarantine => {
            return Err(LifecycleGateError::PolicyDenied(
                "use admission quarantine helpers".into(),
            ));
        }
    };

    let mut k = state.kernel.lock().map_err(|_| {
        LifecycleGateError::KernelFailed("kernel lock poisoned".into())
    })?;
    if k.get_agent(&kernel_pid).is_none() {
        return Err(LifecycleGateError::KernelMissing);
    }

    let result = k.dispatch(SyscallRequest {
        agent_pid: kernel_pid.clone(),
        operation,
        payload,
        reason: Some(format!("{}: {}", actor.source, reason)),
        vakya_id: Some(format!(
            "vakya:lifecycle:{}:{}:{}",
            api_pid,
            op_to_action(op),
            actor.principal_id
        )),
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });

    if matches!(op, LifecycleOp::Stop | LifecycleOp::SignalTerminate) {
        if result.outcome == OpOutcome::Success || result.outcome == OpOutcome::Skipped {
            k.remove_agent(&kernel_pid);
        }
    }

    let outcome = result.outcome;
    drop(k);

    if outcome != OpOutcome::Success && outcome != OpOutcome::Skipped {
        return Err(LifecycleGateError::KernelFailed(format!("{outcome:?}")));
    }

    sync_agent_meta_pause(state, &api_pid, op, &actor.principal_id);

    Ok(LifecycleReceipt {
        outcome,
        kernel_pid,
        api_pid,
        op,
        grant_id,
    })
}

fn sync_agent_meta_pause(state: &SharedState, api_pid: &str, op: LifecycleOp, actor: &str) {
    let (paused, by_field) = match op {
        LifecycleOp::Pause | LifecycleOp::Freeze | LifecycleOp::SignalSuspend => {
            (Some(true), "paused_by")
        }
        LifecycleOp::Resume | LifecycleOp::Thaw | LifecycleOp::SignalResume => {
            (Some(false), "resumed_by")
        }
        _ => return,
    };
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let existing = es
        .folder_get("agent_meta", api_pid)
        .ok()
        .flatten()
        .unwrap_or_else(|| json!({"pid": api_pid}));
    let mut meta = existing.as_object().cloned().unwrap_or_default();
    if let Some(p) = paused {
        meta.insert("paused".into(), json!(p));
        meta.insert(by_field.into(), json!(actor));
        meta.insert(
            if p {
                "paused_at"
            } else {
                "resumed_at"
            }
            .into(),
            json!(chrono::Utc::now().to_rfc3339()),
        );
    }
    let _ = es.folder_put("agent_meta", api_pid, &serde_json::Value::Object(meta));
}

/// Register a new agent and start it — gated.
pub fn register_and_start(
    state: &SharedState,
    params: super::agent_progeny::KernelRegisterParams<'_>,
    actor: &LifecycleActor,
) -> Result<String, String> {
    let caps = super::agent_progeny::ProgenyCaps::default();
    let kernel_pid = {
        let mut k = state.kernel.lock().map_err(|e| e.to_string())?;
        let result = k.dispatch(SyscallRequest {
            agent_pid: "system".to_string(),
            operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: params.agent_name.to_string(),
                namespace: params.namespace.to_string(),
                role: params.role.clone(),
                model: params.model.clone(),
                framework: params.framework.clone(),
            },
            reason: Some(params.reason.clone()),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
        if result.outcome != OpOutcome::Success {
            return Err(format!("kernel register failed: {:?}", result.value));
        }
        let pid = match result.value {
            SyscallValue::AgentPid(p) => p,
            _ => return Err("kernel register returned no pid".into()),
        };

        drop(k);

        dispatch_lifecycle(
            state,
            &pid,
            LifecycleOp::Start,
            actor,
            &LifecycleOpts {
                reason: Some(params.reason.clone()),
                ..Default::default()
            },
            &params.reason,
        )
        .map_err(|e| e.message())?;

        let mut k = state.kernel.lock().map_err(|e| e.to_string())?;
        if let Some(parent) = params.parent_kernel_pid {
            super::agent_progeny::link_progeny(&mut k, &pid, parent, &caps)
                .map_err(|e| e.message())?;
        }
        pid
    };

    super::agent_progeny::persist_progeny_meta(state, &kernel_pid, params.parent_kernel_pid);
    Ok(kernel_pid)
}

/// System-initiated lifecycle (reaper, shutdown, quarantine, deploy internals).
pub fn dispatch_system_lifecycle(
    state: &SharedState,
    pid_hint: &str,
    op: LifecycleOp,
    source: &str,
    reason: &str,
) -> Result<LifecycleReceipt, LifecycleGateError> {
    dispatch_lifecycle(
        state,
        pid_hint,
        op,
        &LifecycleActor::system(source),
        &Default::default(),
        reason,
    )
}

/// Terminate via gate (progeny-safe wrapper).
pub fn terminate_gated(
    state: &SharedState,
    kernel_pid: &str,
    actor: &LifecycleActor,
    reason: &str,
) -> bool {
    dispatch_lifecycle(
        state,
        kernel_pid,
        LifecycleOp::Stop,
        actor,
        &LifecycleOpts {
            reason: Some(reason.to_string()),
            ..Default::default()
        },
        reason,
    )
    .is_ok()
}

pub fn posture_json() -> serde_json::Value {
    json!({
        "schema": SCHEMA,
        "honesty": "All platform kernel lifecycle syscalls route through agent_lifecycle_gate.",
        "lifecycle_strict": intelligence_authority::lifecycle_auth_strict(),
        "effect_path": "governed_effect → character drift + entropy radius + contract stack + admission + CapabilityGrantV2",
        "lifecycle_path": "LifecycleActor → intelligence_authority → kernel dispatch → CapabilityGrantV2",
        "invariants": [
            "quarantined agents cannot start/resume/thaw",
            "unquarantine requires HITL or admin force",
            "dev auth bypass blocked when CONNECTOR_LIFECYCLE_STRICT=1",
            "MCP agent_signal requires lifecycle + charter gates",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_action_mapping() {
        assert_eq!(op_to_action(LifecycleOp::Start), "agent:lifecycle:start");
        assert_eq!(op_to_action(LifecycleOp::Thaw), "agent:lifecycle:thaw");
    }
}
