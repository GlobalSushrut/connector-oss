//! Intelligence Authority Middleware — lifecycle state-transition gate.
//!
//! Hardens start / stop / pause / resume / quarantine so they cannot bypass
//! admission-side isolation. Effect paths already call `admission::check`;
//! this module closes the lifecycle control-plane gap.
//!
//! Invariants (from Connector Intelligence Authority architecture):
//! - Identity/authority mutations require external operator principal.
//! - Quarantined agents cannot start, resume, or receive execution authority.
//! - Unquarantine requires HITL approval (or admin force in lab).
//! - Child authority cannot exceed parent (enforced elsewhere via progeny).

use axum::http::HeaderMap;
use serde_json::{json, Value};

use crate::auth::PlatformRole;
use crate::services::runtime_control;
use crate::state::SharedState;

/// Lifecycle operations that mutate agent execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleOp {
    Start,
    Stop,
    Pause,
    Resume,
    Freeze,
    Thaw,
    Quarantine,
    Unquarantine,
    SignalSuspend,
    SignalResume,
    SignalTerminate,
}

/// Operator options for sensitive transitions.
#[derive(Debug, Clone, Default)]
pub struct LifecycleOpts {
    /// Admin-only break-glass for unquarantine without linked HITL approval.
    pub force: bool,
    pub reason: Option<String>,
}

/// Snapshot of durable agent control flags (`agent_meta`).
#[derive(Debug, Clone, Default)]
pub struct AgentControlSnapshot {
    pub quarantined: bool,
    pub paused: bool,
    pub egress_isolated: bool,
    pub quarantine_reason: Option<String>,
    pub quarantine_hitl_id: Option<String>,
}

pub fn lifecycle_auth_strict() -> bool {
    runtime_control::defense_strict_enabled()
        || std::env::var("CONNECTOR_LIFECYCLE_STRICT")
            .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(false)
}

/// Load control flags for an agent (API pid key in `agent_meta`).
pub fn load_agent_control(state: &SharedState, agent_pid: &str) -> AgentControlSnapshot {
    let es = state.engine_store.lock().unwrap();
    let meta = es
        .folder_get("agent_meta", agent_pid)
        .ok()
        .flatten()
        .unwrap_or_else(|| json!({"pid": agent_pid}));
    drop(es);
    snapshot_from_meta(&meta)
}

fn snapshot_from_meta(meta: &Value) -> AgentControlSnapshot {
    AgentControlSnapshot {
        quarantined: meta
            .get("quarantined")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        paused: meta
            .get("paused")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        egress_isolated: meta
            .get("egress_isolated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        quarantine_reason: meta
            .get("quarantine_reason")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        quarantine_hitl_id: meta
            .get("quarantine_hitl_id")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    }
}

/// Authenticate lifecycle mutator. Rejects dev/open-auth bypass when lifecycle strict.
pub fn require_lifecycle_actor(
    headers: &HeaderMap,
    min_rank: u8,
) -> Result<(String, PlatformRole), Value> {
    if lifecycle_auth_strict() && runtime_control::dev_auth_bypass_allowed() {
        return Err(json!({
            "ok": false,
            "error": "lifecycle_auth_strict",
            "status": 403,
            "hint": "Set CONNECTOR_DEFENSE_STRICT=0 only in lab; lifecycle mutations require verified JWT/API key when CONNECTOR_LIFECYCLE_STRICT=1 or defense-strict.",
        }));
    }

    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|h| h.to_str().ok()));

    let (user_id, role) = if lifecycle_auth_strict() || !runtime_control::dev_auth_bypass_allowed() {
        let Some(token) = token.filter(|t| !t.is_empty()) else {
            return Err(json!({
                "ok": false,
                "error": "Authentication required",
                "status": 401,
            }));
        };
        let claims = crate::auth::verify_token(token).map_err(|_| {
            json!({
                "ok": false,
                "error": "Invalid or expired token",
                "status": 401,
            })
        })?;
        (
            claims.sub,
            PlatformRole::from_str(&claims.role),
        )
    } else if let Some(token) = token.filter(|t| !t.is_empty()) {
        if let Ok(claims) = crate::auth::verify_token(token) {
            (
                claims.sub,
                PlatformRole::from_str(&claims.role),
            )
        } else {
            ("dev".into(), PlatformRole::SuperAdmin)
        }
    } else {
        ("dev".into(), PlatformRole::SuperAdmin)
    };

    let playground_actor = crate::services::playground::is_playground_mode()
        && crate::services::playground::playground_session_id_from_headers(headers).is_some();
    if role.rank() < min_rank && !playground_actor {
        return Err(json!({
            "ok": false,
            "error": format!("Role rank {min_rank}+ required for lifecycle operation"),
            "status": 403,
            "actor_role": role.to_str(),
        }));
    }

    Ok((user_id, role))
}

/// Evaluate whether a lifecycle transition may proceed. Returns Err(JSON) on deny/escalate.
pub fn require_lifecycle_transition(
    state: &SharedState,
    agent_pid: &str,
    op: LifecycleOp,
    actor: &str,
    role: PlatformRole,
    opts: &LifecycleOpts,
) -> Result<(), Value> {
    let ctrl = load_agent_control(state, agent_pid);

    let blocked_execution = |reason: &str, hitl: Option<&str>| {
        Err(json!({
            "ok": false,
            "error": "lifecycle_denied",
            "status": 403,
            "decision": "DENY",
            "reason": reason,
            "quarantine_hitl_id": hitl,
            "hint": "Approve HITL unquarantine or POST /agents/:pid/unquarantine with admin force after review.",
            "honesty": "Intelligence authority middleware — quarantined agents cannot gain execution authority.",
        }))
    };

    match op {
        LifecycleOp::Start | LifecycleOp::Resume | LifecycleOp::Thaw | LifecycleOp::SignalResume => {
            if ctrl.quarantined {
                return blocked_execution(
                    ctrl.quarantine_reason
                        .as_deref()
                        .unwrap_or("agent quarantined"),
                    ctrl.quarantine_hitl_id.as_deref(),
                );
            }
            if ctrl.egress_isolated {
                return blocked_execution(
                    "matrix egress isolation active — unquarantine required",
                    ctrl.quarantine_hitl_id.as_deref(),
                );
            }
        }
        LifecycleOp::Unquarantine => {
            if !ctrl.quarantined && !ctrl.egress_isolated {
                return Ok(());
            }
            let admin_force = opts.force && role.rank() >= PlatformRole::Admin.rank();
            // Hosted trial: session owner may force-clear quarantine (break-glass for demo).
            let playground_force = opts.force
                && crate::services::playground::is_playground_mode()
                && (actor.starts_with("pg_") || role.rank() >= PlatformRole::Developer.rank());
            if admin_force || playground_force {
                audit_lifecycle(
                    state,
                    agent_pid,
                    op,
                    actor,
                    json!({
                        "break_glass": true,
                        "force": true,
                        "playground": playground_force && !admin_force,
                    }),
                );
                return Ok(());
            }
            if !hitl_unquarantine_approved(state, agent_pid, ctrl.quarantine_hitl_id.as_deref()) {
                return Err(json!({
                    "ok": false,
                    "error": "lifecycle_escalate",
                    "status": 403,
                    "decision": "ESCALATE",
                    "reason": "Unquarantine requires approved HITL request",
                    "quarantine_hitl_id": ctrl.quarantine_hitl_id,
                    "hint": format!("POST /api/v1/agents/{agent_pid}/hitl/{{id}}/approve for action unquarantine, or admin force=true"),
                }));
            }
        }
        LifecycleOp::Quarantine => {
            // Operators may always quarantine (containment beats autonomy).
        }
        LifecycleOp::Stop
        | LifecycleOp::Pause
        | LifecycleOp::Freeze
        | LifecycleOp::SignalSuspend
        | LifecycleOp::SignalTerminate => {
            // Emergency / containment paths stay available.
        }
    }

    audit_lifecycle(
        state,
        agent_pid,
        op,
        actor,
        json!({
            "quarantined": ctrl.quarantined,
            "paused": ctrl.paused,
            "egress_isolated": ctrl.egress_isolated,
        }),
    );
    Ok(())
}

fn hitl_unquarantine_approved(
    state: &SharedState,
    agent_pid: &str,
    quarantine_hitl_id: Option<&str>,
) -> bool {
    crate::services::agents::hitl_ensure_hydrated(state);
    let store = crate::services::agents::hitl_store_snapshot();
    if let Some(id) = quarantine_hitl_id {
        if let Some(req) = store.get(id) {
            if req.agent_pid == agent_pid
                && req.action == "unquarantine"
                && matches!(req.status.as_str(), "approved" | "consumed")
            {
                return true;
            }
        }
    }
    store.values().any(|r| {
        r.agent_pid == agent_pid
            && r.action == "unquarantine"
            && matches!(r.status.as_str(), "approved" | "consumed")
    })
}

pub fn audit_lifecycle(
    state: &SharedState,
    agent_pid: &str,
    op: LifecycleOp,
    actor: &str,
    detail: Value,
) {
    use connector_engine::engine_store::EngineAuditEntry;
    let op_slug = match op {
        LifecycleOp::Start => "lifecycle.start",
        LifecycleOp::Stop => "lifecycle.stop",
        LifecycleOp::Pause => "lifecycle.pause",
        LifecycleOp::Resume => "lifecycle.resume",
        LifecycleOp::Freeze => "lifecycle.freeze",
        LifecycleOp::Thaw => "lifecycle.thaw",
        LifecycleOp::Quarantine => "lifecycle.quarantine",
        LifecycleOp::Unquarantine => "lifecycle.unquarantine",
        LifecycleOp::SignalSuspend => "lifecycle.signal_suspend",
        LifecycleOp::SignalResume => "lifecycle.signal_resume",
        LifecycleOp::SignalTerminate => "lifecycle.signal_terminate",
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.append_audit(&EngineAuditEntry {
            timestamp: chrono::Utc::now().timestamp_millis(),
            category: "intelligence_authority".to_string(),
            agent_pid: Some(agent_pid.to_string()),
            action: op_slug.to_string(),
            resource: None,
            verdict: Some("allow".to_string()),
            details: Some(json!({
                "actor": actor,
                "detail": detail,
            })),
            severity: "info".to_string(),
        });
    }
}

/// Suspend kernel agent when entering quarantine (best-effort).
pub fn kernel_suspend_if_present(state: &SharedState, kernel_pid: &str, reason: &str) {
    let _ = crate::substrate::agent_lifecycle_gate::dispatch_system_lifecycle(
        state,
        kernel_pid,
        LifecycleOp::Pause,
        "quarantine",
        reason,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_mode_env_parse() {
        std::env::remove_var("CONNECTOR_LIFECYCLE_STRICT");
        std::env::remove_var("CONNECTOR_DEFENSE_STRICT");
        assert!(!lifecycle_auth_strict());
        std::env::set_var("CONNECTOR_LIFECYCLE_STRICT", "1");
        assert!(lifecycle_auth_strict());
        std::env::remove_var("CONNECTOR_LIFECYCLE_STRICT");
    }

    #[test]
    fn snapshot_reads_quarantine_flags() {
        let meta = json!({
            "quarantined": true,
            "paused": true,
            "egress_isolated": true,
            "quarantine_reason": "injection",
            "quarantine_hitl_id": "hitl_1"
        });
        let s = snapshot_from_meta(&meta);
        assert!(s.quarantined);
        assert!(s.egress_isolated);
        assert_eq!(s.quarantine_hitl_id.as_deref(), Some("hitl_1"));
    }
}
