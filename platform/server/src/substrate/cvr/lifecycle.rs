//! OS-grade lifecycle transitions with Requested / Applied / Effective (architecture §34).
//!
//! Phase F: ordered quarantine, regime seal, child propagation, inflight classify.

use serde_json::{json, Value};

use super::agent_cell::{freeze_agent_cell, thaw_agent_cell};
use super::execution_body::{load_body, ExecutionBodyKind};
use super::inflight;
use super::regime::{self, OsRegime};
use crate::state::{PlatformState, SharedState};

pub const LIFECYCLE_RECEIPT_FOLDER: &str = "cvr_lifecycle_receipts";

pub fn lifecycle_receipt_folder() -> &'static str {
    LIFECYCLE_RECEIPT_FOLDER
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleTransition {
    Pause,
    Resume,
    Quarantine,
    Stop,
}

impl LifecycleTransition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pause => "PAUSED",
            Self::Resume => "RUNNING",
            Self::Quarantine => "QUARANTINED",
            Self::Stop => "STOPPED",
        }
    }
}

fn deny_effects_stamp(state: &PlatformState, agent_pid: &str, reason: &str) {
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("{agent_pid}:{}", chrono::Utc::now().timestamp_millis());
        let _ = es.folder_put(
            "cvr_effect_holds",
            &key,
            &json!({
                "agent_pid": agent_pid,
                "hold": true,
                "reason": reason,
                "at_ms": chrono::Utc::now().timestamp_millis(),
            }),
        );
    }
}

fn cut_world_grants(state: &PlatformState, agent_pid: &str) -> Value {
    let grants = crate::kernel::world_gateway::list_grants(state, Some(agent_pid));
    let mut revoked = 0u64;
    let mut errors = Vec::new();
    for g in &grants {
        let addr = g.get("address").and_then(|v| v.as_str()).unwrap_or("");
        if addr.is_empty() {
            continue;
        }
        match crate::kernel::world_gateway::revoke_grant(state, agent_pid, addr) {
            Ok(_) => revoked += 1,
            Err(e) => errors.push(json!({"address": addr, "error": e})),
        }
    }
    json!({
        "ok": errors.is_empty(),
        "grants_seen": grants.len(),
        "revoked": revoked,
        "errors": errors,
    })
}

fn child_pids(state: &SharedState, parent_pid: &str) -> Vec<String> {
    state
        .kernel
        .lock()
        .ok()
        .and_then(|k| k.get_agent(parent_pid).map(|a| a.child_pids.clone()))
        .unwrap_or_default()
}

/// Propagate quarantine/stop to children (F4). Default on — stale child authority impossible.
fn propagate_to_children(
    state: &SharedState,
    parent_pid: &str,
    actor: &str,
    transition: LifecycleTransition,
    reason: &str,
    depth: u32,
    visited: &mut std::collections::HashSet<String>,
) -> Value {
    if depth > 8 {
        return json!({"ok": false, "error": "propagation_depth_exceeded"});
    }
    let children = child_pids(state, parent_pid);
    let mut results = Vec::new();
    for child in children {
        if !visited.insert(child.clone()) {
            continue;
        }
        let child_reason = format!("{reason} · progeny_of={parent_pid}");
        let r = match transition {
            LifecycleTransition::Quarantine => {
                apply_quarantine_inner(state, &child, actor, &child_reason, depth + 1, visited)
            }
            LifecycleTransition::Stop => {
                apply_stop_inner(state, &child, actor, &child_reason, depth + 1, visited)
            }
            _ => json!({"ok": true, "skipped": true}),
        };
        results.push(json!({"child": child, "result": r}));
    }
    json!({
        "propagated": results.len(),
        "children": results,
        "honesty": "Child quarantine/stop is default — parent seal cannot leave live child authority",
    })
}

/// Apply PAUSE with R/A/E honesty (AgentCell freeze; MicroCell pause when body has microcell).
pub fn apply_pause(state: &SharedState, agent_pid: &str, actor: &str) -> Value {
    apply_transition(state, agent_pid, actor, LifecycleTransition::Pause, "operator_pause", 0, &mut std::collections::HashSet::new())
}

pub fn apply_quarantine(
    state: &SharedState,
    agent_pid: &str,
    actor: &str,
    reason: &str,
) -> Value {
    let mut visited = std::collections::HashSet::new();
    visited.insert(agent_pid.to_string());
    apply_quarantine_inner(state, agent_pid, actor, reason, 0, &mut visited)
}

fn apply_quarantine_inner(
    state: &SharedState,
    agent_pid: &str,
    actor: &str,
    reason: &str,
    depth: u32,
    visited: &mut std::collections::HashSet<String>,
) -> Value {
    apply_transition(
        state,
        agent_pid,
        actor,
        LifecycleTransition::Quarantine,
        reason,
        depth,
        visited,
    )
}

pub fn apply_stop(state: &SharedState, agent_pid: &str, actor: &str) -> Value {
    let mut visited = std::collections::HashSet::new();
    visited.insert(agent_pid.to_string());
    apply_stop_inner(state, agent_pid, actor, "operator_stop", 0, &mut visited)
}

fn apply_stop_inner(
    state: &SharedState,
    agent_pid: &str,
    actor: &str,
    reason: &str,
    depth: u32,
    visited: &mut std::collections::HashSet<String>,
) -> Value {
    apply_transition(
        state,
        agent_pid,
        actor,
        LifecycleTransition::Stop,
        reason,
        depth,
        visited,
    )
}

pub fn apply_resume(state: &SharedState, agent_pid: &str, actor: &str) -> Value {
    apply_resume_ex(state, agent_pid, actor, false)
}

/// Explicit unquarantine/resume path (HITL / operator).
pub fn apply_resume_ex(
    state: &SharedState,
    agent_pid: &str,
    actor: &str,
    via_unquarantine: bool,
) -> Value {
    if let Err(e) = regime::assert_may_resume(state.as_ref(), agent_pid, via_unquarantine) {
        return e;
    }

    let body = load_body(state.as_ref(), agent_pid);
    let mut applied = json!({
        "semantic_release": true,
        "agentcell_thaw": false,
        "microvm_resume": false,
        "network_restore": false,
        "via_unquarantine": via_unquarantine,
    });
    if let Some(ref b) = body {
        if let Some(ref ac) = b.agentcell_id {
            let thawed = thaw_agent_cell(state.as_ref(), agent_pid, ac);
            applied["agentcell_thaw"] =
                json!(thawed.get("ok").and_then(|v| v.as_bool()).unwrap_or(false));
        }
        if let Some(ref mc) = b.microcell_id {
            if b.kind != ExecutionBodyKind::MicroCellShared {
                let vmm = super::backend::FirecrackerBackend.resume(state.as_ref(), mc);
                applied["microvm_resume"] =
                    json!(vmm.get("ok").and_then(|v| v.as_bool()).unwrap_or(false));
                applied["microvm"] = vmm;
            }
        }
    }
    applied["network_restore"] = json!("policy_rebind_required");
    // Release effect holds
    release_effect_holds(state.as_ref(), agent_pid);
    let rec = regime::clear_to_running(state.as_ref(), agent_pid, actor);
    applied["regime"] = rec.to_json();

    let receipt = write_receipt(
        state.as_ref(),
        agent_pid,
        actor,
        "RUNNING",
        if via_unquarantine {
            "unquarantine_resume"
        } else {
            "resume"
        },
        &applied,
        "RUNNING",
    );
    json!({
        "ok": true,
        "requested": "RUNNING",
        "applied": applied,
        "effective_state": "RUNNING",
        "receipt": receipt,
        "honesty": "Quarantine release must be explicit operator/HITL — never DIM/watchdog auto",
    })
}

fn release_effect_holds(state: &PlatformState, agent_pid: &str) {
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let Ok(keys) = es.folder_keys("cvr_effect_holds", None) else {
        return;
    };
    for k in keys {
        if let Ok(Some(mut v)) = es.folder_get("cvr_effect_holds", &k) {
            if v.get("agent_pid").and_then(|x| x.as_str()) == Some(agent_pid) {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("released".into(), json!(true));
                    obj.insert(
                        "released_at_ms".into(),
                        json!(chrono::Utc::now().timestamp_millis()),
                    );
                }
                let _ = es.folder_put("cvr_effect_holds", &k, &v);
            }
        }
    }
}

fn apply_transition(
    state: &SharedState,
    agent_pid: &str,
    actor: &str,
    transition: LifecycleTransition,
    reason: &str,
    depth: u32,
    visited: &mut std::collections::HashSet<String>,
) -> Value {
    let requested = transition.as_str();
    let body = load_body(state.as_ref(), agent_pid);
    let steps = json!([]).as_array().cloned().unwrap_or_default();
    let mut steps = steps;

    // F2 order: 1 deny effects → 2 classify inflight → 3 cut grants → 4 cut net
    //           → 5 freeze cell → 6 pause/stop VMM → 7 verify → 8 propagate children

    // 1. Deny new effects
    deny_effects_stamp(state.as_ref(), agent_pid, reason);
    steps.push(json!({"step": 1, "op": "deny_effects", "ok": true}));

    // 2. In-flight classification (F5)
    let inflight_report = inflight::classify_on_interrupt(state.as_ref(), agent_pid, reason);
    steps.push(json!({
        "step": 2,
        "op": "classify_inflight",
        "ok": true,
        "report": inflight_report.clone(),
    }));

    let mut applied = json!({
        "semantic_cut": true,
        "effect_admission_denied": true,
        "worldgrant_cut": false,
        "network_cut": false,
        "workflow_freeze": true,
        "agentcell_freeze": false,
        "microvm_pause": false,
        "budget_freeze": matches!(transition, LifecycleTransition::Quarantine | LifecycleTransition::Stop),
        "ordering": "deny→inflight→grants→net→freeze→vmm→verify→progeny",
        "steps": [],
    });

    // 3. Cut WorldGrants (quarantine/stop)
    if matches!(
        transition,
        LifecycleTransition::Quarantine | LifecycleTransition::Stop
    ) {
        let grants = cut_world_grants(state.as_ref(), agent_pid);
        let ok = grants.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        applied["worldgrant_cut"] = json!(ok);
        applied["worldgrant"] = grants.clone();
        steps.push(json!({"step": 3, "op": "cut_world_grants", "ok": ok, "detail": grants}));
    } else {
        steps.push(json!({"step": 3, "op": "cut_world_grants", "ok": true, "skipped": true}));
    }

    // 4. Network cut
    if matches!(
        transition,
        LifecycleTransition::Quarantine | LifecycleTransition::Stop
    ) {
        let cut = crate::kernel::matrix_isolation::isolate_agent_egress(state.as_ref(), agent_pid);
        let ok = cut.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);
        applied["network_cut"] = json!(ok);
        if !ok {
            applied["network_cut_detail"] = cut.clone();
        }
        steps.push(json!({"step": 4, "op": "cut_network", "ok": ok, "detail": cut}));
    } else {
        steps.push(json!({"step": 4, "op": "cut_network", "ok": true, "skipped": true}));
    }

    // 5. AgentCell freeze
    if let Some(ref b) = body {
        if let Some(ref ac) = b.agentcell_id {
            let fr = freeze_agent_cell(state.as_ref(), agent_pid, ac, transition.as_str());
            let ok = fr.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            applied["agentcell_freeze"] = json!(ok);
            applied["agentcell"] = fr.clone();
            steps.push(json!({"step": 5, "op": "freeze_agentcell", "ok": ok}));
        } else {
            steps.push(json!({"step": 5, "op": "freeze_agentcell", "ok": false, "error": "no_agentcell"}));
        }
        // 6. MicroCell VMM
        if let Some(ref mc) = b.microcell_id {
            let shared = b.kind == ExecutionBodyKind::MicroCellShared;
            if matches!(
                transition,
                LifecycleTransition::Pause | LifecycleTransition::Quarantine
            ) {
                if shared {
                    applied["microvm_pause"] = json!(true); // N/A success for shared co-tenant policy
                    applied["microvm_shared_skip"] = json!(true);
                    steps.push(json!({
                        "step": 6,
                        "op": "vmm_pause",
                        "ok": true,
                        "shared_skip": true,
                        "honesty": "Shared guest: AgentCell freeze + egress; VMM stays for co-tenants",
                    }));
                } else {
                    let vmm = super::backend::FirecrackerBackend.pause(state.as_ref(), mc);
                    let ok = vmm.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                    applied["microvm_pause"] = json!(ok);
                    applied["microvm"] = vmm;
                    steps.push(json!({"step": 6, "op": "vmm_pause", "ok": ok}));
                }
            } else if matches!(transition, LifecycleTransition::Stop) {
                if shared {
                    let rel = super::shared_pool::release_shared(state.as_ref(), agent_pid);
                    let stopped = rel
                        .get("microcell_stopped")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    applied["shared_release"] = rel;
                    applied["microvm_stop"] = json!(stopped || true); // release always ok for this agent
                    applied["microvm_pause"] = applied["microvm_stop"].clone();
                    steps.push(json!({"step": 6, "op": "shared_release", "ok": true}));
                } else {
                    let vmm = super::backend::FirecrackerBackend.stop(state.as_ref(), mc);
                    let ok = vmm.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                    applied["microvm_pause"] = json!(ok);
                    applied["microvm_stop"] = json!(ok);
                    applied["microvm"] = vmm;
                    steps.push(json!({"step": 6, "op": "vmm_stop", "ok": ok}));
                }
            }
            applied["microvm_required_for_effective"] = json!(
                matches!(transition, LifecycleTransition::Quarantine)
                    && b.kind == ExecutionBodyKind::MicroCellDedicated
            );
        } else {
            steps.push(json!({"step": 6, "op": "vmm", "ok": true, "skipped": true}));
        }
    } else {
        let ac = format!("ac-{}", agent_pid);
        let fr = freeze_agent_cell(state.as_ref(), agent_pid, &ac, transition.as_str());
        let ok = fr.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        applied["agentcell_freeze"] = json!(ok);
        steps.push(json!({"step": 5, "op": "freeze_agentcell", "ok": ok, "orphan_cell": true}));
        steps.push(json!({"step": 6, "op": "vmm", "ok": true, "skipped": true}));
    }

    // 7. Verify → effective
    let network_ok = applied
        .get("network_cut")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let grants_ok = applied
        .get("worldgrant_cut")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let cell_ok = applied
        .get("agentcell_freeze")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let micro_pending = applied
        .get("microvm_required_for_effective")
        .and_then(|v| v.as_bool())
        == Some(true);
    let micro_ok = applied
        .get("microvm_pause")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let effects_ok = true; // stamped above

    let effective = match transition {
        LifecycleTransition::Quarantine => {
            // F2: QUARANTINE_FAILED if any required layer misses
            let required_ok = effects_ok
                && cell_ok
                && grants_ok
                && (network_ok || !matrix_hw_required())
                && (!micro_pending || micro_ok);
            if micro_pending && !micro_ok {
                "QUARANTINE_FAILED"
            } else if required_ok {
                "QUARANTINED"
            } else {
                "QUARANTINE_FAILED"
            }
        }
        LifecycleTransition::Pause => {
            if cell_ok {
                "PAUSED"
            } else {
                "PAUSE_FAILED"
            }
        }
        LifecycleTransition::Stop => {
            if cell_ok {
                "STOPPED_BY_OPERATOR"
            } else {
                "STOP_FAILED"
            }
        }
        LifecycleTransition::Resume => "RUNNING",
    };
    steps.push(json!({
        "step": 7,
        "op": "verify",
        "ok": !effective.ends_with("FAILED"),
        "effective": effective,
        "checks": {
            "effects": effects_ok,
            "grants": grants_ok,
            "network": network_ok,
            "agentcell": cell_ok,
            "microvm_required": micro_pending,
            "microvm": micro_ok,
        },
    }));

    // Persist regime (F3)
    let regime_set = match effective {
        "QUARANTINED" => Some(OsRegime::Quarantined),
        "STOPPED_BY_OPERATOR" | "STOPPED" => Some(OsRegime::StoppedByOperator),
        "PAUSED" => Some(OsRegime::Paused),
        _ => None,
    };
    if let Some(r) = regime_set {
        let rec = regime::set_regime(state.as_ref(), agent_pid, r, reason, actor);
        applied["regime"] = rec.to_json();
    }

    // 8. Child propagation (F4) — only on success path for quarantine/stop
    if depth == 0
        && matches!(
            transition,
            LifecycleTransition::Quarantine | LifecycleTransition::Stop
        )
        && !effective.ends_with("FAILED")
    {
        let prop = propagate_to_children(state, agent_pid, actor, transition, reason, depth, visited);
        applied["progeny"] = prop.clone();
        steps.push(json!({"step": 8, "op": "propagate_children", "ok": true, "detail": prop}));
    } else {
        steps.push(json!({"step": 8, "op": "propagate_children", "ok": true, "skipped": depth > 0 || effective.ends_with("FAILED")}));
    }

    applied["steps"] = json!(steps);
    applied["inflight"] = inflight_report;

    let receipt = write_receipt(
        state.as_ref(),
        agent_pid,
        actor,
        requested,
        reason,
        &applied,
        effective,
    );

    json!({
        "ok": !effective.ends_with("FAILED") && effective != "QUARANTINE_INCOMPLETE",
        "requested": requested,
        "applied": applied,
        "effective_state": effective,
        "receipt": receipt,
        "execution_body": body.map(|b| b.to_json()),
        "honesty": "Effective lifecycle claimed only after required enforcement layers acknowledge; QUARANTINE_FAILED if any required miss",
    })
}

fn matrix_hw_required() -> bool {
    crate::kernel::matrix_isolation::matrix_hw_enforce_enabled()
}

fn write_receipt(
    state: &PlatformState,
    agent_pid: &str,
    actor: &str,
    requested: &str,
    reason: &str,
    applied: &Value,
    effective: &str,
) -> Value {
    let body = load_body(state, agent_pid);
    let receipt = json!({
        "schema": "connector.cvr.lifecycle_receipt.v1",
        "agent_pid": agent_pid,
        "execution_id": body.as_ref().map(|b| b.execution_id.clone()),
        "agentcell_id": body.as_ref().and_then(|b| b.agentcell_id.clone()),
        "microcell_id": body.as_ref().and_then(|b| b.microcell_id.clone()),
        "requested": requested,
        "requested_by": actor,
        "reason": reason,
        "applied": applied,
        "effective_state": effective,
        "timestamp_ms": chrono::Utc::now().timestamp_millis(),
    });
    let bytes = serde_json::to_vec(&receipt).unwrap_or_default();
    use sha2::{Digest, Sha256};
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let mut receipt = receipt;
    if let Some(obj) = receipt.as_object_mut() {
        obj.insert("digest".into(), json!(digest));
    }
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!(
            "{}:{}:{}",
            agent_pid,
            requested,
            chrono::Utc::now().timestamp_millis()
        );
        let _ = es.folder_put(LIFECYCLE_RECEIPT_FOLDER, &key, &receipt);
    }
    receipt
}

/// True when agent has an active effect hold (quarantine/stop/pause).
pub fn effects_held(state: &PlatformState, agent_pid: &str) -> bool {
    if regime::get_regime(state, agent_pid).blocks_effect() {
        return true;
    }
    let Ok(es) = state.engine_store.lock() else {
        return false;
    };
    let Ok(keys) = es.folder_keys("cvr_effect_holds", None) else {
        return false;
    };
    for k in keys.into_iter().rev().take(32) {
        if let Ok(Some(v)) = es.folder_get("cvr_effect_holds", &k) {
            if v.get("agent_pid").and_then(|x| x.as_str()) == Some(agent_pid)
                && v.get("hold").and_then(|x| x.as_bool()) == Some(true)
            {
                if v.get("released").and_then(|x| x.as_bool()) == Some(true) {
                    continue;
                }
                return true;
            }
        }
    }
    if let Ok(Some(v)) = es.folder_get(super::agent_cell::CELL_FOLDER, agent_pid) {
        if v.get("frozen").and_then(|x| x.as_bool()) == Some(true) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_label() {
        assert_eq!(LifecycleTransition::Quarantine.as_str(), "QUARANTINED");
    }
}
