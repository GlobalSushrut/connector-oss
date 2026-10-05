//! AAPI effect-field — durable ledger + BCR spend + compensation receipts.
//! Sidecar to ActionBinding/PATE: never admits effects; records spend physics.

use connector_engine::aapi::{
    ActionEntry, BudgetReservation, BudgetTracker, ReservationStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::{PlatformState, SharedState};

pub const LEDGER_FOLDER: &str = "aapi_action_ledger";
pub const BUDGET_FOLDER: &str = "aapi_budget_ledger";
pub const RESERVATION_FOLDER: &str = "aapi_bcr_reservations";
pub const INVOCATION_FOLDER: &str = "aapi_behavior_invocations";
pub const COMPENSATION_FOLDER: &str = "aapi_compensation_receipts";
pub const INVERSE_FOLDER: &str = "aapi_inverse_registry";

pub const BEHAVIOR_SCHEMA: &str = "connector.aapi.behavior_invocation.v1";
pub const COMPENSATION_SCHEMA: &str = "connector.aapi.compensation_receipt.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorInvocation {
    pub schema: String,
    pub invocation_id: String,
    pub agent_pid: String,
    pub action_digest: String,
    pub intent: String,
    pub resource: String,
    pub reservation_id: Option<String>,
    pub status: String,
    pub inverse_registered: bool,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompensationReceipt {
    pub schema: String,
    pub compensation_id: String,
    pub agent_pid: String,
    pub original_invocation_id: String,
    pub original_digest: String,
    pub inverse_intent: String,
    pub status: String,
    pub created_at_ms: i64,
}

/// Persist an ActionEntry into the durable ledger (S16 / A23).
pub fn persist_action(state: &PlatformState, entry: &ActionEntry) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            LEDGER_FOLDER,
            &entry.record_id,
            &serde_json::to_value(entry).unwrap_or(Value::Null),
        );
    }
}

/// Persist budget tracker snapshot.
pub fn persist_budget(state: &PlatformState, tracker: &BudgetTracker) {
    let key = format!("{}:{}", tracker.agent_pid, tracker.resource);
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            BUDGET_FOLDER,
            &key,
            &serde_json::to_value(tracker).unwrap_or(Value::Null),
        );
    }
}

/// Persist BCR reservation.
pub fn persist_reservation(state: &PlatformState, reservation: &BudgetReservation) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            RESERVATION_FOLDER,
            &reservation.reservation_id,
            &serde_json::to_value(reservation).unwrap_or(Value::Null),
        );
    }
}

/// Load durable actions for an agent (newest-first by timestamp when possible).
pub fn list_durable_actions(state: &PlatformState, agent_pid: &str, limit: usize) -> Vec<Value> {
    let limit = limit.clamp(1, 500);
    let mut out = Vec::new();
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(keys) = es.folder_keys(LEDGER_FOLDER, None) {
            for k in keys.into_iter().rev().take(limit * 4) {
                if let Ok(Some(v)) = es.folder_get(LEDGER_FOLDER, &k) {
                    if v.get("agent_pid").and_then(|x| x.as_str()) == Some(agent_pid) {
                        out.push(v);
                        if out.len() >= limit {
                            break;
                        }
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|x| x.as_i64()).unwrap_or(0);
        let tb = b.get("timestamp").and_then(|x| x.as_i64()).unwrap_or(0);
        tb.cmp(&ta)
    });
    out.truncate(limit);
    out
}

/// Restore ActionEngine budgets + open reservations from engine_store (restart).
pub fn hydrate_engine_from_store(state: &SharedState) {
    let Ok(mut aapi) = state.aapi.lock() else {
        return;
    };
    let Ok(es) = state.engine_store.lock() else {
        return;
    };
    if let Ok(keys) = es.folder_keys(BUDGET_FOLDER, None) {
        for k in keys {
            if let Ok(Some(v)) = es.folder_get(BUDGET_FOLDER, &k) {
                if let Ok(t) = serde_json::from_value::<BudgetTracker>(v) {
                    aapi.restore_budget(t);
                }
            }
        }
    }
    if let Ok(keys) = es.folder_keys(RESERVATION_FOLDER, None) {
        for k in keys {
            if let Ok(Some(v)) = es.folder_get(RESERVATION_FOLDER, &k) {
                if let Ok(r) = serde_json::from_value::<BudgetReservation>(v) {
                    // Only restore non-terminal that still hold budget.
                    if matches!(
                        r.status,
                        ReservationStatus::Reserved | ReservationStatus::Indeterminate
                    ) {
                        aapi.restore_reservation(r);
                    }
                }
            }
        }
    }
}

/// BCR reserve — overspend refuse when budget configured.
pub fn bcr_reserve(
    state: &SharedState,
    agent_pid: &str,
    resource: &str,
    amount: f64,
    idempotency_key: &str,
    action_digest: Option<&str>,
) -> Value {
    let mut aapi = match state.aapi.lock() {
        Ok(g) => g,
        Err(_) => return json!({"ok": false, "error": "aapi_lock"}),
    };
    match aapi.reserve_budget(agent_pid, resource, amount, idempotency_key, action_digest) {
        Some(r) => {
            if let Some(t) = aapi
                .list_budgets()
                .into_iter()
                .find(|b| b.agent_pid == agent_pid && b.resource == resource)
                .cloned()
            {
                drop(aapi);
                persist_budget(state.as_ref(), &t);
                persist_reservation(state.as_ref(), &r);
            } else {
                drop(aapi);
                persist_reservation(state.as_ref(), &r);
            }
            json!({
                "ok": true,
                "reservation": r,
                "honesty": "BCR reserve holds budget; ActionBinding still admits effects",
            })
        }
        None => json!({
            "ok": false,
            "error": "budget_exhausted_or_invalid",
            "agent_pid": agent_pid,
            "resource": resource,
            "amount": amount,
        }),
    }
}

pub fn bcr_commit(state: &SharedState, reservation_id: &str) -> Value {
    let mut aapi = match state.aapi.lock() {
        Ok(g) => g,
        Err(_) => return json!({"ok": false, "error": "aapi_lock"}),
    };
    match aapi.commit_reservation(reservation_id) {
        Some(r) => {
            let tracker = aapi
                .list_budgets()
                .into_iter()
                .find(|b| b.agent_pid == r.agent_pid && b.resource == r.resource)
                .cloned();
            drop(aapi);
            if let Some(t) = tracker {
                persist_budget(state.as_ref(), &t);
            }
            persist_reservation(state.as_ref(), &r);
            // Indeterminate → bump DIM consequence pressure on next refresh (sensor only).
            if r.status == ReservationStatus::Indeterminate {
                raise_dim_indeterminate(state.as_ref(), &r.agent_pid);
            }
            json!({"ok": true, "reservation": r})
        }
        None => json!({"ok": false, "error": "reservation_not_committable", "reservation_id": reservation_id}),
    }
}

pub fn bcr_release(state: &SharedState, reservation_id: &str) -> Value {
    let mut aapi = match state.aapi.lock() {
        Ok(g) => g,
        Err(_) => return json!({"ok": false, "error": "aapi_lock"}),
    };
    match aapi.release_reservation(reservation_id) {
        Some(r) => {
            let tracker = aapi
                .list_budgets()
                .into_iter()
                .find(|b| b.agent_pid == r.agent_pid && b.resource == r.resource)
                .cloned();
            drop(aapi);
            if let Some(t) = tracker {
                persist_budget(state.as_ref(), &t);
            }
            persist_reservation(state.as_ref(), &r);
            json!({"ok": true, "reservation": r})
        }
        None => json!({"ok": false, "error": "reservation_not_releasable", "reservation_id": reservation_id}),
    }
}

fn raise_dim_indeterminate(state: &PlatformState, agent_pid: &str) {
    let mut z = crate::substrate::dim::persist::load(state, agent_pid);
    z.consequence_pressure = (z.consequence_pressure + 0.15).min(1.0);
    z.prediction_error = (z.prediction_error + 0.1).min(1.0);
    crate::substrate::dim::persist::save(state, &z);
}

/// Register an inverse intent for later compensation (A24).
pub fn register_inverse(
    state: &PlatformState,
    agent_pid: &str,
    action_digest: &str,
    inverse_intent: &str,
) -> Value {
    let key = format!("{agent_pid}:{action_digest}");
    let body = json!({
        "agent_pid": agent_pid,
        "action_digest": action_digest,
        "inverse_intent": inverse_intent,
        "registered_at_ms": chrono::Utc::now().timestamp_millis(),
    });
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(INVERSE_FOLDER, &key, &body);
    }
    json!({"ok": true, "inverse": body})
}

pub fn has_inverse(state: &PlatformState, agent_pid: &str, action_digest: &str) -> bool {
    let key = format!("{agent_pid}:{action_digest}");
    if let Ok(es) = state.engine_store.lock() {
        return es.folder_get(INVERSE_FOLDER, &key).ok().flatten().is_some();
    }
    false
}

/// Record BehaviorInvocation after PATE admit (effect-field receipt, not admit).
pub fn record_behavior_invocation(
    state: &PlatformState,
    agent_pid: &str,
    action_digest: &str,
    intent: &str,
    resource: &str,
    reservation_id: Option<&str>,
    status: &str,
) -> BehaviorInvocation {
    let inv = BehaviorInvocation {
        schema: BEHAVIOR_SCHEMA.into(),
        invocation_id: uuid::Uuid::new_v4().to_string(),
        agent_pid: agent_pid.into(),
        action_digest: action_digest.into(),
        intent: intent.into(),
        resource: resource.into(),
        reservation_id: reservation_id.map(|s| s.to_string()),
        status: status.into(),
        inverse_registered: has_inverse(state, agent_pid, action_digest),
        created_at_ms: chrono::Utc::now().timestamp_millis(),
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            INVOCATION_FOLDER,
            &inv.invocation_id,
            &serde_json::to_value(&inv).unwrap_or(Value::Null),
        );
    }
    inv
}

/// Compensate via registered inverse — records CompensationReceipt (does not admit).
pub fn compensate(
    state: &SharedState,
    agent_pid: &str,
    original_invocation_id: &str,
) -> Value {
    let Ok(es) = state.engine_store.lock() else {
        return json!({"ok": false, "error": "store_lock"});
    };
    let Some(inv_v) = es
        .folder_get(INVOCATION_FOLDER, original_invocation_id)
        .ok()
        .flatten()
    else {
        return json!({"ok": false, "error": "invocation_not_found"});
    };
    drop(es);
    let digest = inv_v
        .get("action_digest")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let Ok(es2) = state.engine_store.lock() else {
        return json!({"ok": false, "error": "store_lock"});
    };
    let inv_key = format!("{agent_pid}:{digest}");
    let Some(inv_reg) = es2.folder_get(INVERSE_FOLDER, &inv_key).ok().flatten() else {
        return json!({
            "ok": false,
            "error": "no_inverse_registered",
            "honesty": "Without inverse, compensation is not Autonomous under harden",
        });
    };
    let inverse_intent = inv_reg
        .get("inverse_intent")
        .and_then(|x| x.as_str())
        .unwrap_or("compensate.unknown")
        .to_string();
    drop(es2);

    let executed = if let Some((bridge, tool)) = inverse_intent.split_once(':') {
        crate::services::tools::dispatch_mcp_tool_core(
            state,
            bridge,
            tool,
            agent_pid,
            &json!({"compensation_for": original_invocation_id, "digest": digest}),
            format!("compensate:{original_invocation_id}"),
            crate::services::tools::ToolMissionOpts {
                mission_id: None,
                idempotency_key: Some(original_invocation_id),
            },
        )
        .is_ok()
    } else {
        false
    };
    let receipt = CompensationReceipt {
        schema: COMPENSATION_SCHEMA.into(),
        compensation_id: uuid::Uuid::new_v4().to_string(),
        agent_pid: agent_pid.into(),
        original_invocation_id: original_invocation_id.into(),
        original_digest: digest.into(),
        inverse_intent: inverse_intent.clone(),
        status: if executed { "executed" } else { "not_executed" }.into(),
        created_at_ms: chrono::Utc::now().timestamp_millis(),
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            COMPENSATION_FOLDER,
            &receipt.compensation_id,
            &serde_json::to_value(&receipt).unwrap_or(Value::Null),
        );
    }
    // Audit plane only — still needs PATE to execute inverse effect.
    json!({
        "ok": executed,
        "executed": executed,
        "compensation": receipt,
        "honesty": if executed {
            "Inverse ran through MCP dispatch, which admits with PATE before the effect."
        } else {
            "No bridge:tool inverse ran. Compensation success is not recorded."
        },
    })
}

pub fn posture_json() -> Value {
    json!({
        "schema": "connector.aapi.effect_field.v1",
        "role": "durable ledger + BCR spend + compensation — never admits",
        "folders": [
            LEDGER_FOLDER,
            BUDGET_FOLDER,
            RESERVATION_FOLDER,
            INVOCATION_FOLDER,
            COMPENSATION_FOLDER,
            INVERSE_FOLDER,
        ],
        "outcomes": ["A12", "A23", "A24", "S16", "S17", "S18", "S19"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_engine::aapi::ActionEngine;

    #[test]
    fn bcr_overspend_refuses_in_engine() {
        let mut e = ActionEngine::new();
        e.create_budget("a", "tokens", 10.0);
        assert!(e
            .reserve_budget("a", "tokens", 10.0, "k1", None)
            .is_some());
        assert!(e
            .reserve_budget("a", "tokens", 1.0, "k2", None)
            .is_none());
    }
}
