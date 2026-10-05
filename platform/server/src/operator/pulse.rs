use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::{
    operator::{fix_queue::compute_fix_queue, honesty::operator_envelope},
    services::{
        monitor::kernel_health_snapshot,
        workflow_runtime::WORKFLOW_FOLDER,
    },
    state::SharedState,
};

fn count_workflows_by_state(state: &SharedState) -> (usize, usize, usize) {
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(WORKFLOW_FOLDER, None).unwrap_or_default();
    let mut running = 0usize;
    let mut idle = 0usize;
    let mut other = 0usize;
    for k in keys {
        let Some(v) = es.folder_get(WORKFLOW_FOLDER, &k).ok().flatten() else {
            continue;
        };
        let state_str = v.get("state").and_then(|s| s.as_str()).unwrap_or("");
        match state_str {
            "ENABLED" => running += 1,
            "PAUSED" | "STAGED" | "COMPILED" | "DRAFT" => idle += 1,
            _ => other += 1,
        }
    }
    (running, idle, other)
}

fn count_needs_you(state: &SharedState) -> usize {
    compute_fix_queue(state)
        .get("count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize
}

fn recent_denials(state: &SharedState, limit: usize) -> Vec<Value> {
    let mut out = Vec::new();
    let Ok(es) = state.engine_store.lock() else {
        return out;
    };
    for folder in ["admission_denials", "pate_denials", "action_log"] {
        let Ok(keys) = es.folder_keys(folder, None) else {
            continue;
        };
        for k in keys.into_iter().rev().take(limit) {
            if let Ok(Some(v)) = es.folder_get(folder, &k) {
                // Strip any message / CoT-like bodies — operator pulse is regime/reason only.
                let reason = v
                    .get("denial_reason")
                    .or_else(|| v.get("reason"))
                    .or_else(|| v.get("error"))
                    .cloned()
                    .unwrap_or(json!("denied"));
                let agent = v
                    .get("agent_pid")
                    .or_else(|| v.get("pid"))
                    .cloned()
                    .unwrap_or(json!(null));
                out.push(json!({
                    "folder": folder,
                    "agent_pid": agent,
                    "reason": reason,
                    "at": v.get("timestamp").or_else(|| v.get("at")).cloned(),
                }));
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }
    out
}

fn spend_summary(state: &SharedState) -> Value {
    let Ok(aapi) = state.aapi.lock() else {
        return json!({"ok": false, "error": "aapi_lock"});
    };
    // Coarse: reservation/ledger posture only — no token contents.
    json!({
        "schema": "operator_pulse.spend.v1",
        "aapi_effect_field": crate::substrate::aapi_effect_field::posture_json(),
        "note": "Per-agent budgets via GET /aapi/budgets — pulse shows field posture only",
        "actions_visible": aapi.list_actions(None).len(),
    })
}

fn dim_summary(state: &SharedState) -> Value {
    // Aggregate: count agents with DIM + any degraded — no CoT.
    let mut degraded = 0usize;
    let mut total = 0usize;
    let Ok(es) = state.engine_store.lock() else {
        return json!({"ok": false});
    };
    if let Ok(keys) = es.folder_keys(crate::substrate::dim::DIM_FOLDER, None) {
        for k in keys.into_iter().take(64) {
            if let Ok(Some(v)) = es.folder_get(crate::substrate::dim::DIM_FOLDER, &k) {
                total += 1;
                if v.get("regime")
                    .and_then(|r| r.as_str())
                    .map(|r| r.contains("degraded") || r == "Degraded" || r == "Crisis")
                    .unwrap_or(false)
                {
                    degraded += 1;
                }
            }
        }
    }
    json!({
        "agents_with_dim": total,
        "degraded": degraded,
        "bands": crate::substrate::dim::bands::posture_json(),
        "honesty": "Regime/Φ only — no chain-of-thought",
    })
}

fn hitl_pending_count(state: &SharedState) -> usize {
    let Ok(es) = state.engine_store.lock() else {
        return 0;
    };
    let Ok(keys) = es.folder_keys("iia_hitl_requests", None) else {
        return 0;
    };
    keys.into_iter()
        .filter(|k| {
            es.folder_get("iia_hitl_requests", k)
                .ok()
                .flatten()
                .and_then(|v| {
                    let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("pending");
                    Some(status == "pending" || status == "awaiting")
                })
                .unwrap_or(false)
        })
        .count()
}

/// Build pulse summary for the operator shell (E6 / S26 — unified, no CoT).
pub fn compute_pulse(state: &SharedState) -> Value {
    let (running, idle, _other) = count_workflows_by_state(state);
    let needs_you = count_needs_you(state);
    let health = kernel_health_snapshot(state);
    let hitl = hitl_pending_count(state);

    let node_name = health
        .get("node")
        .and_then(|v| v.as_str())
        .unwrap_or("connector-node")
        .to_string();
    let health_status = health
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    json!({
        "schema": "operator_pulse.v2",
        "workflows": {
            "running": running,
            "idle": idle,
            "needs_you": needs_you
        },
        "node": {
            "name": node_name,
            "health_status": health_status,
            "health": health
        },
        "hitl_pending": hitl,
        "denials_recent": recent_denials(state, 12),
        "spend": spend_summary(state),
        "dim": dim_summary(state),
        "escape_hatches": crate::substrate::escape_hatches::posture_json(),
        "ops_runtime": crate::substrate::ops_runtime::ops_posture(state.as_ref()),
        "fix_queue_visible": needs_you > 0 || hitl > 0,
        "honesty": {
            "no_cot": true,
            "unavailable_fields": if health.get("status").is_none() {
                vec!["node.health_status"]
            } else {
                Vec::<&str>::new()
            }
        }
    })
}

/// `GET /api/v1/operator/pulse`
pub async fn get_operator_pulse(State(state): State<SharedState>) -> Json<Value> {
    Json(operator_envelope(compute_pulse(&state)))
}
