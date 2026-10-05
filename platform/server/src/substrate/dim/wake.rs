//! DIM wake signals — temporal / goal pressure can wake cognition without a new prompt.
//! Authority-neutral: wake is a cognitive cue, not Allow.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::persist;
use super::regulate;
use super::state::{DynamicIntelligenceState, RegulationAction};
use crate::state::PlatformState;

pub const WAKE_FOLDER: &str = "dim_wake_signals";
pub const WAKE_SCHEMA: &str = "connector.dim.wake.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WakeSignal {
    pub schema: String,
    pub wake_id: String,
    pub agent_pid: String,
    pub reason: String,
    pub temporal_pressure: f32,
    pub goal_tension: f32,
    pub regime: String,
    pub consumed: bool,
    pub at_ms: i64,
}

/// Evaluate whether idle agent should wake; persist signal if so (A19 / S9).
pub fn evaluate_wake(state: &PlatformState, agent_pid: &str) -> Value {
    let mut z = super::refresh_for_agent(state, agent_pid);
    let action = regulate::propose_regulation(&z);
    if action != RegulationAction::WakeCognition
        && !(z.temporal_pressure > 0.75 && z.goal_tension > 0.25)
    {
        return json!({
            "ok": true,
            "wake": false,
            "proposed": action.as_str(),
            "condition": z.operator_view(),
            "honesty": "No wake — temporal/goal pressure below threshold",
        });
    }
    // Apply WakeCognition regulation (cognitive elasticity only).
    let _ = regulate::apply_regulation(state, &mut z, RegulationAction::WakeCognition);
    let signal = emit_wake(state, &z, "temporal_goal_pressure");
    json!({
        "ok": true,
        "wake": true,
        "signal": signal,
        "condition": z.operator_view(),
        "honesty": "Wake is cognitive cue without new user prompt — not authorization",
    })
}

fn emit_wake(state: &PlatformState, z: &DynamicIntelligenceState, reason: &str) -> WakeSignal {
    let signal = WakeSignal {
        schema: WAKE_SCHEMA.into(),
        wake_id: uuid::Uuid::new_v4().to_string(),
        agent_pid: z.agent_pid.clone(),
        reason: reason.into(),
        temporal_pressure: z.temporal_pressure,
        goal_tension: z.goal_tension,
        regime: z.regime.as_str().into(),
        consumed: false,
        at_ms: super::state::now_ms(),
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            WAKE_FOLDER,
            &signal.wake_id,
            &serde_json::to_value(&signal).unwrap_or(Value::Null),
        );
    }
    signal
}

/// List pending (unconsumed) wake signals for an agent.
pub fn pending_wakes(state: &PlatformState, agent_pid: &str) -> Vec<Value> {
    let mut out = Vec::new();
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(keys) = es.folder_keys(WAKE_FOLDER, None) {
            for k in keys.into_iter().rev().take(32) {
                if let Ok(Some(v)) = es.folder_get(WAKE_FOLDER, &k) {
                    if v.get("agent_pid").and_then(|x| x.as_str()) != Some(agent_pid) {
                        continue;
                    }
                    if v.get("consumed").and_then(|x| x.as_bool()) == Some(true) {
                        continue;
                    }
                    out.push(v);
                }
            }
        }
    }
    out
}

/// Mark a wake signal consumed (agent loop / operator ack).
pub fn consume_wake(state: &PlatformState, wake_id: &str) -> Value {
    let Ok(mut es) = state.engine_store.lock() else {
        return json!({"ok": false, "error": "store_lock"});
    };
    let Some(mut v) = es.folder_get(WAKE_FOLDER, wake_id).ok().flatten() else {
        return json!({"ok": false, "error": "wake_not_found"});
    };
    if let Some(obj) = v.as_object_mut() {
        obj.insert("consumed".into(), json!(true));
        obj.insert("consumed_at_ms".into(), json!(super::state::now_ms()));
    }
    let _ = es.folder_put(WAKE_FOLDER, wake_id, &v);
    json!({"ok": true, "wake": v})
}
