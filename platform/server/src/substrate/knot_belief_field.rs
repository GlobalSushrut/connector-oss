//! Knot belief-field — interference persistence, DIM-modulated recall hints,
//! selective foresight. Never authorizes effects.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::PlatformState;
use crate::substrate::belief_snapshot::{self, ClaimStatus};
use crate::substrate::dim;

pub const INTERFERENCE_FOLDER: &str = "knot_interference_events";
pub const FORESIGHT_FOLDER: &str = "knot_selective_foresight";
pub const BELIEF_FIELD_SCHEMA: &str = "connector.knot.belief_field.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterferenceEvent {
    pub schema: String,
    pub event_id: String,
    pub agent_pid: String,
    pub claim_ids: Vec<String>,
    pub evidence_cids: Vec<String>,
    pub severity: f32,
    pub at_ms: i64,
}

/// Scan BeliefSnapshot for contradictions and persist interference (A18 / S13).
pub fn detect_and_persist_interference(
    state: &PlatformState,
    agent_pid: &str,
) -> Value {
    let belief = belief_snapshot::project_from_vac(state, "_knot", agent_pid);
    let contrad: Vec<_> = belief
        .claims
        .iter()
        .filter(|c| matches!(c.status, ClaimStatus::Contradicted))
        .collect();
    if contrad.is_empty() {
        return json!({
            "ok": true,
            "interference": false,
            "severity": 0.0,
            "events": [],
        });
    }
    let severity = (contrad.len() as f32 / belief.claims.len().max(1) as f32).clamp(0.05, 1.0);
    let event = InterferenceEvent {
        schema: "connector.knot.interference.v1".into(),
        event_id: uuid::Uuid::new_v4().to_string(),
        agent_pid: agent_pid.into(),
        claim_ids: contrad.iter().map(|c| c.claim_id.clone()).collect(),
        evidence_cids: contrad
            .iter()
            .flat_map(|c| c.evidence_cids.iter().cloned())
            .collect(),
        severity,
        at_ms: chrono::Utc::now().timestamp_millis(),
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            INTERFERENCE_FOLDER,
            &event.event_id,
            &serde_json::to_value(&event).unwrap_or(Value::Null),
        );
    }
    // Feed DIM X without admitting anything.
    let mut z = dim::persist::load(state, agent_pid);
    z.interference = (0.4 * z.interference + 0.6 * severity).clamp(0.0, 1.0);
    z.precision = (z.precision * (1.0 - 0.3 * severity)).clamp(0.05, 1.0);
    let _ = dim::persist::save(state, &z);

    json!({
        "ok": true,
        "interference": true,
        "severity": severity,
        "event": event,
        "honesty": "Contradiction raises interference; no silent overwrite; ActionBinding still gates writes",
    })
}

pub fn list_interference(state: &PlatformState, agent_pid: &str, limit: usize) -> Vec<Value> {
    let limit = limit.clamp(1, 100);
    let mut out = Vec::new();
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(keys) = es.folder_keys(INTERFERENCE_FOLDER, None) {
            for k in keys.into_iter().rev().take(limit * 3) {
                if let Ok(Some(v)) = es.folder_get(INTERFERENCE_FOLDER, &k) {
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
    out
}

/// DIM-derived recall radius multiplier (belief-field parameter only).
pub fn recall_radius_multiplier(state: &PlatformState, agent_pid: &str) -> f32 {
    let z = dim::persist::load(state, agent_pid);
    let mut m = 1.0_f32;
    match z.last_regulation {
        dim::state::RegulationAction::IncreaseRecallRadius => m *= 1.5,
        dim::state::RegulationAction::DecreaseRecallRadius => m *= 0.6,
        _ => {}
    }
    // High interference → slightly wider recall to surface contradictions.
    if z.interference > 0.5 {
        m *= 1.25;
    }
    // High verification pressure → narrower, higher-precision recall.
    if z.consequence_pressure > 0.7 {
        m *= 0.75;
    }
    m.clamp(0.4, 2.5)
}

/// Selective foresight — upcoming mission/goal pressure without authorizing (S15).
pub fn selective_foresight(state: &PlatformState, agent_pid: &str) -> Value {
    let z = dim::persist::load(state, agent_pid);
    let mut hints = Vec::new();

    // Open mission steps for this agent (best-effort scan).
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(keys) = es.folder_keys(crate::kernel::mission_journal::STEP_FOLDER, None) {
            for k in keys.into_iter().rev().take(40) {
                if let Ok(Some(v)) = es.folder_get(crate::kernel::mission_journal::STEP_FOLDER, &k)
                {
                    let pid = v
                        .get("agent_pid")
                        .or_else(|| v.get("owner_pid"))
                        .and_then(|x| x.as_str());
                    if pid != Some(agent_pid) {
                        continue;
                    }
                    let status = v.get("status").and_then(|x| x.as_str()).unwrap_or("");
                    if status == "completed" || status == "done" {
                        continue;
                    }
                    hints.push(json!({
                        "kind": "open_mission_step",
                        "step_id": v.get("step_id"),
                        "mission_id": v.get("mission_id"),
                        "status": status,
                    }));
                    if hints.len() >= 5 {
                        break;
                    }
                }
            }
        }
    }

    if z.temporal_pressure > 0.6 {
        hints.push(json!({
            "kind": "temporal_pressure",
            "value": z.temporal_pressure,
            "hint": "deadline_or_idle_wake_candidate",
        }));
    }
    if z.goal_tension > 0.5 {
        hints.push(json!({
            "kind": "goal_tension",
            "value": z.goal_tension,
        }));
    }

    let body = json!({
        "schema": "connector.knot.selective_foresight.v1",
        "agent_pid": agent_pid,
        "hints": hints,
        "at_ms": chrono::Utc::now().timestamp_millis(),
        "honesty": "Foresight is cognitive cueing only — never Allow",
    });
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("{}_{}", agent_pid, chrono::Utc::now().timestamp_millis());
        let _ = es.folder_put(FORESIGHT_FOLDER, &key, &body);
    }
    body
}

pub fn posture_json() -> Value {
    json!({
        "schema": BELIEF_FIELD_SCHEMA,
        "role": "belief continuity + interference + foresight — never admits",
        "outcomes": ["A17", "A18", "S11", "S12", "S13", "S15"],
        "folders": [INTERFERENCE_FOLDER, FORESIGHT_FOLDER],
    })
}
