//! DIM persistence — restart continuity (DIM-INV-05).

use serde_json::{json, Value};

use super::state::{
    DynamicIntelligenceState, RegulationAction, DIM_FOLDER, DIM_JOURNAL_FOLDER,
};
use crate::state::PlatformState;

pub fn load(state: &PlatformState, agent_pid: &str) -> DynamicIntelligenceState {
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(Some(v)) = es.folder_get(DIM_FOLDER, agent_pid) {
            if let Ok(mut z) = serde_json::from_value::<DynamicIntelligenceState>(v) {
                z.clamp_all();
                return z;
            }
        }
    }
    DynamicIntelligenceState::fresh(agent_pid)
}

pub fn save(state: &PlatformState, z: &DynamicIntelligenceState) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| e.to_string())?;
    es.folder_put(DIM_FOLDER, &z.agent_pid, &z.to_json())
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn journal(state: &PlatformState, z: &DynamicIntelligenceState, action: RegulationAction) {
    let key = format!(
        "{}_{}_{}",
        z.agent_pid,
        z.measured_at_ms,
        action.as_str()
    );
    let entry = json!({
        "schema": "connector.dim.journal.v1",
        "agent_pid": z.agent_pid,
        "action": action.as_str(),
        "regime": z.regime.as_str(),
        "phi": z.homeodynamic_potential,
        "theta": z.cognitive_temperature,
        "revision": z.revision,
        "at_ms": z.measured_at_ms,
        "authority": "unchanged",
    });
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(DIM_JOURNAL_FOLDER, &key, &entry);
    }
}

pub fn list_recent_journal(state: &PlatformState, agent_pid: &str, limit: usize) -> Vec<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let Ok(keys) = es.folder_keys(DIM_JOURNAL_FOLDER, Some(agent_pid)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for k in keys.into_iter().rev().take(limit) {
        if let Ok(Some(v)) = es.folder_get(DIM_JOURNAL_FOLDER, &k) {
            out.push(v);
        }
    }
    out
}
