//! Shared MicroCell pool — N AgentCells per guest (Phase E1).
//!
//! Dedicated MicroCells (V4) never enter this pool (E2).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use super::micro_cell::{self, MicroCellInstance, MICROCELL_FOLDER};
use super::resources::ResourceProfile;
use crate::state::PlatformState;

pub const POOL_FOLDER: &str = "cvr_shared_pool";
pub const POOL_SCHEMA: &str = "connector.cvr.shared_pool.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedPoolEntry {
    pub schema: String,
    pub microcell_id: String,
    pub resource_profile: String,
    pub max_occupants: usize,
    pub occupants: Vec<String>,
    pub state: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl SharedPoolEntry {
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(json!({}))
    }

    pub fn has_capacity(&self) -> bool {
        self.state == "RUNNING" && self.occupants.len() < self.max_occupants
    }
}

fn shared_max() -> usize {
    std::env::var("CONNECTOR_MICROCELL_SHARED_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8)
        .clamp(1, 64)
}

fn pool_keys(state: &PlatformState) -> Vec<String> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    es.folder_keys(POOL_FOLDER, None).unwrap_or_default()
}

fn load_entry(state: &PlatformState, microcell_id: &str) -> Option<SharedPoolEntry> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(POOL_FOLDER, microcell_id).ok().flatten()?;
    serde_json::from_value(v).ok()
}

fn persist_entry(state: &PlatformState, entry: &SharedPoolEntry) -> Result<(), Value> {
    let mut es = state.engine_store.lock().map_err(|e| {
        json!({"ok": false, "error": "lock", "detail": format!("{e}")})
    })?;
    es.folder_put(POOL_FOLDER, &entry.microcell_id, &entry.to_json())
        .map_err(|e| json!({"ok": false, "error": "pool_persist", "detail": format!("{e}")}))?;
    Ok(())
}

/// Acquire a shared MicroCell for `agent_pid` (reuse with capacity, else boot new).
pub fn acquire_shared(
    state: &PlatformState,
    agent_pid: &str,
    resource: ResourceProfile,
) -> Result<(MicroCellInstance, SharedPoolEntry), Value> {
    // Already bound?
    if let Some(existing) = micro_cell::load_for_agent(state, agent_pid) {
        if !existing.dedicated {
            if let Some(mut entry) = load_entry(state, &existing.microcell_id) {
                if !entry.occupants.iter().any(|p| p == agent_pid) {
                    entry.occupants.push(agent_pid.to_string());
                    entry.updated_at_ms = chrono::Utc::now().timestamp_millis();
                    persist_entry(state, &entry)?;
                }
                return Ok((existing, entry));
            }
        }
    }

    // Find capacity in pool matching resource profile.
    let want = resource.as_str();
    for key in pool_keys(state) {
        let Some(mut entry) = load_entry(state, &key) else {
            continue;
        };
        if entry.resource_profile != want || !entry.has_capacity() {
            continue;
        }
        if entry.occupants.iter().any(|p| p == agent_pid) {
            let inst = micro_cell::load(state, &entry.microcell_id).ok_or_else(|| {
                json!({"ok": false, "error": "shared_microcell_missing", "microcell_id": entry.microcell_id})
            })?;
            return Ok((inst, entry));
        }
        // Attach occupant without starting a new VMM.
        entry.occupants.push(agent_pid.to_string());
        entry.updated_at_ms = chrono::Utc::now().timestamp_millis();
        persist_entry(state, &entry)?;
        // Index agent → microcell
        if let Some(mut inst) = micro_cell::load(state, &entry.microcell_id) {
            let _ = micro_cell::persist_agent_index(state, agent_pid, &inst);
            inst.updated_at_ms = entry.updated_at_ms;
            let _ = micro_cell::persist(state, &inst);
            return Ok((inst, entry));
        }
    }

    // Boot a new shared guest.
    let mc_id = format!("mc-s-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let inst = micro_cell::create_and_start_with_resources(
        state,
        &mc_id,
        agent_pid,
        false,
        resource,
    )?;
    let now = chrono::Utc::now().timestamp_millis();
    let entry = SharedPoolEntry {
        schema: POOL_SCHEMA.into(),
        microcell_id: mc_id,
        resource_profile: resource.as_str().into(),
        max_occupants: shared_max(),
        occupants: vec![agent_pid.to_string()],
        state: "RUNNING".into(),
        created_at_ms: now,
        updated_at_ms: now,
    };
    persist_entry(state, &entry)?;
    Ok((inst, entry))
}

/// Release agent from shared pool; stop VMM when last occupant leaves.
pub fn release_shared(state: &PlatformState, agent_pid: &str) -> Value {
    let Some(inst) = micro_cell::load_for_agent(state, agent_pid) else {
        return json!({"ok": true, "released": false, "reason": "no_microcell"});
    };
    if inst.dedicated {
        return json!({"ok": true, "released": false, "reason": "dedicated_not_pooled"});
    }
    let Some(mut entry) = load_entry(state, &inst.microcell_id) else {
        return json!({"ok": true, "released": false, "reason": "not_in_pool"});
    };
    entry.occupants.retain(|p| p != agent_pid);
    entry.updated_at_ms = chrono::Utc::now().timestamp_millis();
    let remaining = entry.occupants.len();
    let _ = persist_entry(state, &entry);
    // Drop agent index
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_delete(MICROCELL_FOLDER, &format!("agent:{agent_pid}"));
    }
    if remaining == 0 {
        let stop = micro_cell::stop(state, &inst.microcell_id);
        entry.state = "STOPPED".into();
        let _ = persist_entry(state, &entry);
        return json!({
            "ok": true,
            "released": true,
            "microcell_stopped": true,
            "stop": stop,
            "microcell_id": inst.microcell_id,
        });
    }
    json!({
        "ok": true,
        "released": true,
        "microcell_stopped": false,
        "remaining_occupants": remaining,
        "microcell_id": inst.microcell_id,
    })
}

pub fn pool_posture(state: &PlatformState) -> Value {
    let keys = pool_keys(state);
    let mut entries = Vec::new();
    let mut running = 0usize;
    let mut occupants = 0usize;
    for k in keys {
        if let Some(e) = load_entry(state, &k) {
            if e.state == "RUNNING" {
                running += 1;
            }
            occupants += e.occupants.len();
            entries.push(e.to_json());
        }
    }
    json!({
        "schema": "connector.cvr.shared_pool.posture.v1",
        "shared_max_per_guest": shared_max(),
        "running_shared_guests": running,
        "total_occupants": occupants,
        "entries": entries,
        "honesty": "Shared pool co-locates AgentCells in one guest — not a density SLA",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_check() {
        let e = SharedPoolEntry {
            schema: POOL_SCHEMA.into(),
            microcell_id: "mc-s-test".into(),
            resource_profile: "default".into(),
            max_occupants: 2,
            occupants: vec!["a".into()],
            state: "RUNNING".into(),
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        assert!(e.has_capacity());
        let full = SharedPoolEntry {
            occupants: vec!["a".into(), "b".into()],
            ..e
        };
        assert!(!full.has_capacity());
    }
}
