//! AgentCell — high-density Linux execution body record + freeze/thaw.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::PlatformState;

pub const CELL_FOLDER: &str = "cvr_agent_cells";
pub const CELL_SCHEMA: &str = "connector.cvr.agent_cell.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCellRecord {
    pub schema: String,
    pub agentcell_id: String,
    pub agent_pid: String,
    pub execution_id: String,
    pub frozen: bool,
    pub freeze_reason: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub materials: Vec<String>,
}

impl AgentCellRecord {
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(json!({}))
    }
}

pub fn create_record(
    state: &PlatformState,
    agent_pid: &str,
    agentcell_id: &str,
    execution_id: &str,
) -> Result<AgentCellRecord, Value> {
    let now = chrono::Utc::now().timestamp_millis();
    let rec = AgentCellRecord {
        schema: CELL_SCHEMA.into(),
        agentcell_id: agentcell_id.to_string(),
        agent_pid: agent_pid.to_string(),
        execution_id: execution_id.to_string(),
        frozen: false,
        freeze_reason: None,
        created_at_ms: now,
        updated_at_ms: now,
        materials: vec![
            "cgroup_v2".into(),
            "namespaces".into(),
            "landlock".into(),
            "seccomp".into(),
            "network_mark".into(),
            "docklock_cage".into(),
        ],
    };
    let mut es = state.engine_store.lock().map_err(|e| {
        json!({"ok": false, "error": "lock", "detail": format!("{e}")})
    })?;
    es.folder_put(CELL_FOLDER, agent_pid, &rec.to_json())
        .map_err(|e| json!({"ok": false, "error": "persist", "detail": format!("{e}")}))?;
    // Also index by cell id
    let _ = es.folder_put(CELL_FOLDER, agentcell_id, &rec.to_json());
    Ok(rec)
}

/// Freeze AgentCell — OS-grade pause below cognition (architecture §34.3).
pub fn freeze_agent_cell(
    state: &PlatformState,
    agent_pid: &str,
    agentcell_id: &str,
    reason: &str,
) -> Value {
    let now = chrono::Utc::now().timestamp_millis();
    // try_freeze_agent takes the engine-store lock. Call it before this function does.
    let cgroup_result = crate::kernel::agent_cgroup::try_freeze_agent(state, agent_pid);
    let cgroup_frozen = cgroup_result
        .get("applied")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut es = match state.engine_store.lock() {
        Ok(e) => e,
        Err(e) => {
            return json!({"ok": false, "error": "lock", "detail": format!("{e}")});
        }
    };
    let mut rec = es
        .folder_get(CELL_FOLDER, agent_pid)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value::<AgentCellRecord>(v).ok())
        .unwrap_or(AgentCellRecord {
            schema: CELL_SCHEMA.into(),
            agentcell_id: agentcell_id.to_string(),
            agent_pid: agent_pid.to_string(),
            execution_id: format!("ex-orphan-{agent_pid}"),
            frozen: false,
            freeze_reason: None,
            created_at_ms: now,
            updated_at_ms: now,
            materials: vec!["cgroup_v2".into(), "network_mark".into()],
        });
    rec.frozen = true;
    rec.freeze_reason = Some(reason.to_string());
    rec.updated_at_ms = now;

    let _ = es.folder_put(CELL_FOLDER, agent_pid, &rec.to_json());
    let _ = es.folder_put(CELL_FOLDER, agentcell_id, &rec.to_json());

    json!({
        "ok": true,
        "agentcell_id": agentcell_id,
        "agent_pid": agent_pid,
        "frozen": true,
        "cgroup_freeze": cgroup_frozen,
        "reason": reason,
        "honesty": "Freeze is below cognition — not a model instruction",
    })
}

pub fn thaw_agent_cell(state: &PlatformState, agent_pid: &str, agentcell_id: &str) -> Value {
    let now = chrono::Utc::now().timestamp_millis();
    let mut es = match state.engine_store.lock() {
        Ok(e) => e,
        Err(e) => {
            return json!({"ok": false, "error": "lock", "detail": format!("{e}")});
        }
    };
    let Some(mut rec) = es
        .folder_get(CELL_FOLDER, agent_pid)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value::<AgentCellRecord>(v).ok())
    else {
        return json!({"ok": false, "error": "agentcell_not_found"});
    };
    rec.frozen = false;
    rec.freeze_reason = None;
    rec.updated_at_ms = now;
    drop(es);
    let _ = crate::kernel::agent_cgroup::try_thaw_agent(state, agent_pid);
    let mut es = match state.engine_store.lock() {
        Ok(e) => e,
        Err(e) => {
            return json!({"ok": false, "error": "lock", "detail": format!("{e}")});
        }
    };
    let _ = es.folder_put(CELL_FOLDER, agent_pid, &rec.to_json());
    let _ = es.folder_put(CELL_FOLDER, agentcell_id, &rec.to_json());
    json!({
        "ok": true,
        "agentcell_id": agentcell_id,
        "frozen": false,
    })
}

pub fn is_frozen(state: &PlatformState, agent_pid: &str) -> bool {
    let Ok(es) = state.engine_store.lock() else {
        return false;
    };
    es.folder_get(CELL_FOLDER, agent_pid)
        .ok()
        .flatten()
        .and_then(|v| v.get("frozen").and_then(|x| x.as_bool()))
        .unwrap_or(false)
}
