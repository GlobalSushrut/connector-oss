//! Rebuildable MemoryNode index keyed by Sequence DNA slots.

use connector_trust::{MemoryDnaType, MemorySequenceDnaV1};
use serde_json::json;

use crate::state::PlatformState;

use super::{now_ms, FOLDER_ROOTS};

pub const FOLDER_NODES: &str = "crk_memory_nodes";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IndexedNode {
    pub dna: MemorySequenceDnaV1,
    pub trust_rank: u8,
    pub active: bool,
    pub skill_scope: Option<String>,
    pub subject: Option<String>,
    pub predicate: Option<String>,
    pub updated_at_ms: i64,
}

pub fn put_node(state: &PlatformState, node: &IndexedNode) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| format!("engine_store lock: {e}"))?;
    let agent = &node.dna.agent_dna;
    let cid = &node.dna.cid;
    let val = serde_json::to_value(node).map_err(|e| format!("serialize: {e}"))?;
    es.folder_put(FOLDER_NODES, &format!("node:{agent}:{cid}"), &val)
        .map_err(|e| format!("put node: {e}"))?;
    push_list(
        &mut **es,
        &format!("by_type:{agent}:{}", node.dna.type_dna.as_str()),
        cid,
    )?;
    if !node.dna.index_key.is_empty() {
        push_list(
            &mut **es,
            &format!("by_index:{agent}:{}", node.dna.index_key),
            cid,
        )?;
    }
    push_list(
        &mut **es,
        &format!("by_root:{agent}:{}", node.dna.auth_root),
        cid,
    )?;
    if let Some(skill) = &node.skill_scope {
        push_list(&mut **es, &format!("by_skill:{agent}:{skill}"), cid)?;
    }
    es.folder_put(
        FOLDER_ROOTS,
        "proj:causal_range",
        &json!({
            "watermark": node.dna.sequence_digest,
            "source_root": node.dna.auth_root,
            "updated_at_ms": now_ms(),
        }),
    )
    .map_err(|e| format!("put watermark: {e}"))?;
    Ok(())
}

fn push_list(
    es: &mut dyn connector_engine::engine_store::EngineStore,
    key: &str,
    cid: &str,
) -> Result<(), String> {
    let mut ids: Vec<String> = es
        .folder_get(FOLDER_NODES, key)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    if !ids.iter().any(|x| x == cid) {
        ids.push(cid.to_string());
    }
    es.folder_put(FOLDER_NODES, key, &serde_json::json!(ids))
        .map_err(|e| format!("put list: {e}"))?;
    Ok(())
}

pub fn get_node(state: &PlatformState, agent_pid: &str, cid: &str) -> Option<IndexedNode> {
    let es = state.engine_store.lock().ok()?;
    let v = es
        .folder_get(FOLDER_NODES, &format!("node:{agent_pid}:{cid}"))
        .ok()
        .flatten()?;
    serde_json::from_value(v).ok()
}

pub fn list_by_type(state: &PlatformState, agent_pid: &str, t: MemoryDnaType) -> Vec<String> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    es.folder_get(FOLDER_NODES, &format!("by_type:{agent_pid}:{}", t.as_str()))
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}
