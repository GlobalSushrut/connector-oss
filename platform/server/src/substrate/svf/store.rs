//! SVF object / receipt store (engine_store folders).

use connector_trust::AgenticObject;
use serde_json::Value;

use crate::state::SharedState;

pub const OBJECT_FOLDER: &str = "svf_agentic_objects";
pub const RECEIPT_FOLDER: &str = "svf_disclosure_receipts";
pub const EFFECT_RECEIPT_FOLDER: &str = "svf_effect_receipts";
pub const REMASK_FOLDER: &str = "svf_observation_remask";

pub fn put_object(state: &SharedState, obj: &AgenticObject) -> Result<(), String> {
    let key = format!("{}:{}", obj.agent_vid, obj.object_id);
    let v = serde_json::to_value(obj).map_err(|e| e.to_string())?;
    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| format!("engine_store:{e}"))?;
    es.folder_put(OBJECT_FOLDER, &key, &v)
        .map_err(|e| format!("folder_put:{e}"))
}

pub fn get_object(state: &SharedState, agent_vid: &str, object_id: &str) -> Option<AgenticObject> {
    let key = format!("{agent_vid}:{object_id}");
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(OBJECT_FOLDER, &key).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn list_objects(state: &SharedState, agent_vid: &str) -> Vec<AgenticObject> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let Ok(keys) = es.folder_keys(OBJECT_FOLDER, Some(agent_vid)) else {
        return Vec::new();
    };
    keys.into_iter()
        .filter_map(|k| es.folder_get(OBJECT_FOLDER, &k).ok().flatten())
        .filter_map(|v| serde_json::from_value::<AgenticObject>(v).ok())
        .collect()
}

pub fn put_json(state: &SharedState, folder: &str, key: &str, value: &Value) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(folder, key, value);
    }
}

/// List disclosure receipts for an agent (keys `{agent_vid}:dr-…`).
pub fn list_receipts(state: &SharedState, agent_vid: &str) -> Vec<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let Ok(keys) = es.folder_keys(RECEIPT_FOLDER, Some(agent_vid)) else {
        return Vec::new();
    };
    keys.into_iter()
        .filter_map(|k| es.folder_get(RECEIPT_FOLDER, &k).ok().flatten())
        .collect()
}

/// List effect receipts for an agent.
pub fn list_effect_receipts(state: &SharedState, agent_vid: &str) -> Vec<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let Ok(keys) = es.folder_keys(EFFECT_RECEIPT_FOLDER, Some(agent_vid)) else {
        return Vec::new();
    };
    keys.into_iter()
        .filter_map(|k| es.folder_get(EFFECT_RECEIPT_FOLDER, &k).ok().flatten())
        .collect()
}
