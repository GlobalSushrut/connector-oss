//! B15 — agent Talk thread persistence (engine_store folder).

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::state::PlatformState;

pub const CHAT_THREADS_FOLDER: &str = "agent_chat_threads_v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatThreadMeta {
    pub thread_id: String,
    pub agent_pid: String,
    pub title: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub turn_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatTurn {
    pub role: String,
    pub content: String,
    pub at_ms: i64,
}

fn thread_key(agent_pid: &str, thread_id: &str) -> String {
    format!("{agent_pid}|{thread_id}")
}

pub fn list_threads(state: &PlatformState, agent_pid: &str) -> Vec<ChatThreadMeta> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let keys = es.folder_keys(CHAT_THREADS_FOLDER, None).unwrap_or_default();
    let prefix = format!("{agent_pid}|");
    let mut out = Vec::new();
    for k in keys {
        if !k.starts_with(&prefix) {
            continue;
        }
        if let Ok(Some(v)) = es.folder_get(CHAT_THREADS_FOLDER, &k) {
            if let Ok(meta) = serde_json::from_value::<ChatThreadMeta>(
                v.get("meta").cloned().unwrap_or(v),
            ) {
                out.push(meta);
            }
        }
    }
    out.sort_by(|a, b| b.updated_at_ms.cmp(&a.updated_at_ms));
    out
}

pub fn get_thread(
    state: &PlatformState,
    agent_pid: &str,
    thread_id: &str,
) -> Option<serde_json::Value> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(CHAT_THREADS_FOLDER, &thread_key(agent_pid, thread_id))
        .ok()
        .flatten()
}

pub fn create_thread(state: &PlatformState, agent_pid: &str, title: Option<&str>) -> ChatThreadMeta {
    let now = chrono::Utc::now().timestamp_millis();
    let thread_id = format!(
        "thr_{}",
        &hex::encode(Sha256::digest(format!("{agent_pid}|{now}").as_bytes()))[..12]
    );
    let meta = ChatThreadMeta {
        thread_id: thread_id.clone(),
        agent_pid: agent_pid.into(),
        title: title.unwrap_or("Talk").into(),
        created_at_ms: now,
        updated_at_ms: now,
        turn_count: 0,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            CHAT_THREADS_FOLDER,
            &thread_key(agent_pid, &thread_id),
            &json!({ "meta": meta, "turns": [] }),
        );
    }
    meta
}

pub fn append_turn(
    state: &PlatformState,
    agent_pid: &str,
    thread_id: &str,
    role: &str,
    content: &str,
) -> Result<u64, String> {
    let key = thread_key(agent_pid, thread_id);
    let mut es = state.engine_store.lock().map_err(|e| format!("{e:?}"))?;
    let mut doc = es
        .folder_get(CHAT_THREADS_FOLDER, &key)
        .map_err(|e| format!("{e:?}"))?
        .ok_or_else(|| "thread_not_found".to_string())?;
    let turn = ChatTurn {
        role: role.into(),
        content: content.into(),
        at_ms: chrono::Utc::now().timestamp_millis(),
    };
    let turns = doc
        .get_mut("turns")
        .and_then(|t| t.as_array_mut())
        .ok_or_else(|| "thread_corrupt".to_string())?;
    turns.push(serde_json::to_value(&turn).unwrap_or(json!({})));
    let count = turns.len() as u64;
    if let Some(meta) = doc.get_mut("meta").and_then(|m| m.as_object_mut()) {
        meta.insert("turn_count".into(), json!(count));
        meta.insert("updated_at_ms".into(), json!(turn.at_ms));
    }
    es.folder_put(CHAT_THREADS_FOLDER, &key, &doc)
        .map_err(|e| format!("{e:?}"))?;
    Ok(count)
}
