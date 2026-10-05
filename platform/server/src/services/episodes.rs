//! AMA-2: Episode object service — groups agent sessions into coherent named episodes.
//!
//! Episodes are the "logrotate" layer: a session creates raw packets,
//! and an episode groups one or more sessions into a named, bounded unit
//! (Conversation, Workflow, CodingTask, SupportCase, etc.).
//!
//! Routes:
//!   POST /agents/{pid}/episodes              — create episode from session range
//!   GET  /agents/{pid}/episodes              — list all episodes
//!   GET  /agents/{pid}/episodes/{episode_id} — episode detail + linked packets

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::SharedState;
use connector_engine::engine_store::EngineStore;

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}
fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[derive(Debug, Deserialize)]
pub struct CreateEpisodeRequest {
    pub session_ids: Vec<String>,
    pub episode_type: Option<String>,
    pub title: Option<String>,
    pub outcome: Option<String>,
    pub end_ms: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EpisodeRecord {
    pub episode_id: String,
    pub agent_pid: String,
    pub session_ids: Vec<String>,
    pub start_ms: i64,
    pub end_ms: Option<i64>,
    pub memory_cids: Vec<String>,
    pub summary_cid: Option<String>,
    pub episode_type: String,
    pub outcome: Option<String>,
    pub title: Option<String>,
    pub created_at: String,
}

/// POST /agents/{pid}/episodes — create episode from session IDs
pub async fn create_episode(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
    Json(req): Json<CreateEpisodeRequest>,
) -> Json<serde_json::Value> {
    if req.session_ids.is_empty() {
        return Json(serde_json::json!({
            "ok": false,
            "error": {"code": "session_ids_required", "message": "session_ids must not be empty"}
        }));
    }

    let ts_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let episode_id = format!("ep_{:x}_{:x}", now_ms(), ts_ns);
    let episode_type = req
        .episode_type
        .unwrap_or_else(|| "conversation".to_string());

    // memory_cids gathered lazily on demand; not pre-collected at create time
    let memory_cids: Vec<String> = Vec::new();

    let episode = EpisodeRecord {
        episode_id: episode_id.clone(),
        agent_pid: pid.clone(),
        session_ids: req.session_ids.clone(),
        start_ms: now_ms(),
        end_ms: req.end_ms,
        memory_cids: memory_cids.clone(),
        summary_cid: None,
        episode_type: episode_type.clone(),
        outcome: req.outcome.clone(),
        title: req.title.clone(),
        created_at: now_iso(),
    };

    // Persist episode
    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(
            &format!("episodes:{}", pid),
            &episode_id,
            &serde_json::to_value(&episode).unwrap_or_default(),
        );
    }

    Json(serde_json::json!({
        "ok": true,
        "episode_id": episode_id,
        "agent_pid": pid,
        "session_ids": req.session_ids,
        "episode_type": episode_type,
        "memory_cids_count": memory_cids.len(),
        "title": req.title,
        "outcome": req.outcome,
        "created_at": now_iso(),
    }))
}

/// GET /agents/{pid}/episodes — list all episodes for agent
pub async fn list_episodes(
    State(state): State<SharedState>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let episodes: Vec<serde_json::Value> = {
        let es = state.engine_store.lock().unwrap();
        // List all episodes stored under episodes:{pid} folder
        // folder_list returns key strings; folder_get retrieves each
        let folder_name = format!("episodes:{}", pid);
        let keys: Vec<String> = es.folder_keys(&folder_name, None).unwrap_or_default();
        keys.iter()
            .filter_map(|key| es.folder_get(&folder_name, key).ok().flatten())
            .collect()
    };

    Json(serde_json::json!({
        "ok": true,
        "agent_pid": pid,
        "count": episodes.len(),
        "episodes": episodes,
    }))
}

/// GET /agents/{pid}/episodes/{episode_id} — episode detail
pub async fn get_episode(
    State(state): State<SharedState>,
    Path((pid, episode_id)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    let episode = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get(&format!("episodes:{}", pid), &episode_id)
            .ok()
            .flatten()
    };

    match episode {
        None => Json(serde_json::json!({
            "ok": false,
            "error": {"code": "episode_not_found", "message": format!("episode {} not found for agent {}", episode_id, pid)}
        })),
        Some(ep) => Json(serde_json::json!({
            "ok": true,
            "episode": ep,
        })),
    }
}

/// POST /agents/{pid}/episodes/{episode_id}/close — close episode with outcome
pub async fn close_episode(
    State(state): State<SharedState>,
    Path((pid, episode_id)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let outcome = body
        .get("outcome")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let summary_cid = body
        .get("summary_cid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let updated = {
        let folder_name = format!("episodes:{}", pid);
        let mut es = state.engine_store.lock().unwrap();
        let existing = es.folder_get(&folder_name, &episode_id).ok().flatten();
        if let Some(mut ep) = existing {
            if let Some(obj) = ep.as_object_mut() {
                obj.insert("end_ms".to_string(), serde_json::json!(now_ms()));
                if let Some(ref o) = outcome {
                    obj.insert("outcome".to_string(), serde_json::json!(o));
                }
                if let Some(ref sc) = summary_cid {
                    obj.insert("summary_cid".to_string(), serde_json::json!(sc));
                }
            }
            let _ = es.folder_put(&folder_name, &episode_id, &ep);
            Some(ep)
        } else {
            None
        }
    };

    match updated {
        None => Json(serde_json::json!({
            "ok": false,
            "error": {"code": "episode_not_found", "message": format!("episode {} not found", episode_id)}
        })),
        Some(ep) => Json(serde_json::json!({
            "ok": true,
            "episode": ep,
            "closed_at": now_iso(),
        })),
    }
}
