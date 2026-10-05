//! Situation, presence, and source-version records. None of them admit an effect.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::{PlatformState, SharedState};

pub const SOURCE_FOLDER: &str = "source_version_v1";
pub const SITUATION_FOLDER: &str = "situation_v1";

pub fn source_version_record(asset_cid: &str, content_sha256: &str) -> Value {
    json!({
        "schema": "connector.source_version.v1",
        "asset_cid": asset_cid,
        "content_sha256": content_sha256,
        "parser": "connector.mempacket_ingest",
        "parser_version": "v1",
        "lifecycle": "ingested",
        "eligible": "absent",
        "active": "absent",
        "admits": false,
        "honesty": "The ingest parser wrote a knowledge packet. Eligibility and active context stay absent.",
    })
}

pub fn persist_source_version(state: &PlatformState, asset_cid: &str, content: &str) {
    if asset_cid.is_empty() || content.is_empty() {
        return;
    }
    let digest = format!("{:x}", Sha256::digest(content.as_bytes()));
    let record = source_version_record(asset_cid, &digest);
    if let Ok(mut store) = state.engine_store.lock() {
        let _ = store.folder_put(SOURCE_FOLDER, asset_cid, &record);
    }
}

pub fn classify_presence(kernel_status: Option<&str>, parent_pid: Option<&str>) -> Value {
    let runtime = matches!(kernel_status, Some("running") | Some("waiting") | Some("suspended"));
    let child = parent_pid.is_some_and(|pid| !pid.trim().is_empty());
    json!({
        "schema": "connector.agent_presence.v1",
        "runtime_instance": if runtime { "present" } else { "absent" },
        "child_agent": if child { "present" } else { "absent" },
        "kernel_status": kernel_status.unwrap_or("absent"),
        "swarm": "absent",
        "admits": false,
        "honesty": "A running, waiting, or suspended kernel status is a runtime instance. A parent pid is a child principal. Swarm membership is absent and does not grant.",
    })
}

pub fn situation_from_checkpoints(
    agent_pid: &str,
    checkpoint_ids: &[String],
    task_id: Option<&str>,
    task_stored: bool,
) -> Option<Value> {
    if checkpoint_ids.is_empty() && !task_stored {
        return None;
    }
    Some(json!({
        "schema": "connector.situation.v1",
        "situation_id": format!("sit_{agent_pid}"),
        "agent_pid": agent_pid,
        "task": if task_stored { "present" } else { "absent" },
        "task_id": if task_stored { task_id } else { None },
        "checkpoint_ids": checkpoint_ids,
        "commitments": "absent",
        "authority": false,
        "admits": false,
        "honesty": "Index of stored checkpoints and, when the task row exists, one PATE task. It does not admit an effect.",
    }))
}

fn authorized(headers: &HeaderMap, pid: &str) -> bool {
    crate::services::agents::caller(headers).is_some()
        || crate::kernel::agent_identity_envelope::agent_self_access(headers, pid)
}

fn kernel_pid(state: &PlatformState, pid: &str) -> String {
    state
        .engine_store
        .lock()
        .ok()
        .and_then(|store| {
            store
                .folder_get("agent_meta", pid)
                .ok()
                .flatten()
                .and_then(|meta| meta.get("kernel_pid").and_then(|value| value.as_str()).map(str::to_string))
        })
        .unwrap_or_else(|| pid.to_string())
}

fn checkpoint_ids(state: &PlatformState, pid: &str) -> Vec<String> {
    let Ok(store) = state.engine_store.lock() else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    for key in store
        .folder_keys(crate::substrate::agent_memory::context_store::CHECKPOINT_FOLDER, None)
        .unwrap_or_default()
    {
        let Some(row) = store
            .folder_get(crate::substrate::agent_memory::context_store::CHECKPOINT_FOLDER, &key)
            .ok()
            .flatten()
        else {
            continue;
        };
        let agent_vid = row.get("agent_vid").and_then(|value| value.as_str()).unwrap_or("");
        if agent_vid == pid {
            ids.push(key);
        }
    }
    ids
}

fn task_stored(state: &PlatformState, task_id: &str) -> bool {
    state
        .engine_store
        .lock()
        .ok()
        .and_then(|store| store.folder_get(crate::substrate::pate::ATU_FOLDER, task_id).ok().flatten())
        .is_some()
}

/// GET /api/v1/agents/:pid/presence
pub async fn get_presence(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<Value> {
    if !authorized(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required", "admits": false}));
    }
    let detail = crate::substrate::agent_progeny::agent_progeny_detail(&state, &kernel_pid(state.as_ref(), &pid));
    let subtree = detail.get("subtree");
    let status = subtree.and_then(|node| node.get("kernel_status")).and_then(|value| value.as_str());
    let parent = subtree.and_then(|node| node.get("parent_pid")).and_then(|value| value.as_str());
    Json(json!({
        "ok": true,
        "presence": classify_presence(status, parent),
    }))
}

#[derive(Debug, Deserialize, Default)]
pub struct SituationBody {
    #[serde(default)]
    pub task_id: Option<String>,
}

/// GET /api/v1/agents/:pid/situation
pub async fn get_situation(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
) -> Json<Value> {
    if !authorized(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required", "admits": false}));
    }
    let row = state
        .engine_store
        .lock()
        .ok()
        .and_then(|store| store.folder_get(SITUATION_FOLDER, &pid).ok().flatten());
    match row {
        Some(record) => Json(json!({"ok": true, "status": "present", "situation": record, "admits": false})),
        None => Json(json!({"ok": true, "status": "absent", "admits": false})),
    }
}

/// POST /api/v1/agents/:pid/situation — store an index only when a checkpoint or task row exists.
pub async fn post_situation(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(pid): Path<String>,
    Json(body): Json<SituationBody>,
) -> Json<Value> {
    if let Some(error) = crate::services::workspace_records::lifecycle_error(&headers) {
        return Json(error);
    }
    if !authorized(&headers, &pid) {
        return Json(json!({"ok": false, "error": "auth_required", "executed": false, "admits": false}));
    }
    let requested = body.task_id.unwrap_or_default();
    let requested = requested.trim();
    let stored_task = !requested.is_empty() && task_stored(state.as_ref(), requested);
    let checkpoints = checkpoint_ids(state.as_ref(), &pid);
    let Some(record) = situation_from_checkpoints(
        &pid,
        &checkpoints,
        if stored_task { Some(requested) } else { None },
        stored_task,
    ) else {
        return Json(json!({
            "ok": true,
            "status": "absent",
            "executed": false,
            "admits": false,
            "honesty": "No checkpoint or stored PATE task was found, so no situation record was written.",
        }));
    };
    let saved = state
        .engine_store
        .lock()
        .ok()
        .and_then(|mut store| store.folder_put(SITUATION_FOLDER, &pid, &record).ok());
    if saved.is_none() {
        return Json(json!({"ok": false, "error": "situation_not_stored", "executed": false, "admits": false}));
    }
    Json(json!({"ok": true, "status": "present", "situation": record, "executed": false, "admits": false}))
}

pub fn promote_source(record: &Value, step: &str, activation_id: Option<&str>) -> Result<Value, &'static str> {
    if record.get("lifecycle").and_then(|value| value.as_str()) != Some("ingested") {
        return Err("ingested_source_required");
    }
    let mut next = record.clone();
    match step {
        "eligible" => {
            next["eligible"] = json!("present");
            next["active"] = json!("absent");
            next["model_context"] = json!("absent");
        }
        "active" => {
            if next.get("eligible").and_then(|value| value.as_str()) != Some("present") {
                return Err("eligible_required");
            }
            let Some(activation_id) = activation_id.filter(|value| !value.is_empty()) else {
                return Err("activation_required");
            };
            next["active"] = json!("index");
            next["activation_id"] = json!(activation_id);
            next["model_context"] = json!("absent");
        }
        _ => return Err("unknown_step"),
    }
    next["admits"] = json!(false);
    next["honesty"] = json!("Eligible is an operator mark. Active is an index to an activation receipt. Neither puts the file into model context.");
    Ok(next)
}

async fn promote(
    state: &SharedState,
    headers: &HeaderMap,
    pid: &str,
    cid: &str,
    step: &str,
) -> Json<Value> {
    if let Some(error) = crate::services::workspace_records::lifecycle_error(headers) {
        return Json(error);
    }
    if !authorized(headers, pid) {
        return Json(json!({"ok": false, "error": "auth_required", "executed": false, "admits": false}));
    }
    let current = state
        .engine_store
        .lock()
        .ok()
        .and_then(|store| store.folder_get(SOURCE_FOLDER, cid).ok().flatten());
    let Some(current) = current else {
        return Json(json!({"ok": false, "error": "source_absent", "executed": false, "admits": false}));
    };
    let activation_id = crate::services::workspace_records::latest_activation(state.as_ref(), pid)
        .and_then(|row| row.get("activation_id").and_then(|value| value.as_str()).map(str::to_string));
    let next = match promote_source(&current, step, activation_id.as_deref()) {
        Ok(next) => next,
        Err(error) => return Json(json!({"ok": false, "error": error, "executed": false, "admits": false})),
    };
    let saved = state
        .engine_store
        .lock()
        .ok()
        .and_then(|mut store| store.folder_put(SOURCE_FOLDER, cid, &next).ok());
    if saved.is_none() {
        return Json(json!({"ok": false, "error": "source_not_stored", "executed": false, "admits": false}));
    }
    Json(json!({"ok": true, "source": next, "executed": false, "admits": false}))
}

/// POST /api/v1/agents/:pid/sources/:cid/eligible
pub async fn post_source_eligible(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((pid, cid)): Path<(String, String)>,
) -> Json<Value> {
    promote(&state, &headers, &pid, &cid, "eligible").await
}

/// POST /api/v1/agents/:pid/sources/:cid/active
pub async fn post_source_active(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((pid, cid)): Path<(String, String)>,
) -> Json<Value> {
    promote(&state, &headers, &pid, &cid, "active").await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_keeps_swarm_absent() {
        let running_child = classify_presence(Some("running"), Some("parent"));
        assert_eq!(running_child["runtime_instance"], "present");
        assert_eq!(running_child["child_agent"], "present");
        assert_eq!(running_child["swarm"], "absent");
        assert_eq!(running_child["admits"], false);
        let idle = classify_presence(Some("completed"), None);
        assert_eq!(idle["runtime_instance"], "absent");
        assert_eq!(idle["child_agent"], "absent");
    }

    #[test]
    fn situation_requires_a_stored_source() {
        assert!(situation_from_checkpoints("agent", &[], None, false).is_none());
        let record = situation_from_checkpoints("agent", &["ckpt-1".into()], Some("missing"), false).unwrap();
        assert_eq!(record["task"], "absent");
        assert_eq!(record["authority"], false);
        assert_eq!(record["admits"], false);
        assert_eq!(record["checkpoint_ids"][0], "ckpt-1");
    }

    #[test]
    fn source_version_is_not_active_context() {
        let record = source_version_record("asset_1", "abc");
        assert_eq!(record["parser"], "connector.mempacket_ingest");
        assert_eq!(record["eligible"], "absent");
        assert_eq!(record["active"], "absent");
        assert_eq!(record["admits"], false);
    }

    #[test]
    fn eligible_does_not_enter_model_context() {
        let ingested = source_version_record("asset_1", "abc");
        let eligible = promote_source(&ingested, "eligible", None).unwrap();
        assert_eq!(eligible["eligible"], "present");
        assert_eq!(eligible["active"], "absent");
        assert_eq!(eligible["model_context"], "absent");
        assert_eq!(promote_source(&eligible, "active", None).unwrap_err(), "activation_required");
        let linked = promote_source(&eligible, "active", Some("act_1")).unwrap();
        assert_eq!(linked["active"], "index");
        assert_eq!(linked["model_context"], "absent");
        assert_eq!(linked["admits"], false);
    }
}
