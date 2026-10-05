//! Moment manifest store + HTTP handlers (I-09 / I-12 recall hydrate).

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use base64::Engine;
use connector_trust::{MomentManifestV2, MomentPartV2, MOMENT_MANIFEST_SCHEMA};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    operator::honesty::operator_envelope,
    state::{PlatformState, SharedState},
};

pub const MOMENT_FOLDER: &str = "moment_manifests_v2";

pub fn persist_moment(state: &PlatformState, moment: &MomentManifestV2) -> String {
    debug_assert_eq!(moment.schema, MOMENT_MANIFEST_SCHEMA);
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        MOMENT_FOLDER,
        &moment.moment_id,
        &serde_json::to_value(moment).unwrap_or_default(),
    );
    moment.moment_id.clone()
}

pub fn moment_count(state: &PlatformState) -> usize {
    let es = state.engine_store.lock().unwrap();
    es.folder_keys(MOMENT_FOLDER, None)
        .map(|k| k.len())
        .unwrap_or(0)
}

pub fn load_moment(state: &PlatformState, moment_id: &str) -> Option<MomentManifestV2> {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(MOMENT_FOLDER, moment_id)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
}

/// Commit moment after LLM completion (called from billing side-effects).
pub fn commit_llm_moment(
    state: &PlatformState,
    session_id: &str,
    agent_pid: &str,
    model: &str,
    prompt_tokens: u32,
    completion_tokens: u32,
    usage_event_id: Option<&str>,
    admission_ticket_id: Option<&str>,
) -> MomentManifestV2 {
    let mut moment = MomentManifestV2::new_llm_turn(
        session_id,
        agent_pid,
        model,
        prompt_tokens,
        completion_tokens,
    );
    moment.usage_event_id = usage_event_id.map(str::to_string);
    moment.admission_ticket_id = admission_ticket_id.map(str::to_string);
    persist_moment(state, &moment);
    moment
}

/// Thin moment for multipart Object Fabric complete (P6.2) — part refs only, no assembled blob.
pub fn commit_thin_object_parts_moment(
    state: &PlatformState,
    session_id: &str,
    agent_pid: &str,
    parts: Vec<MomentPartV2>,
) -> MomentManifestV2 {
    let now = chrono::Utc::now().timestamp_millis();
    let moment = MomentManifestV2 {
        schema: MOMENT_MANIFEST_SCHEMA.into(),
        moment_id: format!("mom_{}", uuid::Uuid::new_v4().simple()),
        session_id: session_id.into(),
        agent_pid: agent_pid.into(),
        tenant_id: None,
        admission_ticket_id: None,
        causal_envelope_id: None,
        usage_event_id: None,
        parts,
        occurred_at_ms: now,
        contract_version: 2,
    };
    persist_moment(state, &moment);
    moment
}

#[derive(Deserialize)]
pub struct MomentListQuery {
    pub session_id: Option<String>,
    pub agent_pid: Option<String>,
    pub limit: Option<usize>,
}

/// `GET /api/v1/memory/moment/:id`
pub async fn get_moment(
    State(state): State<SharedState>,
    Path(moment_id): Path<String>,
) -> Json<Value> {
    match load_moment(state.as_ref(), &moment_id) {
        Some(m) => Json(operator_envelope(json!({
            "schema": MOMENT_MANIFEST_SCHEMA,
            "moment": m,
        }))),
        None => Json(operator_envelope(json!({
            "ok": false,
            "error": "moment_not_found",
            "moment_id": moment_id,
        }))),
    }
}

/// `GET /api/v1/memory/moments`
pub async fn list_moments(
    State(state): State<SharedState>,
    Query(q): Query<MomentListQuery>,
) -> Json<Value> {
    let limit = q.limit.unwrap_or(50).min(200);
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(MOMENT_FOLDER, None).unwrap_or_default();
    let mut moments: Vec<MomentManifestV2> = keys
        .iter()
        .filter_map(|k| es.folder_get(MOMENT_FOLDER, k).ok().flatten())
        .filter_map(|v| serde_json::from_value::<MomentManifestV2>(v).ok())
        .filter(|m| {
            q.session_id
                .as_ref()
                .map(|s| &m.session_id == s)
                .unwrap_or(true)
                && q.agent_pid
                    .as_ref()
                    .map(|a| &m.agent_pid == a)
                    .unwrap_or(true)
        })
        .collect();
    moments.sort_by(|a, b| b.occurred_at_ms.cmp(&a.occurred_at_ms));
    moments.truncate(limit);
    Json(operator_envelope(json!({
        "schema": "moment_list.v1",
        "count": moments.len(),
        "moments": moments,
    })))
}

#[derive(Deserialize)]
pub struct MomentRecallRequest {
    pub max_bytes: Option<usize>,
    pub max_parts: Option<usize>,
}

/// `POST /api/v1/memory/moment/:id/recall` — hydrate-by-budget from Object Fabric + inline text (I-12).
pub async fn recall_moment(
    State(state): State<SharedState>,
    Path(moment_id): Path<String>,
    _headers: HeaderMap,
    Json(req): Json<MomentRecallRequest>,
) -> Json<Value> {
    let Some(moment) = load_moment(state.as_ref(), &moment_id) else {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "moment_not_found",
        })));
    };
    let max_bytes = req.max_bytes.unwrap_or(64 * 1024);
    let max_parts = req.max_parts.unwrap_or(32);
    let mut used_bytes = 0usize;
    let mut included = Vec::new();
    let mut skipped = Vec::new();
    let mut truncated = false;
    let mut hydrate_errors = Vec::new();

    for part in &moment.parts {
        if included.len() >= max_parts {
            truncated = true;
            skipped.push(json!({
                "part_kind": part.part_kind,
                "reason": "max_parts",
                "object_ref": part.object_ref,
            }));
            continue;
        }

        let mut hydrated = json!({
            "part_kind": part.part_kind,
            "mime_type": part.mime_type,
            "object_ref": part.object_ref,
            "content_hash": part.content_hash,
        });

        let mut size = 0usize;
        if let Some(text) = &part.text {
            size = size.saturating_add(text.len());
            hydrated["text"] = json!(text);
        }

        // Hydrate object_ref / content_hash from Object Fabric when present.
        let fabric_key = part.object_ref.as_deref().or(part.content_hash.as_deref());
        if let Some(key) = fabric_key {
            match crate::services::object_fabric::get_object(&state, key) {
                Some((bytes, meta)) => {
                    size = size.saturating_add(bytes.len());
                    if used_bytes.saturating_add(size) > max_bytes {
                        truncated = true;
                        skipped.push(json!({
                            "part_kind": part.part_kind,
                            "reason": "max_bytes",
                            "object_ref": part.object_ref,
                            "size_bytes": bytes.len(),
                        }));
                        continue;
                    }
                    let preview_cap = (max_bytes.saturating_sub(used_bytes)).min(4096);
                    let preview = if bytes.len() <= preview_cap {
                        base64::engine::general_purpose::STANDARD.encode(&bytes)
                    } else {
                        truncated = true;
                        base64::engine::general_purpose::STANDARD.encode(&bytes[..preview_cap])
                    };
                    hydrated["payload_b64"] = json!(preview);
                    hydrated["payload_bytes"] = json!(bytes.len());
                    hydrated["payload_truncated"] = json!(bytes.len() > preview_cap);
                    hydrated["fabric_meta"] = meta;
                    used_bytes = used_bytes.saturating_add(if bytes.len() > preview_cap {
                        preview_cap
                    } else {
                        bytes.len()
                    });
                    if part.text.is_some() {
                        used_bytes = used_bytes
                            .saturating_add(part.text.as_ref().map(|t| t.len()).unwrap_or(0));
                    }
                    included.push(hydrated);
                    continue;
                }
                None => {
                    hydrate_errors.push(json!({
                        "object_ref": key,
                        "error": "object_not_found",
                    }));
                }
            }
        }

        if used_bytes.saturating_add(size) > max_bytes {
            truncated = true;
            skipped.push(json!({
                "part_kind": part.part_kind,
                "reason": "max_bytes",
                "object_ref": part.object_ref,
            }));
            continue;
        }
        used_bytes = used_bytes.saturating_add(size);
        included.push(hydrated);
    }

    Json(operator_envelope(json!({
        "schema": "moment_recall.v1",
        "moment_id": moment_id,
        "skeleton": moment,
        "hydrated_parts": included,
        "skipped_parts": skipped.len(),
        "skipped": skipped,
        "truncated": truncated,
        "hydrate_errors": hydrate_errors,
        "budget": { "max_bytes": max_bytes, "max_parts": max_parts, "used_bytes": used_bytes },
        "honesty": if truncated {
            "recall truncated by budget — not full moment materialization"
        } else {
            "recall within budget"
        },
    })))
}
