//! Asset Container & Knowledge Ingestion API
//!
//! Kafka-style pipeline: /v/assets/ → Validation → Cleaning → /k/knowledge/

use crate::auth::{verify_token, PlatformRole};
use crate::state::SharedState;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use vac_core::cid::compute_cid;
use vac_core::kernel::{SyscallPayload, SyscallRequest, SyscallValue};
use vac_core::types::{
    CognitivePath, MemPacket, MemoryKernelOp, MemoryType, PacketType, Source, SourceKind,
};

// ── Auth helper ───────────────────────────────────────────────────────────────
fn caller(headers: &axum::http::HeaderMap) -> Option<(String, PlatformRole)> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Some(("dev".to_string(), PlatformRole::SuperAdmin));
    }
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))?;
    let claims = verify_token(token).ok()?;
    let role = PlatformRole::from_str(&claims.role);
    Some((claims.sub, role))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn classify_asset(filename: &str) -> String {
    filename
        .split('.')
        .last()
        .unwrap_or("raw")
        .to_ascii_lowercase()
}

fn sanitize_filename(name: &str) -> Option<String> {
    let name = name.trim().trim_start_matches('/');
    if name.is_empty() || name.contains('\\') || name.contains('\0') {
        return None;
    }
    let mut parts = Vec::new();
    for part in name.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains('\0') {
            return None;
        }
        parts.push(part);
    }
    Some(parts.join("/"))
}

#[derive(Deserialize)]
pub struct CreateContainerRequest {
    pub name: String,
    #[serde(default)]
    pub allowed_types: Option<Vec<String>>,
    #[serde(default)]
    pub quota_bytes: Option<u64>,
    #[serde(default)]
    pub agent_pid: Option<String>,
}

#[derive(Deserialize)]
pub struct UploadRequest {
    pub filename: String,
    pub content: String,
}

#[derive(Deserialize)]
pub struct IngestRequest {
    pub container_id: String,
    #[serde(default)]
    pub target_ns: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub agent_pid: Option<String>,
}

/// POST /assets/containers — Create asset container in /v/ namespace
pub async fn create_container(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateContainerRequest>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Auth required", "status": 401})),
    };
    if role.rank() < 2 {
        return Json(serde_json::json!({"error": "Writer+ required", "status": 403}));
    }

    let id = format!("ac_{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let now = now_ms();
    let allowed = req
        .allowed_types
        .unwrap_or_else(|| vec!["txt".into(), "md".into(), "json".into(), "csv".into()]);

    let container = serde_json::json!({
        "id": id,
        "name": req.name,
        "namespace": format!("v/{}", id),
        "allowed_types": allowed,
        "quota_bytes": req.quota_bytes.unwrap_or(1024*1024*1024),
        "used_bytes": 0,
        "asset_count": 0,
        "created_at": now,
        "owner": user_id,
        "agent_pid": req.agent_pid.unwrap_or_default(),
    });

    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put("asset_containers", &id, &container);
    }

    Json(serde_json::json!({"ok": true, "container": container}))
}

/// GET /assets/containers — List containers
pub async fn list_containers(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<ListQuery>,
) -> Json<serde_json::Value> {
    if caller(&headers).is_none() {
        return Json(serde_json::json!({"error": "Auth required", "status": 401}));
    }
    let agent_pid = query.agent_pid.unwrap_or_default();
    let containers: Vec<serde_json::Value> = {
        let es = state.engine_store.lock().unwrap();
        let keys = es.folder_keys("asset_containers", None).unwrap_or_default();
        keys.iter()
            .filter_map(|k| es.folder_get("asset_containers", k).ok().flatten())
            .filter(|container| {
                agent_pid.is_empty()
                    || container.get("agent_pid").and_then(|v| v.as_str()) == Some(agent_pid.as_str())
            })
            .collect()
    };
    Json(serde_json::json!({"containers": containers, "count": containers.len()}))
}

/// GET /assets/containers/:id — container plus stored file records. Content bytes stay out.
pub async fn get_container(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(container_id): Path<String>,
) -> Json<serde_json::Value> {
    if caller(&headers).is_none() {
        return Json(serde_json::json!({"error": "Auth required", "status": 401}));
    }
    let (container, assets) = {
        let es = state.engine_store.lock().unwrap();
        let container = es
            .folder_get("asset_containers", &container_id)
            .ok()
            .flatten();
        let assets = es
            .folder_keys("asset_records", None)
            .unwrap_or_default()
            .iter()
            .filter_map(|key| es.folder_get("asset_records", key).ok().flatten())
            .filter(|record| {
                record.get("container_id").and_then(|v| v.as_str()) == Some(container_id.as_str())
            })
            .collect::<Vec<_>>();
        (container, assets)
    };
    let Some(container) = container else {
        return Json(serde_json::json!({"ok": false, "error": "Container not found", "status": 404}));
    };
    Json(serde_json::json!({
        "ok": true,
        "container": container,
        "assets": assets,
        "count": assets.len(),
        "activation": "stored files are not model context",
    }))
}

/// POST /assets/containers/:id/upload — Upload file to container
pub async fn upload_asset(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(container_id): Path<String>,
    Json(req): Json<UploadRequest>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Auth required", "status": 401})),
    };
    if role.rank() < 2 {
        return Json(serde_json::json!({"error": "Writer+ required", "status": 403}));
    }

    if let Err(deny) = crate::substrate::admission_gate::require_memory_write(
        &state,
        &user_id,
        &format!("v/{container_id}"),
    ) {
        return Json(deny);
    }

    // Validate container exists
    let container = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("asset_containers", &container_id)
            .ok()
            .flatten()
    };
    if container.is_none() {
        return Json(serde_json::json!({"error": "Container not found", "status": 404}));
    }

    let filename = match sanitize_filename(&req.filename) {
        Some(name) => name,
        None => return Json(serde_json::json!({"error": "invalid_filename", "status": 400})),
    };
    let ext = filename.split('.').last().unwrap_or("").to_lowercase();
    const MAX_ASSET_BYTES: usize = 25 * 1024 * 1024;
    if req.content.len() > MAX_ASSET_BYTES {
        return Json(serde_json::json!({"error": "asset_too_large", "status": 413}));
    }
    let agent_pid = container
        .as_ref()
        .and_then(|row| row.get("agent_pid"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or(user_id.as_str())
        .to_string();
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_pid,
        "assets",
        "upload",
        &serde_json::json!({"container_id": container_id, "filename": filename}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let cid = format!("asset_{}", &uuid::Uuid::new_v4().to_string()[..12]);
    let now = now_ms();
    let size_bytes = req.content.len() as u64;

    let record = serde_json::json!({
        "cid": cid,
        "filename": filename,
        "file_type": ext,
        "size_bytes": size_bytes,
        "container_id": container_id,
        "status": "pending",
        "lifecycle": "stored",
        "eligible": "absent",
        "active": "absent",
        "uploaded_at": now,
        "uploaded_by": user_id,
    });

    {
        let mut es = state.engine_store.lock().unwrap();
        let mut container = match es
            .folder_get("asset_containers", &container_id)
            .ok()
            .flatten()
        {
            Some(c) => c,
            None => {
                drop(es);
                open_proceed.finish_observed(false);
                return Json(serde_json::json!({"error": "Container not found", "status": 404, "executed": false, "admits": false}));
            }
        };
        let quota = container
            .get("quota_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(1024 * 1024 * 1024);
        let used = container
            .get("used_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if used.saturating_add(size_bytes) > quota {
            drop(es);
            open_proceed.finish_observed(false);
            return Json(
                serde_json::json!({"error": "quota_exceeded", "status": 413, "quota_bytes": quota, "used_bytes": used, "executed": false, "admits": false}),
            );
        }
        container["used_bytes"] = serde_json::json!(used + size_bytes);
        let _ = es.folder_put("asset_containers", &container_id, &container);
        let _ = es.folder_put("asset_records", &cid, &record);
        let _ = es.folder_put(
            "asset_content",
            &cid,
            &serde_json::json!({"content": req.content}),
        );
    }

    open_proceed.finish_observed(true);
    Json(serde_json::json!({"ok": true, "asset": record, "task_id": admitted.task_id, "executed": true, "admits": false}))
}

/// POST /assets/ingest — Process assets into knowledge
pub async fn ingest_assets(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<IngestRequest>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller(&headers) {
        Some(c) => c,
        None => return Json(serde_json::json!({"error": "Auth required", "status": 401})),
    };
    if role.rank() < 2 {
        return Json(serde_json::json!({"error": "Writer+ required", "status": 403}));
    }

    let target_ns = req
        .target_ns
        .clone()
        .unwrap_or_else(|| format!("k/{}", req.container_id));
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, &user_id, &target_ns)
    {
        return Json(deny);
    }

    let pending: Vec<serde_json::Value> = {
        let es = state.engine_store.lock().unwrap();
        let keys = es.folder_keys("asset_records", None).unwrap_or_default();
        keys.iter()
            .filter_map(|k| es.folder_get("asset_records", k).ok().flatten())
            .filter(|r| {
                r.get("container_id").and_then(|v| v.as_str()) == Some(&req.container_id)
                    && r.get("status").and_then(|v| v.as_str()) == Some("pending")
            })
            .collect()
    };

    if pending.is_empty() {
        return Json(serde_json::json!({"ok": false, "error": "No pending assets"}));
    }
    let agent_pid = {
        let store = state.engine_store.lock().unwrap();
        store
            .folder_get("asset_containers", &req.container_id)
            .ok()
            .flatten()
            .and_then(|row| row.get("agent_pid").and_then(|value| value.as_str()).map(str::to_string))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| user_id.clone())
    };
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_pid,
        "assets",
        "ingest",
        &serde_json::json!({"container_id": req.container_id}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let ingest_run_id = format!("assets_{}", uuid::Uuid::new_v4());
    let mut processed = 0;
    let now = now_ms();
    let mut written_packets: Vec<MemPacket> = Vec::new();
    let mut written_cids: Vec<String> = Vec::new();

    for asset in &pending {
        let asset_cid = asset.get("cid").and_then(|v| v.as_str()).unwrap_or("");
        let filename = asset
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let file_type = asset
            .get("file_type")
            .and_then(|v| v.as_str())
            .unwrap_or("raw");
        let content = {
            let es = state.engine_store.lock().unwrap();
            es.folder_get("asset_content", asset_cid)
                .ok()
                .flatten()
                .and_then(|c| {
                    c.get("content")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
        };

        if let Some(text) = content {
            // Clean text
            let cleaned = text.trim().replace("\r\n", "\n");
            let content_for_version = cleaned.clone();
            let payload = serde_json::json!({
                "text": cleaned,
                "source_asset_cid": asset_cid,
                "filename": filename,
                "file_type": file_type,
                "container_id": req.container_id,
                "target_namespace": target_ns,
                "ingested_by": user_id,
            });
            let payload_cid = match compute_cid(&payload) {
                Ok(cid) => cid,
                Err(_) => continue,
            };

            let mut packet = MemPacket::new(
                PacketType::Extraction,
                payload,
                payload_cid,
                user_id.clone(),
                "ingestion".to_string(),
                Source {
                    kind: SourceKind::SelfSource,
                    principal_id: "ingest".into(),
                },
                now,
            )
            .with_namespace(target_ns.clone())
            .with_session(format!("ingest-{}", req.container_id))
            .with_tags(vec![
                "knowledge_seed".into(),
                classify_asset(filename),
                file_type.to_string(),
                req.container_id.clone(),
            ]);
            packet.memory_type = MemoryType::Semantic;
            packet.abstraction_level = 3;
            packet.cognitive_path = Some(CognitivePath::memory(&user_id, &MemoryType::Semantic));
            packet.metadata.insert(
                "ingest_mode".into(),
                serde_json::Value::String("asset_pipeline".into()),
            );
            packet.metadata.insert(
                "target_namespace".into(),
                serde_json::Value::String(target_ns.clone()),
            );
            packet.metadata.insert(
                "asset_cid".into(),
                serde_json::Value::String(asset_cid.to_string()),
            );

            let mut k = state.kernel.lock().unwrap();
            let result = k.dispatch(SyscallRequest {
                agent_pid: "system".to_string(),
                operation: MemoryKernelOp::MemWrite,
                payload: SyscallPayload::MemWrite {
                    packet: packet.clone(),
                },
                reason: Some(format!("ingest {}", asset_cid)),
                vakya_id: None,
                trace_parent: None,
                trace_state: None,
                api_version: None,
            });

            if result.outcome == vac_core::types::OpOutcome::Success {
                processed += 1;
                written_packets.push(packet);
                if let SyscallValue::Cid(cid) = result.value {
                    written_cids.push(cid.to_string());
                }
                // Update status
                let mut es = state.engine_store.lock().unwrap();
                let mut updated = asset.clone();
                if let Some(obj) = updated.as_object_mut() {
                    obj.insert("status".into(), serde_json::json!("ingested"));
                    obj.insert("lifecycle".into(), serde_json::json!("ingested"));
                    obj.insert("eligible".into(), serde_json::json!("absent"));
                    obj.insert("active".into(), serde_json::json!("absent"));
                    obj.insert("knowledge_namespace".into(), serde_json::json!(target_ns));
                }
                let _ = es.folder_put("asset_records", asset_cid, &updated);
                drop(es);
                crate::services::workspace_followthrough::persist_source_version(
                    state.as_ref(),
                    asset_cid,
                    &content_for_version,
                );
            }
        }
    }

    // Ingest into knowledge graph
    if !written_packets.is_empty() {
        let mut knot = state.knot.lock().unwrap();
        knot.ingest_packets(&written_packets, 0);
    }

    open_proceed.finish_observed(processed > 0);
    Json(serde_json::json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": processed > 0,
        "admits": false,
        "ingest_run_id": ingest_run_id,
        "processed": processed,
        "total": pending.len(),
        "target_namespace": target_ns,
        "knowledge_cids": written_cids,
        "lifecycle": "ingested",
        "eligible": "absent",
        "active": "absent",
        "honesty": "Ingested knowledge is not eligible and is not active context.",
        "pipeline": {
            "stages": ["validate_asset", "mem_write", "knot_ingest"],
            "spec": "GET /api/v1/memory/knowledge/pipeline/spec",
        },
    }))
}
