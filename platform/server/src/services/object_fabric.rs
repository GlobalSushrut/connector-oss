//! Object Fabric platform API — content-addressed blob store (I-10 / P6.1).
//!
//! Blob bytes live under `{data_dir}/object_fabric_cas/` (filesystem CAS).
//! `engine_store` holds lean metadata only — `payload_b64` is no longer the SoT.
//!
//! P6.2: multipart chunk manifest + incomplete fail-closed; complete → thin moment with part refs.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path as FsPath, PathBuf};

use crate::{
    operator::honesty::operator_envelope,
    services::admission::{self, AdmissionOp, AdmissionRequest},
    state::SharedState,
};

pub const OBJECT_FABRIC_FOLDER: &str = "object_fabric_v2";
/// Filesystem CAS root under `PlatformConfig.data_dir`.
pub const OBJECT_FABRIC_CAS_DIR: &str = "object_fabric_cas";
/// Multipart upload manifests (P6.2 / I-22) — incomplete uploads fail closed.
pub const OBJECT_FABRIC_MULTIPART_FOLDER: &str = "object_fabric_multipart_v1";
pub const CHUNK_MANIFEST_SCHEMA: &str = "object_fabric_chunk_manifest.v1";

/// One chunk in a multipart upload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkPart {
    pub index: u32,
    pub content_hash: String,
    pub byte_length: u64,
}

/// Chunk manifest for multipart Object Fabric uploads (Core type for P6.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkManifest {
    pub schema: String,
    pub upload_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub total_bytes: u64,
    pub expected_chunks: u32,
    #[serde(default)]
    pub chunks: Vec<ChunkPart>,
    /// True only after all expected chunks are present and verified.
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moment_id: Option<String>,
    pub created_at_ms: i64,
}

impl ChunkManifest {
    pub fn new(upload_id: impl Into<String>, total_bytes: u64, expected_chunks: u32) -> Self {
        Self {
            schema: CHUNK_MANIFEST_SCHEMA.into(),
            upload_id: upload_id.into(),
            content_type: None,
            total_bytes,
            expected_chunks,
            chunks: Vec::new(),
            complete: false,
            object_ref: None,
            moment_id: None,
            created_at_ms: chrono::Utc::now().timestamp_millis(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
            && self.expected_chunks > 0
            && self.chunks.len() as u32 == self.expected_chunks
            && self.chunks.iter().map(|c| c.byte_length).sum::<u64>() == self.total_bytes
    }
}

/// Fail-closed: incomplete multipart must not commit.
pub fn assert_multipart_complete(manifest: &ChunkManifest) -> Result<(), &'static str> {
    if !manifest.is_complete() {
        return Err("multipart_incomplete_fail_closed");
    }
    Ok(())
}

fn content_hash(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

fn cas_root(data_dir: &str) -> PathBuf {
    FsPath::new(data_dir).join(OBJECT_FABRIC_CAS_DIR)
}

/// `sha256:<64-hex>` → `{data_dir}/object_fabric_cas/<aa>/<rest>` (sharded path).
fn normalize_cas_hex(hash_hex: &str) -> Option<String> {
    let hex = hash_hex
        .strip_prefix("sha256:")
        .unwrap_or(hash_hex)
        .trim()
        .to_ascii_lowercase();
    if hex.len() != 64 {
        return None;
    }
    if !hex
        .as_bytes()
        .iter()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    Some(hex)
}

fn cas_blob_path(data_dir: &str, hash_hex: &str) -> Option<PathBuf> {
    let hex = normalize_cas_hex(hash_hex)?;
    let path = cas_root(data_dir).join(&hex[..2]).join(&hex[2..]);
    if !path.starts_with(cas_root(data_dir)) {
        return None;
    }
    Some(path)
}

fn write_cas_blob(data_dir: &str, hash: &str, data: &[u8]) -> Result<PathBuf, String> {
    let path = cas_blob_path(data_dir, hash).ok_or_else(|| "cas_invalid_hash".to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("cas mkdir: {e}"))?;
    }
    // Idempotent: same hash ⇒ same bytes; skip rewrite when already present.
    if path.exists() {
        let existing = std::fs::read(&path).map_err(|e| format!("cas read existing: {e}"))?;
        if existing.as_slice() != data {
            return Err("cas_hash_collision".into());
        }
        return Ok(path);
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data).map_err(|e| format!("cas write: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("cas rename: {e}"))?;
    Ok(path)
}

fn read_cas_blob(data_dir: &str, hash: &str) -> Option<Vec<u8>> {
    let path = cas_blob_path(data_dir, hash)?;
    let bytes = std::fs::read(&path).ok()?;
    let expected = content_hash(&bytes);
    let hex = normalize_cas_hex(hash)?;
    let want = format!("sha256:{hex}");
    if expected != want {
        tracing::warn!(%want, %expected, "object_fabric CAS hash mismatch — rejecting");
        return None;
    }
    Some(bytes)
}

/// True when the CAS file for `hash` exists under `data_dir` (P6.2 multipart fail-closed).
pub fn cas_blob_exists(data_dir: &str, hash: &str) -> bool {
    cas_blob_path(data_dir, hash).is_some_and(|p| p.is_file())
}

/// Fail-closed: every chunk content_hash must exist in Object Fabric CAS.
pub fn assert_multipart_chunks_in_cas(
    data_dir: &str,
    manifest: &ChunkManifest,
) -> Result<(), String> {
    for part in &manifest.chunks {
        if !cas_blob_exists(data_dir, &part.content_hash) {
            return Err(format!(
                "multipart_chunk_missing_in_cas:index={}:hash={}",
                part.index, part.content_hash
            ));
        }
    }
    Ok(())
}

/// Parsed `bytes=START-END` (inclusive end) or bare `START-END` / `START-` query values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    /// Inclusive end offset; `None` means through EOF.
    pub end_inclusive: Option<u64>,
}

/// Parse range hydrate query: `bytes=0-1023`, `0-1023`, or `0-`.
pub fn parse_bytes_range_param(raw: &str) -> Option<ByteRange> {
    let s = raw.trim();
    let s = s
        .strip_prefix("bytes=")
        .or_else(|| s.strip_prefix("BYTES="))
        .unwrap_or(s)
        .trim();
    let (start_s, end_s) = s.split_once('-')?;
    let start: u64 = start_s.trim().parse().ok()?;
    let end_s = end_s.trim();
    let end_inclusive = if end_s.is_empty() {
        None
    } else {
        Some(end_s.parse().ok()?)
    };
    if let Some(end) = end_inclusive {
        if end < start {
            return None;
        }
    }
    Some(ByteRange {
        start,
        end_inclusive,
    })
}

/// Seek-read a byte range from the CAS file when it exists.
/// Verifies the full blob hash before returning a slice (EXEC-06).
pub fn read_cas_blob_range(data_dir: &str, hash: &str, range: ByteRange) -> Option<(Vec<u8>, u64)> {
    let bytes = read_cas_blob(data_dir, hash)?;
    let total = bytes.len() as u64;
    let start = range.start.min(total) as usize;
    let end_exclusive = match range.end_inclusive {
        Some(end) => end.saturating_add(1).min(total) as usize,
        None => bytes.len(),
    };
    if start >= end_exclusive {
        return Some((Vec::new(), total));
    }
    Some((bytes[start..end_exclusive].to_vec(), total))
}

#[derive(Debug, Deserialize, Default)]
pub struct ObjectGetQuery {
    /// Range hydrate: `bytes=0-N` or `0-N` (P6.2 stub).
    #[serde(default)]
    pub range: Option<String>,
    /// Alias for `range` accepting `0-N` / `bytes=0-N`.
    #[serde(default)]
    pub bytes: Option<String>,
}

impl ObjectGetQuery {
    fn byte_range(&self) -> Option<ByteRange> {
        self.range
            .as_deref()
            .or(self.bytes.as_deref())
            .and_then(parse_bytes_range_param)
    }
}

fn require_auth(headers: &HeaderMap) -> Result<(), Response> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    if crate::auth::extract_claims(headers).is_some() {
        return Ok(());
    }
    Err((
        StatusCode::UNAUTHORIZED,
        Json(json!({"ok": false, "error": "authentication_required"})),
    )
        .into_response())
}

pub fn object_count(state: &SharedState) -> usize {
    let es = state.engine_store.lock().unwrap();
    es.folder_keys(OBJECT_FABRIC_FOLDER, None)
        .map(|k| k.len())
        .unwrap_or(0)
}

pub fn put_object(
    state: &SharedState,
    data: &[u8],
    content_type: &str,
    tenant_id: Option<&str>,
) -> (String, Value) {
    let hash = content_hash(data);
    let key = hash.strip_prefix("sha256:").unwrap_or(&hash).to_string();
    let data_dir = &state.config.data_dir;
    let storage_backend = match write_cas_blob(data_dir, &hash, data) {
        Ok(_) => "fs_cas",
        Err(e) => {
            tracing::error!(error = %e, "object_fabric CAS put failed — refusing payload_b64 SoT fallback");
            // Keep metadata honest: no blob written.
            let record = json!({
                "content_hash": hash,
                "content_type": content_type,
                "byte_length": data.len(),
                "tenant_id": tenant_id,
                "stored_at_ms": chrono::Utc::now().timestamp_millis(),
                "storage_backend": "unavailable",
                "error": e,
            });
            return (hash, record);
        }
    };
    // Lean meta only — bytes are on disk under object_fabric_cas/.
    let record = json!({
        "content_hash": hash,
        "content_type": content_type,
        "byte_length": data.len(),
        "tenant_id": tenant_id,
        "stored_at_ms": chrono::Utc::now().timestamp_millis(),
        "storage_backend": storage_backend,
    });
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(OBJECT_FABRIC_FOLDER, &key, &record);
    (hash, record)
}

pub fn get_object(state: &SharedState, hash_key: &str) -> Option<(Vec<u8>, Value)> {
    let key = hash_key
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or(hash_key.trim());
    let data_dir = state.config.data_dir.clone();
    // Prefer filesystem CAS (P6.1 SoT).
    if let Some(bytes) = read_cas_blob(&data_dir, key) {
        let es = state.engine_store.lock().unwrap();
        let mut v = es
            .folder_get(OBJECT_FABRIC_FOLDER, key)
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                json!({
                    "content_hash": format!("sha256:{key}"),
                    "storage_backend": "fs_cas",
                    "byte_length": bytes.len(),
                })
            });
        if let Some(obj) = v.as_object_mut() {
            obj.remove("payload_b64");
            obj.insert("storage_backend".into(), json!("fs_cas"));
        }
        return Some((bytes, v));
    }
    // Legacy read path: older records may still have payload_b64 in engine_store.
    let es = state.engine_store.lock().unwrap();
    let mut v = es.folder_get(OBJECT_FABRIC_FOLDER, key).ok().flatten()?;
    let b64 = v.get("payload_b64")?.as_str()?.to_string();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .ok()?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("storage_backend".into(), json!("legacy_payload_b64"));
    }
    Some((bytes, v))
}

#[derive(Deserialize)]
pub struct ObjectPutJson {
    pub agent_pid: String,
    #[serde(default)]
    pub namespace: Option<String>,
    pub content_type: Option<String>,
    pub data_b64: String,
}

/// `PUT /api/v1/memory/objects` (JSON body) or raw bytes via post handler.
pub async fn put_object_json(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<ObjectPutJson>,
) -> Result<Json<Value>, Response> {
    if let Err(r) = require_auth(&headers) {
        return Err(r);
    }
    let namespace = req.namespace.as_deref().unwrap_or("object-fabric");
    if let Err(err) = crate::substrate::governed_effect::evaluate_effect(
        &state,
        Some(&headers),
        &req.agent_pid,
        namespace,
        AdmissionOp::MemoryWrite,
        None,
    ) {
        return Ok(Json(operator_envelope(json!({
            "ok": false,
            "error": "admission_denied",
            "message": err.human_readable.clone(),
        }))));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &req.agent_pid,
        "object_fabric",
        "put",
        &serde_json::json!({"namespace": namespace}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Ok(Json(body)),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let data = base64::engine::general_purpose::STANDARD
        .decode(req.data_b64.as_bytes())
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "error": "invalid_base64", "message": e.to_string()})),
            )
                .into_response()
        })?;
    let tenant = crate::substrate::outbound::verified_tenant_id(&headers);
    let ct = req
        .content_type
        .as_deref()
        .unwrap_or("application/octet-stream");
    let (hash, meta) = put_object(&state, &data, ct, tenant.as_deref());
    if meta.get("storage_backend").and_then(|v| v.as_str()) != Some("fs_cas") {
        open_proceed.finish_observed(false);
        return Ok(Json(operator_envelope(json!({
            "ok": false,
            "error": "cas_put_failed",
            "object_ref": hash,
            "meta": meta,
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
        }))));
    }
    open_proceed.finish_observed(true);
    Ok(Json(operator_envelope(json!({
        "schema": "object_fabric_put.v1",
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "object_ref": hash,
        "meta": meta,
    }))))
}

/// `GET /api/v1/memory/objects/:hash`
///
/// Optional range hydrate: `?range=bytes=0-N` or `?bytes=0-N` seeks the fs CAS file.
pub async fn get_object_by_hash(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
    Query(query): Query<ObjectGetQuery>,
) -> Result<Response, Response> {
    if let Err(r) = require_auth(&headers) {
        return Err(r);
    }
    let key = hash.trim();
    let Some(hex) = normalize_cas_hex(key) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid_cas_hash"})),
        )
            .into_response());
    };
    let data_dir = state.config.data_dir.clone();

    // P6.2: range hydrate stub — seek CAS file when `range`/`bytes` query present.
    if let Some(range) = query.byte_range() {
        let Some((slice, total)) = read_cas_blob_range(&data_dir, &hex, range) else {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(json!({"ok": false, "error": "object_not_found"})),
            )
                .into_response());
        };
        let start = range.start.min(total);
        let end_inclusive = if slice.is_empty() {
            start.saturating_sub(1)
        } else {
            start + slice.len() as u64 - 1
        };
        let ct = {
            let es = state.engine_store.lock().unwrap();
            es.folder_get(OBJECT_FABRIC_FOLDER, &hex)
                .ok()
                .flatten()
                .and_then(|m| {
                    m.get("content_type")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| "application/octet-stream".into())
        };
        let mut resp = Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_TYPE, ct)
            .header(
                header::CONTENT_RANGE,
                format!("bytes {start}-{end_inclusive}/{total}"),
            )
            .header("x-connector-object-hash", hash.as_str())
            .header("x-connector-range-hydrate", "fs_cas_seek_stub")
            .body(slice.into())
            .unwrap();
        if let Ok(v) = axum::http::HeaderValue::from_str(&format!("sha256:{hex}")) {
            resp.headers_mut().insert("x-connector-content-hash", v);
        }
        return Ok(resp);
    }

    let Some((bytes, meta)) = get_object(&state, &hash) else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "object_not_found"})),
        )
            .into_response());
    };
    let ct = meta
        .get("content_type")
        .and_then(|v| v.as_str())
        .unwrap_or("application/octet-stream");
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, ct)
        .header("x-connector-object-hash", hash.as_str())
        .body(bytes.into())
        .unwrap();
    if let Some(h) = meta.get("content_hash").and_then(|v| v.as_str()) {
        if let Ok(v) = axum::http::HeaderValue::from_str(h) {
            resp.headers_mut().insert("x-connector-content-hash", v);
        }
    }
    Ok(resp)
}

/// `POST /api/v1/memory/objects` — raw body upload.
pub async fn put_object_bytes(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, Response> {
    if let Err(r) = require_auth(&headers) {
        return Err(r);
    }
    let agent_pid = headers
        .get("x-connector-agent-pid")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("object-fabric-uploader");
    if let Err(err) = crate::substrate::governed_effect::evaluate_effect(
        &state,
        Some(&headers),
        agent_pid,
        "object-fabric",
        AdmissionOp::MemoryWrite,
        None,
    ) {
        return Ok(Json(operator_envelope(json!({
            "ok": false,
            "error": "admission_denied",
            "message": err.human_readable.clone(),
        }))));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        agent_pid,
        "object_fabric",
        "put_bytes",
        &serde_json::json!({"bytes": body.len()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Ok(Json(body)),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let tenant = crate::substrate::outbound::verified_tenant_id(&headers);
    let (hash, meta) = put_object(&state, &body, ct, tenant.as_deref());
    if meta.get("storage_backend").and_then(|v| v.as_str()) != Some("fs_cas") {
        open_proceed.finish_observed(false);
        return Ok(Json(operator_envelope(json!({
            "ok": false,
            "error": "cas_put_failed",
            "object_ref": hash,
            "meta": meta,
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
        }))));
    }
    open_proceed.finish_observed(true);
    Ok(Json(operator_envelope(json!({
        "schema": "object_fabric_put.v1",
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "object_ref": hash,
        "meta": meta,
    }))))
}

#[derive(Deserialize)]
pub struct MultipartCompleteRequest {
    pub upload_id: String,
    pub agent_pid: Option<String>,
}

/// `POST /api/v1/memory/objects/multipart/complete` — fail-closed (P6.2).
///
/// Incomplete manifests and missing CAS chunks are rejected. On success, commits a
/// thin moment (`MomentManifestV2`) with object_ref part refs (no single assembled blob).
pub async fn multipart_complete(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<MultipartCompleteRequest>,
) -> Result<Json<Value>, Response> {
    if let Err(r) = require_auth(&headers) {
        return Err(r);
    }
    let agent_pid = req.agent_pid.as_deref().unwrap_or("object-fabric-uploader");
    if let Err(err) = crate::substrate::governed_effect::evaluate_effect(
        &state,
        Some(&headers),
        agent_pid,
        "object-fabric",
        AdmissionOp::MemoryWrite,
        None,
    ) {
        return Ok(Json(operator_envelope(json!({
            "ok": false,
            "error": "admission_denied",
            "message": err.human_readable.clone(),
        }))));
    }
    let mut manifest = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get(OBJECT_FABRIC_MULTIPART_FOLDER, &req.upload_id)
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_value::<ChunkManifest>(v).ok())
    };
    let Some(ref mut manifest) = manifest else {
        return Ok(Json(operator_envelope(json!({
            "ok": false,
            "error": "multipart_manifest_not_found",
            "upload_id": req.upload_id,
            "fail_closed": true,
        }))));
    };
    if let Err(code) = assert_multipart_complete(manifest) {
        return Ok(Json(operator_envelope(json!({
            "ok": false,
            "error": code,
            "upload_id": manifest.upload_id,
            "expected_chunks": manifest.expected_chunks,
            "received_chunks": manifest.chunks.len(),
            "complete": manifest.complete,
            "fail_closed": true,
            "honesty": "incomplete multipart must not commit to moment / object SoT",
        }))));
    }
    let data_dir = state.config.data_dir.clone();
    if let Err(code) = assert_multipart_chunks_in_cas(&data_dir, manifest) {
        return Ok(Json(operator_envelope(json!({
            "ok": false,
            "error": "multipart_chunks_missing_fail_closed",
            "detail": code,
            "upload_id": manifest.upload_id,
            "fail_closed": true,
            "honesty": "all chunk content_hashes must exist in object_fabric CAS before moment commit",
        }))));
    }

    // Idempotent: if a prior complete already linked a moment, return it.
    if let Some(ref existing_mid) = manifest.moment_id {
        if crate::services::moment::load_moment(state.as_ref(), existing_mid).is_some() {
            return Ok(Json(operator_envelope(json!({
                "ok": true,
                "schema": "object_fabric_multipart_complete.v1",
                "upload_id": manifest.upload_id,
                "moment_id": existing_mid,
                "object_ref": manifest.object_ref,
                "part_count": manifest.chunks.len(),
                "thin_moment": true,
                "idempotent": true,
                "honesty": "thin moment commit — part refs only; no assembled single CAS blob",
            }))));
        }
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        agent_pid,
        "object_fabric",
        "multipart_complete",
        &serde_json::json!({"upload_id": manifest.upload_id}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Ok(Json(body)),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mime = manifest.content_type.clone();
    let mut chunks = manifest.chunks.clone();
    chunks.sort_by_key(|c| c.index);
    let parts: Vec<connector_trust::MomentPartV2> = chunks
        .iter()
        .map(|c| connector_trust::MomentPartV2 {
            part_kind: "object_ref".into(),
            text: Some(format!("multipart_chunk index={}", c.index)),
            object_ref: Some(c.content_hash.clone()),
            content_hash: Some(c.content_hash.clone()),
            mime_type: mime.clone(),
        })
        .collect();

    let session_id = format!("multipart:{}", manifest.upload_id);
    let moment = crate::services::moment::commit_thin_object_parts_moment(
        state.as_ref(),
        &session_id,
        agent_pid,
        parts,
    );
    manifest.moment_id = Some(moment.moment_id.clone());
    // Thin complete: object_ref points at the moment skeleton, not an assembled blob.
    manifest.object_ref = Some(format!("moment:{}", moment.moment_id));
    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(
            OBJECT_FABRIC_MULTIPART_FOLDER,
            &manifest.upload_id,
            &serde_json::to_value(&*manifest).unwrap_or_default(),
        );
    }

    open_proceed.finish_observed(true);
    Ok(Json(operator_envelope(json!({
        "ok": true,
        "schema": "object_fabric_multipart_complete.v1",
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "upload_id": manifest.upload_id,
        "moment_id": moment.moment_id,
        "object_ref": manifest.object_ref,
        "part_count": moment.parts.len(),
        "parts": moment.parts,
        "thin_moment": true,
        "honesty": "thin moment commit — part refs only; no assembled single CAS blob",
    }))))
}

#[cfg(test)]
mod multipart_tests {
    use super::*;

    #[test]
    fn parse_bytes_range_param_accepts_bytes_prefix() {
        let r = parse_bytes_range_param("bytes=0-99").unwrap();
        assert_eq!(r.start, 0);
        assert_eq!(r.end_inclusive, Some(99));
        let open = parse_bytes_range_param("10-").unwrap();
        assert_eq!(open.start, 10);
        assert_eq!(open.end_inclusive, None);
    }

    #[test]
    fn incomplete_manifest_fail_closed() {
        let mut m = ChunkManifest::new("up1", 100, 2);
        m.chunks.push(ChunkPart {
            index: 0,
            content_hash: "sha256:aa".into(),
            byte_length: 50,
        });
        assert!(!m.is_complete());
        assert_eq!(
            assert_multipart_complete(&m),
            Err("multipart_incomplete_fail_closed")
        );
    }

    #[test]
    fn complete_manifest_passes_assert() {
        let mut m = ChunkManifest::new("up2", 100, 2);
        m.chunks = vec![
            ChunkPart {
                index: 0,
                content_hash: "sha256:aa".into(),
                byte_length: 40,
            },
            ChunkPart {
                index: 1,
                content_hash: "sha256:bb".into(),
                byte_length: 60,
            },
        ];
        m.complete = true;
        assert!(m.is_complete());
        assert!(assert_multipart_complete(&m).is_ok());
    }

    #[test]
    fn missing_cas_chunks_fail_closed() {
        let dir =
            std::env::temp_dir().join(format!("of_cas_miss_{}", uuid::Uuid::new_v4().simple()));
        let _ = std::fs::create_dir_all(&dir);
        let mut m = ChunkManifest::new("up3", 10, 1);
        m.chunks = vec![ChunkPart {
            index: 0,
            content_hash: "sha256:deadbeef".into(),
            byte_length: 10,
        }];
        m.complete = true;
        let err = assert_multipart_chunks_in_cas(dir.to_str().unwrap(), &m).unwrap_err();
        assert!(err.contains("multipart_chunk_missing_in_cas"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cas_rejects_non_hex_and_traversal() {
        assert!(normalize_cas_hex("../etc/passwd").is_none());
        assert!(normalize_cas_hex("sha256:deadbeef").is_none());
        assert!(normalize_cas_hex(&"a".repeat(64)).is_some());
        assert!(cas_blob_path("/tmp", "../../../etc/passwd").is_none());
        assert!(cas_blob_path("/tmp", &format!("sha256:{}", "ab".repeat(32))).is_some());
    }
}
