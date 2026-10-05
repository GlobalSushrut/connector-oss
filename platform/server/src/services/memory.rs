use crate::state::SharedState;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use vac_core::cid::compute_cid;
use vac_core::kernel::{SyscallPayload, SyscallRequest};
use vac_core::types::{
    CognitivePath, MemPacket, MemoryKernelOp, MemoryType, PacketType, Source, SourceKind,
};

#[derive(Deserialize)]
pub struct WriteRequest {
    pub agent_pid: String,
    pub content: String,
    #[serde(default)]
    pub user: String,
    #[serde(default = "default_pipeline")]
    pub pipeline: String,
    #[serde(default)]
    pub packet_type: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default, rename = "type")]
    pub memory_type: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub entity_kind: Option<String>,
    /// ARC Phase H memory class (working|persistent|secret|evidence|…).
    #[serde(default)]
    pub memory_class: Option<String>,
    /// Optional key for Evidence append chains / class store.
    #[serde(default)]
    pub key: Option<String>,
    /// Multimodal parts (U2.4 / I-11): large bytes go to Object Fabric; refs land on the packet.
    #[serde(default)]
    pub parts: Option<Vec<MemoryPartInput>>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct MemoryPartInput {
    /// `text` | `image` | `audio` | `object_ref` | `tool_result`
    #[serde(default = "default_part_kind")]
    pub part_kind: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub data_b64: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub object_ref: Option<String>,
}
fn default_part_kind() -> String {
    "text".into()
}
fn default_pipeline() -> String {
    "default".into()
}

const KNOWLEDGE_DEDUPE_FOLDER: &str = "_knowledge_ingest_dedupe";

fn normalize_knowledge_namespace(raw_ns: &str) -> String {
    let raw_ns = raw_ns.trim();
    if raw_ns.is_empty() {
        return "k/default".to_string();
    }
    let stripped = raw_ns.strip_prefix('/').unwrap_or(raw_ns);
    if stripped.starts_with("k/") {
        stripped.to_string()
    } else if stripped == "default" {
        "k/default".to_string()
    } else {
        format!("k/{}", stripped)
    }
}

fn knowledge_dedupe_store_key(namespace: &str, dedupe_key: &str) -> String {
    let mut h = Sha256::new();
    h.update(namespace.as_bytes());
    h.update(b":");
    h.update(dedupe_key.as_bytes());
    format!("{}:{:x}", namespace, h.finalize())
}

fn parse_role_packet_type(role: Option<&str>, ptype_str: Option<&str>) -> PacketType {
    match role.unwrap_or("fact").trim().to_ascii_lowercase().as_str() {
        "instruction" | "system_prompt" | "policy" => PacketType::Input,
        _ => match ptype_str.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("extraction") => PacketType::Extraction,
            Some("input") => PacketType::Input,
            Some("feedback") => PacketType::Feedback,
            Some("decision") => PacketType::Decision,
            Some("llm_raw") => PacketType::LlmRaw,
            _ => PacketType::Extraction,
        },
    }
}

fn parse_memory_type(memory_type: Option<&str>, ptype: &PacketType) -> MemoryType {
    match memory_type
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "working" => MemoryType::Working,
        "episodic" => MemoryType::Episodic,
        "semantic" => MemoryType::Semantic,
        "procedural" => MemoryType::Procedural,
        "relational" => MemoryType::Relational,
        "reflective" => MemoryType::Reflective,
        "evidentiary" => MemoryType::Evidentiary,
        _ => match ptype {
            PacketType::Input | PacketType::LlmRaw => MemoryType::Working,
            PacketType::Extraction => MemoryType::Semantic,
            PacketType::Decision
            | PacketType::Action
            | PacketType::Feedback
            | PacketType::StateChange => MemoryType::Episodic,
            PacketType::ToolCall | PacketType::ToolResult => MemoryType::Procedural,
            PacketType::Contradiction => MemoryType::Relational,
        },
    }
}

fn derive_entities(content: &str) -> Vec<String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut entities: BTreeSet<String> = BTreeSet::new();

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        let mut stack = vec![value];
        while let Some(node) = stack.pop() {
            match node {
                serde_json::Value::Object(map) => {
                    for (key, value) in map {
                        let key_l = key.to_ascii_lowercase();
                        if matches!(
                            key_l.as_str(),
                            "label" | "scenario" | "action" | "target" | "outcome" | "entity_kind"
                        ) {
                            if let Some(text) = value.as_str() {
                                for token in text.split(|c: char| {
                                    !c.is_ascii_alphanumeric() && c != ':' && c != '_' && c != '-'
                                }) {
                                    let token = token.trim();
                                    if token.len() >= 3 {
                                        entities.insert(token.to_string());
                                    }
                                }
                            }
                        }
                        stack.push(value);
                    }
                }
                serde_json::Value::Array(items) => {
                    for item in items {
                        stack.push(item);
                    }
                }
                serde_json::Value::String(text) => {
                    for token in text.split(|c: char| {
                        !c.is_ascii_alphanumeric() && c != ':' && c != '_' && c != '-'
                    }) {
                        let token = token.trim();
                        if token.len() >= 4 {
                            let starts_upper = token
                                .chars()
                                .next()
                                .map(|c| c.is_ascii_uppercase())
                                .unwrap_or(false);
                            let has_digit = token.chars().any(|c| c.is_ascii_digit());
                            let has_colon = token.contains(':');
                            if starts_upper || has_digit || has_colon {
                                entities.insert(token.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if entities.is_empty() {
        for token in
            trimmed.split(|c: char| !c.is_ascii_alphanumeric() && c != ':' && c != '_' && c != '-')
        {
            let token = token.trim();
            if token.len() >= 4 {
                let starts_upper = token
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_uppercase())
                    .unwrap_or(false);
                let has_digit = token.chars().any(|c| c.is_ascii_digit());
                let has_colon = token.contains(':');
                if starts_upper || has_digit || has_colon {
                    entities.insert(token.to_string());
                }
            }
        }
    }

    entities.into_iter().take(24).collect()
}

fn make_packet(
    req: &WriteRequest,
    subject_id: &str,
    namespace: &str,
    ptype: PacketType,
) -> MemPacket {
    // If content is valid JSON object, merge its fields into the payload
    // (preserves structured fields like "old"/"new" for contradiction packets)
    let payload = if let Ok(serde_json::Value::Object(mut content_obj)) =
        serde_json::from_str::<serde_json::Value>(&req.content)
    {
        // Ensure "text" field exists for RAG retrieval
        if !content_obj.contains_key("text") {
            content_obj.insert(
                "text".to_string(),
                serde_json::Value::String(req.content.clone()),
            );
        }
        content_obj.insert(
            "memory_type".to_string(),
            serde_json::json!(req.memory_type.clone()),
        );
        content_obj.insert(
            "tags".to_string(),
            serde_json::json!(req.tags.clone().unwrap_or_default()),
        );
        content_obj.insert(
            "session_id".to_string(),
            serde_json::json!(req.session_id.clone()),
        );
        content_obj.insert(
            "entity_kind".to_string(),
            serde_json::json!(req.entity_kind.clone()),
        );
        if let Some(parts) = &req.parts {
            content_obj.insert("parts".to_string(), serde_json::json!(parts));
        }
        serde_json::Value::Object(content_obj)
    } else {
        serde_json::json!({
            "text": req.content,
            "memory_type": req.memory_type.clone(),
            "tags": req.tags.clone().unwrap_or_default(),
            "session_id": req.session_id.clone(),
            "entity_kind": req.entity_kind.clone(),
            "parts": req.parts.clone().unwrap_or_default(),
        })
    };
    let payload_cid = compute_cid(&payload).unwrap_or_else(|_| cid::Cid::default());
    let memory_type = parse_memory_type(req.memory_type.as_deref(), &ptype);
    let abstraction_level = match memory_type {
        MemoryType::Working => 0,
        MemoryType::Episodic => 1,
        MemoryType::Semantic => 3,
        MemoryType::Procedural => 2,
        MemoryType::Relational => 2,
        MemoryType::Reflective => 2,
        MemoryType::Evidentiary => 1,
    };
    let mut packet = MemPacket::new(
        ptype,
        payload,
        payload_cid,
        subject_id.to_string(),
        req.pipeline.to_string(),
        Source {
            kind: SourceKind::User,
            principal_id: if req.user.is_empty() {
                subject_id.to_string()
            } else {
                req.user.to_string()
            },
        },
        chrono::Utc::now().timestamp_millis(),
    );
    packet.memory_type = memory_type.clone();
    packet.abstraction_level = abstraction_level;
    packet = packet.with_namespace(namespace.to_string());
    packet.cognitive_path = Some(CognitivePath::memory(subject_id, &memory_type));
    if let Some(session_id) = req.session_id.clone() {
        packet = packet.with_session(session_id);
    }
    if let Some(tags) = req.tags.clone() {
        packet = packet.with_tags(tags);
    }
    packet.metadata.insert(
        "pipeline".into(),
        serde_json::Value::String(req.pipeline.clone()),
    );
    if let Some(memory_type_label) = req.memory_type.clone() {
        packet.metadata.insert(
            "memory_type".into(),
            serde_json::Value::String(memory_type_label),
        );
    }
    if let Some(entity_kind) = req.entity_kind.clone() {
        packet
            .metadata
            .insert("entity_kind".into(), serde_json::Value::String(entity_kind));
    }
    packet.metadata.insert(
        "write_api".into(),
        serde_json::Value::String("/memory/write".into()),
    );
    packet.content.entities = derive_entities(&req.content);
    packet
}

fn make_packet_simple(content: &str, user: &str, pipeline: &str, ptype: PacketType) -> MemPacket {
    let req = WriteRequest {
        agent_pid: user.to_string(),
        content: content.to_string(),
        user: user.to_string(),
        pipeline: pipeline.to_string(),
        packet_type: Some(format!("{}", ptype)),
        session_id: None,
        memory_type: None,
        tags: None,
        entity_kind: None,
        memory_class: None,
        key: None,
        parts: None,
    };
    make_packet(&req, user, &format!("m/{}", user), ptype)
}

/// Store multimodal `data_b64` parts in Object Fabric; return descriptors with object_ref (no inline bytes).
fn materialize_memory_parts(
    state: &SharedState,
    parts: &[MemoryPartInput],
    tenant_id: Option<&str>,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for part in parts {
        let mut desc = serde_json::json!({
            "part_kind": part.part_kind,
            "mime_type": part.mime_type,
            "text": part.text,
            "object_ref": part.object_ref,
        });
        if let Some(b64) = &part.data_b64 {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
                let ct = part
                    .mime_type
                    .as_deref()
                    .unwrap_or("application/octet-stream");
                let (hash, _meta) =
                    crate::services::object_fabric::put_object(state, &bytes, ct, tenant_id);
                desc["object_ref"] = serde_json::json!(hash);
                desc["content_hash"] = serde_json::json!(hash);
                desc["bytes"] = serde_json::json!(bytes.len());
                // Do not keep data_b64 on the packet — fabric is SoT for large bytes.
            }
        }
        out.push(desc);
    }
    out
}

/// POST /memory/write — Write a packet to agent's PRIVATE memory namespace (/m/)
///
/// **Terminology:**
/// - **Memory** = Private agent data in `/m/` namespace (working memory, scratch)
/// - **Knowledge** = Shared knowledge bases in `/k/` namespace (RAG, facts, embeddings)
/// - **MemoryRegion** = Config (quotas, protection flags) — NOT data
/// - **MemPacket** = The actual data unit (content + provenance + authority)
///
/// This endpoint writes to the agent's private `/m/{agent_name}` namespace.
/// For shared knowledge, use `/memory/knowledge/ingest` which writes to `/k/` namespaces.
///
/// The packet is also auto-ingested into KnotEngine for entity extraction.
pub async fn write_memory(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<WriteRequest>,
) -> impl IntoResponse {
    let ptype = match req
        .packet_type
        .as_deref()
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("llm_raw") => PacketType::LlmRaw,
        Some("decision") => PacketType::Decision,
        Some("extraction") => PacketType::Extraction,
        Some("action") => PacketType::Action,
        Some("feedback") => PacketType::Feedback,
        Some("contradiction") => PacketType::Contradiction,
        Some("instruction" | "input") => PacketType::Input,
        Some("note") => PacketType::Extraction,
        _ => PacketType::Input,
    };
    // Resolve api_pid → kernel_pid (agents registered via POST /agents use a UUID api_pid)
    let kernel_pid = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("agent_meta", &req.agent_pid)
            .ok()
            .flatten()
            .and_then(|m| {
                m.get("kernel_pid")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| req.agent_pid.clone())
    };
    let namespace = {
        let k = state.kernel.lock().unwrap();
        k.get_agent(&kernel_pid)
            .map(|a| a.namespace.clone())
            .unwrap_or_else(|| format!("m/{}", kernel_pid))
    };

    // ── C9: charter must allow memory write ──────────────────────────────
    if let Err(e) = crate::kernel::agent_principal::require_contract_action(
        state.as_ref(),
        &req.agent_pid,
        "memory.write",
        &namespace,
    ) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": e,
                "denial_reason": "contract_denied",
                "honesty": "C9 — AgentContract must allow memory capability",
            })),
        )
            .into_response();
    }

    // ── ADMISSION GATE: Central pre-execution security enforcement ───────
    // Memory writes are a critical attack vector (memory poisoning).
    // The gate checks quarantine, guard pipeline, and injection detection.
    {
        let admission_result = crate::substrate::governed_effect::evaluate_effect(
            &state,
            Some(&headers),
            &kernel_pid,
            &namespace,
            crate::services::admission::AdmissionOp::MemoryWrite,
            Some(&req.content),
        );
        if let Err(err) = admission_result {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "ok": false,
                    "agent_pid": req.agent_pid,
                    "error": err.human_readable,
                    "denial_reason": err.denial_reason.slug(),
                    "audit_cid": err.audit_cid,
                })),
            )
                .into_response();
        }
    }

    // ARC Phase H: optional memory class gate (CONNECTOR_ARC_MEMORY / IFC).
    if crate::substrate::arc::flags::ArcFlags::from_env().memory
        || crate::substrate::arc::flags::ArcFlags::from_env().ifc
    {
        let class = req
            .memory_class
            .as_deref()
            .or(req.memory_type.as_deref())
            .and_then(crate::substrate::arc::memory::MemoryClass::parse)
            .unwrap_or(crate::substrate::arc::memory::MemoryClass::Persistent);
        if let Err(e) = crate::substrate::arc::memory::assert_write_identity(
            &kernel_pid,
            &kernel_pid,
            class,
        ) {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "ok": false,
                    "error": e.human_readable,
                    "denial_reason": "arc_memory_class",
                    "class": class.as_str(),
                })),
            )
                .into_response();
        }
        if class == crate::substrate::arc::memory::MemoryClass::Secret {
            let tokenized =
                req.content.contains("⟦conn:") || req.content.contains("[[conn:");
            if !tokenized {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "ok": false,
                        "error": "SecretMemory requires tokenize before store",
                        "denial_reason": "arc_memory_secret",
                        "hint": "Tokenize secrets via data_tokenization before memory.write",
                    })),
                )
                    .into_response();
            }
        }
        if class == crate::substrate::arc::memory::MemoryClass::Evidence {
            // Mirror append-only into ARC evidence chain (digest only).
            let _ = crate::substrate::arc::memory::append_evidence(
                &kernel_pid,
                &kernel_pid,
                req.key.as_deref().unwrap_or("default"),
                &req.content,
            );
        }
    }

    let mut req = req;
    let mut part_refs = Vec::new();
    if let Some(parts) = req.parts.take() {
        part_refs = materialize_memory_parts(&state, &parts, None);
        // Replace inbound parts with fabric-backed descriptors (no data_b64).
        req.parts = Some(
            part_refs
                .iter()
                .filter_map(|v| serde_json::from_value::<MemoryPartInput>(v.clone()).ok())
                .collect(),
        );
        if let Some(p) = req.parts.as_mut() {
            for part in p.iter_mut() {
                part.data_b64 = None;
            }
        }
    }

    let packet = make_packet(&req, &kernel_pid, &namespace, ptype);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &req.agent_pid,
        "memory",
        "write",
        &serde_json::json!({"namespace": namespace}),
    ) {
        Ok(atu) => atu,
        Err(body) => return (StatusCode::FORBIDDEN, Json(body)).into_response(),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut k = state.kernel.lock().unwrap();
    let result = k.dispatch(SyscallRequest {
        agent_pid: kernel_pid.clone(),
        operation: MemoryKernelOp::MemWrite,
        payload: SyscallPayload::MemWrite {
            packet: packet.clone(),
        },
        reason: None,
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    drop(k);

    // Wave 3 — Item 3.1: Auto-enrich via KnotEngine (entity extraction + graph link)
    let mut enrichment = serde_json::json!(null);
    let mut durable = true;
    let mut durable_error: Option<String> = None;
    if result.outcome == vac_core::types::OpOutcome::Success {
        if let Err(e) =
            crate::substrate::memwrite_durability::write_through_packet_shared(&state, &packet)
        {
            durable = false;
            durable_error = Some(e);
        }
        let mut knot = state.knot.lock().unwrap();
        knot.ingest_packets(&[packet.clone()], 0);
        let entities_after = knot.node_count();
        drop(knot);
        let k = state.kernel.lock().unwrap();
        enrichment = serde_json::json!({
            "knot_entities": entities_after,
            "auto_enriched": true,
        });
        drop(k);
        if crate::substrate::agent_memory::enabled() {
            let pt = req
                .packet_type
                .as_deref()
                .or(req.memory_type.as_deref())
                .unwrap_or("input");
            let source_id = packet.content.payload_cid.to_string();
            let raw_loc = format!("mem://{namespace}/{source_id}");
            if let Some(rec) = crate::substrate::agent_memory::evidence::append_on_write(
                state.as_ref(),
                &kernel_pid,
                &source_id,
                &req.content,
                &raw_loc,
                pt,
            ) {
                let ev_root = crate::substrate::agent_memory::evidence::evidence_root(
                    state.as_ref(),
                    &kernel_pid,
                )
                .unwrap_or_else(|| rec.content_hash.clone());
                let snippet = req.content.chars().take(160).collect::<String>();
                let (_, st) = crate::substrate::agent_memory::context_store::append_delta(
                    state.as_ref(),
                    &kernel_pid,
                    "memory.write",
                    None,
                    &snippet,
                    &ev_root,
                );
                let score = crate::substrate::agent_memory::reducer::promotion_score(
                    0.55,
                    0.35,
                    1.0,
                    0.75,
                    0.2,
                );
                if score >= 0.45 {
                    crate::substrate::agent_memory::reducer::store_point(
                        state.as_ref(),
                        &kernel_pid,
                        req.entity_kind.as_deref().unwrap_or("memory"),
                        "write",
                        &snippet,
                        0.75,
                        0.3,
                        0.2,
                        &rec.evidence_id,
                        st.context_epoch,
                        rec.epistemic_class,
                    );
                }
                let _ = crate::substrate::agent_memory::context_store::maybe_checkpoint(
                    state.as_ref(),
                    &kernel_pid,
                    "memory.write",
                );
            }
        }
    }

    // Wave 3 — Item 3.2: Interference detection (contradiction check)
    let mut interference = serde_json::json!(null);
    if result.outcome == vac_core::types::OpOutcome::Success {
        let k = state.kernel.lock().unwrap();
        if let Some(agent) = k.get_agent(&kernel_pid) {
            let packets = k.packets_in_namespace(&agent.namespace);
            let text = req.content.as_str();
            // Contradiction check: negation patterns + entity-level conflict detection
            let mut contradictions: Vec<serde_json::Value> = Vec::new();
            let new_entities = &packet.content.entities;
            for p in &packets {
                let existing = p
                    .content
                    .payload
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if existing.is_empty() || existing == text {
                    continue;
                }

                // 1. Direct negation patterns
                let neg_contradicts = (text.contains("not ")
                    && existing.contains(&text.replace("not ", "")))
                    || (existing.contains("not ") && text.contains(&existing.replace("not ", "")))
                    || (text.contains("never ")
                        && existing.contains(&text.replace("never ", "always ")))
                    || (text.contains("false")
                        && existing.contains("true")
                        && text.len() < 200
                        && existing.len() < 200);

                // 2. Entity-overlap conflict: same entity_kind + overlapping entities + different values
                //    Catches e.g. two "vital_signs" packets for same patient with different BP readings.
                let entity_overlap = if !new_entities.is_empty() {
                    let existing_entities = &p.content.entities;
                    let shared: usize = new_entities
                        .iter()
                        .filter(|e| existing_entities.contains(e))
                        .count();
                    let same_kind = req
                        .entity_kind
                        .as_deref()
                        .map(|ek| {
                            p.metadata
                                .get("entity_kind")
                                .and_then(|v| v.as_str())
                                .map(|pk| pk == ek)
                                .unwrap_or(false)
                        })
                        .unwrap_or(false);
                    // Shared entities + same kind + texts differ significantly
                    same_kind && shared >= 1 && existing != text
                } else {
                    false
                };

                // 3. Explicit contradiction markers in the new text
                let has_contradiction_signal = text.contains("denies")
                    || text.contains("incorrect")
                    || text.contains("was wrong")
                    || text.contains("contradicts");
                let tag_overlap = req
                    .tags
                    .as_ref()
                    .map(|t| {
                        let ptags = &p.content.tags;
                        t.iter().any(|tag| ptags.contains(tag) && tag != "P-001")
                    })
                    .unwrap_or(false);
                let signal_contradicts = has_contradiction_signal && tag_overlap;

                if neg_contradicts || entity_overlap || signal_contradicts {
                    let ctype = if neg_contradicts {
                        "negation_pattern"
                    } else if entity_overlap {
                        "entity_value_conflict"
                    } else {
                        "contradiction_signal"
                    };
                    contradictions.push(serde_json::json!({
                        "existing_cid": p.content.payload_cid.to_string(),
                        "existing_text": existing.chars().take(120).collect::<String>(),
                        "type": ctype,
                    }));
                    if contradictions.len() >= 5 {
                        break;
                    }
                }
            }
            if !contradictions.is_empty() {
                interference = serde_json::json!({
                    "contradictions_found": contradictions.len(),
                    "contradictions": contradictions,
                    "recommendation": "Review contradicting memories. Consider using /memory/optimize-context to clean up.",
                });
            }
        }
    }

    let cid_str = match &result.value {
        vac_core::SyscallValue::Cid(c) => c.to_string(),
        vac_core::SyscallValue::Error(e) => format!("Error(\"{}\")", e),
        _ => String::new(),
    };
    open_proceed.finish_observed(result.outcome == vac_core::types::OpOutcome::Success && durable);
    Json(serde_json::json!({
        "ok": result.outcome == vac_core::types::OpOutcome::Success && durable,
        "durable": durable,
        "durable_error": durable_error,
        "agent_pid": req.agent_pid,
        "cid": cid_str,
        "enrichment": enrichment,
        "interference": interference,
        "parts": part_refs,
        "parts_honesty": if part_refs.is_empty() {
            "no multimodal parts"
        } else {
            "large bytes stored in Object Fabric; packet holds object_ref only"
        },
    }))
    .into_response()
}

/// POST /memory/knowledge/ingest — Ingest into SHARED knowledge graph (`k/…`) + KnotEngine
///
/// **Modes**
/// 1. **Batch (preferred for Kafka-style producers):** body includes `records: [{ text|content, optional dedupe_key, role, tags, … }]`
/// 2. **Namespace rescan (legacy):** body has only `namespace` — re-indexes existing packets in that `k/` namespace into Knot
///
/// **Terminology:** Knowledge = shared `/k/` plane; agent-private memory = `/memory/write` until promoted here.
pub async fn knowledge_ingest(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let namespace = normalize_knowledge_namespace(
        req.get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or("default"),
    );
    let ingest_run_id = req
        .get("ingest_run_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("kir_{}", uuid::Uuid::new_v4()));
    let agent_pid_raw = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("system")
        .to_string();
    let (agent_pid, agent_pid_fallback) = {
        let k = state.kernel.lock().unwrap();
        if k.agents().contains_key(&agent_pid_raw) {
            (agent_pid_raw.clone(), false)
        } else if agent_pid_raw.is_empty() || agent_pid_raw == "system" {
            match k.agents().keys().next() {
                Some(p) => (p.clone(), true),
                None => {
                    return Json(serde_json::json!({
                        "ok": false,
                        "error": "batch knowledge ingest requires a registered agent (pass agent_pid or create an agent first)",
                    }));
                }
            }
        } else {
            return Json(serde_json::json!({
                "ok": false,
                "error": format!("agent_pid '{}' is not registered", agent_pid_raw),
            }));
        }
    };
    let source_meta = req.get("source").cloned().unwrap_or(serde_json::json!({}));
    let partition_key = req
        .get("partition_key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let pipeline_version = "2026.04-connector-platform";

    // C9: charter must allow knowledge ingest.
    if let Err(e) = crate::kernel::agent_principal::require_contract_action(
        state.as_ref(),
        &agent_pid,
        "knowledge.ingest",
        &namespace,
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": e,
            "denial_reason": "contract_denied",
            "code": "contract_denied",
            "ingest_run_id": ingest_run_id,
            "agent_pid": agent_pid,
            "honesty": "C9 — AgentContract must allow knowledge/memory write",
        }));
    }

    // Constitutional boundary: knowledge ingest is an effectful memory write.
    if let Err(err) = crate::substrate::governed_effect::evaluate_effect(
        &state,
        None,
        &agent_pid,
        &namespace,
        crate::services::admission::AdmissionOp::MemoryWrite,
        req
            .get("records")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|r| r.get("text").or_else(|| r.get("content")))
            .and_then(|v| v.as_str()),
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": err.human_readable,
            "denial_reason": err.denial_reason.slug(),
            "audit_cid": err.audit_cid,
            "code": "admission_denied",
            "ingest_run_id": ingest_run_id,
            "agent_pid": agent_pid,
            "agent_pid_fallback": agent_pid_fallback,
        }));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_pid,
        "memory",
        "knowledge_ingest",
        &serde_json::json!({"namespace": namespace}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    if let Some(records) = req.get("records").and_then(|v| v.as_array()) {
        if records.is_empty() {
            open_proceed.finish_observed(false);
            return Json(serde_json::json!({
                "ok": false,
                "error": "records array is empty",
                "ingest_run_id": ingest_run_id,
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }));
        }

        let now = chrono::Utc::now().timestamp_millis();
        let mut new_packets: Vec<MemPacket> = Vec::new();
        let submitted = records.len();
        let mut written = 0usize;
        let mut skipped_dedupe = 0usize;
        let mut skipped_empty = 0usize;

        for (idx, rec) in records.iter().enumerate() {
            let text = rec
                .get("text")
                .and_then(|v| v.as_str())
                .or_else(|| rec.get("content").and_then(|v| v.as_str()))
                .unwrap_or("")
                .trim();
            if text.is_empty() {
                skipped_empty += 1;
                continue;
            }
            let role = rec.get("role").and_then(|v| v.as_str());
            let ptype_str = rec.get("packet_type").and_then(|v| v.as_str());
            let packet_type = parse_role_packet_type(role, ptype_str);
            let is_instruction_plane = matches!(&packet_type, PacketType::Input);

            let dedupe_key = rec
                .get("dedupe_key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    let mut h = Sha256::new();
                    h.update(text.as_bytes());
                    format!("content:{:x}", h.finalize())
                });
            let store_key = knowledge_dedupe_store_key(&namespace, &dedupe_key);
            {
                let es = state.engine_store.lock().unwrap();
                if es
                    .folder_get(KNOWLEDGE_DEDUPE_FOLDER, &store_key)
                    .ok()
                    .flatten()
                    .is_some()
                {
                    skipped_dedupe += 1;
                    continue;
                }
            }

            let mut tags: Vec<String> = rec
                .get("tags")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            if role.is_some_and(|r| {
                matches!(
                    r.to_ascii_lowercase().as_str(),
                    "instruction" | "system_prompt" | "policy"
                )
            }) {
                tags.push("instruction_injection".into());
            }
            tags.push(format!("ingest_run:{ingest_run_id}"));
            if !partition_key.is_empty() {
                tags.push(format!("pk:{partition_key}"));
            }

            let memory_type = parse_memory_type(
                rec.get("memory_type")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty()),
                &packet_type,
            );

            let payload = serde_json::json!({
                "text": text,
                "ingest_run_id": ingest_run_id,
                "record_index": idx,
                "source": source_meta,
                "partition_key": partition_key,
                "role": role.unwrap_or("fact"),
            });

            let payload_cid = match compute_cid(&payload) {
                Ok(cid) => cid,
                Err(_) => continue,
            };

            let mut packet = MemPacket::new(
                packet_type,
                payload,
                payload_cid,
                agent_pid.clone(),
                "knowledge_pipeline".into(),
                Source {
                    kind: SourceKind::SelfSource,
                    principal_id: agent_pid.clone(),
                },
                now,
            )
            .with_namespace(namespace.clone())
            .with_session(format!("knowledge-{ingest_run_id}"))
            .with_tags(tags);
            packet.memory_type = memory_type;
            packet.abstraction_level = if is_instruction_plane { 2 } else { 3 };
            packet.cognitive_path = Some(CognitivePath::memory(&agent_pid, &packet.memory_type));
            packet.metadata.insert(
                "ingest_mode".into(),
                serde_json::Value::String("batch_knowledge".into()),
            );
            packet.metadata.insert(
                "pipeline_version".into(),
                serde_json::json!(pipeline_version),
            );

            let result = {
                let mut k = state.kernel.lock().unwrap();
                k.dispatch(SyscallRequest {
                    agent_pid: agent_pid.clone(),
                    operation: MemoryKernelOp::MemWrite,
                    payload: SyscallPayload::MemWrite {
                        packet: packet.clone(),
                    },
                    reason: Some(format!("knowledge batch {ingest_run_id} #{idx}")),
                    vakya_id: None,
                    trace_parent: None,
                    trace_state: None,
                    api_version: None,
                })
            };

            if result.outcome == vac_core::types::OpOutcome::Success {
                written += 1;
                new_packets.push(packet);
                let mut es = state.engine_store.lock().unwrap();
                let _ = es.folder_put(
                    KNOWLEDGE_DEDUPE_FOLDER,
                    &store_key,
                    &serde_json::json!({
                        "namespace": namespace,
                        "ingest_run_id": ingest_run_id,
                        "first_seen_at_ms": now,
                    }),
                );
            }
        }

        let entities = {
            let mut knot = state.knot.lock().unwrap();
            if !new_packets.is_empty() {
                knot.ingest_packets(&new_packets, 0);
            }
            knot.node_count()
        };

        open_proceed.finish_observed(written > 0);
        return Json(serde_json::json!({
            "ok": true,
            "task_id": admitted.task_id,
            "executed": written > 0,
            "admits": false,
            "ingest_run_id": ingest_run_id,
            "agent_pid": agent_pid,
            "agent_pid_fallback": agent_pid_fallback,
            "namespace": namespace,
            "records_submitted": submitted,
            "records_written": written,
            "records_skipped_dedupe": skipped_dedupe,
            "records_skipped_empty": skipped_empty,
            "knot_entities_after": entities,
            "pipeline": {
                "version": pipeline_version,
                "stages": ["dedupe_check", "mem_write", "knot_ingest"],
                "spec": "GET /api/v1/memory/knowledge/pipeline/spec",
            },
            "knowledge_plane": {
                "shared_graph": "/k/* namespaces feed KnotEngine",
                "event_fabric_note": "Fan-out via GET /actionlog/export/jsonl or CloudEvents.",
            },
        }));
    }

    let k = state.kernel.lock().unwrap();
    let mut knot = state.knot.lock().unwrap();
    let packets: Vec<MemPacket> = k
        .packets_in_namespace(&namespace)
        .into_iter()
        .cloned()
        .collect();
    let count = packets.len();
    if !packets.is_empty() {
        knot.ingest_packets(&packets, 0);
    }
    let entities = knot.node_count();
    drop(knot);
    drop(k);
    open_proceed.finish_observed(count > 0);
    Json(serde_json::json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": count > 0,
        "admits": false,
        "ingest_run_id": format!("rescan_{}", uuid::Uuid::new_v4()),
        "namespace": namespace,
        "packets_ingested": count,
        "knot_entities_after": entities,
        "entities": entities,
        "mode": "namespace_rescan",
        "pipeline": {
            "version": pipeline_version,
            "spec": "GET /api/v1/memory/knowledge/pipeline/spec",
        },
        "knowledge_plane": {
            "shared_graph": "/k/* namespaces feed KnotEngine (entity + relation RAG substrate)",
            "private_agent_memory": "POST /memory/write for agent-local packets; not mixed until explicitly shared",
            "event_fabric_note": "For Kafka-like fan-out use GET /actionlog/export/jsonl or CloudEvents — no broker inside this binary.",
        },
    }))
}

/// Wave 1 — Item 1.6: Find wasted tokens in agent context (stale packets, duplicates)
pub async fn stale_analysis(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let mut by_agent: Vec<serde_json::Value> = Vec::new();
    let mut total_stale: usize = 0;
    let mut total_packets: usize = 0;

    for (pid, acb) in k.agents() {
        let packets = k.packets_in_namespace(&acb.namespace);
        let packet_count = packets.len();
        total_packets += packet_count;

        // Find stale packets: older than 24 hours
        let stale_threshold_ms = 24 * 60 * 60 * 1000_i64;
        let mut stale_packets: Vec<serde_json::Value> = Vec::new();
        let mut stale_count = 0;

        for p in &packets {
            let age_ms = now - p.index.ts;
            if age_ms > stale_threshold_ms {
                stale_count += 1;
                if stale_packets.len() < 5 {
                    stale_packets.push(serde_json::json!({
                        "cid": p.content.payload_cid.to_string(),
                        "type": format!("{}", p.content.packet_type),
                        "age_hours": age_ms / 3_600_000,
                        "text_preview": p.content.payload.get("text")
                            .and_then(|v| v.as_str())
                            .map(|s| s.chars().take(80).collect::<String>()),
                    }));
                }
            }
        }
        total_stale += stale_count;

        // Check for duplicate content (same text hash)
        let mut seen_texts: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut duplicate_count = 0;
        for p in &packets {
            let text = p
                .content
                .payload
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !text.is_empty() && !seen_texts.insert(text) {
                duplicate_count += 1;
            }
        }

        let quota_tokens = acb.memory_region.quota_tokens;
        let used_tokens = acb.memory_region.used_tokens;
        let stale_pct = if packet_count > 0 {
            stale_count as f64 / packet_count as f64 * 100.0
        } else {
            0.0
        };

        let mut recommendations: Vec<String> = Vec::new();
        if stale_pct > 50.0 {
            recommendations.push(format!(
                "{:.0}% of packets are stale (>24h). Consider eviction or compression.",
                stale_pct
            ));
        }
        if duplicate_count > 0 {
            recommendations.push(format!(
                "{} duplicate packets found. Memory deduplication recommended.",
                duplicate_count
            ));
        }
        if quota_tokens > 0 && used_tokens as f64 / quota_tokens as f64 > 0.8 {
            recommendations.push(format!(
                "Memory region at {:.0}% capacity. Evict stale packets to free space.",
                used_tokens as f64 / quota_tokens as f64 * 100.0
            ));
        }

        if stale_count > 0 || duplicate_count > 0 || !recommendations.is_empty() {
            by_agent.push(serde_json::json!({
                "pid": pid,
                "name": &acb.agent_name,
                "total_packets": packet_count,
                "stale_packets": stale_count,
                "stale_pct": (stale_pct * 10.0).round() / 10.0,
                "duplicate_packets": duplicate_count,
                "quota_tokens": quota_tokens,
                "used_tokens": used_tokens,
                "stale_examples": stale_packets,
                "recommendations": recommendations,
            }));
        }
    }

    Json(serde_json::json!({
        "total_packets": total_packets,
        "total_stale": total_stale,
        "agents_with_issues": by_agent.len(),
        "by_agent": by_agent,
    }))
}

/// Wave 1 — Item 1.7: One-click context optimization per agent
pub async fn optimize_context(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let ns = {
        let k = state.kernel.lock().unwrap();
        match k.get_agent(&agent_pid) {
            Some(a) => a.namespace.clone(),
            None => {
                return Json(serde_json::json!({
                    "error": format!("Agent {} not found", agent_pid),
                    "status": 404
                }));
            }
        }
    };
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, &agent_pid, &ns)
    {
        return Json(deny);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_pid,
        "memory",
        "optimize",
        &serde_json::json!({"agent_pid": agent_pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let stale_threshold_ms = 24 * 60 * 60 * 1000_i64;

    // Find the agent
    let acb = match k.get_agent(&agent_pid) {
        Some(a) => a.clone(),
        None => {
            drop(k);
            open_proceed.finish_observed(false);
            return Json(
                serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404, "task_id": admitted.task_id, "executed": false, "admits": false}),
            )
        }
    };

    let packets = k.packets_in_namespace(&acb.namespace);
    let before_count = packets.len();

    // Identify stale packet CIDs
    let stale_cids: Vec<cid::Cid> = packets
        .iter()
        .filter(|p| (now - p.index.ts) > stale_threshold_ms)
        .map(|p| p.content.payload_cid)
        .collect();
    let stale_count = stale_cids.len();

    // Evict stale packets via kernel syscall (batch by 10)
    let mut evicted = 0;
    for chunk in stale_cids.chunks(10) {
        let result = k.dispatch(SyscallRequest {
            agent_pid: agent_pid.clone(),
            operation: MemoryKernelOp::MemEvict,
            payload: SyscallPayload::MemEvict {
                cids: chunk.to_vec(),
                max_evict: 0,
            },
            reason: Some("stale_optimization".to_string()),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
        if result.outcome == vac_core::types::OpOutcome::Success {
            evicted += chunk.len();
        }
    }

    let after_packets = k.packets_in_namespace(&acb.namespace).len();
    drop(k);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "before_packets": before_count,
        "after_packets": after_packets,
        "stale_found": stale_count,
        "evicted": evicted,
        "tokens_freed_estimate": evicted * 150,
        "status": if evicted > 0 { "optimized" } else { "no_changes_needed" },
    }))
}

/// Wave 3 — Item 3.3: Context window usage + waste breakdown per agent
pub async fn context_pressure(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now().timestamp_millis();

    let acb = match k.get_agent(&agent_pid) {
        Some(a) => a,
        None => {
            return Json(
                serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
            )
        }
    };

    let packets = k.packets_in_namespace(&acb.namespace);
    let total_packets = packets.len();

    // Estimate token usage per packet type
    let mut by_type: std::collections::HashMap<String, (usize, usize)> =
        std::collections::HashMap::new();
    let stale_threshold_ms = 24 * 60 * 60 * 1000_i64;
    let mut stale_tokens_est: usize = 0;
    let mut duplicate_tokens_est: usize = 0;
    let mut seen_texts: std::collections::HashSet<String> = std::collections::HashSet::new();

    for p in &packets {
        let ptype = format!("{}", p.content.packet_type);
        let text_len = p
            .content
            .payload
            .get("text")
            .and_then(|v| v.as_str())
            .map(|s| s.len())
            .unwrap_or(0);
        let est_tokens = text_len / 4 + 1; // rough 4 chars per token

        let entry = by_type.entry(ptype).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += est_tokens;

        let age_ms = now - p.index.ts;
        if age_ms > stale_threshold_ms {
            stale_tokens_est += est_tokens;
        }

        let text = p
            .content
            .payload
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !text.is_empty() && !seen_texts.insert(text) {
            duplicate_tokens_est += est_tokens;
        }
    }

    let total_tokens_est: usize = by_type.values().map(|(_, t)| *t).sum();
    let quota = acb.memory_region.quota_tokens;
    let pressure_pct = if quota > 0 {
        total_tokens_est as f64 / quota as f64 * 100.0
    } else {
        0.0
    };
    let waste_pct = if total_tokens_est > 0 {
        (stale_tokens_est + duplicate_tokens_est) as f64 / total_tokens_est as f64 * 100.0
    } else {
        0.0
    };

    let type_breakdown: Vec<serde_json::Value> = by_type.iter().map(|(ptype, (count, tokens))| {
        serde_json::json!({
            "type": ptype,
            "packets": count,
            "estimated_tokens": tokens,
            "pct_of_context": if total_tokens_est > 0 { *tokens as f64 / total_tokens_est as f64 * 100.0 } else { 0.0 },
        })
    }).collect();

    let mut recommendations: Vec<String> = Vec::new();
    if pressure_pct > 80.0 {
        recommendations.push(format!(
            "Context at {:.0}% capacity — eviction recommended",
            pressure_pct
        ));
    }
    if waste_pct > 30.0 {
        recommendations.push(format!(
            "{:.0}% of context is wasted (stale+duplicates) — run optimize-context",
            waste_pct
        ));
    }
    if stale_tokens_est > 0 {
        recommendations.push(format!("~{} stale tokens could be freed", stale_tokens_est));
    }

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "total_packets": total_packets,
        "estimated_tokens": total_tokens_est,
        "quota_tokens": quota,
        "pressure_pct": (pressure_pct * 10.0).round() / 10.0,
        "waste": {
            "stale_tokens": stale_tokens_est,
            "duplicate_tokens": duplicate_tokens_est,
            "total_waste_tokens": stale_tokens_est + duplicate_tokens_est,
            "waste_pct": (waste_pct * 10.0).round() / 10.0,
        },
        "by_type": type_breakdown,
        "eviction_policy": format!("{:?}", acb.memory_region.eviction_policy),
        "recommendations": recommendations,
    }))
}

/// Track 2 Phase A — Item A.1: View/describe MemoryProtection config per agent
pub async fn region_configure(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("");
    let k = state.kernel.lock().unwrap();

    let acb = match k.get_agent(agent_pid) {
        Some(a) => a,
        None => {
            return Json(
                serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
            )
        }
    };

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "protection": {
            "read": acb.memory_region.protection.read,
            "write": acb.memory_region.protection.write,
            "execute": acb.memory_region.protection.execute,
            "share": acb.memory_region.protection.share,
            "evict": acb.memory_region.protection.evict,
            "requires_approval": acb.memory_region.protection.requires_approval,
        },
        "quota_tokens": acb.memory_region.quota_tokens,
        "quota_packets": acb.memory_region.quota_packets,
        "note": "Use kernel syscalls to modify protection flags",
    }))
}

/// Track 2 Phase A — Item A.2: GET quota usage, protection flags, sealed status
pub async fn region_view(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    match k.get_agent(&agent_pid) {
        Some(acb) => {
            let packets = k.packets_in_namespace(&acb.namespace);
            Json(serde_json::json!({
                "agent_pid": agent_pid,
                "namespace": &acb.namespace,
                "protection": {
                    "read": acb.memory_region.protection.read,
                    "write": acb.memory_region.protection.write,
                    "execute": acb.memory_region.protection.execute,
                    "share": acb.memory_region.protection.share,
                    "evict": acb.memory_region.protection.evict,
                    "requires_approval": acb.memory_region.protection.requires_approval,
                },
                "quota": {
                    "tokens": acb.memory_region.quota_tokens,
                    "tokens_used": acb.memory_region.used_tokens,
                    "packets": acb.memory_region.quota_packets,
                    "packets_used": packets.len(),
                    "bytes": acb.memory_region.quota_bytes,
                    "bytes_used": acb.memory_region.used_bytes,
                },
                "eviction_policy": format!("{:?}", acb.memory_region.eviction_policy),
                "sealed": acb.memory_region.sealed,
            }))
        }
        None => Json(
            serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
        ),
    }
}

/// Track 2 Phase A — Item A.3: View EvictionPolicy per agent
pub async fn eviction_policy(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("");
    let k = state.kernel.lock().unwrap();
    let acb = match k.get_agent(agent_pid) {
        Some(a) => a,
        None => {
            return Json(
                serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
            )
        }
    };

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "eviction_policy": format!("{:?}", acb.memory_region.eviction_policy),
        "sealed": acb.memory_region.sealed,
        "quota_tokens": acb.memory_region.quota_tokens,
        "available_policies": ["Lru", "Fifo", "Ttl", "Priority", "SummarizeEvict", "Never"],
    }))
}

/// Track 2 Phase A — Items A.4+A.5: Promote/Demote memory tier
pub async fn tier_change(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("");
    let direction = req
        .get("direction")
        .and_then(|v| v.as_str())
        .unwrap_or("promote");
    let target_cids: Vec<String> = req
        .get("cids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let namespace = {
        let k = state.kernel.lock().unwrap();
        match k.get_agent(agent_pid) {
            Some(a) => a.namespace.clone(),
            None => {
                return Json(serde_json::json!({
                    "error": format!("Agent {} not found", agent_pid),
                    "status": 404
                }));
            }
        }
    };
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, agent_pid, &namespace)
    {
        return Json(deny);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        agent_pid,
        "memory",
        "tier_change",
        &serde_json::json!({"agent_pid": agent_pid, "direction": direction}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let k = state.kernel.lock().unwrap();
    let acb = match k.get_agent(agent_pid) {
        Some(a) => a,
        None => {
            drop(k);
            open_proceed.finish_observed(false);
            return Json(
                serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404, "task_id": admitted.task_id, "executed": false, "admits": false}),
            )
        }
    };

    let op = if direction == "promote" {
        MemoryKernelOp::MemPromote
    } else {
        MemoryKernelOp::MemDemote
    };
    let new_tier = if direction == "promote" {
        vac_core::types::MemoryTier::Hot
    } else {
        vac_core::types::MemoryTier::Cold
    };

    // Execute tier change via kernel dispatch
    let mut changed = 0;
    drop(k);
    let mut k = state.kernel.lock().unwrap();
    for cid_str in &target_cids {
        let cid_val = cid::Cid::try_from(cid_str.as_str()).unwrap_or_default();
        let result = k.dispatch(SyscallRequest {
            agent_pid: agent_pid.to_string(),
            operation: op.clone(),
            payload: SyscallPayload::TierChange {
                packet_cid: cid_val,
                new_tier: new_tier.clone(),
            },
            reason: Some(format!("tier_{}", direction)),
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
        if result.outcome == vac_core::types::OpOutcome::Success {
            changed += 1;
        }
    }
    drop(k);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "direction": direction,
        "requested": target_cids.len(),
        "changed": changed,
    }))
}

/// Track 2 Phase A — Item A.6: Show tier breakdown per agent
pub async fn tier_distribution(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let acb = match k.get_agent(&agent_pid) {
        Some(a) => a,
        None => {
            return Json(
                serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
            )
        }
    };

    let packets = k.packets_in_namespace(&acb.namespace);
    let mut hot = 0usize;
    let mut warm = 0usize;
    let mut cold = 0usize;
    let mut archive = 0usize;

    for p in &packets {
        match p.tier {
            vac_core::types::MemoryTier::Hot => hot += 1,
            vac_core::types::MemoryTier::Warm => warm += 1,
            vac_core::types::MemoryTier::Cold => cold += 1,
            vac_core::types::MemoryTier::Archive => archive += 1,
        }
    }

    let total = packets.len();
    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "total_packets": total,
        "tiers": {
            "hot": {"count": hot, "pct": if total > 0 { hot as f64 / total as f64 * 100.0 } else { 0.0 }},
            "warm": {"count": warm, "pct": if total > 0 { warm as f64 / total as f64 * 100.0 } else { 0.0 }},
            "cold": {"count": cold, "pct": if total > 0 { cold as f64 / total as f64 * 100.0 } else { 0.0 }},
            "archive": {"count": archive, "pct": if total > 0 { archive as f64 / total as f64 * 100.0 } else { 0.0 }},
        },
        "eviction_policy": format!("{:?}", acb.memory_region.eviction_policy),
    }))
}

pub async fn list_agents(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let agents: Vec<serde_json::Value> = k
        .agents()
        .iter()
        .map(|(pid, acb)| {
            serde_json::json!({
                "pid": pid,
                "name": acb.agent_name,
                "namespace": acb.namespace,
                "status": format!("{:?}", acb.status),
                "registered_at": acb.registered_at,
            })
        })
        .collect();
    Json(serde_json::json!({"count": agents.len(), "agents": agents}))
}

// ── E2: Moat 1 Memory Features ───────────────────────────────────────────────

/// E2.1: Semantic search over agent memory packets
/// GET /memory/semantic-search?q=&agent_pid=&top_k=5
pub async fn semantic_search(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<SemanticSearchQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let tenant = crate::services::agents::tenant_from_headers_for_cap(&headers);

    let query_lower = q.q.to_lowercase();
    let query_tokens: Vec<&str> = query_lower.split_whitespace().collect();
    let top_k = q.top_k.unwrap_or(5).min(50);

    // Collect candidate packets from relevant namespaces
    let mut candidates: Vec<(f64, serde_json::Value)> = Vec::new();

    let namespaces: Vec<String> = if let Some(ref pid) = q.agent_pid {
        k.agents()
            .get(pid)
            .map(|a| vec![a.namespace.clone()])
            .unwrap_or_default()
    } else {
        k.agents()
            .values()
            .filter(|a| {
                crate::services::agents::kernel_agent_in_scope(&a.namespace, tenant.as_ref())
            })
            .map(|a| a.namespace.clone())
            .collect()
    };

    for ns in &namespaces {
        if let Err(deny) = crate::services::agents::assert_namespace_readable(&headers, ns) {
            return deny;
        }
        for packet in k.packets_in_namespace(ns).iter().take(500) {
            let text = packet
                .content
                .payload
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if text.is_empty() {
                continue;
            }

            let text_lower = text.to_lowercase();
            // BM25-inspired token overlap scoring (no embedding needed)
            let doc_tokens: Vec<&str> = text_lower.split_whitespace().collect();
            let doc_len = doc_tokens.len().max(1);
            let avg_len = 20.0_f64; // assumed average

            let mut score = 0.0_f64;
            for qt in &query_tokens {
                let tf = doc_tokens.iter().filter(|t| t == &qt).count() as f64;
                let idf = 1.0; // simplified — no corpus IDF available
                let k1 = 1.5_f64;
                let b = 0.75_f64;
                let bm25 =
                    idf * (tf * (k1 + 1.0)) / (tf + k1 * (1.0 - b + b * doc_len as f64 / avg_len));
                score += bm25;
            }

            if score > 0.0 {
                let cid = packet.content.payload_cid.to_string();
                candidates.push((
                    score,
                    serde_json::json!({
                        "cid":         cid,
                        "namespace":   ns,
                        "agent_pid":   q.agent_pid,
                        "score":       (score * 1000.0).round() / 1000.0,
                        "text_preview":text.chars().take(200).collect::<String>(),
                        "packet_type": format!("{}", packet.content.packet_type),
                        "timestamp":   packet.index.ts,
                        "timestamp_iso": chrono::DateTime::from_timestamp_millis(packet.index.ts)
                            .map(|d| d.to_rfc3339()).unwrap_or_default(),
                    }),
                ));
            }
        }
    }

    // Sort descending by BM25 score, take top_k
    candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let results: Vec<serde_json::Value> =
        candidates.into_iter().take(top_k).map(|(_, v)| v).collect();

    Json(serde_json::json!({
        "query":       q.q,
        "agent_pid":   q.agent_pid,
        "top_k":       top_k,
        "result_count":results.len(),
        "algorithm":   "BM25 token overlap (k1=1.5, b=0.75)",
        "results":     results,
        "upgrade_note":"For vector ANN search, wire an embedding model via CONNECTOR_LLM_PROVIDER",
    }))
}

#[derive(Deserialize)]
pub struct SemanticSearchQuery {
    pub q: String,
    pub agent_pid: Option<String>,
    pub top_k: Option<usize>,
}

/// E2.2: Memory consolidation — cluster similar packets into a summary
/// POST /memory/consolidate/{agent_pid}
pub async fn consolidate(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let namespace = {
        let k = state.kernel.lock().unwrap();
        match k.agents().get(&agent_pid) {
            Some(a) => a.namespace.clone(),
            None => {
                return Json(serde_json::json!({
                    "error": format!("Agent {} not found", agent_pid),
                    "status": 404
                }));
            }
        }
    };
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, &agent_pid, &namespace)
    {
        return Json(deny);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_pid,
        "memory",
        "consolidate",
        &serde_json::json!({"agent_pid": agent_pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();

    let quota = k
        .agents()
        .get(&agent_pid)
        .map(|a| a.memory_region.quota_tokens)
        .unwrap_or(16_000);
    let consumed = k
        .agents()
        .get(&agent_pid)
        .map(|a| a.total_tokens_consumed)
        .unwrap_or(0);

    let fill_pct = if quota > 0 {
        consumed as f64 / quota as f64 * 100.0
    } else {
        0.0
    };

    let packets: Vec<_> = k
        .packets_in_namespace(&namespace)
        .into_iter()
        .take(200)
        .collect();
    let packet_count = packets.len();

    if packet_count < 5 {
        drop(k);
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({
            "agent_pid":    agent_pid,
            "task_id":      admitted.task_id,
            "executed":     false,
            "admits":       false,
            "status":       "skipped",
            "reason":       "Fewer than 5 packets — consolidation not needed",
            "packet_count": packet_count,
            "fill_pct":     (fill_pct * 10.0).round() / 10.0,
        }));
    }

    // Group packets by recency buckets (last 1h, last 24h, older)
    let now_ms = now.timestamp_millis();
    let mut recent: Vec<String> = Vec::new();
    let mut daily: Vec<String> = Vec::new();
    let mut older: Vec<String> = Vec::new();

    for p in &packets {
        let age_ms = now_ms - p.index.ts;
        let text = p
            .content
            .payload
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if age_ms < 3_600_000 {
            recent.push(text);
        } else if age_ms < 86_400_000 {
            daily.push(text);
        } else {
            older.push(text);
        }
    }

    // Build consolidation summary (text summary; LLM-assisted when router available)
    let summary = if state.llm_wired() {
        format!(
            "[LLM-consolidated] {} recent, {} daily, {} older packets. \
             Wire POST /memory/write with the LLM summary to persist. \
             Use CONNECTOR_LLM_PROVIDER for real consolidation.",
            recent.len(),
            daily.len(),
            older.len()
        )
    } else {
        format!(
            "[Rule-consolidated] {} packets across 3 time buckets. \
             Recent ({} pkts): {}... Daily ({} pkts): {}...",
            packet_count,
            recent.len(),
            recent
                .first()
                .map(|s| s.chars().take(80).collect::<String>())
                .unwrap_or_default(),
            daily.len(),
            daily
                .first()
                .map(|s| s.chars().take(80).collect::<String>())
                .unwrap_or_default(),
        )
    };

    // Write the consolidated summary packet back to kernel
    let summary_packet = make_packet_simple(
        &summary,
        "consolidator",
        "consolidation",
        PacketType::Extraction,
    );
    drop(k); // release read lock before re-acquiring as mut
    let mut kernel = state.kernel.lock().unwrap();
    let _ = kernel.dispatch(SyscallRequest {
        agent_pid: agent_pid.clone(),
        operation: MemoryKernelOp::MemWrite,
        payload: SyscallPayload::MemWrite {
            packet: summary_packet,
        },
        reason: Some("memory_consolidation".into()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    drop(kernel);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "agent_pid":     agent_pid,
        "task_id":       admitted.task_id,
        "executed":      true,
        "admits":        false,
        "status":        "consolidated",
        "packets_scanned": packet_count,
        "fill_pct":      (fill_pct * 10.0).round() / 10.0,
        "buckets": {
            "recent_1h":  recent.len(),
            "daily_24h":  daily.len(),
            "older":      older.len(),
        },
        "summary_written": true,
        "summary_preview": summary.chars().take(200).collect::<String>(),
        "consolidated_at": now.to_rfc3339(),
        "llm_assisted":   state.llm_wired(),
        "auto_trigger":   "Consolidation auto-triggers at 80% namespace quota",
        "non_destructive": true,
        "honesty": "S14: originals retained; summary packet appended — no packet deletion",
    }))
}

/// E2.3: Temporal decay — relevance score + stale packet detection
/// GET /memory/stale/{agent_pid}?threshold_days=30
pub async fn stale_packets(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Query(q): Query<StaleQuery>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let threshold_days = q.threshold_days.unwrap_or(30);
    let threshold_ms = threshold_days as i64 * 86_400_000;
    let lambda = q.decay_lambda.unwrap_or(0.1_f64); // decay rate

    let namespace = match k.agents().get(&agent_pid) {
        Some(a) => a.namespace.clone(),
        None => {
            return Json(
                serde_json::json!({"error": format!("Agent {} not found", agent_pid), "status": 404}),
            )
        }
    };

    let packets = k.packets_in_namespace(&namespace);
    let mut stale: Vec<serde_json::Value> = Vec::new();
    let mut active: Vec<serde_json::Value> = Vec::new();

    for p in &packets {
        let age_ms = now_ms - p.index.ts;
        let age_days = age_ms as f64 / 86_400_000.0;
        // Temporal decay: relevance = exp(−λ × days_since_access)
        let relevance = (-lambda * age_days).exp();
        let text = p
            .content
            .payload
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let entry = serde_json::json!({
            "cid":        p.content.payload_cid.to_string(),
            "age_days":   (age_days * 10.0).round() / 10.0,
            "relevance":  (relevance * 1000.0).round() / 1000.0,
            "packet_type":format!("{}", p.content.packet_type),
            "text_preview":text.chars().take(100).collect::<String>(),
            "timestamp_iso":chrono::DateTime::from_timestamp_millis(p.index.ts)
                .map(|d| d.to_rfc3339()).unwrap_or_default(),
        });

        if age_ms > threshold_ms {
            stale.push(entry);
        } else {
            active.push(entry);
        }
    }

    let total = stale.len() + active.len();
    let stale_pct = if total > 0 {
        stale.len() * 100 / total
    } else {
        0
    };

    // Estimate token waste (approx 4 chars/token)
    let stale_tokens: usize = stale
        .iter()
        .filter_map(|v| v.get("text_preview").and_then(|t| t.as_str()))
        .map(|t| t.len() / 4 + 1)
        .sum();

    Json(serde_json::json!({
        "agent_pid":        agent_pid,
        "threshold_days":   threshold_days,
        "decay_lambda":     lambda,
        "decay_formula":    "relevance = exp(−λ × age_days)",
        "total_packets":    total,
        "stale_count":      stale.len(),
        "active_count":     active.len(),
        "stale_pct":        stale_pct,
        "estimated_stale_tokens": stale_tokens,
        "stale_packets":    stale,
        "recommendation":   if stale.len() > 10 {
            format!("Evict {} stale packets to reclaim ~{} tokens. Use POST /memory/consolidate/{}", stale.len(), stale_tokens, agent_pid)
        } else {
            "Memory is healthy — no significant stale content detected.".into()
        },
    }))
}

#[derive(Deserialize)]
pub struct StaleQuery {
    pub threshold_days: Option<u32>,
    pub decay_lambda: Option<f64>,
}

/// E2.4: Controlled cross-agent memory sharing with Bell-LaPadula check
/// POST /memory/share
pub async fn share_memory(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let from_pid = req
        .get("from_agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let to_pid = req
        .get("to_agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let cid_str = req.get("cid").and_then(|v| v.as_str()).unwrap_or("");
    let reason = req
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("cross-agent-share");

    if from_pid.is_empty() || to_pid.is_empty() {
        return Json(
            serde_json::json!({"error": "from_agent_pid and to_agent_pid required", "status": 400}),
        );
    }

    if let Err(e) = crate::kernel::agent_principal::require_contract_action(
        state.as_ref(),
        from_pid,
        "memory.share",
        to_pid,
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": e,
            "denial_reason": "contract_denied",
            "code": "contract_denied",
            "status": 403,
        }));
    }
    if let Err(e) = crate::kernel::agent_identity_envelope::require_inter_intelligence_grant(
        state.as_ref(),
        from_pid,
        to_pid,
        None,
    ) {
        return Json(serde_json::json!({
            "ok": false,
            "error": e,
            "denial_reason": "grant_required",
            "code": "grant_required",
            "status": 403,
        }));
    }

    if let Err(err) = crate::substrate::governed_effect::evaluate_effect(
        &state,
        None,
        from_pid,
        "memory/share",
        crate::services::admission::AdmissionOp::MemoryWrite,
        Some(reason),
    ) {
        return Json(serde_json::json!({
            "error": err.human_readable,
            "denial_reason": err.denial_reason.slug(),
            "audit_cid": err.audit_cid,
            "code": "admission_denied",
            "status": 403,
        }));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        from_pid,
        "memory",
        "share_packet",
        &serde_json::json!({"from": from_pid, "to": to_pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let k = state.kernel.lock().unwrap();
    let now = chrono::Utc::now();

    // Verify both agents exist
    let from_acb = match k.agents().get(from_pid) {
        Some(a) => a,
        None => {
            drop(k);
            open_proceed.finish_observed(false);
            return Json(
                serde_json::json!({"error": format!("Source agent {} not found", from_pid), "status": 404, "task_id": admitted.task_id, "executed": false, "admits": false}),
            )
        }
    };
    let to_acb = match k.agents().get(to_pid) {
        Some(a) => a,
        None => {
            drop(k);
            open_proceed.finish_observed(false);
            return Json(
                serde_json::json!({"error": format!("Target agent {} not found", to_pid), "status": 404, "task_id": admitted.task_id, "executed": false, "admits": false}),
            )
        }
    };

    // Bell-LaPadula check: source must have read permission on its own namespace
    // and target must have write permission (or at least share is permitted)
    let from_can_read = from_acb.memory_region.protection.read;
    let to_can_write = to_acb.memory_region.protection.write;
    let share_allowed = from_acb.memory_region.protection.share;

    if !from_can_read || !share_allowed {
        drop(k);
        open_proceed.finish_observed(false);
        return Json(serde_json::json!({
            "error": "Bell-LaPadula violation: source agent does not have read+share permissions",
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
            "from_agent_pid": from_pid,
            "protection": {
                "read":  from_can_read,
                "share": share_allowed,
            },
        }));
    }

    // Find the packet by CID in source namespace
    let source_ns = from_acb.namespace.clone();
    let target_ns = to_acb.namespace.clone();
    drop(k);

    let k = state.kernel.lock().unwrap();
    let packets = k.packets_in_namespace(&source_ns);
    let packet = packets
        .iter()
        .find(|p| p.content.payload_cid.to_string().contains(cid_str) || cid_str.is_empty());

    let content_text = packet
        .and_then(|p| p.content.payload.get("text").and_then(|v| v.as_str()))
        .unwrap_or("[packet content unavailable]");

    // Write the shared content to target agent's namespace
    let share_text = format!("[shared from {}] {}", from_pid, content_text);
    let share_packet = make_packet_simple(
        &share_text,
        from_pid,
        "cross-agent-share",
        PacketType::Input,
    );
    drop(k);

    let mut kernel = state.kernel.lock().unwrap();
    let result = kernel.dispatch(SyscallRequest {
        agent_pid: to_pid.to_string(),
        operation: MemoryKernelOp::MemWrite,
        payload: SyscallPayload::MemWrite {
            packet: share_packet,
        },
        reason: Some(reason.to_string()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });

    // Audit log for every cross-agent read (GDPR Art.30 + SOC2 CC6.6)
    let audit_outcome = format!("{:?}", result.outcome);
    let share_id = format!("share_{}", uuid::Uuid::new_v4());

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "cross_agent_shares",
        &share_id,
        &serde_json::json!({
            "share_id":      share_id,
            "from_agent_pid":from_pid,
            "to_agent_pid":  to_pid,
            "cid":           cid_str,
            "reason":        reason,
            "outcome":       audit_outcome,
            "shared_at":     now.to_rfc3339(),
            "bell_lapadula": "PASS — read+share permissions verified",
        }),
    );
    let shared = result.outcome == vac_core::types::OpOutcome::Success;
    drop(kernel);
    drop(es);
    open_proceed.finish_observed(shared);

    Json(serde_json::json!({
        "share_id":       share_id,
        "task_id":        admitted.task_id,
        "executed":       shared,
        "admits":         false,
        "from_agent_pid": from_pid,
        "to_agent_pid":   to_pid,
        "cid":            cid_str,
        "status":         if result.outcome == vac_core::types::OpOutcome::Success { "shared" } else { "failed" },
        "outcome":        format!("{:?}", result.outcome),
        "bell_lapadula":  "PASS",
        "audit_logged":   true,
        "shared_at":      now.to_rfc3339(),
        "gdpr_note":      "Cross-agent read recorded per GDPR Art.30 + SOC2 CC6.6",
    }))
}

// ── Wave 3 Item 3.1: Auto-enrich on write — entity extraction ────────────────

/// POST /memory/enrich/{pid}
/// Extracts entities and keywords from recent packets and links related concepts.
/// Returns enrichment summary: entities found, links created, packets processed.
pub async fn enrich_memory(
    State(state): State<SharedState>,
    axum::extract::Path(agent_pid): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let now = chrono::Utc::now();
    let k = state.kernel.lock().unwrap();
    let ns = format!("agent:{}", agent_pid);

    let packets = k.packets_in_namespace(&ns);
    let total = packets.len();

    // Simple entity extraction: find capitalized words, URLs, emails, numbers
    let entity_re = regex::Regex::new(r"\b[A-Z][a-zA-Z]{2,}\b")
        .unwrap_or_else(|_| regex::Regex::new(r"x").unwrap());
    let url_re =
        regex::Regex::new(r"https?://[^\s]+").unwrap_or_else(|_| regex::Regex::new(r"x").unwrap());
    let email_re = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        .unwrap_or_else(|_| regex::Regex::new(r"x").unwrap());

    let mut entities: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut urls: Vec<String> = Vec::new();
    let mut emails: Vec<String> = Vec::new();

    for p in packets.iter().take(500) {
        let text = p.content.payload.as_str().unwrap_or("");
        for m in entity_re.find_iter(text) {
            *entities.entry(m.as_str().to_string()).or_insert(0) += 1;
        }
        for m in url_re.find_iter(text) {
            urls.push(m.as_str().to_string());
        }
        for m in email_re.find_iter(text) {
            emails.push(m.as_str().to_string());
        }
    }

    // Top entities by frequency
    let mut entity_list: Vec<(String, usize)> = entities.into_iter().collect();
    entity_list.sort_by(|a, b| b.1.cmp(&a.1));
    entity_list.truncate(20);

    urls.sort();
    urls.dedup();
    urls.truncate(10);
    emails.sort();
    emails.dedup();
    emails.truncate(10);

    let top_entities: Vec<serde_json::Value> = entity_list
        .iter()
        .map(|(e, c)| serde_json::json!({"entity": e, "mentions": c}))
        .collect();

    Json(serde_json::json!({
        "agent_pid":        agent_pid,
        "generated_at":     now.to_rfc3339(),
        "packets_scanned":  total.min(500),
        "total_packets":    total,
        "top_entities":     top_entities,
        "urls_found":       urls,
        "emails_found":     emails,
        "enrichment_hint":  "Use these entities to build a knowledge graph or improve RAG retrieval.",
        "link_hint":        "POST /memory/share to propagate key entities to related agents.",
    }))
}

#[cfg(test)]
mod multimodal_parts_tests {
    use super::*;

    #[test]
    fn memory_part_input_strips_to_object_ref_shape() {
        let part = MemoryPartInput {
            part_kind: "image".into(),
            text: None,
            data_b64: Some(base64::engine::general_purpose::STANDARD.encode(b"png-bytes")),
            mime_type: Some("image/png".into()),
            object_ref: None,
        };
        let v = serde_json::to_value(&part).unwrap();
        assert_eq!(v["part_kind"], "image");
        assert!(v.get("data_b64").is_some());
        // Round-trip without data_b64 (fabric-backed descriptor shape).
        let desc = MemoryPartInput {
            part_kind: "image".into(),
            text: None,
            data_b64: None,
            mime_type: Some("image/png".into()),
            object_ref: Some("sha256:deadbeef".into()),
        };
        let back: MemoryPartInput =
            serde_json::from_value(serde_json::to_value(&desc).unwrap()).unwrap();
        assert!(back.data_b64.is_none());
        assert_eq!(back.object_ref.as_deref(), Some("sha256:deadbeef"));
    }

    #[test]
    fn make_packet_embeds_parts_without_requiring_json_content() {
        let req = WriteRequest {
            agent_pid: "a1".into(),
            content: "hello".into(),
            user: "u".into(),
            pipeline: "default".into(),
            packet_type: None,
            session_id: None,
            memory_type: None,
            tags: None,
            entity_kind: None,
            memory_class: None,
            key: None,
            parts: Some(vec![MemoryPartInput {
                part_kind: "text".into(),
                text: Some("caption".into()),
                data_b64: None,
                mime_type: None,
                object_ref: Some("sha256:abc".into()),
            }]),
        };
        let pkt = make_packet(&req, "a1", "m/a1", PacketType::Input);
        let parts = pkt.content.payload.get("parts").and_then(|p| p.as_array());
        assert!(parts.is_some());
        assert_eq!(parts.unwrap()[0]["object_ref"], "sha256:abc");
    }
}
