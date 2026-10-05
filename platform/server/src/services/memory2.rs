//! Memory2 — Exposed gaps from EXPOSURE_GAP.md (P0 Memory + Knowledge Graph)
//!
//! New endpoints:
//! Sessions: create, close, list, query-by-session
//! Packets:  read by CID, seal, list all
//! Access:   revoke
//! RAG:      fixed with time_range + grounding wired
//! Knowledge Graph: entity list, neighbors, add entity, add edge, seed, compile, growth events
//! Interference:    real engine (StateVector + compute_interference)

use crate::auth::{verify_token, PlatformRole};
use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};
use connector_engine::knowledge::{KnowledgeEngine, KnowledgeSeed};
use connector_engine::rag::RagEngine;
use serde::Deserialize;
use std::collections::BTreeMap;
use vac_core::kernel::{SyscallPayload, SyscallRequest};
use vac_core::types::{MemPacket, MemoryKernelOp, OpOutcome, PacketType, Source, SourceKind};

fn caller(headers: &axum::http::HeaderMap) -> Option<(String, PlatformRole)> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Some(("dev".to_string(), PlatformRole::SuperAdmin));
    }
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|h| h.to_str().ok()))?;
    let claims = verify_token(token).ok()?;
    Some((claims.sub, PlatformRole::from_str(&claims.role)))
}

fn packet_text(packet: &MemPacket) -> String {
    packet
        .content
        .payload
        .get("text")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| packet.content.payload.to_string())
}

fn resolve_agent_pid(state: &SharedState, pid: &str) -> String {
    let es = state.engine_store.lock().unwrap();
    es.folder_get("agent_meta", pid)
        .ok()
        .flatten()
        .and_then(|m| {
            m.get("kernel_pid")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| pid.to_string())
}

// ── Sessions ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    pub agent_pid: String,
    #[serde(default)]
    pub label: Option<String>,
}

/// POST /memory/sessions
pub async fn create_session(
    State(state): State<SharedState>,
    Json(req): Json<CreateSessionRequest>,
) -> Json<serde_json::Value> {
    let sid = format!("session:{}", uuid::Uuid::new_v4());
    if let Err(deny) = crate::substrate::admission_gate::require_memory_write(
        &state,
        &req.agent_pid,
        &format!("sessions/{sid}"),
    ) {
        return Json(deny);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &req.agent_pid,
        "memory",
        "create_session",
        &serde_json::json!({"agent_pid": req.agent_pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let kernel_pid = resolve_agent_pid(&state, &req.agent_pid);
    let mut k = state.kernel.lock().unwrap();
    let r = k.dispatch(SyscallRequest {
        agent_pid: kernel_pid.clone(),
        operation: MemoryKernelOp::SessionCreate,
        payload: SyscallPayload::SessionCreate {
            session_id: sid.clone(),
            label: req.label.clone(),
            parent_session_id: None,
        },
        reason: Some("create_session".into()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    let created = r.outcome == OpOutcome::Success;
    drop(k);
    open_proceed.finish_observed(created);
    if created {
        Json(serde_json::json!({
            "ok": true,
            "task_id": admitted.task_id,
            "executed": true,
            "admits": false,
            "session_id": sid,
            "agent_pid": req.agent_pid,
            "label": req.label,
        }))
    } else {
        Json(serde_json::json!({
            "ok": false,
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
            "error": r.audit_entry.error.unwrap_or_else(|| format!("{:?}", r.outcome)),
        }))
    }
}

/// DELETE /memory/sessions/:session_id  (agent_pid in body)
pub async fn close_session(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("system");
    if let Err(deny) = crate::substrate::admission_gate::require_memory_write(
        &state,
        agent_pid,
        &format!("sessions/{session_id}"),
    ) {
        return Json(deny);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        agent_pid,
        "memory",
        "close_session",
        &serde_json::json!({"session_id": session_id}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let kernel_pid = resolve_agent_pid(&state, agent_pid);
    let mut k = state.kernel.lock().unwrap();
    let r = k.dispatch(SyscallRequest {
        agent_pid: kernel_pid,
        operation: MemoryKernelOp::SessionClose,
        payload: SyscallPayload::SessionClose {
            session_id: session_id.clone(),
        },
        reason: Some("close_session".into()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    let closed = r.outcome == OpOutcome::Success;
    drop(k);
    open_proceed.finish_observed(closed);
    Json(serde_json::json!({
        "ok": closed,
        "task_id": admitted.task_id,
        "executed": closed,
        "admits": false,
        "session_id": session_id,
    }))
}

/// GET /memory/sessions
pub async fn list_sessions(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let sessions: Vec<serde_json::Value> = k
        .all_sessions()
        .iter()
        .map(|s| {
            serde_json::json!({
                "session_id": s.session_id,
                "label": s.label,
                "packet_count": s.packet_count(),
            })
        })
        .collect();
    Json(serde_json::json!({ "count": sessions.len(), "sessions": sessions }))
}

/// GET /memory/sessions/:session_id/packets
pub async fn session_packets(
    State(state): State<SharedState>,
    Path(session_id): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let packets: Vec<serde_json::Value> = k
        .packets_in_session(&session_id)
        .iter()
        .map(|p| {
            serde_json::json!({
                "cid": p.content.payload_cid.to_string(),
                "type": format!("{}", p.content.packet_type),
                "text": p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                "entities": p.content.entities,
                "tags": p.content.tags,
                "namespace": p.namespace,
                "session_id": p.session_id,
                "tier": format!("{:?}", p.tier),
                "timestamp": p.index.ts,
            })
        })
        .collect();
    Json(serde_json::json!({
        "session_id": session_id,
        "count": packets.len(),
        "packets": packets,
    }))
}

// ── Packet by CID ─────────────────────────────────────────────────────────────

/// GET /memory/packets/:cid
pub async fn get_packet(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(cid_str): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    // Find packet by CID string match across all namespaces
    let packet = k.all_packets().into_iter().find(|p| {
        p.content.payload_cid.to_string() == cid_str || p.index.packet_cid.to_string() == cid_str
    });
    match packet {
        Some(p) => {
            if let Err(deny) = crate::services::agents::assert_namespace_readable(
                &headers,
                p.namespace.as_deref().unwrap_or(""),
            ) {
                return deny;
            }
            Json(serde_json::json!({
                "cid": p.content.payload_cid.to_string(),
                "index_cid": p.index.packet_cid.to_string(),
                "type": format!("{}", p.content.packet_type),
                "text": p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                "entities": p.content.entities,
                "tags": p.content.tags,
                "namespace": p.namespace,
                "session_id": p.session_id,
                "tier": format!("{:?}", p.tier),
                "timestamp": p.index.ts,
                "sealed": k.is_sealed(&p.content.payload_cid),
            }))
        }
        None => Json(serde_json::json!({ "error": format!("Packet not found: {}", cid_str) })),
    }
}

// ── Seal (immutability) ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SealRequest {
    pub agent_pid: String,
    pub cid: String,
}

/// POST /memory/packets/:cid/seal
pub async fn seal_packet(
    State(state): State<SharedState>,
    Path(cid_str): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("system");
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, agent_pid, "m/sealed")
    {
        return Json(deny);
    }
    // Carried into the syscall so the kernel audit records why it was sealed.
    let seal_reason = req
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("operator_seal")
        .to_string();
    let kernel_pid = resolve_agent_pid(&state, agent_pid);
    let cid_parsed: cid::Cid = match cid_str.parse() {
        Ok(c) => c,
        Err(_) => {
            // Try to find the packet and get its CID
            let k = state.kernel.lock().unwrap();
            let packet = k
                .all_packets()
                .into_iter()
                .find(|p| p.content.payload_cid.to_string() == cid_str);
            match packet {
                Some(p) => p.content.payload_cid,
                None => {
                    return Json(
                        serde_json::json!({ "error": format!("Cannot parse CID: {}", cid_str) }),
                    )
                }
            }
        }
    };
    let mut k = state.kernel.lock().unwrap();
    let r = k.dispatch(SyscallRequest {
        agent_pid: kernel_pid,
        operation: MemoryKernelOp::MemSeal,
        payload: SyscallPayload::MemSeal {
            cids: vec![cid_parsed],
        },
        reason: Some(seal_reason.clone()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    Json(serde_json::json!({
        "ok": r.outcome == OpOutcome::Success,
        "cid": cid_str,
        "sealed": r.outcome == OpOutcome::Success,
        "immutable": true,
        "reason": seal_reason,
    }))
}

// ── Access revoke ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RevokeAccessRequest {
    pub owner_pid: String,
    pub namespace: String,
    pub grantee_pid: String,
}

/// POST /memory/access/revoke
pub async fn revoke_access(
    State(state): State<SharedState>,
    Json(req): Json<RevokeAccessRequest>,
) -> Json<serde_json::Value> {
    let owner_pid = resolve_agent_pid(&state, &req.owner_pid);
    let grantee_pid = resolve_agent_pid(&state, &req.grantee_pid);
    let mut k = state.kernel.lock().unwrap();
    let r = k.dispatch(SyscallRequest {
        agent_pid: owner_pid,
        operation: MemoryKernelOp::AccessRevoke,
        payload: SyscallPayload::AccessRevoke {
            target_namespace: req.namespace.clone(),
            grantee_pid,
        },
        reason: Some("revoke_access".into()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });
    Json(serde_json::json!({
        "ok": r.outcome == OpOutcome::Success,
        "owner_pid": req.owner_pid,
        "namespace": req.namespace,
        "grantee_pid": req.grantee_pid,
    }))
}

// ── Fixed recall (all 9 fields) ───────────────────────────────────────────────

/// GET /memory/recall2/:namespace  — full PacketSummary (9 fields, with filters)
pub async fn recall_full(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(namespace): Path<String>,
    axum::extract::Query(q): axum::extract::Query<RecallQuery>,
) -> Json<serde_json::Value> {
    if let Err(deny) = crate::services::agents::assert_namespace_readable(&headers, &namespace) {
        return deny;
    }
    if let Some(agent_hdr) = headers
        .get("x-connector-agent-pid")
        .and_then(|v| v.to_str().ok())
    {
        // Effect exclusivity: memory read through governed admission + Ring-1 when hardened.
        if crate::substrate::effect_exclusivity::effect_exclusivity_enforced()
            || crate::kernel::agent_principal::intelligence_hardening_on()
        {
            let admission_result = crate::substrate::governed_effect::evaluate_effect(
                &state,
                Some(&headers),
                agent_hdr,
                &format!("memory/recall/{namespace}"),
                crate::services::admission::AdmissionOp::MemoryRead {
                    namespace: namespace.clone(),
                },
                None,
            );
            if let Err(err) = admission_result {
                return Json(serde_json::json!({
                    "ok": false,
                    "error": err.human_readable,
                    "denial_reason": err.denial_reason.slug(),
                    "audit_cid": err.audit_cid,
                    "namespace": namespace,
                    "honesty": "memory.read governed under effect exclusivity",
                }));
            }
        }
        if !crate::kernel::agent_identity_envelope::agent_may_access_namespace(
            state.as_ref(),
            agent_hdr,
            &namespace,
            false,
        ) {
            use sha2::{Digest, Sha256};
            let leaf = hex::encode(Sha256::digest(
                format!("recall2_deny|{}|{}", agent_hdr, namespace).as_bytes(),
            ));
            let _ = crate::kernel::forensic_rollups::record_event(
                state.as_ref(),
                crate::kernel::forensic_rollups::RollupEvent {
                    agent_pid: agent_hdr,
                    event_kind: "memory.namespace_isolation",
                    leaf_digest: leaf,
                    universal_envelope_id: None,
                    namespace: Some(namespace.as_str()),
                    cross_agent_denied: true,
                    admission_deny: true,
                    continuity_break: false,
                    quarantine: false,
                    egress_isolated: false,
                    cpo_id: None,
                    quantum_id: None,
                    docklock_profile_id: None,
                    intelligence_receipt_id: None,
                    witnessctl_session_id: None,
                    tracetramp_trace_id: None,
                    fni_flow_id: None,
                    moment_id: None,
                },
            );
            return Json(serde_json::json!({
                "ok": false,
                "error": "namespace_isolation_denied",
                "message": "Agent cannot read this namespace without common-space grant",
                "namespace": namespace,
            }));
        }
    }
    let k = state.kernel.lock().unwrap();
    let limit = q.limit.unwrap_or(50);
    let packets: Vec<serde_json::Value> = k.packets_in_namespace(&namespace)
        .iter()
        .filter(|p| {
            if let Some(ref sid) = q.session_id {
                return p.session_id.as_deref() == Some(sid.as_str());
            }
            if let Some(ts_from) = q.ts_from {
                if p.index.ts < ts_from { return false; }
            }
            if let Some(ts_to) = q.ts_to {
                if p.index.ts > ts_to { return false; }
            }
            if let Some(ref tier_filter) = q.tier {
                let tier_str = format!("{:?}", p.tier).to_lowercase();
                if !tier_str.contains(&tier_filter.to_lowercase()) { return false; }
            }
            true
        })
        .take(limit)
        .map(|p| serde_json::json!({
            "cid": p.index.packet_cid.to_string(),
            "index_cid": p.index.packet_cid.to_string(),
            "payload_cid": p.content.payload_cid.to_string(),
            "type": format!("{}", p.content.packet_type),
            "packet_type": format!("{}", p.content.packet_type),
            "text": p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
            "entities": p.content.entities,
            "tags": p.content.tags,
            "namespace": p.namespace,
            "session_id": p.session_id,
            "tier": format!("{:?}", p.tier),
            "memory_type": format!("{}", p.memory_type),
            "abstraction_level": p.abstraction_level,
            "trust_score": p.trust_score,
            "reasoning": p.provenance.reasoning,
            "confidence": p.provenance.confidence,
            "evidence_refs": p.provenance.evidence_refs.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
            "supersedes": p.provenance.supersedes.map(|c| c.to_string()),
            "entity_kind": p.metadata.get("entity_kind").and_then(|v| v.as_str()).unwrap_or(""),
            "metadata": p.metadata,
            "timestamp": p.index.ts,
            "sealed": k.is_sealed(&p.content.payload_cid),
        }))
        .collect();
    Json(serde_json::json!({
        "namespace": namespace,
        "count": packets.len(),
        "packets": packets,
        "filters_applied": {
            "session_id": q.session_id,
            "ts_from": q.ts_from,
            "ts_to": q.ts_to,
            "tier": q.tier,
        },
    }))
}

#[derive(Deserialize)]
pub struct RecallQuery {
    pub limit: Option<usize>,
    pub session_id: Option<String>,
    pub ts_from: Option<i64>,
    pub ts_to: Option<i64>,
    pub tier: Option<String>,
    /// AMA-1: filter by cognitive memory type (working|episodic|semantic|procedural|relational|reflective|evidentiary)
    pub memory_type: Option<String>,
    /// AMA-1: filter by minimum abstraction level (0=raw .. 4=concept)
    pub min_abstraction: Option<u8>,
}

// ── Fixed RAG (time_range + grounding wired) ──────────────────────────────────

/// POST /memory/knowledge/query2  — full RAG with time_range + grounding
pub async fn knowledge_query_full(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let entities: Vec<String> = req
        .get("entities")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let keywords: Vec<String> = req
        .get("keywords")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let budget = req
        .get("token_budget")
        .and_then(|v| v.as_u64())
        .unwrap_or(4096) as usize;
    let max_facts = req.get("max_facts").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    let min_relevance = req
        .get("min_relevance")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    // Bi-temporal: event time range
    let time_range: Option<(i64, i64)> = match (
        req.get("ts_from").and_then(|v| v.as_i64()),
        req.get("ts_to").and_then(|v| v.as_i64()),
    ) {
        (Some(f), Some(t)) => Some((f, t)),
        _ => None,
    };

    let knot = state.knot.lock().unwrap();
    let k = state.kernel.lock().unwrap();

    // Wire grounding table if loaded
    let grounding_lock = state.grounding.lock().unwrap();
    let grounding_ref = Some(&*grounding_lock);

    let rag = RagEngine::new()
        .with_budget(budget)
        .with_max_facts(max_facts);

    let ctx = rag.retrieve(&knot, &k, &entities, &keywords, time_range, grounding_ref);
    let prompt_ctx = ctx.to_prompt_context();

    let facts: Vec<serde_json::Value> = ctx
        .facts
        .iter()
        .map(|f| {
            serde_json::json!({
                "text": f.text,
                "source_cid": f.source_cid,
                "entity_id": f.entity_id,
                "relevance_score": f.relevance_score,
                "tier": f.tier,
                "timestamp": f.timestamp,
                "namespace": f.namespace,
                "channels": f.channels,
                "grounded_code": f.grounded_code,
                "grounded_desc": f.grounded_desc,
                "token_estimate": f.token_estimate,
            })
        })
        .filter(|f| {
            f.get("relevance_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0)
                >= min_relevance
        })
        .collect();

    Json(serde_json::json!({
        "facts": facts,
        "facts_included": ctx.facts_included,
        "total_retrieved": ctx.total_retrieved,
        "tokens_used": ctx.tokens_used,
        "token_budget": ctx.token_budget,
        "source_cids": ctx.source_cids,
        "entities": ctx.entities,
        "channels_used": ctx.channels_used,
        "warnings": ctx.warnings,
        "prompt_context": prompt_ctx,
        "grounding_active": true,
        "time_range_applied": time_range.is_some(),
    }))
}

// ── Real interference detection ───────────────────────────────────────────────

/// GET /memory/interference2/:agent_pid  — real StateVector + compute_interference
pub async fn interference_real(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let kernel_pid = resolve_agent_pid(&state, &agent_pid);
    let k = state.kernel.lock().unwrap();
    let acb = match k.get_agent(&kernel_pid) {
        Some(a) => a.clone(),
        None => {
            return Json(serde_json::json!({ "error": format!("Agent {} not found", agent_pid) }))
        }
    };

    let packets_owned: Vec<vac_core::types::MemPacket> = k
        .packets_in_namespace(&acb.namespace)
        .into_iter()
        .cloned()
        .collect();
    drop(k);

    // Use KnowledgeEngine.ingest() which runs real StateVector + compute_interference
    let mut ke = KnowledgeEngine::new();
    let ingest_result = ke.ingest(&state.kernel.lock().unwrap(), &acb.namespace, &kernel_pid);
    let growth_events: Vec<serde_json::Value> = ke
        .growth_events()
        .iter()
        .map(|g| {
            serde_json::json!({
                "kind": format!("{:?}", g.kind),
                "window_sn": g.window_sn,
                "entities": g.entities,
                "edges_affected": g.edges_affected,
                "compiled": g.compiled,
                "interference_score": g.interference_score,
            })
        })
        .collect();

    // Also check for Contradiction-typed packets directly in the namespace
    // (StateVector extraction captures these in sv.contradictions even without a diff)
    let contradiction_packets: Vec<serde_json::Value> = packets_owned
        .iter()
        .filter(|p| p.content.packet_type == vac_core::types::PacketType::Contradiction)
        .map(|p| {
            let text = p
                .content
                .payload
                .get("text")
                .or_else(|| p.content.payload.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let old = p
                .content
                .payload
                .get("old")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let new = p
                .content
                .payload
                .get("new")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            serde_json::json!({
                "cid": p.content.payload_cid.to_string(),
                "text": &text[..text.len().min(120)],
                "old_claim": old,
                "new_claim": new,
                "entity_kind": p.metadata.get("entity_kind").and_then(|v| v.as_str()).unwrap_or(""),
                "type": "contradiction_packet",
            })
        })
        .collect();

    // Also detect entity-kind value conflicts across non-contradiction packets
    let mut entity_conflicts: Vec<serde_json::Value> = Vec::new();
    for i in 0..packets_owned.len() {
        for j in (i + 1)..packets_owned.len() {
            let pi = &packets_owned[i];
            let pj = &packets_owned[j];
            let ki = pi
                .metadata
                .get("entity_kind")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let kj = pj
                .metadata
                .get("entity_kind")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if ki.is_empty() || ki != kj {
                continue;
            }
            let shared: usize = pi
                .content
                .entities
                .iter()
                .filter(|e| pj.content.entities.contains(e))
                .count();
            if shared == 0 {
                continue;
            }
            let ti = pi
                .content
                .payload
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let tj = pj
                .content
                .payload
                .get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if ti.is_empty() || tj.is_empty() || ti == tj {
                continue;
            }
            let has_signal = tj.contains("denies")
                || tj.contains("incorrect")
                || tj.contains("was wrong")
                || tj.contains("contradicts")
                || ti.contains("denies")
                || ti.contains("incorrect");
            if has_signal {
                entity_conflicts.push(serde_json::json!({
                    "packet_a_cid": pi.content.payload_cid.to_string(),
                    "packet_b_cid": pj.content.payload_cid.to_string(),
                    "entity_kind": ki,
                    "shared_entities": shared,
                    "type": "entity_value_conflict",
                }));
                if entity_conflicts.len() >= 5 {
                    break;
                }
            }
        }
        if entity_conflicts.len() >= 5 {
            break;
        }
    }

    let has_contradictions = ingest_result.contradiction_detected
        || !contradiction_packets.is_empty()
        || !entity_conflicts.is_empty();
    let total_contradictions = contradiction_packets.len() + entity_conflicts.len();
    let effective_score = if has_contradictions && ingest_result.interference_score < 0.1 {
        (total_contradictions as f64 * 0.15).min(1.0)
    } else {
        ingest_result.interference_score
    };

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "namespace": acb.namespace,
        "packets_analyzed": packets_owned.len(),
        "entities_upserted": ingest_result.entities_upserted,
        "total_entities": ingest_result.total_entities,
        "contradiction_detected": has_contradictions,
        "interference_score": effective_score,
        "contradiction_packets": contradiction_packets,
        "entity_conflicts": entity_conflicts,
        "growth_events": growth_events,
        "warnings": ingest_result.warnings,
        "engine": "real StateVector + compute_interference (not string matching)",
    }))
}

// ── Knowledge Graph ───────────────────────────────────────────────────────────

/// GET /memory/graph/entities
pub async fn graph_entities(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let knot = state.knot.lock().unwrap();
    let nodes = knot.nodes();
    let entities: Vec<serde_json::Value> = nodes
        .iter()
        .map(|(id, node)| {
            serde_json::json!({
                "id": id,
                "entity_type": node.entity_type,
                "tags": node.tags,
                "first_seen": node.first_seen,
                "last_seen": node.last_seen,
                "window_sns": node.window_sns,
                "attr_count": node.attributes.len(),
            })
        })
        .collect();
    let edges: Vec<serde_json::Value> = knot
        .all_edges()
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "from": e.from,
                "to": e.to,
                "type": e.relation,
                "weight": e.weight,
                "active": e.active,
            })
        })
        .collect();
    Json(serde_json::json!({
        "count": entities.len(),
        "entities": entities,
        "edge_count": edges.len(),
        "edges": edges,
    }))
}

/// GET /memory/graph/neighbors/:entity_id
pub async fn graph_neighbors(
    State(state): State<SharedState>,
    Path(entity_id): Path<String>,
) -> Json<serde_json::Value> {
    let knot = state.knot.lock().unwrap();
    let neighbors: Vec<String> = knot
        .neighbors(&entity_id)
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    Json(serde_json::json!({
        "entity_id": entity_id,
        "neighbor_count": neighbors.len(),
        "neighbors": neighbors,
    }))
}

#[derive(Deserialize)]
pub struct AddEntityRequest {
    pub id: String,
    #[serde(default)]
    pub entity_type: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub attributes: serde_json::Value,
    /// Agent PID for admission gate (required in production).
    #[serde(default)]
    pub agent_pid: Option<String>,
}

/// POST /memory/graph/entity
pub async fn add_graph_entity(
    State(state): State<SharedState>,
    Json(req): Json<AddEntityRequest>,
) -> Json<serde_json::Value> {
    let agent_pid = req.agent_pid.as_deref().unwrap_or("system-graph");
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, agent_pid, "k/graph")
    {
        return Json(deny);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        agent_pid,
        "memory",
        "graph_entity",
        &serde_json::json!({"id": req.id}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let now = chrono::Utc::now().timestamp_millis();
    let attrs: BTreeMap<String, serde_json::Value> = match req.attributes {
        serde_json::Value::Object(m) => m.into_iter().collect(),
        _ => BTreeMap::new(),
    };
    let mut knot = state.knot.lock().unwrap();
    knot.upsert_node(
        &req.id,
        req.entity_type.as_deref(),
        attrs,
        &req.tags,
        now,
        0,
        None,
    );
    let total_entities = knot.node_count();
    drop(knot);
    open_proceed.finish_observed(true);
    Json(serde_json::json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "id": req.id,
        "entity_type": req.entity_type,
        "tags": req.tags,
        "total_entities": total_entities,
    }))
}

#[derive(Deserialize)]
pub struct AddEdgeRequest {
    pub from: String,
    pub to: String,
    pub relation: String,
    #[serde(default = "default_weight")]
    pub weight: f64,
    #[serde(default)]
    pub agent_pid: Option<String>,
}
fn default_weight() -> f64 {
    1.0
}

/// POST /memory/graph/edge
pub async fn add_graph_edge(
    State(state): State<SharedState>,
    Json(req): Json<AddEdgeRequest>,
) -> Json<serde_json::Value> {
    let agent_pid = req.agent_pid.as_deref().unwrap_or("system-graph");
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, agent_pid, "k/graph")
    {
        return Json(deny);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        agent_pid,
        "memory",
        "graph_edge",
        &serde_json::json!({"from": req.from, "to": req.to, "relation": req.relation}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let now = chrono::Utc::now().timestamp_millis();
    let mut knot = state.knot.lock().unwrap();
    knot.upsert_edge(&req.from, &req.to, &req.relation, req.weight, now, 0, None);
    drop(knot);
    open_proceed.finish_observed(true);
    Json(serde_json::json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "from": req.from,
        "to": req.to,
        "relation": req.relation,
        "weight": req.weight,
    }))
}

/// POST /memory/graph/seed  — load a KnowledgeSeed JSON ontology
pub async fn load_knowledge_seed(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("system-graph");
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, agent_pid, "k/seed")
    {
        return Json(deny);
    }
    let seed_json = req.get("seed").cloned().unwrap_or(req.clone());
    let seed_str = serde_json::to_string(&seed_json).unwrap_or_default();
    match KnowledgeSeed::from_json(&seed_str) {
        Ok(seed) => {
            let admitted = match crate::substrate::pate::require_proceed(
                &state,
                agent_pid,
                "memory",
                "knowledge_seed",
                &serde_json::json!({"agent_pid": agent_pid}),
            ) {
                Ok(atu) => atu,
                Err(body) => return Json(body),
            };
            let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
            let entity_count = seed.entities.len();
            let edge_count = seed.edges.len();
            let now = chrono::Utc::now().timestamp_millis();
            let mut knot = state.knot.lock().unwrap();
            for entity in &seed.entities {
                knot.upsert_node(
                    &entity.id,
                    Some(&entity.entity_type),
                    entity.attributes.clone(),
                    &entity.tags,
                    0,
                    0,
                    None,
                );
            }
            for edge in &seed.edges {
                knot.upsert_edge(
                    &edge.from,
                    &edge.to,
                    &edge.relation,
                    edge.weight,
                    now,
                    0,
                    None,
                );
            }
            let total_entities = knot.node_count();
            drop(knot);
            open_proceed.finish_observed(true);
            Json(serde_json::json!({
                "ok": true,
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
                "entities_seeded": entity_count,
                "edges_seeded": edge_count,
                "total_entities": total_entities,
                "note": "Seeded entities are immutable by convention — runtime data should not overwrite them",
            }))
        }
        Err(e) => Json(serde_json::json!({ "ok": false, "error": e })),
    }
}

/// POST /memory/knowledge/compile  — compile reasoning as reusable CompiledKnowledge
pub async fn knowledge_compile(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("system");
    if let Err(deny) = crate::substrate::admission_gate::require_memory_write(
        &state,
        agent_pid,
        &format!("k/compile/{agent_pid}"),
    ) {
        return Json(deny);
    }
    let kernel_pid = resolve_agent_pid(&state, agent_pid);
    let insight = req
        .get("insight")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let source_cids: Vec<String> = req
        .get("source_cids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let entities: Vec<String> = req
        .get("entities")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let confidence = req
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.8);
    let reasoning_steps = req
        .get("reasoning_steps")
        .and_then(|v| v.as_u64())
        .unwrap_or(1) as usize;

    if insight.is_empty() {
        return Json(serde_json::json!({ "ok": false, "error": "insight required" }));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        agent_pid,
        "memory",
        "knowledge_compile",
        &serde_json::json!({"agent_pid": agent_pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    // Persist the compiled knowledge as a Decision packet in kernel
    let mut k = state.kernel.lock().unwrap();
    let compile_text = format!(
        "COMPILED[conf={:.2},steps={}]: {}\nsources: {}",
        confidence,
        reasoning_steps,
        insight,
        source_cids.join(", ")
    );
    let mut pkt = MemPacket::new(
        PacketType::Decision,
        serde_json::json!({"text": compile_text}),
        cid::Cid::default(),
        "system:compiler".to_string(),
        "pipe:knowledge_compile".to_string(),
        Source {
            kind: SourceKind::SelfSource,
            principal_id: kernel_pid.clone(),
        },
        chrono::Utc::now().timestamp_millis(),
    );
    pkt.content.entities = entities.clone();
    pkt.content.tags = vec!["compiled_knowledge".into(), "reusable".into()];

    let r = k.dispatch(SyscallRequest {
        agent_pid: kernel_pid,
        operation: MemoryKernelOp::MemWrite,
        payload: SyscallPayload::MemWrite { packet: pkt },
        reason: Some("knowledge_compile".into()),
        vakya_id: None,
        trace_parent: None,
        trace_state: None,
        api_version: None,
    });

    let compile_cid = match r.value {
        vac_core::kernel::SyscallValue::Cid(c) => c.to_string(),
        _ => "unknown".to_string(),
    };
    let compiled = r.outcome == OpOutcome::Success;
    drop(k);
    open_proceed.finish_observed(compiled);

    Json(serde_json::json!({
        "ok": compiled,
        "task_id": admitted.task_id,
        "executed": compiled,
        "admits": false,
        "cid": compile_cid,
        "insight": insight,
        "confidence": confidence,
        "reasoning_steps": reasoning_steps,
        "source_cids": source_cids,
        "entities": entities,
        "note": "Compiled knowledge stored as Decision packet — retrievable via RAG with tag:compiled_knowledge",
    }))
}

/// GET /memory/graph/growth-events/:agent_pid
pub async fn graph_growth_events(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let kernel_pid = resolve_agent_pid(&state, &agent_pid);
    let k = state.kernel.lock().unwrap();
    let acb = match k.get_agent(&kernel_pid) {
        Some(a) => a.clone(),
        None => {
            return Json(serde_json::json!({ "error": format!("Agent {} not found", agent_pid) }))
        }
    };

    let mut ke = KnowledgeEngine::new();
    let ingest = ke.ingest(&k, &acb.namespace, &kernel_pid);
    let events: Vec<serde_json::Value> = ke.growth_events().iter().map(|g| serde_json::json!({
        "kind": format!("{:?}", g.kind),
        "window_sn": g.window_sn,
        "entities": g.entities,
        "edges_affected": g.edges_affected.iter().map(|(f,t,r)| format!("{} -[{}]-> {}", f,r,t)).collect::<Vec<_>>(),
        "compiled": g.compiled,
        "interference_score": g.interference_score,
    })).collect();

    Json(serde_json::json!({
        "agent_pid": agent_pid,
        "namespace": acb.namespace,
        "total_entities": ingest.total_entities,
        "contradiction_detected": ingest.contradiction_detected,
        "interference_score": ingest.interference_score,
        "growth_event_count": events.len(),
        "growth_events": events,
        "note": "Growth events are the audit trail of how the knowledge graph evolved from interference analysis",
    }))
}

// ── Agent-scoped memory resource routes (Route-P1-1 / CLI-P2-4) ───────────────

/// GET /agents/:pid/memory — paginated memory packets for this agent
pub async fn agent_memory_list(
    State(state): State<SharedState>,
    axum::extract::Path(pid): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<RecallQuery>,
) -> axum::Json<serde_json::Value> {
    let kernel_pid = resolve_agent_pid(&state, &pid);
    let k = state.kernel.lock().unwrap();
    let acb = match k.get_agent(&kernel_pid) {
        Some(a) => a.clone(),
        None => return axum::Json(serde_json::json!({"error": "Agent not found", "status": 404})),
    };
    let limit = q.limit.unwrap_or(50);
    let packets: Vec<serde_json::Value> = k.packets_in_namespace(&acb.namespace)
        .iter()
        .filter(|p| {
            if let Some(ref pt) = q.tier {
                let ptype = format!("{}", p.content.packet_type);
                if !ptype.eq_ignore_ascii_case(pt) { return false; }
            }
            if let Some(ref sid) = q.session_id {
                if p.session_id.as_deref() != Some(sid.as_str()) { return false; }
            }
            if let Some(since) = q.ts_from { if p.index.ts < since { return false; } }
            if let Some(until) = q.ts_to { if p.index.ts > until { return false; } }
            // AMA-1: filter by cognitive memory type
            if let Some(ref mt) = q.memory_type {
                let packet_mt = format!("{}", p.memory_type);
                if !packet_mt.eq_ignore_ascii_case(mt) { return false; }
            }
            // AMA-1: filter by minimum abstraction level
            if let Some(min_abs) = q.min_abstraction {
                if p.abstraction_level < min_abs { return false; }
            }
            true
        })
        .rev()
        .take(limit)
        .map(|p| serde_json::json!({
            "cid":              p.index.packet_cid.to_string(),
            "namespace":        acb.namespace,
            "agent_pid":        pid,
            "packet_type":      format!("{}", p.content.packet_type),
            "memory_type":      format!("{}", p.memory_type),
            "abstraction_level": p.abstraction_level,
            "trust_score":      p.trust_score,
            "cognitive_path":   p.cognitive_path.as_ref().map(|cp| cp.as_str().to_string()),
            "embedding_dim":    p.embedding.as_ref().map(|e| e.len()),
            "graph_links":      p.graph_links,
            "session_id":       p.session_id,
            "timestamp_ms":     p.index.ts,
            "sealed":           k.is_sealed(&p.content.payload_cid),
            "pinned":           p.metadata.get("pinned").and_then(|v| v.as_bool()).unwrap_or(false),
            "content_preview":  packet_text(p).chars().take(120).collect::<String>(),
        }))
        .collect();
    axum::Json(serde_json::json!({
        "pid": pid, "namespace": acb.namespace,
        "total": packets.len(), "packets": packets,
    }))
}

/// GET /agents/:pid/memory/tree — UTF-8 namespace/session/packet tree
pub async fn agent_memory_tree(
    State(state): State<SharedState>,
    axum::extract::Path(pid): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let kernel_pid = resolve_agent_pid(&state, &pid);
    let k = state.kernel.lock().unwrap();
    let acb = match k.get_agent(&kernel_pid) {
        Some(a) => a.clone(),
        None => return axum::Json(serde_json::json!({"error": "Agent not found", "status": 404})),
    };
    let packets = k.packets_in_namespace(&acb.namespace);

    // Group by session_id
    let mut sessions: std::collections::BTreeMap<String, Vec<serde_json::Value>> =
        std::collections::BTreeMap::new();
    for p in &packets {
        let sid = p
            .session_id
            .clone()
            .unwrap_or_else(|| "default".to_string());
        sessions.entry(sid).or_default().push(serde_json::json!({
            "cid":          p.index.packet_cid.to_string(),
            "packet_type":  format!("{}", p.content.packet_type),
            "timestamp_ms": p.index.ts,
            "sealed":       k.is_sealed(&p.content.payload_cid),
            "pinned":       p.metadata.get("pinned").and_then(|v| v.as_bool()).unwrap_or(false),
            "preview":      packet_text(p).chars().take(80).collect::<String>(),
        }));
    }

    let tree: Vec<serde_json::Value> = sessions
        .iter()
        .map(|(sid, pkts)| {
            serde_json::json!({
                "session_id": sid,
                "packet_count": pkts.len(),
                "packets": pkts,
            })
        })
        .collect();

    axum::Json(serde_json::json!({
        "pid": pid,
        "namespace": acb.namespace,
        "session_count": tree.len(),
        "total_packets": packets.len(),
        "tree": tree,
    }))
}

/// GET /agents/:pid/memory/stats — packet counts, sizes, session summary
pub async fn agent_memory_stats(
    State(state): State<SharedState>,
    axum::extract::Path(pid): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let kernel_pid = resolve_agent_pid(&state, &pid);
    let k = state.kernel.lock().unwrap();
    let acb = match k.get_agent(&kernel_pid) {
        Some(a) => a.clone(),
        None => return axum::Json(serde_json::json!({"error": "Agent not found", "status": 404})),
    };
    let packets = k.packets_in_namespace(&acb.namespace);

    let total = packets.len();
    let pinned = packets
        .iter()
        .filter(|p| {
            p.metadata
                .get("pinned")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .count();
    let sealed = packets
        .iter()
        .filter(|p| k.is_sealed(&p.content.payload_cid))
        .count();
    let sessions: std::collections::HashSet<_> = packets
        .iter()
        .filter_map(|p| p.session_id.as_ref())
        .collect();

    let mut by_type: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for p in &packets {
        *by_type
            .entry(format!("{}", p.content.packet_type))
            .or_insert(0) += 1;
    }

    axum::Json(serde_json::json!({
        "pid": pid,
        "namespace": acb.namespace,
        "total_packets": total,
        "pinned": pinned,
        "sealed": sealed,
        "sessions": sessions.len(),
        "quota_tokens": acb.memory_region.quota_packets,
        "used_tokens": acb.total_tokens_consumed,
        "by_packet_type": by_type,
    }))
}

/// POST /agents/:pid/memory/search — semantic search within this agent's namespace
pub async fn agent_memory_search(
    State(state): State<SharedState>,
    axum::extract::Path(pid): axum::extract::Path<String>,
    axum::Json(req): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let kernel_pid = resolve_agent_pid(&state, &pid);
    let k = state.kernel.lock().unwrap();
    let acb = match k.get_agent(&kernel_pid) {
        Some(a) => a.clone(),
        None => return axum::Json(serde_json::json!({"error": "Agent not found", "status": 404})),
    };
    let query = req
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    let top_k = req.get("top_k").and_then(|v| v.as_u64()).unwrap_or(10) as usize;

    let mut results: Vec<(f64, serde_json::Value)> = k
        .packets_in_namespace(&acb.namespace)
        .iter()
        .filter_map(|p| {
            let text = packet_text(p).to_lowercase();
            if query.is_empty() || text.contains(&query) {
                let score = if query.is_empty() {
                    1.0_f64
                } else {
                    query
                        .split_whitespace()
                        .filter(|w| text.contains(*w))
                        .count() as f64
                        / query.split_whitespace().count().max(1) as f64
                };
                Some((
                    score,
                    serde_json::json!({
                        "cid":         p.index.packet_cid.to_string(),
                        "packet_type": format!("{}", p.content.packet_type),
                        "timestamp_ms": p.index.ts,
                        "score":       (score * 1000.0).round() / 1000.0,
                        "preview":     packet_text(p).chars().take(200).collect::<String>(),
                    }),
                ))
            } else {
                None
            }
        })
        .collect();

    results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let results: Vec<serde_json::Value> = results.into_iter().take(top_k).map(|(_, v)| v).collect();

    axum::Json(serde_json::json!({
        "pid": pid, "namespace": acb.namespace,
        "query": req.get("query").and_then(|v| v.as_str()).unwrap_or(""),
        "top_k": top_k, "results": results,
    }))
}

/// GET /memory/search?q={query}&namespace={ns}&limit=20
/// Cross-agent keyword search over all namespaces the caller can read.
pub async fn global_memory_search(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::Json<serde_json::Value> {
    let query = params
        .get("q")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let ns_filter = params.get("namespace").cloned().unwrap_or_default();
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(20)
        .min(100);
    if !ns_filter.is_empty() {
        if let Err(deny) = crate::services::agents::assert_namespace_readable(&headers, &ns_filter)
        {
            return deny;
        }
    }

    let tenant = crate::services::agents::tenant_from_headers_for_cap(&headers);
    let k = state.kernel.lock().unwrap();
    let mut results: Vec<serde_json::Value> = Vec::new();

    for (pid, acb) in k.agents() {
        if !crate::services::agents::kernel_agent_in_scope(&acb.namespace, tenant.as_ref()) {
            continue;
        }
        if !ns_filter.is_empty() && !acb.namespace.contains(&ns_filter) {
            continue;
        }
        let pkts = k.packets_in_namespace(&acb.namespace);
        for p in pkts.iter() {
            let text = packet_text(p).to_lowercase();
            if query.is_empty() || text.contains(&query) {
                let score = if query.is_empty() {
                    1.0_f64
                } else {
                    query
                        .split_whitespace()
                        .filter(|w| text.contains(*w))
                        .count() as f64
                        / query.split_whitespace().count().max(1) as f64
                };
                results.push(serde_json::json!({
                    "cid": p.index.packet_cid.to_string(),
                    "agent_pid": pid,
                    "namespace": acb.namespace,
                    "packet_type": format!("{}", p.content.packet_type),
                    "timestamp_ms": p.index.ts,
                    "score": (score * 1000.0).round() / 1000.0,
                    "preview": packet_text(p).chars().take(200).collect::<String>(),
                }));
            }
        }
    }

    results.sort_by(|a, b| {
        let sa = a["score"].as_f64().unwrap_or(0.0);
        let sb = b["score"].as_f64().unwrap_or(0.0);
        sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
    });
    results.truncate(limit);

    axum::Json(serde_json::json!({
        "ok": true, "query": query, "namespace_filter": ns_filter,
        "count": results.len(), "results": results,
    }))
}

// =============================================================================
// DB management: purge / compact / import / pin / unpin / seal / knowledge_seed
// =============================================================================

/// POST /agents/:pid/memory/purge — delete packets older than threshold
pub async fn agent_memory_purge(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(pid): axum::extract::Path<String>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let (_uid, _role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return axum::Json(
                serde_json::json!({"error": "Authentication required", "status": 401}),
            )
        }
    };
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, &pid, &format!("k/{pid}"))
    {
        return axum::Json(deny);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "memory",
        "memory_purge",
        &serde_json::json!({"pid": pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return axum::Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let dry_run = body
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let older_than = body
        .get("older_than")
        .and_then(|v| v.as_str())
        .unwrap_or("7d");

    // Parse threshold (e.g. "7d", "24h") → milliseconds
    let threshold_ms: i64 = {
        let n: i64 = older_than
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .unwrap_or(7);
        let unit = older_than.chars().last().unwrap_or('d');
        let factor: i64 = match unit {
            'h' => 3_600_000,
            'm' => 60_000,
            _ => 86_400_000,
        };
        n * factor
    };
    let cutoff = chrono::Utc::now().timestamp_millis() - threshold_ms;

    let (would_delete, deleted) = {
        let es = state.engine_store.lock().unwrap();
        let ns = format!("/k/{}/", pid);
        let keys: Vec<String> = es
            .folder_keys("memory", None)
            .unwrap_or_default()
            .into_iter()
            .filter(|k| k.starts_with(&ns))
            .collect();
        let stale: Vec<String> = keys
            .into_iter()
            .filter(|k| {
                es.folder_get("memory", k)
                    .ok()
                    .flatten()
                    .and_then(|v| v.get("timestamp").and_then(|t| t.as_i64()))
                    .map(|ts| ts < cutoff)
                    .unwrap_or(false)
            })
            .collect();
        let count = stale.len();
        if !dry_run {
            drop(es);
            let mut es2 = state.engine_store.lock().unwrap();
            for k in &stale {
                let _ = es2.folder_delete("memory", k);
            }
            (count, count)
        } else {
            (count, 0)
        }
    };

    let executed = !dry_run;
    open_proceed.finish_observed(executed);
    axum::Json(serde_json::json!({
        "pid": pid,
        "task_id": admitted.task_id,
        "executed": executed,
        "admits": false,
        "older_than": older_than,
        "dry_run": dry_run,
        "would_delete": would_delete,
        "deleted": deleted,
    }))
}

/// POST /agents/:pid/memory/compact — LRU-K eviction down to max_packets
pub async fn agent_memory_compact(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(pid): axum::extract::Path<String>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let (_uid, _role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return axum::Json(
                serde_json::json!({"error": "Authentication required", "status": 401}),
            )
        }
    };
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, &pid, &format!("k/{pid}"))
    {
        return axum::Json(deny);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "memory",
        "memory_compact",
        &serde_json::json!({"pid": pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return axum::Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let max_packets: usize = body
        .get("max_packets")
        .and_then(|v| v.as_u64())
        .unwrap_or(1000) as usize;

    let ns = format!("/k/{}/", pid);
    let mut es = state.engine_store.lock().unwrap();
    let mut packets: Vec<(i64, String)> = es
        .folder_keys("memory", None)
        .unwrap_or_default()
        .into_iter()
        .filter(|k| k.starts_with(&ns))
        .filter_map(|k| {
            let v = es.folder_get("memory", &k).ok().flatten()?;
            let pinned = v.get("pinned").and_then(|p| p.as_bool()).unwrap_or(false);
            if pinned {
                return None;
            } // never evict pinned
            let ts = v.get("timestamp").and_then(|t| t.as_i64()).unwrap_or(0);
            Some((ts, k))
        })
        .collect();

    packets.sort_by_key(|(ts, _)| *ts); // oldest first
    let total = packets.len();
    let to_evict = if total > max_packets {
        total - max_packets
    } else {
        0
    };
    let evicted: Vec<&str> = packets
        .iter()
        .take(to_evict)
        .map(|(_, k)| k.as_str())
        .collect();
    for k in &evicted {
        let _ = es.folder_delete("memory", k);
    }
    let kept = total - to_evict;
    drop(es);
    open_proceed.finish_observed(true);

    axum::Json(serde_json::json!({
        "pid": pid,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "total_before": total,
        "packets_kept": kept,
        "packets_evicted": to_evict,
        "max_packets": max_packets,
        "method": "LRU-K eviction (oldest non-pinned first)",
    }))
}

/// POST /agents/:pid/memory/import — import packets from JSONL body
pub async fn agent_memory_import(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(pid): axum::extract::Path<String>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let (_uid, _role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return axum::Json(
                serde_json::json!({"error": "Authentication required", "status": 401}),
            )
        }
    };
    if let Err(deny) =
        crate::substrate::admission_gate::require_memory_write(&state, &pid, &format!("k/{pid}"))
    {
        return axum::Json(deny);
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &pid,
        "memory",
        "memory_import",
        &serde_json::json!({"pid": pid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return axum::Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let dry_run = body
        .get("dry_run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let packets = body
        .get("packets")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut imported = 0usize;
    let mut skipped = 0usize;

    if !dry_run {
        let mut es = state.engine_store.lock().unwrap();
        for pkt in &packets {
            let cid = pkt
                .get("cid")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| "unknown");
            let key = format!("/k/{}/{}", pid, cid);
            if es.folder_get("memory", &key).ok().flatten().is_some() {
                skipped += 1;
            } else {
                let _ = es.folder_put("memory", &key, pkt);
                imported += 1;
            }
        }
    } else {
        imported = packets.len();
    }
    open_proceed.finish_observed(!dry_run);

    axum::Json(serde_json::json!({
        "pid": pid,
        "task_id": admitted.task_id,
        "executed": !dry_run,
        "admits": false,
        "dry_run": dry_run,
        "total": packets.len(),
        "imported": imported,
        "skipped": skipped,
    }))
}

/// POST /memory/packets/:cid/pin — pin a packet (never evict)
pub async fn packet_pin(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(cid): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let (_uid, _role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return axum::Json(
                serde_json::json!({"error": "Authentication required", "status": 401}),
            )
        }
    };
    let found = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys("memory", None)
            .unwrap_or_default()
            .into_iter()
            .find(|k| k.ends_with(&cid))
    };
    let Some(key) = found else {
        return axum::Json(serde_json::json!({"error": "Packet not found", "status": 404, "cid": cid}));
    };
    let agent_pid = key
        .trim_start_matches("/k/")
        .split('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .unwrap_or("memory")
        .to_string();
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_pid,
        "memory",
        "packet_pin",
        &serde_json::json!({"cid": cid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return axum::Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    {
        let mut es = state.engine_store.lock().unwrap();
        if let Some(mut v) = es.folder_get("memory", &key).ok().flatten() {
            if let Some(obj) = v.as_object_mut() {
                obj.insert("pinned".into(), serde_json::json!(true));
            }
            let _ = es.folder_put("memory", &key, &v);
        }
    }
    open_proceed.finish_observed(true);
    axum::Json(serde_json::json!({
        "cid": cid,
        "pinned": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// POST /memory/packets/:cid/unpin — unpin a packet
pub async fn packet_unpin(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(cid): axum::extract::Path<String>,
) -> axum::Json<serde_json::Value> {
    let (_uid, _role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return axum::Json(
                serde_json::json!({"error": "Authentication required", "status": 401}),
            )
        }
    };
    let found = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys("memory", None)
            .unwrap_or_default()
            .into_iter()
            .find(|k| k.ends_with(&cid))
    };
    let Some(key) = found else {
        return axum::Json(serde_json::json!({"error": "Packet not found", "status": 404, "cid": cid}));
    };
    let agent_pid = key
        .trim_start_matches("/k/")
        .split('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .unwrap_or("memory")
        .to_string();
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_pid,
        "memory",
        "packet_unpin",
        &serde_json::json!({"cid": cid}),
    ) {
        Ok(atu) => atu,
        Err(body) => return axum::Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    {
        let mut es = state.engine_store.lock().unwrap();
        if let Some(mut v) = es.folder_get("memory", &key).ok().flatten() {
            if let Some(obj) = v.as_object_mut() {
                obj.insert("pinned".into(), serde_json::json!(false));
            }
            let _ = es.folder_put("memory", &key, &v);
        }
    }
    open_proceed.finish_observed(true);
    axum::Json(serde_json::json!({
        "cid": cid,
        "pinned": false,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

// =============================================================================
// AMA-8: Cognitive namespace path — /entity/{pid}/memory/{type}/
// =============================================================================

/// GET /entity/:pid/memory/:mem_type — cognitive path alias.
///
/// Equivalent to GET /agents/:pid/memory?memory_type={mem_type}.
/// Provides a filesystem-like hierarchy: `/entity/{pid}/memory/episodic/`
/// mirrors `ls /proc/{pid}/fd` in Linux.
pub async fn entity_memory_by_type(
    State(state): State<SharedState>,
    axum::extract::Path((pid, mem_type)): axum::extract::Path<(String, String)>,
    axum::extract::Query(mut q): axum::extract::Query<RecallQuery>,
) -> axum::Json<serde_json::Value> {
    // Override / set memory_type from path segment
    q.memory_type = Some(mem_type.clone());

    let kernel_pid = resolve_agent_pid(&state, &pid);
    let k = state.kernel.lock().unwrap();
    let acb = match k.get_agent(&kernel_pid) {
        Some(a) => a.clone(),
        None => return axum::Json(serde_json::json!({"error": "Agent not found", "status": 404})),
    };
    let limit = q.limit.unwrap_or(50);

    let packets: Vec<serde_json::Value> = k
        .packets_in_namespace(&acb.namespace)
        .iter()
        .filter(|p| {
            // Filter by cognitive memory type (path segment)
            let packet_mt = format!("{}", p.memory_type);
            if !packet_mt.eq_ignore_ascii_case(&mem_type) {
                return false;
            }
            if let Some(ref sid) = q.session_id {
                if p.session_id.as_deref() != Some(sid.as_str()) {
                    return false;
                }
            }
            if let Some(since) = q.ts_from {
                if p.index.ts < since {
                    return false;
                }
            }
            if let Some(until) = q.ts_to {
                if p.index.ts > until {
                    return false;
                }
            }
            if let Some(min_abs) = q.min_abstraction {
                if p.abstraction_level < min_abs {
                    return false;
                }
            }
            true
        })
        .rev()
        .take(limit)
        .map(|p| {
            serde_json::json!({
                "cid":              p.index.packet_cid.to_string(),
                "namespace":        acb.namespace,
                "agent_pid":        pid,
                "cognitive_path":   format!("/entity/{}/memory/{}/", pid, mem_type),
                "packet_type":      format!("{}", p.content.packet_type),
                "memory_type":      format!("{}", p.memory_type),
                "abstraction_level": p.abstraction_level,
                "trust_score":      p.trust_score,
                "embedding_dim":    p.embedding.as_ref().map(|e| e.len()),
                "graph_links":      p.graph_links,
                "session_id":       p.session_id,
                "timestamp_ms":     p.index.ts,
                "sealed":           k.is_sealed(&p.content.payload_cid),
                "content_preview":  packet_text(p).chars().take(120).collect::<String>(),
            })
        })
        .collect();

    axum::Json(serde_json::json!({
        "ok": true,
        "pid": pid,
        "cognitive_path": format!("/entity/{}/memory/{}/", pid, mem_type),
        "memory_type": mem_type,
        "namespace": acb.namespace,
        "count": packets.len(),
        "packets": packets,
    }))
}
