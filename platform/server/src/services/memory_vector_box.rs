//! Lift VAC MemPackets into MemoryVectorBox for inspect / analyse / play.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use vac_core::types::MemPacket;

use crate::state::SharedState;

fn packet_cid_str(p: &MemPacket) -> String {
    p.index.packet_cid.to_string()
}

fn packet_type_str(p: &MemPacket) -> String {
    format!("{:?}", p.content.packet_type).to_ascii_lowercase()
}

fn actor_of(p: &MemPacket) -> String {
    p.authority
        .actor
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| p.subject_id.clone())
}

/// Lift a kernel MemPacket into the universal vector box.
pub fn lift_mem_packet(packet: &MemPacket, identity_key: &str) -> connector_trust::MemoryVectorBox {
    let cid = packet_cid_str(packet);
    let ptype = packet_type_str(packet);
    let predicate = packet
        .content
        .tags
        .first()
        .cloned()
        .unwrap_or_else(|| "memory".into());
    let subject = if packet.subject_id.is_empty() {
        identity_key
    } else {
        packet.subject_id.as_str()
    };

    let identity = packet
        .metadata
        .get("identity_key")
        .and_then(|v| v.as_str())
        .unwrap_or(identity_key);

    let mut box_ = connector_trust::MemoryVectorBox::from_parts(
        &ptype,
        subject,
        &predicate,
        &cid,
        packet.index.ts,
        identity,
        connector_trust::MemoryRawPlane {
            packet_type: ptype.clone(),
            payload: packet.content.payload.clone(),
            payload_cid: Some(packet.content.payload_cid.to_string()),
            tags: packet.content.tags.clone(),
            encoding: packet.content.encoding.clone(),
        },
        connector_trust::MemoryLogPlane {
            actor: packet.authority.actor.clone(),
            source_kind: Some(format!("{:?}", packet.provenance.source.kind)),
            trust_tier: Some(packet.provenance.trust_tier),
            capability_ref: packet.authority.capability_ref.clone(),
            policy_ref: packet.authority.policy_ref.clone(),
            evidence_refs: packet
                .provenance
                .evidence_refs
                .iter()
                .map(|c| c.to_string())
                .collect(),
            vakya_id: packet.authority.vakya_id.clone(),
            audit_cid: None,
            admission_ticket_id: packet
                .metadata
                .get("admission_ticket_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        },
    );

    // Prefer kernel-written super_key / prolly_key when present (MemWrite path).
    if let Some(sk) = packet
        .metadata
        .get("super_key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        box_.super_key = sk.to_string();
    } else if !packet.index.prolly_key.is_empty() {
        if let Ok(sk) = std::str::from_utf8(&packet.index.prolly_key) {
            box_.super_key = sk.to_string();
        }
    }

    box_.namespace = packet.namespace.clone();
    box_.session_id = packet.session_id.clone();
    box_.embedding = packet.embedding.clone();
    box_.graph_links = packet.graph_links.clone();
    box_.memory_type = Some(format!("{:?}", packet.memory_type).to_ascii_lowercase());
    box_
}

#[derive(Deserialize)]
pub struct VectorBoxQuery {
    pub agent_pid: Option<String>,
    pub namespace: Option<String>,
    pub limit: Option<usize>,
}

/// GET /memory/vector-box — list vector boxes for an agent/namespace.
pub async fn list_vector_boxes(
    State(state): State<SharedState>,
    Query(q): Query<VectorBoxQuery>,
) -> Json<serde_json::Value> {
    let limit = q.limit.unwrap_or(50).min(500);
    let agent = q.agent_pid.unwrap_or_else(|| "system".into());
    let ns_filter = q.namespace;

    let k = state.kernel.lock().unwrap();
    let mut boxes = Vec::new();
    for p in k.all_packets() {
        if let Some(ref ns) = ns_filter {
            if p.namespace.as_deref() != Some(ns.as_str()) {
                continue;
            }
        } else {
            let actor = actor_of(p);
            let ns_ok = p
                .namespace
                .as_deref()
                .map(|n| n.contains(&agent))
                .unwrap_or(false);
            if actor != agent && p.subject_id != agent && !ns_ok {
                continue;
            }
        }
        boxes.push(lift_mem_packet(p, &agent));
        if boxes.len() >= limit {
            break;
        }
    }

    Json(serde_json::json!({
        "ok": true,
        "count": boxes.len(),
        "identity_key": agent,
        "boxes": boxes,
        "contract": "connector.memory_vector_box.v2",
    }))
}

/// GET /memory/vector-box/:cid — single box by CID (play surface).
pub async fn get_vector_box(
    State(state): State<SharedState>,
    Path(cid): Path<String>,
) -> Json<serde_json::Value> {
    let k = state.kernel.lock().unwrap();
    let packet = match cid::Cid::try_from(cid.as_str()) {
        Ok(c) => k.get_packet(&c),
        Err(_) => k
            .all_packets()
            .into_iter()
            .find(|p| packet_cid_str(p) == cid),
    };
    match packet {
        Some(p) => {
            let identity = actor_of(p);
            let box_ = lift_mem_packet(p, &identity);
            Json(serde_json::json!({
                "ok": true,
                "box": box_,
                "play": {
                    "super_key": box_.super_key,
                    "identity_key": box_.identity_key,
                    "cid": box_.cid,
                    "timestamp_ms": box_.timestamp_ms,
                    "raw_preview": box_.raw.payload,
                    "log": box_.log,
                }
            }))
        }
        None => Json(serde_json::json!({
            "ok": false,
            "error": format!("packet cid '{}' not found", cid),
        })),
    }
}

/// GET /memory/data-context/:agent_pid — assemble data context from boxes + graph links.
pub async fn get_data_context(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<serde_json::Value> {
    let mut ctx =
        connector_trust::DataContextContainer::new(format!("ctx_{agent_pid}"), agent_pid.clone());

    {
        let k = state.kernel.lock().unwrap();
        for p in k.all_packets().into_iter().take(100) {
            let actor = actor_of(p);
            let ns_ok = p
                .namespace
                .as_deref()
                .map(|n| n.contains(&agent_pid))
                .unwrap_or(false);
            if actor != agent_pid && p.subject_id != agent_pid && !ns_ok {
                continue;
            }
            let box_ = lift_mem_packet(p, &agent_pid);
            if matches!(
                format!("{:?}", p.memory_type).to_ascii_lowercase().as_str(),
                "relational"
            ) {
                ctx.relational.push(connector_trust::RelationalContainer {
                    container_id: format!("rel_{}", box_.cid),
                    identity_key: agent_pid.clone(),
                    super_key: Some(box_.super_key.clone()),
                    member_super_keys: vec![box_.super_key.clone()],
                    member_cids: vec![box_.cid.clone()],
                    edges: box_
                        .graph_links
                        .iter()
                        .map(|g| connector_trust::data_context::IdentityGraphEdgeRef {
                            from_node_id: box_.cid.clone(),
                            to_node_id: g.clone(),
                            relation: "graph_link".into(),
                            evidence_cid: Some(box_.cid.clone()),
                        })
                        .collect(),
                    contract_version: 2,
                });
            }
            for link in &box_.graph_links {
                ctx.graph_edges
                    .push(connector_trust::data_context::IdentityGraphEdgeRef {
                        from_node_id: box_.cid.clone(),
                        to_node_id: link.clone(),
                        relation: "graph_link".into(),
                        evidence_cid: Some(box_.cid.clone()),
                    });
            }
            ctx.graph_nodes.push(connector_trust::IdentityGraphNodeRef {
                node_id: box_.cid.clone(),
                label: Some(box_.super_key.clone()),
                kinds: vec![box_.memory_type.clone().unwrap_or_else(|| "memory".into())],
                identity_key: Some(agent_pid.clone()),
                packet_cids: vec![box_.cid.clone()],
            });
            ctx.boxes.push(box_);
        }
    }

    Json(serde_json::json!({
        "ok": true,
        "context": ctx,
        "contract": "connector.data_context.v2",
    }))
}
