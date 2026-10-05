//! **CNP (Connector Native Protocol)** — control-plane surface for the 7-layer native stack.
//!
//! Exposes spec + constants from `connector-engine::cnp` so operators see the same types the
//! OSS stack implements. MCP/A2A remain **bridges**; CNP is the spine.

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;

use crate::state::SharedState;
use connector_engine::cnp::types::{
    ActuationCommand, CnpPayload,
    CNP_ACK_TIMEOUT_MS, CNP_DEFAULT_CIPHER, CNP_DEFAULT_PORT_BUFFER, CNP_DEFAULT_TTL_MS,
    CNP_MAX_DELEGATION_DEPTH, CNP_MAX_INLINE_BYTES, CNP_MAX_KNOWLEDGE_ITEMS, CNP_MAX_MESSAGE_BYTES,
    CNP_MAX_NEGOTIATION_ROUNDS, CNP_MAX_RETRIES, CNP_MAX_TENSION_BATCH, CNP_NEGOTIATION_TTL_MS,
    CNP_NONCE_WINDOW_MS,
};
use connector_engine::cnp::{CnpLayer, CnpPortType, CnpVersion};

fn cnp_layers_catalog() -> serde_json::Value {
    let rows: Vec<(CnpLayer, &'static str, String)> = vec![
        (
            CnpLayer::L1Codec,
            "L1 — Content codec",
            "DAG-CBOR framing, SHA-256 content IDs; abjective wire plane.".to_string(),
        ),
        (
            CnpLayer::L2Transport,
            "L2 — Encrypted transport",
            "Length-prefixed TCP frames (CNP1) on CONNECTOR_CNP_BIND. QUIC/mTLS product path is not live.".to_string(),
        ),
        (
            CnpLayer::L3Security,
            "L3 — Port security",
            "HMAC, anti-replay, TTL, rate limits on port traffic.".to_string(),
        ),
        (
            CnpLayer::L4Channel,
            "L4 — Typed ports",
            "MemoryShare, ToolDelegate, EventStream, RequestResponse, Broadcast, Pipeline."
                .to_string(),
        ),
        (
            CnpLayer::L5Routing,
            "L5 — Cross-cell routing",
            "Static 1-hop when CONNECTOR_CNP_PEERS is set; inbound forward when to≠local. No multi-hop mesh.".to_string(),
        ),
        (
            CnpLayer::L6Contract,
            "L6 — Intent & contracts",
            "Negotiation rounds, knowledge exchange, gateway semantics.".to_string(),
        ),
        (
            CnpLayer::L7Cognitive,
            "L7 — Cognitive exchange",
            "Structured tensions, commitments, plans — subjective agent plane.".to_string(),
        ),
    ];
    let v: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(layer, title, summary)| {
            json!({
                "layer": serde_json::to_value(layer).unwrap_or(json!(format!("{:?}", layer))),
                "title": title,
                "summary": summary,
            })
        })
        .collect();
    json!(v)
}

fn cnp_port_types_catalog() -> serde_json::Value {
    let types = vec![
        CnpPortType::MemoryShare,
        CnpPortType::ToolDelegate,
        CnpPortType::EventStream,
        CnpPortType::RequestResponse,
        CnpPortType::Broadcast,
        CnpPortType::Pipeline,
    ];
    json!(types
        .into_iter()
        .map(|p| serde_json::to_value(p).unwrap_or(json!(format!("{:?}", p))))
        .collect::<Vec<_>>())
}

/// Primary wire payload variants (`CnpPayload` discriminant names).
fn cnp_payload_kinds() -> serde_json::Value {
    json!([
        "raw",
        "sensor",
        "actuation",
        "tensor",
        "packet_share",
        "tool_grant",
        "event",
        "request",
        "response",
        "pipeline_handoff",
        "cognitive",
        "knowledge_request",
        "knowledge_response",
        "negotiation",
        "text"
    ])
}

fn cnp_constants() -> serde_json::Value {
    json!({
        "wire_version": format!("{}", CnpVersion::CURRENT),
        "cnp_default_ttl_ms": CNP_DEFAULT_TTL_MS,
        "cnp_max_message_bytes": CNP_MAX_MESSAGE_BYTES,
        "cnp_max_inline_bytes": CNP_MAX_INLINE_BYTES,
        "cnp_default_cipher": CNP_DEFAULT_CIPHER,
        "cnp_nonce_window_ms": CNP_NONCE_WINDOW_MS,
        "cnp_default_port_buffer": CNP_DEFAULT_PORT_BUFFER,
        "cnp_max_delegation_depth": CNP_MAX_DELEGATION_DEPTH,
        "cnp_max_retries": CNP_MAX_RETRIES,
        "cnp_ack_timeout_ms": CNP_ACK_TIMEOUT_MS,
        "cnp_max_negotiation_rounds": CNP_MAX_NEGOTIATION_ROUNDS,
        "cnp_negotiation_ttl_ms": CNP_NEGOTIATION_TTL_MS,
        "cnp_max_tension_batch": CNP_MAX_TENSION_BATCH,
        "cnp_max_knowledge_items": CNP_MAX_KNOWLEDGE_ITEMS,
    })
}

/// Live mesh snapshot: ties **this** cell + kernel to CNP L5/L4 operator view.
pub fn cnp_mesh_snapshot(state: &SharedState) -> serde_json::Value {
    let (kernel_agents, packets, audits) = {
        let k = state.kernel.lock().unwrap();
        (k.agent_count(), k.packet_count(), k.audit_log().len())
    };
    let (knot_sn, knot_nodes) = {
        let knot = state.knot.lock().unwrap();
        (knot.last_ingest_sn, knot.node_count())
    };
    let local_cell_id = state.storage_layout.cell_id.clone();
    let geo_id = crate::services::mesh_status::local_geo_id();
    let region = crate::services::mesh_status::cell_region();

    json!({
        "native_protocol": "CNP",
        "local_cell_id": local_cell_id,
        "geo_id": geo_id,
        "region": region,
        "role": if crate::cnp::wire::l5_static_routing_live() {
            "Sovereign cell. CNP L2 TCP + L5 static 1-hop routing live via CONNECTOR_CNP_PEERS. No multi-hop mesh, mTLS product, or agent migration."
        } else {
            "Sovereign cell. CNP L2 TCP on CONNECTOR_CNP_BIND. Set CONNECTOR_CNP_PEERS for L5 static routes. Agent state does not replicate."
        },
        "live_kernel": {
            "registered_agents": kernel_agents,
            "packets_indexed": packets,
            "audit_entries": audits,
        },
        "knot_stability": {
            "last_ingest_serial": knot_sn,
            "knowledge_entities": knot_nodes,
            "note": "Serialised graph ingest complements CNP message ordering for cross-agent knowledge.",
        },
        "bridge_map": {
            "cnp": "Native (connector-engine::cnp) — sessions, ports, stack",
            "mcp": "External tool bridge — POST /api/v1/protocols/mcp/*, kernel ToolDispatch",
            "a2a": {
                "bridge": "Cross-vendor tasks — POST /api/v1/protocols/a2a/*",
                "sot": "connector.fabric.task.v2",
                "cnp_layers": "A2A TaskState maps to CNP L6 contract + L7 cognitive (see fabric_task::cnp_layer_semantics)",
                "machine_tasks": "CONP EntityId + intelligence mark + grant_id required",
            },
            "acp_anp_ap2": "ACP / ANP / AP2 — /api/v1/protocols/acp|anp|ap2/*",
        },
        "operator_routes": {
            "cnp_overview": "GET /api/v1/cnp/overview",
            "cnp_send": "POST /api/v1/cnp/send",
            "cnp_actuation": "POST /api/v1/cnp/actuation",
            "cnp_messages": "POST /api/v1/cnp/messages",
            "cnp_inbox": "GET /api/v1/cnp/inbox",
            "cnp_wire": "GET /api/v1/cnp/wire",
            "topology_mesh": "GET /api/v1/topology/center",
            "memory_plane": "GET /api/v1/memory/plane/overview",
        },
    })
}

/// GET /cnp/overview — full protocol catalog for dashboards and codegen.
pub async fn get_cnp_overview(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let mesh = cnp_mesh_snapshot(&state);
    let mtls_honesty = crate::cnp::stack::security::cnp_mtls_honesty();
    let mtls_stub = crate::cnp::stack::security::cnp_mtls_stub_allowed();
    Json(json!({
        "ok": true,
        "data": {
            "name": "CNP",
            "full_name": "Connector Native Protocol",
            "summary": "Low-level, OSS-native 7-layer stack: codec → transport → security → ports → cross-cell routing → contracts → cognitive exchange. Superset of MCP (tools) and A2A (tasks) with robotics/edge/ML payload lanes.",
            "implementation_crate": "connector_engine::cnp",
            "stack": cnp_layers_catalog(),
            "port_types": cnp_port_types_catalog(),
            "payload_kinds": cnp_payload_kinds(),
            "constants": cnp_constants(),
            "delivery_outcomes": ["delivered", "queued", "rejected", "failed", "expired"],
            "mesh_snapshot": mesh,
            "wire": crate::cnp::wire::wire_status(),
            "l5_static_live": crate::cnp::wire::l5_static_routing_live(),
            "honesty": "L2 TCP + L5 static 1-hop when CONNECTOR_CNP_PEERS is set. Multi-hop mesh, mTLS product, SWIM, and cluster replication are not live.",
            "mtls": {
                "peer_tls": mtls_honesty,
                "mutual_auth_product": false,
                "lab_stub_allowed": mtls_stub,
                "lab_stub_flag": "CONNECTOR_CNP_ALLOW_MTLS_STUB=1",
                "honesty": "CNP establish_mtls fail-closed without lab stub; empty-key success forbidden. Real mutual_auth not productized.",
            },
        }
    }))
}

fn require_admin_or_dev(headers: &HeaderMap) -> Result<(), Json<serde_json::Value>> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = crate::auth::extract_claims(headers) else {
        return Err(Json(json!({"ok": false, "error": "Unauthorized"})));
    };
    let role = crate::auth::PlatformRole::from_str(&claims.role);
    if role.rank() < crate::auth::PlatformRole::Admin.rank() {
        return Err(Json(json!({"ok": false, "error": "Admin privileges required"})));
    }
    Ok(())
}

/// GET /cnp/wire — listener bind status.
pub async fn get_cnp_wire(
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, Json<serde_json::Value>> {
    require_admin_or_dev(&headers)?;
    Ok(Json(json!({
        "ok": true,
        "wire": crate::cnp::wire::wire_status(),
        "peers": crate::cnp::wire::peer_map(),
        "l5_static_live": crate::cnp::wire::l5_static_routing_live(),
        "cnp_l5_mode": if crate::cnp::wire::l5_static_routing_live() { "static_1hop" } else { "local_only" },
        "honesty": "L2 TCP + L5 static 1-hop when CONNECTOR_CNP_PEERS is set. No multi-hop mesh or mTLS product.",
    })))
}

/// GET /cnp/inbox — local L2 deliveries.
pub async fn get_cnp_inbox(
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, Json<serde_json::Value>> {
    require_admin_or_dev(&headers)?;
    Ok(Json(json!({
        "ok": true,
        "inbox": crate::cnp::wire::inbox_snapshot(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct CnpSendRequest {
    pub dest_cell: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub agent_pid: Option<String>,
    #[serde(default)]
    pub package: Option<connector_native_contract::PackagePin>,
}

/// POST /cnp/send — serialize a cognitive message onto the L2 wire.
pub async fn post_cnp_send(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CnpSendRequest>,
) -> Result<Json<serde_json::Value>, Json<serde_json::Value>> {
    require_admin_or_dev(&headers)?;
    let dest = req.dest_cell.trim();
    if dest.is_empty() {
        return Err(Json(json!({"ok": false, "error": "dest_cell_required"})));
    }
    let agent_pid = req
        .agent_pid
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "operator".into());
    let (_driver, atu) = crate::substrate::protocol_drivers::admit_cnp_send(
        &state,
        &agent_pid,
        dest,
        &req.text,
        None,
        req.package.clone(),
    )
    .map_err(|e| {
        Json(crate::substrate::protocol_drivers::admit_denied_json("cnp", &e))
    })?;
    let msg = crate::cnp::stack::cognitive::CognitiveMessage {
        message_id: format!("cnp_{}", chrono::Utc::now().timestamp_millis()),
        agent_pid: agent_pid.clone(),
        intent: crate::cnp::stack::cognitive::classify_intent(&req.text),
        payload: crate::cnp::stack::cognitive::CognitivePayload::Text(req.text.clone()),
        confidence: 1.0,
        timestamp: chrono::Utc::now().timestamp_millis(),
    };
    let stack = crate::cnp::wire::global_stack();
    let g = stack.lock().map_err(|e| Json(json!({"ok": false, "error": e.to_string()})))?;
    match g.send_packet(dest, msg) {
        Ok(()) => {
            let _ = crate::substrate::pate::complete_augmented_task(
                &state,
                &atu,
                "cnp_sent",
                json!({"dest_cell": dest}),
            );
            Ok(Json(json!({
                "ok": true,
                "dest_cell": dest,
                "action_digest": atu.action_digest,
                "pate_task_id": atu.task_id,
                "honesty": "Bytes written to local inbox or forwarded via L5 static 1-hop peer; admitted via protocol_drivers/cnp.",
            })))
        }
        Err(e) => Err(Json(json!({
            "ok": false,
            "error": format!("{e:?}"),
        }))),
    }
}

#[derive(Debug, Deserialize)]
pub struct CnpActuationRequest {
    #[serde(default)]
    pub message_id: Option<String>,
    pub from_agent: String,
    pub to_agent: String,
    pub command: String,
    #[serde(default)]
    pub parameters: serde_json::Value,
    #[serde(default)]
    pub deadline_us: Option<u64>,
    #[serde(default)]
    pub package: Option<connector_native_contract::PackagePin>,
    #[serde(default)]
    pub mission_id: Option<String>,
}

/// POST /cnp/messages — plan alias for CNP actuation envelopes.
pub async fn post_cnp_messages(
    state: State<SharedState>,
    headers: HeaderMap,
    body: Json<CnpActuationRequest>,
) -> Result<Json<serde_json::Value>, Json<serde_json::Value>> {
    post_cnp_actuation(state, headers, body).await
}

/// POST /cnp/actuation — admit `connector.cnp.actuation.v1` via ActionBinding/PATE.
pub async fn post_cnp_actuation(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<CnpActuationRequest>,
) -> Result<Json<serde_json::Value>, Json<serde_json::Value>> {
    require_admin_or_dev(&headers)?;
    let from = req.from_agent.trim();
    let to = req.to_agent.trim();
    if from.is_empty() || to.is_empty() || req.command.trim().is_empty() {
        return Err(Json(json!({
            "ok": false,
            "error": "from_agent_to_agent_command_required",
            "status": 400,
        })));
    }
    let command = crate::substrate::protocol_drivers::parse_actuation_command(
        &req.command,
        &req.parameters,
    )
    .map_err(|e| Json(json!({ "ok": false, "error": e, "status": 400 })))?;
    let skip_note = matches!(command, ActuationCommand::EmergencyStop);
    let (_driver, atu) = crate::substrate::protocol_drivers::admit_cnp_actuation(
        &state,
        from,
        to,
        &command,
        &req.parameters,
        req.deadline_us,
        req.mission_id.clone(),
        req.package.clone(),
    )
    .map_err(|e| Json(crate::substrate::protocol_drivers::admit_denied_json("cnp", &e)))?;

    let message_id = req
        .message_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("cnp_act_{}", uuid::Uuid::new_v4()));
    let payload = CnpPayload::Actuation {
        target_id: to.to_string(),
        command: command.clone(),
        deadline_us: req.deadline_us,
    };
    let cmd_name = crate::substrate::protocol_drivers::actuation_command_name(&command);
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            "cnp_actuation_receipts",
            &message_id,
            &json!({
                "schema": "connector.cnp.actuation.v1",
                "message_id": message_id,
                "from_agent": from,
                "to_agent": to,
                "command": cmd_name,
                "parameters": req.parameters,
                "deadline_us": req.deadline_us,
                "payload": payload,
                "action_digest": atu.action_digest,
                "pate_task_id": atu.task_id,
                "at_ms": chrono::Utc::now().timestamp_millis(),
            }),
        );
    }

    let mut fields = HashMap::new();
    fields.insert("schema".into(), "connector.cnp.actuation.v1".into());
    fields.insert("command".into(), cmd_name.into());
    fields.insert("message_id".into(), message_id.clone());
    let msg = crate::cnp::stack::cognitive::CognitiveMessage {
        message_id: message_id.clone(),
        agent_pid: from.to_string(),
        intent: crate::cnp::stack::cognitive::Intent::Command,
        payload: crate::cnp::stack::cognitive::CognitivePayload::Structured(fields),
        confidence: 1.0,
        timestamp: chrono::Utc::now().timestamp_millis(),
    };
    let stack = crate::cnp::wire::global_stack();
    let wire = {
        let g = stack
            .lock()
            .map_err(|e| Json(json!({"ok": false, "error": e.to_string()})))?;
        match g.send_packet(to, msg) {
            Ok(()) => json!({"delivered": true, "dest": to}),
            Err(e) => json!({
                "delivered": false,
                "dest": to,
                "error": format!("{e:?}"),
                "honesty": "Actuation admitted; wire delivery needs local cell or CONNECTOR_CNP_PEERS",
            }),
        }
    };
    let _ = crate::substrate::pate::complete_augmented_task(
        &state,
        &atu,
        "cnp_actuation",
        json!({"message_id": message_id, "wire": wire}),
    );
    Ok(Json(json!({
        "ok": true,
        "schema": "connector.cnp.actuation.v1",
        "message_id": message_id,
        "from_agent": from,
        "to_agent": to,
        "command": cmd_name,
        "action_digest": atu.action_digest,
        "pate_task_id": atu.task_id,
        "package_gate_skipped": skip_note,
        "wire": wire,
        "sil_certified": false,
        "honesty": "CNP actuation admitted via ActionBinding/PATE and persisted. Not a SIL-certified motion loop or ROS body HAL.",
    })))
}
