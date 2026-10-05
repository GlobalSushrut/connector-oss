//! **Distributed mesh — shared knowledge, instruction, and memory** at the same operator plane.
//!
//! Agents collaborate via: **`k/` shared graph** (facts + instruction-role packets), **kernel AccessGrant**
//! (namespace edges), **POST /memory/share** (packet copy), and **multi-agent pipelines** (iterate / simulate).

use axum::{extract::State, Json};
use serde_json::json;

use crate::state::SharedState;
use vac_core::types::MemoryKernelOp;

/// GET /multiagent/mesh/knowledge-plane — live mesh: agents, grants, shared writes, Knot, routes.
pub async fn get_mesh_knowledge_plane(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let (agents, grant_edges, shared_writes, agent_count, kernel_packets, audit_cap) = {
        let k = state.kernel.lock().unwrap();
        let agents: Vec<serde_json::Value> = k
            .agents()
            .iter()
            .map(|(pid, acb)| {
                json!({
                    "pid": pid,
                    "name": acb.agent_name,
                    "status": format!("{:?}", acb.status),
                    "namespace": acb.namespace,
                    "readable_namespaces": acb.readable_namespaces,
                    "writable_namespaces": acb.writable_namespaces,
                    "allowed_tools_count": acb.allowed_tools.len(),
                    "total_packets": acb.total_packets,
                    "total_tokens_consumed": acb.total_tokens_consumed,
                })
            })
            .collect();

        let grant_edges: Vec<serde_json::Value> = k
            .audit_log()
            .iter()
            .rev()
            .take(600)
            .filter(|e| e.operation == MemoryKernelOp::AccessGrant)
            .take(100)
            .map(|e| {
                json!({
                    "timestamp_ms": e.timestamp,
                    "grantor_pid": e.agent_pid,
                    "target": e.target,
                    "outcome": format!("{:?}", e.outcome),
                    "reason": e.reason,
                })
            })
            .collect();

        let shared_writes: Vec<serde_json::Value> = k
            .audit_log()
            .iter()
            .rev()
            .take(800)
            .filter(|e| {
                e.operation == MemoryKernelOp::MemWrite
                    && e.reason.as_ref().map_or(false, |r| {
                        let l = r.to_ascii_lowercase();
                        l.contains("cross-agent")
                            || l.contains("knowledge batch")
                            || l.contains("ingest")
                            || l.contains("share")
                            || l.contains("instruction")
                    })
            })
            .take(60)
            .map(|e| {
                json!({
                    "timestamp_ms": e.timestamp,
                    "agent_pid": e.agent_pid,
                    "target": e.target,
                    "outcome": format!("{:?}", e.outcome),
                    "reason": e.reason,
                })
            })
            .collect();

        let agent_count = k.agent_count();
        let kernel_packets = k.packet_count();
        let audit_cap = k.audit_log().len();
        (
            agents,
            grant_edges,
            shared_writes,
            agent_count,
            kernel_packets,
            audit_cap,
        )
    };

    let (knot_sn, knot_nodes, k_vn_dirty) = {
        let knot = state.knot.lock().unwrap();
        (knot.last_ingest_sn, knot.node_count(), knot.k_vn_dirty)
    };

    let share_ledger_tail: Vec<serde_json::Value> = {
        let es = state.engine_store.lock().unwrap();
        let keys = es
            .folder_keys("cross_agent_shares", None)
            .unwrap_or_default();
        keys.into_iter()
            .rev()
            .take(25)
            .filter_map(|key| es.folder_get("cross_agent_shares", &key).ok().flatten())
            .collect()
    };

    let cell_id = state.storage_layout.cell_id.clone();

    Json(json!({
        "ok": true,
        "data": {
            "collaboration_model": {
                "summary": "Knowledge (facts), instruction/policy text, and episodic memory participate in one mesh: shared corpora live under k/* and Knot; private agent buffers stay namespaced until grant, share, or batch ingest promotes them.",
                "same_plane": "POST /memory/knowledge/ingest with role=fact|instruction updates the shared plane all agents can query; per-agent iteration uses POST /multiagent/pipeline and kernel ToolDispatch.",
                "distributed_cell": cell_id,
            },
            "live": {
                "agents": agents,
                "agent_count": agent_count,
                "kernel_packets": kernel_packets,
                "audit_entries": audit_cap,
            },
            "knot_shared_substrate": {
                "last_ingest_serial": knot_sn,
                "entity_count": knot_nodes,
                "k_vn_recompute_pending": k_vn_dirty,
                "meaning": "Ordered ingest gives a stable shared graph for multi-agent retrieval and RAG-style iteration.",
            },
            "mesh_edges": {
                "access_grants_recent": grant_edges,
                "mem_writes_collaboration_recent": shared_writes,
                "cross_agent_share_ledger_tail": share_ledger_tail,
            },
            "operator_routes": {
                "mesh_plane": "GET /api/v1/multiagent/mesh/knowledge-plane",
                "agent_map": "GET /api/v1/multiagent/map",
                "grant_namespace": "POST /api/v1/multiagent/grant",
                "revoke": "POST /api/v1/multiagent/revoke",
                "share_packet": "POST /api/v1/memory/share",
                "knowledge_batch_ingest": "POST /api/v1/memory/knowledge/ingest (records[]; role=instruction|fact)",
                "knowledge_query": "POST /api/v1/memory/knowledge/query",
                "pipeline_iterate": "POST /api/v1/multiagent/pipeline",
                "topology_cells": "GET /api/v1/topology/center",
                "knowledge_pipeline_spec": "GET /api/v1/memory/knowledge/pipeline/spec",
                "cnp_mesh": "GET /api/v1/cnp/overview",
            },
            "iterate_simulate_learn": {
                "pipelines": "Orchestration Intelligence v1 — k8s-style control plane schedules waves; light intelligence leaves chain via real parallel join_all; GET /multiagent/intelligence/standard",
                "intelligence_chain": "POST /multiagent/pipeline returns orchestration.intelligence_chain[] — wave output fingerprints link to next wave input",
                "shared_learn": "Promote stable facts to k/* via batch ingest; use grants so peers can read each other’s namespaces during simulation.",
                "governance": "AccessGrant + Bell-LaPadula checks on /memory/share; audit exports for fleet-wide review.",
            },
        }
    }))
}
