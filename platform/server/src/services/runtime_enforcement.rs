use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use vac_core::types::{AgentControlBlock, AgentRole};

use crate::machine::{control_plane_os_telemetry, machine_fingerprint};
use crate::services::runtime_control::load_runtime_policy;
use crate::state::SharedState;

/// Runtime enforcement — **Event Virtual Machine (EVM)** framing.
///
/// An agent is an EVM: state changes only through **auditable kernel transitions**
/// (memory ops, tool dispatch, etc.). “Virtualization” here means **strict, dynamic
/// policy + serial audit order + Knot-windowed knowledge** — not simulated Linux
/// cgroups/seccomp per agent (optional only via external deployment).
pub async fn get_runtime_enforcement(State(state): State<SharedState>) -> impl IntoResponse {
    let mode = *state.runtime_mode.read().unwrap();
    let policy = {
        let es = state.engine_store.lock().unwrap();
        load_runtime_policy(&**es)
    };

    let os_telemetry = control_plane_os_telemetry();
    let mut control_plane_context = os_telemetry.clone();
    if let Some(o) = control_plane_context.as_object_mut() {
        o.insert("server_os".to_string(), json!(std::env::consts::OS));
        o.insert(
            "machine_fingerprint".to_string(),
            json!(machine_fingerprint()),
        );
        o.insert(
            "disclaimer".to_string(),
            json!("Telemetry describes this connector-platform OS process (+ cgroup context), not a dedicated kernel PID per logical agent."),
        );
    }

    let host_kernel = { state.kernel_host.lock().unwrap().snapshot_json() };

    let (audit_entries, packet_count, agent_count, live_agents_json, cells) = {
        let k = state.kernel.lock().unwrap();
        let mut agents: Vec<_> = k.agents().values().collect();
        agents.sort_by(|a, b| a.agent_pid.cmp(&b.agent_pid));
        let agents: Vec<_> = agents.into_iter().take(64).collect();
        let cells: Vec<_> = agents
            .iter()
            .map(|acb| execution_cell_from_acb(acb))
            .collect();
        let live: Vec<_> = agents
            .iter()
            .map(|acb| {
                json!({
                    "agent_pid": acb.agent_pid,
                    "agent_name": acb.agent_name,
                    "status": format!("{:?}", acb.status),
                    "namespace": acb.namespace,
                    "registered_at_ms": acb.registered_at,
                    "last_active_at_ms": acb.last_active_at,
                    "parent_pid": acb.parent_pid,
                })
            })
            .collect();
        (
            k.audit_log().len(),
            k.packet_count(),
            k.agents().len(),
            live,
            cells,
        )
    };
    let (knot_last_sn, knot_k_vn_dirty, knot_nodes) = {
        let knot = state.knot.lock().unwrap();
        (knot.last_ingest_sn, knot.k_vn_dirty, knot.node_count())
    };

    let total_denials: usize = cells
        .iter()
        .filter_map(|c| c.get("policy_denials").and_then(|x| x.as_array()))
        .map(|a| a.len())
        .sum();
    let violated = cells
        .iter()
        .filter(|c| c.get("status").and_then(|s| s.as_str()) == Some("failed"))
        .count();
    let strict_n = cells
        .iter()
        .filter(|c| c.get("evm_strictness").and_then(|s| s.as_str()) == Some("strict"))
        .count();
    let standard_n = cells.len().saturating_sub(strict_n);

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "data": {
                "runtime_mode": mode.as_str(),
                "runtime_policy": policy,
                "host_kernel": host_kernel,
                "event_virtual_machine": {
                    "definition": "Each agent is an Event Virtual Machine (EVM): execution is a stream of kernel transitions (memory, tool, policy). Isolation is logical — namespaces, allowlists, budgets, HITL — ordered by the audit log. This is not a hardware VM per agent unless you wrap workers externally.",
                    "os_execution_posture": {
                        "control_plane": "The connector-platform binary runs as real OS processes on this host; MCP ToolDispatch is issued from that process (see execution_isolation on tool responses).",
                        "enterprise_isolation": "Standard enterprise posture: run the server under systemd with hardening, place MCP bridge endpoints on separate hosts/VPCs, use network policy + secrets management; optional gVisor/Firecracker for third-party tool workers.",
                        "stability": "Kernel audit ordering + Knot ingest serials give deterministic evolution of shared knowledge; OS stability comes from process supervision and resource limits at deploy time.",
                    },
                    "tool_execution_isolation": "ToolDispatch transitions are gated (semantic injection score, tool scopes, circuit breaker on invoke-scoped, CLS/contracts). Remote MCP bridges are separate OS processes/services — the control plane still records transitions in-kernel for provenance.",
                    "knot_consensus_stability": {
                        "last_ingest_serial": knot_last_sn,
                        "k_vn_recompute_pending": knot_k_vn_dirty,
                        "knowledge_entity_count": knot_nodes,
                        "meaning": "KnotEngine uses serial windows (last_ingest_sn) and consolidation (K_vn) to keep shared knowledge graph mutations stable for retrieval — complementary to per-agent packet isolation.",
                    },
                    "kernel_transition_log": {
                        "audit_entries": audit_entries,
                        "packets": packet_count,
                        "agents_registered": agent_count,
                    },
                },
                "live_agent_lifecycle": {
                    "source": "kernel AgentControlBlock registry (real registration / status / namespace)",
                    "agent_count": agent_count,
                    "agents": live_agents_json,
                },
                "control_plane_os_telemetry": os_telemetry,
                "effect_exclusivity": crate::substrate::effect_exclusivity::effect_exclusivity_status(state.as_ref()),
                "probabilistic_llm": crate::substrate::probabilistic_llm::status(),
                "isolation_summary": {
                    "model": "evm_execution_cell",
                    "active_execution_cells": cells.len(),
                    "active_sandboxes": cells.len(),
                    "strict_cells": strict_n,
                    "standard_cells": standard_n,
                    "container_isolation": strict_n,
                    "process_isolation": standard_n,
                    "violated_execution_cells": violated,
                    "violated_sandboxes": violated,
                    "total_denials": total_denials,
                    "sandbox_data_source": "kernel_agent_control_blocks",
                    "control_plane_context": control_plane_context,
                    "host_evidence": {
                        "node_runtime": format!("{} / {}", std::env::consts::OS, std::env::consts::ARCH),
                        "legacy_note": "Dashboard compatibility; prefer control_plane_context + control_plane_os_telemetry for live host fields.",
                    },
                    "isolation_telemetry_roadmap": {
                        "current": "Live host telemetry (PID, kernel_release, cgroup excerpt) + live agent lifecycle + Knot serials + audit counts; GET /monitor/cgroups for VAC-style budget accounting.",
                        "phase_b": "Dedicated tool-runner subprocess pool with capability sets; signed transition envelopes; OTel on denial rates + tool latency.",
                        "phase_c": "Deployment-level hardware isolation (K8s gVisor, Firecracker) as an optional profile — never synthesized in JSON.",
                    },
                },
                "sandboxes": cells,
            }
        })),
    )
}

fn normalize_cell_for_dashboard(mut cell: serde_json::Value) -> serde_json::Value {
    if let Some(o) = cell.as_object_mut() {
        if let Some(lb) = o.get("logical_boundaries").cloned() {
            o.entry("restrictions".to_string()).or_insert(lb);
        }
        if let Some(cap) = o.get("capability_attenuation").cloned() {
            o.entry("capabilities".to_string()).or_insert(cap);
        }
        if let Some(d) = o.get("policy_denials").cloned() {
            o.entry("denials".to_string()).or_insert(d);
        }
        if let Some(a) = o.get("audit_anchors").cloned() {
            o.entry("forensic_evidence".to_string()).or_insert(a);
        }
        if let Some(l) = o.get("evm_strictness").cloned() {
            o.entry("isolation_level".to_string())
                .or_insert(json!(format!("evm_{}", l.as_str().unwrap_or("standard"))));
        }
    }
    cell
}

pub async fn get_runtime_enforcement_detail(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let found = state
        .kernel
        .lock()
        .unwrap()
        .agents()
        .values()
        .find(|acb| acb.agent_pid == id)
        .map(|acb| execution_cell_from_acb(acb));
    match found {
        Some(cell) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "data": normalize_cell_for_dashboard(cell) })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": { "code": "execution_cell_not_found", "message": format!("Execution cell '{}' not found", id) }
            })),
        ),
    }
}

fn iso8601_from_ms(ms: i64) -> Option<String> {
    chrono::DateTime::from_timestamp_millis(ms).map(|dt| dt.to_rfc3339())
}

/// One execution cell per registered kernel agent (real `AgentControlBlock` fields only).
fn execution_cell_from_acb(acb: &AgentControlBlock) -> serde_json::Value {
    let id = acb.agent_pid.clone();
    let strictness = match acb.role {
        AgentRole::Admin => "strict",
        _ => "standard",
    };
    let status = acb.status.to_string();
    let budget_envelope = if let Some(tb) = acb.token_budget.as_ref() {
        json!({
            "daily_limit_tokens": tb.daily_limit,
            "hourly_limit_tokens": tb.hourly_limit,
            "burst_limit_tokens": tb.burst_limit,
            "used_today_tokens": tb.used_today,
            "used_this_hour_tokens": tb.used_this_hour,
            "cost_center": tb.cost_center,
            "reset_at_daily_ms": tb.reset_at_daily,
            "reset_at_hourly_ms": tb.reset_at_hourly,
        })
    } else {
        json!({
            "note": "No token_budget on this agent (kernel default = unlimited until configured).",
        })
    };

    let capability_attenuation: Vec<serde_json::Value> = acb
        .allowed_tools
        .iter()
        .map(|t| {
            json!({
                "capability": format!("tool:{t}"),
                "risk": "info",
                "delegation_depth": 0,
                "attenuated_from": "kernel_allowed_tools",
            })
        })
        .collect();

    let mut audit = serde_json::Map::new();
    if let Some(ts) = iso8601_from_ms(acb.last_active_at) {
        audit.insert("last_transition_iso".to_string(), json!(ts));
    }
    if let Some(ts) = iso8601_from_ms(acb.registered_at) {
        audit.insert("registered_at_iso".to_string(), json!(ts));
    }

    json!({
        "execution_cell_id": id,
        "sandbox_id": acb.agent_pid,
        "agent_pid": acb.agent_pid,
        "agent_name": acb.agent_name,
        "evm_strictness": strictness,
        "status": status,
        "budget_envelope": budget_envelope,
        "logical_boundaries": {
            "memory_namespace": acb.namespace,
            "memory_quota_tokens": acb.memory_region.quota_tokens,
            "memory_used_tokens": acb.memory_region.used_tokens,
            "memory_quota_bytes": acb.memory_region.quota_bytes,
            "memory_used_bytes": acb.memory_region.used_bytes,
            "readable_namespaces": acb.readable_namespaces,
            "writable_namespaces": acb.writable_namespaces,
        },
        "capability_attenuation": capability_attenuation,
        "policy_denials": json!([]),
        "audit_anchors": serde_json::Value::Object(audit),
    })
}
