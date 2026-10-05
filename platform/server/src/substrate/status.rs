//! Substrate health and durability metrics (backend-only operator surface).

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::{
    operator::honesty::operator_envelope,
    state::SharedState,
};

/// `GET /api/v1/substrate/status`
pub async fn get_substrate_status(State(state): State<SharedState>) -> Json<Value> {
    crate::substrate::handoff_queue::reap_stale_pending_handoffs(state.as_ref());
    let durability = crate::substrate::durability::durability_snapshot(&state);
    let usage_events = crate::substrate::usage_event::usage_event_count(state.as_ref());
    let artifact_records = crate::substrate::artifact_log::artifact_log_count(state.as_ref());
    let causal_envelopes = crate::substrate::causal::causal_envelope_count(state.as_ref());
    let isolation = *state.isolation_runtime.read().unwrap();
    let local_cell_id = std::env::var("CONNECTOR_CELL_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| state.storage_layout.cell_id.clone());
    let mut ha = json!({
        "automatic_failover": false,
        "product_sot": "single_node",
        "mesh_fabric": false,
        "peer_tls": crate::distributed::transport::peer_tls_honesty(),
        "cluster_feature_compiled": cfg!(feature = "cluster"),
        "local_cell_id": local_cell_id,
        "cells_by_region": {
            "capability": "distributed::service_registry::ServiceRegistry::get_cells_by_region",
            "wired_to_fabric": false,
            "note": "Registry API exists; mesh fabric not claimed until vac-cluster soak.",
        },
    });
    #[cfg(feature = "cluster")]
    {
        if let Some(obj) = ha.as_object_mut() {
            obj.insert(
                "cluster_boot".into(),
                crate::cluster_boot::cluster_boot_status(&state.storage_layout.cell_id),
            );
        }
    }
    Json(operator_envelope(json!({
        "schema": "substrate_status.v1",
        "durability": durability,
        "usage": {
            "usage_event_count": usage_events,
            "source_of_truth": "billing_usage_events",
        },
        "artifact_log": {
            "record_count": artifact_records,
            "folder": crate::substrate::artifact_log::ARTIFACT_LOG_FOLDER,
        },
        "causal": {
            "envelope_count": causal_envelopes,
            "folder": crate::substrate::causal::CAUSAL_ENVELOPE_FOLDER,
        },
        "moments": {
            "count": crate::services::moment::moment_count(state.as_ref()),
        },
        "object_fabric": {
            "count": crate::services::object_fabric::object_count(&state),
            "storage_backend": "fs_cas",
            "honesty": "CAS blobs under data_dir/object_fabric_cas; storage_backend=fs_cas when put succeeds",
        },
        "retention": {
            "policy": crate::substrate::retention::load_policy(state.as_ref()),
            "job": "substrate::retention::run_retention_job_stub",
            "honesty": "not yet moving cold tiers",
        },
        "isolation": {
            "declared_runtime": isolation.as_str(),
            "downgrade_env": "CONNECTOR_ALLOW_ISOLATION_DOWNGRADE",
            "subprocess_break_glass": crate::substrate::cage_security::subprocess_isolation_allowed(),
            "prodish_enforced": crate::substrate::cage_security::prodish_isolation_enforced(),
        },
        "sandbox_unbypassable": crate::substrate::sandbox_unbypassable::posture_json(state.as_ref(), None),
        "product_promise": {
            "thesis": "tools + env + isolation + monitoring + proof — not absolute security",
            "posture": crate::substrate::proof_export::product_posture_with_state(state.as_ref()),
            "docs": [
                "platform/docs/arch/CONNECTOR_CAPABILITY_STANDARD.md",
                "platform/docs/arch/CONNECTOR_PRODUCT_PROMISE.md",
                "platform/docs/arch/CONNECTOR_FINAL_OUTCOMES.md",
                "platform/docs/arch/CONNECTOR_ARC.md",
            ],
        },
        "lab_banner": {
            "show": crate::services::playground::is_playground_mode()
                || !crate::kernel::agent_principal::intelligence_hardening_on(),
            "label": if crate::services::playground::is_playground_mode() {
                "LAB / PLAYGROUND"
            } else if !crate::kernel::agent_principal::intelligence_hardening_on() {
                "LAB / PILOT (hardening off)"
            } else {
                "HARDEN"
            },
            "honesty": "Soft-fail and playground must never be presented as production membrane",
        },
        "harden_posture": crate::substrate::harden_posture::posture_triad(state.as_ref()),
        "node_contract": crate::substrate::node_contract::posture_json(state.as_ref()),
        "workload_profile": crate::substrate::workload_profile::posture_json(state.as_ref()),
        "crash_recovery": crate::substrate::crash_recovery::posture_json(state.as_ref()),
        "escape_hatches": crate::substrate::escape_hatches::posture_json(),
        "dim_bands": crate::substrate::dim::bands::posture_json(),
        "ops_runtime": crate::substrate::ops_runtime::ops_posture(state.as_ref()),
        "cvr": crate::substrate::cvr::cvr_posture(state.as_ref()),
        "arc": crate::substrate::arc::posture_json(),
        "agent_memory": crate::substrate::agent_memory::posture_json(),
        "context_rollup": crate::substrate::agent_memory::rollup::posture_json(),
        "svf": crate::substrate::svf::posture_json(),
        "aapi_effect_field": crate::substrate::aapi_effect_field::posture_json(),
        "knot_belief_field": crate::substrate::knot_belief_field::posture_json(),
        "cfni": {
            "enabled": crate::substrate::cfni::cfni_enabled(),
            "enforce_production": crate::substrate::cfni::cfni_enforce_production(),
            "header": connector_trust::CFNI_HEADER,
        },
        "dns": {
            "mode": "in_process",
            "honesty": "Cage DNS (*.cnktros) is an in-process registry — not distributed DNS",
        },
        "kerneld": {
            "status": kerneld_status(),
            "honesty": "Fail-closed egress helper; absent is valid for single-node lab",
        },
        "quota_sot": {
            "path": "services::agents + VAC kernel registration caps",
            "live_catalog": "vac_kernel_acb via GET /api/v1/agents",
            "sot_status": "GET /api/v1/agents/sot-status",
            "dual_registry": false,
            "deprecated_parallel": [
                "agent_lifecycle::AgentRegistry (orphaned)",
                "crate::agents::* planners",
                "services::agent_resource_manager"
            ],
        },
        "knowledge": {
            "index_mode": "in_process",
            "honesty": "HNSW/inverted index is single-node; Knot rebuilds from MemPackets at boot",
            "mesh_fabric": false,
        },
        "ha": ha,
        "concurrency": {
            "kernel_lock": "Mutex",
            "honesty": "Single-node Tokio + coarse kernel/engine_store Mutex — not horizontally sharded. Background jobs drop locks before await.",
            "bulkheads": state.bulkheads.status_json(),
            "session_owners": "concurrency::session_owner (INV-17/18)",
            "runtime_snapshots": "substrate::agent_runtime_snapshot (INV-16)",
            "stream_gate": crate::substrate::governed_stream_gate::posture_json(),
            "runtime_invariants": "/api/v1/substrate/runtime-invariants",
        },
        "flow_lease": crate::substrate::flow_lease::lease_snapshot(state.as_ref()),
        "handoff_queue": crate::substrate::handoff_queue::handoff_queue_stats(state.as_ref()),
        "cage_security": crate::substrate::cage_security::cage_security_status(state.as_ref()),
        "matrix_isolation": {
            "schema": "connector.matrix.isolation.status.v1",
            "matrix_hw_enforce": crate::kernel::matrix_isolation::matrix_hw_enforce_enabled(),
            "ring1_enforce": crate::kernel::docklock::ring1_enforce_enabled(),
            "threat_model": "chaotic_distributed_matrix_intelligence_hardware_capable",
        },
        "glue": glue_honesty(),
        "open_auth": {
            "loopback_bind_check": "reject_open_auth_non_loopback_bind at boot",
            "defense_strict_disables_open_auth": crate::services::runtime_control::defense_strict_enabled(),
        },
        "intelligence_authority": {
            "lifecycle": crate::substrate::agent_lifecycle_gate::posture_json(),
            "effects": crate::substrate::governed_effect::posture_json(),
            "identity_stack": crate::substrate::identity_stack::posture_json(),
            "address_dac": crate::kernel::address_contracts::posture_json(),
            "autonomy_tier": crate::substrate::rgo::autonomy_posture_json(),
            "egcm_shadow": std::env::var("CONNECTOR_EGCM_SHADOW").unwrap_or_else(|_| "1".into()),
        },
        "packet_dna": crate::substrate::packet_dna::status_json(),
    })))
}

/// Glue executor posture — fail-closed stub under production / defense-strict.
fn glue_honesty() -> Value {
    let env = std::env::var("CONNECTOR_ENV")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let prodish = matches!(env.as_str(), "production" | "prod")
        || crate::services::runtime_control::defense_strict_enabled();
    let allow_stub = std::env::var("CONNECTOR_GLUE_ALLOW_STUB")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    let stub_blocked = prodish && !allow_stub;
    json!({
        "schema": "glue_honesty.v1",
        "executor": "stub",
        "prodish": prodish,
        "allow_stub_env": "CONNECTOR_GLUE_ALLOW_STUB",
        "allow_stub": allow_stub,
        "stub_blocked_in_prod": stub_blocked,
        "honesty": if stub_blocked {
            "Glue stub blocked in prod"
        } else if allow_stub {
            "Glue stub allowed via CONNECTOR_GLUE_ALLOW_STUB (break-glass lab only) — not a shipping surface"
        } else {
            "Glue stub available in non-prod; not a shipping integration surface"
        },
        "crate": "oss/connector/crates/connector-glue",
    })
}

fn kerneld_status() -> &'static str {
    if std::env::var_os("CONNECTOR_KERNELD_SOCKET").is_some()
        || std::env::var_os("CONNECTOR_KERNELD_URL").is_some()
    {
        "configured"
    } else if std::path::Path::new("/run/connector/kerneld.sock").exists() {
        "socket_present"
    } else {
        "absent"
    }
}
