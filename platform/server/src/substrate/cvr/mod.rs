//! CVR — Connector Virtualization Runtime (Agent Isolation §§7–39).
//!
//! Engineer-facing: IsolationProfile (V0–V4). Product primitive: MicroCell.
//! Default backend: Firecracker. Agent ≠ execution body.

pub mod profile;
pub mod host_probe;
pub mod runtime_bundle;
pub mod execution_body;
pub mod backend;
pub mod lifecycle;
pub mod agent_cell;
pub mod micro_cell;
pub mod microd_client;
pub mod resources;
pub mod auto_policy;
pub mod shared_pool;
pub mod regime;
pub mod promote;
pub mod inflight;
pub mod api;
pub mod runtime_adapter;
pub mod ecosystem;
pub mod backends;
pub mod deployment_verify;
pub mod production_gate;

pub use profile::{
    IsolationIntent, IsolationProfile, ResolvedIsolation, resolve_isolation, resolve_for_agent,
};
pub use host_probe::{HostProbe, probe_host};
pub use runtime_bundle::RuntimeBundlePosture;
pub use execution_body::{
    ExecutionBody, ExecutionBodyKind, bind_on_start, load_body, persist_body, posture_for_agent,
};
pub use backend::{FirecrackerBackend, MicroVmBackend, MicroVmMeasure};
pub use lifecycle::{
    LifecycleTransition, apply_pause, apply_quarantine, apply_stop, apply_resume, apply_resume_ex,
    lifecycle_receipt_folder,
};
pub use agent_cell::{AgentCellRecord, freeze_agent_cell, thaw_agent_cell};
pub use resources::ResourceProfile;
pub use auto_policy::AutoPolicyTable;
pub use promote::{promote_to_microcell, PromoteTarget};
pub use regime::{OsRegime, get_regime, assert_may_auto_start};

use serde_json::{json, Value};

use crate::state::PlatformState;

/// Aggregate CVR posture for `/substrate/status` and proof export.
pub fn cvr_posture(state: &PlatformState) -> Value {
    let probe = probe_host();
    let bundle = RuntimeBundlePosture::discover();
    let backend = FirecrackerBackend::default();
    json!({
        "schema": "connector.cvr.v1",
        "role": "Connector Virtualization Runtime — AgentCell + MicroCell",
        "docs": [
            "platform/docs/arch/CONNECTOR_AGENT_ISOLATION.md",
            "platform/docs/arch/CONNECTOR_ISOLATION_IMPLEMENTATION_PLAN.md",
            "platform/docs/arch/CONNECTOR_OS_ECOSYSTEM_ARCHITECTURE.md",
        ],
        "runtime_adapter": runtime_adapter::catalog(),
        "host_probe": probe.to_json(),
        "runtime_bundle": bundle.to_json(),
        "microvm_backend": {
            "default": "firecracker",
            "available": backend.probe().ok,
            "measure": backend.measure(),
            "honesty": "Firecracker is the default MicroVmBackend — engineers select MicroCell posture, not VMM knobs",
        },
        "microd": microd_client::posture_json(),
        "boot_model": {
            "principle": "Host boots MicroCell runtime READY — not one VM per agent",
            "service": "connector-microd.service",
            "ready_when": "HostProbe verified + ready file",
        },
        "isolation_profiles": IsolationProfile::catalog(),
        "auto_policy": AutoPolicyTable::load().to_json(),
        "resource_profiles": ResourceProfile::catalog(),
        "shared_pool": shared_pool::pool_posture(state),
        "lifecycle": {
            "quarantine_order": ["deny_effects", "classify_inflight", "cut_grants", "cut_network", "freeze_agentcell", "vmm_pause", "verify", "propagate_children"],
            "auto_revival": "forbidden for QUARANTINED / STOPPED_BY_OPERATOR",
            "promote": "POST /agents/:pid/isolation/promote",
        },
        "default_intent": IsolationIntent::from_env().as_str(),
        "node_resolution": resolve_isolation(IsolationIntent::from_env(), None).to_json(),
        "agent_bodies_sample": sample_bodies(state, 8),
        "honesty": "Requested ≠ Applied ≠ Effective — MicroCell Applied only when HostProbe + bundle verify; auto never grants authority; sealed regimes never auto-revive",
    })
}

fn sample_bodies(state: &PlatformState, limit: usize) -> Value {
    let Ok(es) = state.engine_store.lock() else {
        return json!([]);
    };
    let Ok(keys) = es.folder_keys(execution_body::BODY_FOLDER, None) else {
        return json!([]);
    };
    let mut out = Vec::new();
    for k in keys.into_iter().rev().take(limit) {
        if let Ok(Some(v)) = es.folder_get(execution_body::BODY_FOLDER, &k) {
            out.push(v);
        }
    }
    json!(out)
}
