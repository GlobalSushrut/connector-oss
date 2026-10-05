//! Semantic Virtualization Fabric — projection + disclosure runtime.
//! Schemas: `connector_trust::svf`. Docs: platform/docs/arch/CONNECTOR_SVF.md
//!
//! Does **not** replace PATE / WorldGrant / DIM / ARC / AffordanceEnvelope.

pub mod api;
pub mod derived;
pub mod expand;
pub mod fade_bind;
pub mod graph;
pub mod grants;
pub mod materialize;
pub mod materialize_flow;
pub mod observe;
pub mod project;
pub mod remask;
pub mod resolve;
pub mod semanticize;
pub mod store;
pub mod tool_stubs;

use serde_json::{json, Value};

use crate::state::SharedState;

pub use expand::{expand, ExpandRequest, ExpandResult};
pub use materialize::{assert_cdp_thawed, materialize_after_admit, record_expand_receipt};
pub use materialize_flow::{admit_resolve_materialize, materialize_with_resolve};
pub use observe::observe_tool_result;
pub use project::{gateway_injection_block, project_objects};
pub use remask::remask_observation;
pub use resolve::{parse_object_id, resolve, resolve_json};
pub use semanticize::semanticize_agent;
pub use store::{get_object, list_objects, put_object, OBJECT_FOLDER, RECEIPT_FOLDER};
pub use tool_stubs::{gateway_tool_stub_block, tool_stubs};

fn env_on(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Master switch; also follows augmented / unbypassable broker lane.
pub fn svf_enabled() -> bool {
    env_on("CONNECTOR_SVF")
        || env_on("CONNECTOR_AUGMENTED_ENV")
        || crate::substrate::llm_broker_gate::broker_unbypassable()
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn broker_epoch(state: &SharedState, agent_pid: &str) -> u64 {
    crate::substrate::llm_context_broker::current_generation(state, agent_pid)
}

pub fn posture_json() -> Value {
    json!({
        "schema": "connector.svf.posture.v1",
        "flag": "CONNECTOR_SVF",
        "enabled": svf_enabled(),
        "honesty": "projection+disclosure — does not replace PATE/WorldGrant/DIM/ARC",
        "sandwich": "validate_opaque → pate.admit → expand_after_admit → credential_proxy",
        "phase_5": {
            "dal": "owns turn — PROJECT/propose/act/verify; stamp live broker_epoch",
            "agent_loop": "CIP inhibit + epoch check → tools sandwich",
            "ring1": "proposals only — no Talk auto-dispatch",
            "ltl": "receipts stitched for next Talk",
            "api": "POST /dal/start · POST /dal/:run_id/turn",
        },
        "phase_6": {
            "relations": "COPG svf_* edges + optional Knot mirror (informational)",
            "derived": "DerivedKnowledge → evidence E2 + MomentProof",
            "fade_bind": "EvidenceMeta F0–F3/P0–P3 → ContextFragment.fade_state",
            "belief_field": "interference/foresight remain cognitive — not object edges",
        },
        "phase_7": {
            "cli": "connectorctl svf posture|objects|stubs|grants|derived|receipts|fade-sync",
            "dal_cli": "connectorctl dal posture|start|show",
            "status": "substrate.status.svf + /api/v1/svf/posture",
            "receipts": "GET /svf/receipts/:agent — disclosure vs effect",
            "tracetramp": "disclosure≠materialize in MomentProof.tracetramp.svf_honesty",
            "reach": "A10b–A10g gated in CONNECTOR_REACH_CHECKLIST.md",
        },
        "docs": "platform/docs/arch/CONNECTOR_SVF.md",
    })
}
