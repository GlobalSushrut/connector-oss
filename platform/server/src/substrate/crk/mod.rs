//! Cognitive Range Kernel (RangeGuard) — action-scoped governed cognition.
//!
//! Owns: MEMORY → WHAT MAY INFLUENCE THIS MOMENT.
//! Never authorizes world effects. Returns READY|AMBIGUOUS|STALE|UNTRUSTED|INSUFFICIENT.
//!
//! Distinct from SVF ContextManifest (disclosure). Distinct from building a new DB —
//! projections and indexes sit on VAC/CAS/KernelStore.

pub mod activation;
pub mod api;
pub mod context_frame;
pub mod continuity_rollup;
pub mod cover;
pub mod demo;
pub mod eligibility;
pub mod harness;
pub mod influence;
pub mod memory_commit;
pub mod moment_range;
pub mod node_index;
pub mod procedure_capsule;
pub mod recall_session;
pub mod relations;
pub mod search;
pub mod selector;
pub mod sequence_dna;
pub mod store_scans;
pub mod talk_bind;
pub mod temporal_ledger;
pub mod transfer;
pub mod trust_firewall;

use connector_trust::{
    ActionCueEnvelope, CrkState, InfluenceManifest, MomentRange, ACTION_CUE_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::SharedState;

pub const SELECTOR_VERSION: &str = "crk.selector.v3-seqdna";
pub const FOLDER_COMMITS: &str = "crk_memory_commits";
pub const FOLDER_CLAIMS: &str = "crk_state_claims";
pub const FOLDER_PROCEDURES: &str = "crk_procedures";
pub const FOLDER_RANGES: &str = "crk_moment_ranges";
pub const FOLDER_MANIFESTS: &str = "crk_influence_manifests";
pub const FOLDER_TRANSFERS: &str = "crk_transfers";
pub const FOLDER_ROOTS: &str = "crk_memory_roots";

pub(crate) fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Digest helper for CRK ids and API claim ids.
pub fn digest_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Build an action cue from DAL / API inputs.
pub fn cue_from(
    agent_pid: &str,
    generation: u64,
    bound_skill: Option<&str>,
    phase: &str,
    action_digest: &str,
    risk: &str,
    token_budget: u64,
    max_range_cover: u32,
) -> ActionCueEnvelope {
    ActionCueEnvelope {
        schema: ACTION_CUE_SCHEMA.into(),
        agent_pid: agent_pid.into(),
        generation,
        bound_skill: bound_skill.map(|s| s.to_string()),
        phase: phase.into(),
        action_digest: action_digest.into(),
        risk: risk.into(),
        token_budget,
        max_range_cover: if max_range_cover == 0 {
            8
        } else {
            max_range_cover
        },
    }
}

/// Primary entry: eligibility → type-aware DNA → budget cover → MomentRange.
///
/// Embeddings/KECS never authorize. CRK never Allow/Deny.
pub fn window(
    state: &SharedState,
    cue: &ActionCueEnvelope,
) -> Result<(MomentRange, InfluenceManifest, CrkState), String> {
    let pinned_root = memory_commit::current_root(state.as_ref(), &cue.agent_pid)
        .unwrap_or_else(|| format!("genesis:{}", cue.agent_pid));

    let eligible = eligibility::filter_candidates(state.as_ref(), cue)?;
    let procedure = procedure_capsule::select_for_skill(
        state.as_ref(),
        &cue.agent_pid,
        cue.bound_skill.as_deref(),
    );

    let prior_cids = latest_context_cids(state.as_ref(), &cue.agent_pid);

    let dna = activation::activate_dynamic(
        state.as_ref(),
        cue,
        &eligible,
        procedure.as_ref(),
        &prior_cids,
        &pinned_root,
    );
    let (selected, exclusions, state_out) = cover::budget_cover(cue, &dna);

    let conflicts: Vec<String> = dna
        .conflicts
        .iter()
        .map(|(a, b)| format!("{a}|{b}"))
        .collect();

    let mut range = moment_range::build(
        cue,
        selected,
        state_out,
        procedure.as_ref(),
        conflicts,
    );
    // Ensure procedure id on range even if CID list used procedure id.
    if range.procedure_id.is_none() {
        range.procedure_id = procedure.as_ref().map(|p| p.procedure_id.clone());
    }

    let manifest = influence::build(cue, &range, &exclusions, &pinned_root, procedure.as_ref());

    moment_range::persist(state.as_ref(), &range)?;
    influence::persist(state.as_ref(), &manifest)?;

    Ok((range, manifest, state_out))
}

pub fn status() -> Value {
    json!({
        "schema": "connector.crk.status.v1",
        "product": "RangeGuard",
        "kernel": "Cognitive Range Kernel",
        "owns": "MEMORY → WHAT MAY INFLUENCE THIS MOMENT",
        "never_authorizes": true,
        "states": ["READY", "AMBIGUOUS", "STALE", "UNTRUSTED", "INSUFFICIENT"],
        "selector_version": SELECTOR_VERSION,
        "memory_sequence_dna": "connector.crk.memory_sequence_dna.v1",
        "activation": "type_aware_dna_v1",
        "routes": [
            "GET /api/v1/range/status",
            "POST /api/v1/range/window",
            "POST /api/v1/range/observe",
            "POST /api/v1/range/commit",
            "POST /api/v1/range/relate",
            "POST /api/v1/range/search",
            "GET /api/v1/range/replay/:manifest_id",
            "POST /api/v1/range/rollup",
            "POST /api/v1/range/demo/rangeguard"
        ],
        "wired": [
            "dal.recall→crk.window",
            "talk→crk.transfer",
            "broker.attach_transfer",
            "seqdna→activation→budget_cover"
        ],
        "honesty": "Exposure and influence-bound receipts — not mechanistic model causality. Not a new database; projections on VAC.",
        "not": ["better RAG", "temporal KG product", "LLM fine-tune", "court-grade"],
    })
}

fn latest_context_cids(state: &crate::state::PlatformState, agent_pid: &str) -> Vec<String> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let Ok(Some(v)) = es.folder_get(FOLDER_RANGES, &format!("latest:{agent_pid}")) else {
        return Vec::new();
    };
    let Some(mid) = v.get("moment_range_id").and_then(|x| x.as_str()) else {
        return Vec::new();
    };
    drop(es);
    moment_range::load(state, mid)
        .map(|r| r.context_cids)
        .unwrap_or_default()
}
