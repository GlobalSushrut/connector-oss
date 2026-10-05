//! InfluenceManifest — exposure / influence-bound receipt (≠ SVF ContextManifest).

use connector_trust::{
    ActionCueEnvelope, InfluenceManifest, MomentRange, VerifiedProcedureCapsule,
    INFLUENCE_MANIFEST_SCHEMA,
};

use crate::state::PlatformState;

use super::{digest_hex, now_ms, SELECTOR_VERSION, FOLDER_MANIFESTS};

pub fn build(
    cue: &ActionCueEnvelope,
    range: &MomentRange,
    exclusions: &[String],
    pinned_root: &str,
    procedure: Option<&VerifiedProcedureCapsule>,
) -> InfluenceManifest {
    let cold = digest_hex(exclusions.join("|").as_bytes());
    let contract = digest_hex(
        format!(
            "{}|{}|{}",
            cue.max_range_cover, cue.token_budget, SELECTOR_VERSION
        )
        .as_bytes(),
    );
    let mid = format!(
        "imf_{}",
        &digest_hex(
            format!("{}|{}|{}", range.moment_range_id, range.action_digest, pinned_root).as_bytes()
        )[..16]
    );
    InfluenceManifest {
        schema: INFLUENCE_MANIFEST_SCHEMA.into(),
        manifest_id: mid,
        agent_pid: cue.agent_pid.clone(),
        generation: cue.generation,
        action_digest: cue.action_digest.clone(),
        moment_range_id: range.moment_range_id.clone(),
        hot_cids: range.context_cids.clone(),
        cold_index_digest: cold,
        procedure_id: procedure.map(|p| p.procedure_id.clone()),
        procedure_version: procedure.map(|p| p.procedure_version.clone()),
        state_claim_ids: range
            .context_cids
            .iter()
            .filter(|c| c.starts_with("claim_") || c.starts_with("claim:"))
            .cloned()
            .collect(),
        excluded_conflicts: exclusions.to_vec(),
        provenance_root: pinned_root.into(),
        temporal_snapshot_ms: now_ms(),
        selector_version: SELECTOR_VERSION.into(),
        range_contract_hash: contract,
        honesty: "exposure_and_influence_bound — not mechanistic model causality".into(),
    }
}

pub fn persist(state: &PlatformState, manifest: &InfluenceManifest) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| format!("engine_store lock: {e}"))?;
    let val = serde_json::to_value(manifest).map_err(|e| format!("serialize: {e}"))?;
    es.folder_put(FOLDER_MANIFESTS, &manifest.manifest_id, &val)
        .map_err(|e| format!("put manifest: {e}"))?;
    Ok(())
}

pub fn load(state: &PlatformState, manifest_id: &str) -> Option<InfluenceManifest> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(FOLDER_MANIFESTS, manifest_id).ok().flatten()?;
    serde_json::from_value(v).ok()
}
