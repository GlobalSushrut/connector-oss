//! Causal Memory Skeleton — irreducible long-term structure (§8).

use connector_trust::{CausalMemorySkeleton, MomentProof, ProofLevel, CAUSAL_SKELETON_SCHEMA};
use uuid::Uuid;

use crate::state::PlatformState;

pub const SKELETON_FOLDER: &str = "agent_memory_skeletons";

pub fn from_moment(
    state: &PlatformState,
    mp: &MomentProof,
    material_evidence: Vec<String>,
    derivation: Option<String>,
) -> CausalMemorySkeleton {
    let sk = CausalMemorySkeleton {
        schema: CAUSAL_SKELETON_SCHEMA.into(),
        skeleton_id: format!("SK-{}", Uuid::new_v4().simple()),
        moment_id: mp.moment_id.clone(),
        agent_vid: mp.agent_vid.clone(),
        before: mp.previous_context_root.clone(),
        trigger: mp.trigger.clone(),
        authority: mp.authority_root.clone(),
        material_evidence,
        derivation,
        decision: mp.connector_decision.clone(),
        action: mp.proposed_action.clone(),
        outcome: mp.actual_effect.clone(),
        proof_level: mp.current_proof_level,
        context_epoch: mp
            .transition_id
            .as_ref()
            .map(|_| 0)
            .unwrap_or(0),
        timestamp_ms: mp.timestamp_ms,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            SKELETON_FOLDER,
            &sk.skeleton_id,
            &serde_json::to_value(&sk).unwrap_or_default(),
        );
    }
    sk
}

pub fn get(state: &PlatformState, skeleton_id: &str) -> Option<CausalMemorySkeleton> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(SKELETON_FOLDER, skeleton_id).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn for_moment(state: &PlatformState, moment_id: &str) -> Option<CausalMemorySkeleton> {
    let es = state.engine_store.lock().ok()?;
    let keys = es.folder_keys(SKELETON_FOLDER, None).ok()?;
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(SKELETON_FOLDER, &k) {
            if v.get("moment_id").and_then(|x| x.as_str()) == Some(moment_id) {
                return serde_json::from_value(v).ok();
            }
        }
    }
    None
}
