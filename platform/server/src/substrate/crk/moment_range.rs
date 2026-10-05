//! MomentRange — per-DAL-step working memory cover.

use connector_trust::{
    ActionCueEnvelope, CrkState, MomentRange, VerifiedProcedureCapsule, MOMENT_RANGE_SCHEMA,
};

use crate::state::PlatformState;

use super::{digest_hex, now_ms, FOLDER_RANGES};

pub fn build(
    cue: &ActionCueEnvelope,
    context_cids: Vec<String>,
    state: CrkState,
    procedure: Option<&VerifiedProcedureCapsule>,
    unresolved_conflicts: Vec<String>,
) -> MomentRange {
    let now = now_ms();
    let material = format!(
        "{}|{}|{}|{}|{}",
        cue.agent_pid,
        cue.action_digest,
        cue.phase,
        context_cids.join(","),
        cue.generation
    );
    let id = format!("mr_{}", &digest_hex(material.as_bytes())[..16]);
    MomentRange {
        schema: MOMENT_RANGE_SCHEMA.into(),
        moment_range_id: id,
        agent_pid: cue.agent_pid.clone(),
        action_digest: cue.action_digest.clone(),
        phase: cue.phase.clone(),
        bound_skill: cue.bound_skill.clone(),
        context_cids,
        range_generation: cue.generation,
        token_budget: cue.token_budget,
        state,
        unresolved_conflicts,
        procedure_id: procedure.map(|p| p.procedure_id.clone()),
        created_at_ms: now,
    }
}

pub fn persist(state: &PlatformState, range: &MomentRange) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| format!("engine_store lock: {e}"))?;
    let val = serde_json::to_value(range).map_err(|e| format!("serialize: {e}"))?;
    es.folder_put(FOLDER_RANGES, &range.moment_range_id, &val)
        .map_err(|e| format!("put range: {e}"))?;
    es.folder_put(
        FOLDER_RANGES,
        &format!("latest:{}", range.agent_pid),
        &serde_json::json!({ "moment_range_id": range.moment_range_id }),
    )
    .map_err(|e| format!("put latest: {e}"))?;
    Ok(())
}

pub fn load(state: &PlatformState, moment_range_id: &str) -> Option<MomentRange> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(FOLDER_RANGES, moment_range_id).ok().flatten()?;
    serde_json::from_value(v).ok()
}
