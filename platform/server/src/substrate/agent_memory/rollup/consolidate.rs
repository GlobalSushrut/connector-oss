//! Memory consolidation before fade — group events into DecisionMemory (§19).

use connector_trust::{DecisionMemory, EpistemicClass};
use uuid::Uuid;

use crate::state::PlatformState;

use super::super::context_store;
use super::super::reducer;

pub fn consolidate_write_to_decision(
    state: &PlatformState,
    agent_vid: &str,
    subject: &str,
    before: &str,
    trigger: &str,
    after: &str,
    reason: &str,
    evidence_refs: Vec<String>,
    consequence: &str,
    epistemic: EpistemicClass,
) -> DecisionMemory {
    let ctx = context_store::load_state(state, agent_vid);
    let dm = reducer::store_decision(
        state,
        agent_vid,
        subject,
        before,
        trigger,
        after,
        reason,
        evidence_refs,
        0.8,
        consequence,
        ctx.context_epoch,
        epistemic,
    );
    // Bump decision ref on linked evidence
    for eid in &dm.evidence_refs {
        let mut meta = super::eligibility::load_meta(state, agent_vid, eid);
        meta.decision_ref_count += 1;
        meta.consequence = meta.consequence.max(0.6);
        super::eligibility::save_meta(state, agent_vid, eid, &meta);
    }
    dm
}

pub fn consolidate_session_end(
    state: &PlatformState,
    agent_vid: &str,
    session_id: &str,
    decisions: Vec<String>,
    actions: Vec<String>,
    unresolved: Vec<String>,
) -> connector_trust::SessionRollup {
    let ctx = context_store::load_state(state, agent_vid);
    let sr = connector_trust::SessionRollup {
        schema: connector_trust::SESSION_ROLLUP_SCHEMA.into(),
        session_id: session_id.into(),
        agent_vid: agent_vid.into(),
        start_context_root: ctx.context_root.clone(),
        end_context_root: ctx.context_root.clone(),
        goals_started: vec![],
        goals_completed: vec![],
        decisions,
        actions,
        unresolved,
        evidence_root: ctx.evidence_root.clone(),
        started_at_ms: chrono::Utc::now().timestamp_millis(),
        ended_at_ms: chrono::Utc::now().timestamp_millis(),
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("{agent_vid}:{session_id}");
        let _ = es.folder_put(
            "agent_memory_session_rollups",
            &key,
            &serde_json::to_value(&sr).unwrap_or_default(),
        );
    }
    sr
}
