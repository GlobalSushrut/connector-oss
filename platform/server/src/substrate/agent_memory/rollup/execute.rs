//! Rollup execution — fail-closed fade transitions (§45–§46).

use connector_trust::{
    ContextRollup, EvidenceRecord, FadeState, ProofLevel, CONTEXT_ROLLUP_SCHEMA,
};
use uuid::Uuid;

use crate::state::PlatformState;

use super::eligibility::{evaluate, load_meta, save_meta, EvidenceMeta};
use super::fade::proof_for_state;
use super::policy;
use super::rehydrate;
use super::tombstone;

pub const ROLLUP_FOLDER: &str = "agent_memory_rollups";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub struct FadeResult {
    pub ok: bool,
    pub denied: bool,
    pub reason: Option<String>,
    pub rollup: Option<ContextRollup>,
    pub tombstone: Option<connector_trust::EvidenceTombstone>,
}

/// Execute one fade step for evidence. Fail-closed if consequential refs missing.
pub fn execute_fade(
    state: &PlatformState,
    rec: &EvidenceRecord,
    storage_pressure: f32,
) -> FadeResult {
    if !super::enabled() {
        return FadeResult {
            ok: false,
            denied: true,
            reason: Some("rollup_disabled".into()),
            rollup: None,
            tombstone: None,
        };
    }
    let policy = {
        let meta = load_meta(state, &rec.agent_vid, &rec.evidence_id);
        if let Some(ref cls) = meta.evidence_class {
            policy::resolve_for_class(
                state,
                &rec.agent_vid,
                connector_trust::EvidenceClass::parse(cls),
            )
        } else {
            policy::resolve(state, &rec.agent_vid, None)
        }
    };
    let explain = evaluate(state, rec, &policy, storage_pressure);
    if !explain.fade_eligible {
        return FadeResult {
            ok: false,
            denied: true,
            reason: explain.fade_denied_reason,
            rollup: None,
            tombstone: None,
        };
    }
    let mut meta = load_meta(state, &rec.agent_vid, &rec.evidence_id);
    let target = match meta.fade_state.next() {
        Some(t) => t,
        None => {
            return FadeResult {
                ok: false,
                denied: true,
                reason: Some("already_f3".into()),
                rollup: None,
                tombstone: None,
            };
        }
    };
    // Safety gate (§45): decision-critical refs must exist before F2→F3
    if target == FadeState::F3Skeleton && meta.decision_ref_count == 0 && meta.consequence < 0.5
    {
        let mut m = super::metrics::load(state, &rec.agent_vid);
        m.fade_denied_count += 1;
        super::metrics::save(state, &m);
        return FadeResult {
            ok: false,
            denied: true,
            reason: Some("fail_closed:no_decision_ref".into()),
            rollup: None,
            tombstone: None,
        };
    }
    let prev_proof = proof_for_state(meta.fade_state);
    let new_proof = proof_for_state(target);
    let bytes_before = meta.bytes;
    let bytes_after = match target {
        FadeState::F0Full => bytes_before,
        FadeState::F1Distilled => (bytes_before / 4).max(256),
        FadeState::F2Decision => 512,
        FadeState::F3Skeleton => 128,
    };

    // On F0→F1: distill + archive placeholder from location (rehydrate later)
    if meta.fade_state == FadeState::F0Full && target == FadeState::F1Distilled {
        let stub = format!("archived:{}", rec.raw_location);
        rehydrate::archive_payload(
            state,
            &rec.agent_vid,
            &rec.evidence_id,
            &rec.content_hash,
            &stub,
        );
        rehydrate::distill_into_meta(state, &rec.agent_vid, &rec.evidence_id, &stub);
    }

    meta.fade_state = target;
    meta.bytes = bytes_after;
    save_meta(state, &rec.agent_vid, &rec.evidence_id, &meta);

    let rollup = ContextRollup {
        schema: CONTEXT_ROLLUP_SCHEMA.into(),
        rollup_id: format!("RU-{}", Uuid::new_v4().simple()),
        agent_vid: rec.agent_vid.clone(),
        context_range_start_ms: rec.event_time_ms,
        context_range_end_ms: now_ms(),
        source_evidence_root: rec.content_hash.clone(),
        retained_evidence_root: rec.content_hash.clone(),
        decision_refs: vec![],
        moment_refs: vec![],
        action_refs: vec![],
        previous_proof_level: prev_proof,
        new_proof_level: new_proof,
        bytes_before,
        bytes_after,
        fade_policy: policy.policy_id.clone(),
        faded_objects: vec![rec.evidence_id.clone()],
        retained_objects: vec![rec.content_hash.clone()],
        created_at_ms: now_ms(),
        node_signature: None,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            ROLLUP_FOLDER,
            &rollup.rollup_id,
            &serde_json::to_value(&rollup).unwrap_or_default(),
        );
    }

    let tomb = if target == FadeState::F3Skeleton {
        Some(tombstone::create(
            state,
            rec,
            bytes_before,
            prev_proof,
            new_proof,
            &policy.policy_id,
            vec![],
            vec![],
            vec![],
            "rollup_f3_skeleton",
        ))
    } else {
        None
    };

    let mut m = super::metrics::load(state, &rec.agent_vid);
    m.bytes_faded_total += bytes_before.saturating_sub(bytes_after);
    match target {
        FadeState::F0Full => m.f0_count += 1,
        FadeState::F1Distilled => m.f1_count += 1,
        FadeState::F2Decision => m.f2_count += 1,
        FadeState::F3Skeleton => m.f3_count += 1,
    }
    super::metrics::save(state, &m);

    crate::substrate::svf::fade_bind::after_evidence_fade(state, &rec.agent_vid, &rec.evidence_id);

    FadeResult {
        ok: true,
        denied: false,
        reason: None,
        rollup: Some(rollup),
        tombstone: tomb,
    }
}

pub fn run_aging_pass(state: &PlatformState, agent_vid: &str, limit: usize) -> Vec<FadeResult> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let prefix = format!("{agent_vid}:");
    let Ok(keys) = es.folder_keys(
        super::super::evidence::EVIDENCE_INDEX_FOLDER,
        Some(&prefix),
    ) else {
        return vec![];
    };
    drop(es);
    let mut out = Vec::new();
    for k in keys.into_iter().take(limit) {
        let Ok(es) = state.engine_store.lock() else {
            break;
        };
        let Ok(Some(v)) = es.folder_get(super::super::evidence::EVIDENCE_INDEX_FOLDER, &k) else {
            continue;
        };
        drop(es);
        let Ok(rec) = serde_json::from_value::<EvidenceRecord>(v) else {
            continue;
        };
        let policy = policy::resolve(state, agent_vid, None);
        let explain = evaluate(state, &rec, &policy, 0.3);
        if explain.fade_eligible {
            out.push(execute_fade(state, &rec, 0.3));
        }
    }
    out
}
