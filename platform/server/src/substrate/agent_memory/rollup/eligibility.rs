//! Rollup eligibility — FadeLock, retention policy, reference counts (§12–§16, §44–§45).

use connector_trust::{EvidenceRecord, FadeLock, FadePolicy, FadeState, RollupExplain};
use serde_json::{json, Value};

use crate::state::PlatformState;

use super::fade::{fade_score, target_fade_state, FadeInputs, T1, T2, T3};

pub const META_FOLDER: &str = "agent_memory_evidence_meta";
pub const LOCK_FOLDER: &str = "agent_memory_fade_locks";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvidenceMeta {
    #[serde(default = "default_meta_fade")]
    pub fade_state: connector_trust::FadeState,
    pub bytes: u64,
    pub causal_ref_count: u64,
    pub decision_ref_count: u64,
    pub authority_ref_count: u64,
    pub action_ref_count: u64,
    pub open_dependency_count: u64,
    pub incident_ref_count: u64,
    pub consequence: f32,
    pub distilled_excerpts: Vec<String>,
    pub normalized_facts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_class: Option<String>,
}

fn default_meta_fade() -> connector_trust::FadeState {
    connector_trust::FadeState::F0Full
}

impl Default for EvidenceMeta {
    fn default() -> Self {
        Self {
            fade_state: connector_trust::FadeState::F0Full,
            bytes: 0,
            causal_ref_count: 0,
            decision_ref_count: 0,
            authority_ref_count: 0,
            action_ref_count: 0,
            open_dependency_count: 0,
            incident_ref_count: 0,
            consequence: 0.0,
            distilled_excerpts: vec![],
            normalized_facts: vec![],
            evidence_class: None,
        }
    }
}

pub fn load_meta(state: &PlatformState, agent_vid: &str, evidence_id: &str) -> EvidenceMeta {
    let key = format!("{agent_vid}:{evidence_id}");
    let Ok(es) = state.engine_store.lock() else {
        return EvidenceMeta {
            fade_state: FadeState::F0Full,
            ..Default::default()
        };
    };
    if let Ok(Some(v)) = es.folder_get(META_FOLDER, &key) {
        return serde_json::from_value(v).unwrap_or_default();
    }
    EvidenceMeta {
        fade_state: FadeState::F0Full,
        ..Default::default()
    }
}

pub fn save_meta(
    state: &PlatformState,
    agent_vid: &str,
    evidence_id: &str,
    meta: &EvidenceMeta,
) {
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("{agent_vid}:{evidence_id}");
        let _ = es.folder_put(
            META_FOLDER,
            &key,
            &serde_json::to_value(meta).unwrap_or_default(),
        );
    }
}

pub fn init_meta_from_record(state: &PlatformState, rec: &EvidenceRecord, content_len: usize) {
    let mut meta = load_meta(state, &rec.agent_vid, &rec.evidence_id);
    if meta.bytes == 0 {
        meta.bytes = content_len as u64;
        meta.fade_state = rec.fade_state;
        save_meta(state, &rec.agent_vid, &rec.evidence_id, &meta);
    }
}

pub fn has_fade_lock(state: &PlatformState, agent_vid: &str, evidence_id: &str) -> Option<FadeLock> {
    let es = state.engine_store.lock().ok()?;
    let key = format!("{agent_vid}:{evidence_id}");
    let v = es.folder_get(LOCK_FOLDER, &key).ok().flatten()?;
    let lock: FadeLock = serde_json::from_value(v).ok()?;
    if let Some(exp) = lock.expires_at_ms {
        if now_ms() > exp {
            return None;
        }
    }
    Some(lock)
}

pub fn put_fade_lock(
    state: &PlatformState,
    agent_vid: &str,
    evidence_id: &str,
    reason: &str,
    expires_at_ms: Option<i64>,
    policy_ref: Option<String>,
) -> FadeLock {
    let lock = FadeLock {
        schema: connector_trust::FADE_LOCK_SCHEMA.into(),
        evidence_id: evidence_id.into(),
        agent_vid: agent_vid.into(),
        reason: reason.into(),
        created_at_ms: now_ms(),
        expires_at_ms,
        policy_ref,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("{agent_vid}:{evidence_id}");
        let _ = es.folder_put(
            LOCK_FOLDER,
            &key,
            &serde_json::to_value(&lock).unwrap_or_default(),
        );
    }
    lock
}

pub fn evaluate(
    state: &PlatformState,
    rec: &EvidenceRecord,
    policy: &FadePolicy,
    storage_pressure: f32,
) -> RollupExplain {
    let meta = load_meta(state, &rec.agent_vid, &rec.evidence_id);
    let age_ms = now_ms().saturating_sub(rec.ingest_time_ms);
    let score = fade_score(&FadeInputs {
        age_ms,
        storage_pressure,
        causal_importance: (meta.causal_ref_count as f32 * 0.05).clamp(0.0, 1.0),
        action_relevance: (meta.action_ref_count as f32 * 0.1).clamp(0.0, 1.0),
        risk_consequence: meta.consequence.clamp(0.0, 1.0),
        unresolved_dependency: (meta.open_dependency_count as f32 * 0.2).clamp(0.0, 1.0),
        historical_ref_importance: ((meta.decision_ref_count + meta.incident_ref_count) as f32
            * 0.08)
            .clamp(0.0, 1.0),
        epistemic: rec.epistemic_class,
    });
    let target = target_fade_state(meta.fade_state, score, policy);
    let lock = has_fade_lock(state, &rec.agent_vid, &rec.evidence_id);
    let proof = connector_trust::ProofLevel::for_fade_state(meta.fade_state);
    let next_proof = connector_trust::ProofLevel::for_fade_state(
        meta.fade_state.next().unwrap_or(meta.fade_state),
    );

    let (eligible, denied) = if lock.is_some() {
        (false, Some("fade_lock".into()))
    } else if policy.legal_retention {
        (false, Some("legal_retention_required".into()))
    } else if policy
        .minimum_proof_level
        .is_some_and(|min| proof_rank(next_proof) > proof_rank(min))
    {
        (false, Some("minimum_proof_level".into()))
    } else if rec.epistemic_class == connector_trust::EpistemicClass::Authoritative
        && meta.authority_ref_count > 0
    {
        (false, Some("E0_authority_retention".into()))
    } else if meta.open_dependency_count > 0 {
        (false, Some("unresolved_dependency".into()))
    } else if target == meta.fade_state {
        (false, Some("already_at_target".into()))
    } else {
        (true, None)
    };

    RollupExplain {
        schema: "connector.rollup.explain.v1".into(),
        evidence_id: rec.evidence_id.clone(),
        fade_state: meta.fade_state,
        proof_level: proof,
        fade_score: score,
        fade_eligible: eligible,
        fade_denied_reason: denied,
        causal_ref_count: meta.causal_ref_count,
        decision_ref_count: meta.decision_ref_count,
        tracetramp_display: tracetramp_display(&rec.evidence_id, meta.fade_state, proof, score),
    }
}

fn proof_rank(p: connector_trust::ProofLevel) -> u8 {
    match p {
        connector_trust::ProofLevel::P0Full => 0,
        connector_trust::ProofLevel::P1Distilled => 1,
        connector_trust::ProofLevel::P2Contextual => 2,
        connector_trust::ProofLevel::P3Commitment => 3,
    }
}

pub fn tracetramp_display(
    evidence_id: &str,
    fade_state: FadeState,
    proof: connector_trust::ProofLevel,
    score: f32,
) -> Value {
    json!({
        "evidence_id": evidence_id,
        "fade_state": fade_state.as_str(),
        "proof_level": proof.as_str(),
        "proof_symbol": proof.tracetramp_symbol(),
        "fade_score": score,
        "thresholds": { "T1": T1, "T2": T2, "T3": T3 },
        "raw_available": matches!(fade_state, FadeState::F0Full),
        "distilled_available": matches!(fade_state, FadeState::F0Full | FadeState::F1Distilled),
        "decision_reconstruction": !matches!(fade_state, FadeState::F3Skeleton),
    })
}

pub fn default_policy() -> FadePolicy {
    FadePolicy::default()
}
