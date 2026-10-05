//! Context reducer — promotion score P_m and DecisionMemory (§12–§14).

use connector_trust::{
    DecisionMemory, EpistemicClass, MemoryPoint, MemoryTierTarget, DECISION_MEMORY_SCHEMA,
    MEMORY_POINT_SCHEMA,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::state::PlatformState;

pub const POINTS_FOLDER: &str = "agent_memory_points";
pub const DECISIONS_FOLDER: &str = "agent_memory_decisions";

const W1: f32 = 0.30;
const W2: f32 = 0.25;
const W3: f32 = 0.20;
const W4: f32 = 0.15;
const W5: f32 = 0.10;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// P_m = w1*authority + w2*consequence + w3*recency + w4*confidence + w5*volatility
pub fn promotion_score(
    authority: f32,
    consequence: f32,
    recency: f32,
    confidence: f32,
    volatility: f32,
) -> f32 {
    (W1 * authority.clamp(0.0, 1.0)
        + W2 * consequence.clamp(0.0, 1.0)
        + W3 * recency.clamp(0.0, 1.0)
        + W4 * confidence.clamp(0.0, 1.0)
        + W5 * volatility.clamp(0.0, 1.0))
    .clamp(0.0, 1.0)
}

pub fn tier_for_score(score: f32) -> MemoryTierTarget {
    if score >= 0.75 {
        MemoryTierTarget::Hot
    } else if score >= 0.45 {
        MemoryTierTarget::Warm
    } else {
        MemoryTierTarget::EvidenceOnly
    }
}

pub fn store_decision(
    state: &PlatformState,
    agent_vid: &str,
    subject: &str,
    before: &str,
    trigger: &str,
    after: &str,
    reason: &str,
    evidence_refs: Vec<String>,
    confidence: f32,
    consequence: &str,
    context_epoch: u64,
    epistemic: EpistemicClass,
) -> DecisionMemory {
    let dm = DecisionMemory {
        schema: DECISION_MEMORY_SCHEMA.into(),
        decision_id: format!("DM-{}", Uuid::new_v4().simple()),
        subject: subject.into(),
        before_state: before.into(),
        trigger: trigger.into(),
        after_state: after.into(),
        reason: reason.into(),
        authority_ref: None,
        evidence_refs,
        confidence,
        consequence: consequence.into(),
        context_epoch,
        epistemic_class: epistemic,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("{agent_vid}:{}", dm.decision_id);
        let _ = es.folder_put(
            DECISIONS_FOLDER,
            &key,
            &serde_json::to_value(&dm).unwrap_or_default(),
        );
    }
    dm
}

pub fn store_point(
    state: &PlatformState,
    agent_vid: &str,
    entity: &str,
    consequence: &str,
    state_label: &str,
    confidence: f32,
    entropy: f32,
    volatility: f32,
    evidence_ref: &str,
    context_epoch: u64,
    epistemic: EpistemicClass,
) -> MemoryPoint {
    let point_id = format!(
        "MP-{}",
        &format!(
            "{:x}",
            Sha256::digest(format!("{agent_vid}{entity}{}", now_ms()).as_bytes())
        )[..16]
    );
    let mp = MemoryPoint {
        schema: MEMORY_POINT_SCHEMA.into(),
        point_id: point_id.clone(),
        time_ms: now_ms(),
        entity: entity.into(),
        consequence: consequence.into(),
        state: state_label.into(),
        confidence,
        entropy,
        volatility,
        evidence_ref: evidence_ref.into(),
        context_epoch,
        epistemic_class: epistemic,
        proof_level: connector_trust::ProofLevel::P0Full,
        fade_state: connector_trust::FadeState::F0Full,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("{agent_vid}:{point_id}");
        let _ = es.folder_put(
            POINTS_FOLDER,
            &key,
            &serde_json::to_value(&mp).unwrap_or_default(),
        );
    }
    mp
}

pub fn recent_decision_summaries(state: &PlatformState, agent_vid: &str, limit: usize) -> Vec<String> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let prefix = format!("{agent_vid}:");
    let Ok(keys) = es.folder_keys(DECISIONS_FOLDER, Some(&prefix)) else {
        return vec![];
    };
    let mut out = Vec::new();
    for k in keys.into_iter().rev().take(limit) {
        if let Ok(Some(v)) = es.folder_get(DECISIONS_FOLDER, &k) {
            if let Ok(dm) = serde_json::from_value::<DecisionMemory>(v) {
                out.push(format!(
                    "{}: {} → {} ({})",
                    dm.subject, dm.before_state, dm.after_state, dm.reason
                ));
            }
        }
    }
    out
}

pub fn hot_points(state: &PlatformState, agent_vid: &str, limit: usize) -> Vec<String> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let prefix = format!("{agent_vid}:");
    let Ok(keys) = es.folder_keys(POINTS_FOLDER, Some(&prefix)) else {
        return vec![];
    };
    let mut out = Vec::new();
    for k in keys.into_iter().rev().take(limit) {
        if let Ok(Some(v)) = es.folder_get(POINTS_FOLDER, &k) {
            if let Ok(mp) = serde_json::from_value::<MemoryPoint>(v) {
                let score = promotion_score(0.5, 0.5, 0.8, mp.confidence, mp.volatility);
                if tier_for_score(score) == MemoryTierTarget::Hot {
                    out.push(format!("{}: {} ({})", mp.entity, mp.state, mp.consequence));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promotion_score_bounds() {
        let s = promotion_score(1.0, 1.0, 1.0, 1.0, 1.0);
        assert!((s - 1.0).abs() < 0.001);
        let s2 = promotion_score(0.0, 0.0, 0.0, 0.0, 0.0);
        assert!(s2 < 0.01);
    }
}
