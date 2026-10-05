//! Fade score — w_t·T + w_s·S + w_c·C + w_a·A + w_r·R + w_u·U + w_h·H (§11).

use connector_trust::{EpistemicClass, FadePolicy, FadeState, ProofLevel};

const WT: f32 = 0.15;
const WS: f32 = 0.10;
const WC: f32 = 0.25;
const WA: f32 = 0.15;
const WR: f32 = 0.20;
const WU: f32 = 0.10;
const WH: f32 = 0.05;

pub struct FadeInputs {
    pub age_ms: i64,
    pub storage_pressure: f32,
    pub causal_importance: f32,
    pub action_relevance: f32,
    pub risk_consequence: f32,
    pub unresolved_dependency: f32,
    pub historical_ref_importance: f32,
    pub epistemic: EpistemicClass,
}

pub fn fade_score(inputs: &FadeInputs) -> f32 {
    let age_norm = (inputs.age_ms as f32 / (30.0 * 86_400_000.0)).clamp(0.0, 1.0);
    let epistemic_penalty = match inputs.epistemic {
        EpistemicClass::Authoritative => -0.5,
        EpistemicClass::Observed => 0.0,
        EpistemicClass::Derived => 0.1,
        EpistemicClass::Inferred => 0.25,
        EpistemicClass::Predicted => 0.35,
    };
    // High score → safe to fade; high causal/consequence/refs → subtract (preserve).
    (WT * age_norm
        + WS * inputs.storage_pressure.clamp(0.0, 1.0)
        - WC * inputs.causal_importance.clamp(0.0, 1.0)
        - WA * inputs.action_relevance.clamp(0.0, 1.0)
        - WR * inputs.risk_consequence.clamp(0.0, 1.0)
        - WU * inputs.unresolved_dependency.clamp(0.0, 1.0)
        - WH * inputs.historical_ref_importance.clamp(0.0, 1.0)
        + epistemic_penalty)
    .clamp(-1.0, 1.0)
}

/// Thresholds for state transitions (§44).
pub const T1: f32 = 0.15;
pub const T2: f32 = 0.45;
pub const T3: f32 = 0.75;

pub fn target_fade_state(current: FadeState, score: f32, policy: &FadePolicy) -> FadeState {
    let _ = policy;
    if score < T1 {
        return FadeState::F0Full;
    }
    if score < T2 {
        return match current {
            FadeState::F0Full => FadeState::F1Distilled,
            other => other,
        };
    }
    if score < T3 {
        return match current {
            FadeState::F0Full | FadeState::F1Distilled => FadeState::F2Decision,
            other => other,
        };
    }
    FadeState::F3Skeleton
}

pub fn proof_for_state(state: FadeState) -> ProofLevel {
    ProofLevel::for_fade_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_causal_lowers_fade_score() {
        let low = fade_score(&FadeInputs {
            age_ms: 90 * 86_400_000,
            storage_pressure: 0.8,
            causal_importance: 0.1,
            action_relevance: 0.1,
            risk_consequence: 0.1,
            unresolved_dependency: 0.0,
            historical_ref_importance: 0.1,
            epistemic: EpistemicClass::Observed,
        });
        let high = fade_score(&FadeInputs {
            age_ms: 90 * 86_400_000,
            storage_pressure: 0.8,
            causal_importance: 0.95,
            action_relevance: 0.1,
            risk_consequence: 0.1,
            unresolved_dependency: 0.0,
            historical_ref_importance: 0.1,
            epistemic: EpistemicClass::Observed,
        });
        assert!(high < low, "high causal should resist fade: high={high} low={low}");
    }

    #[test]
    fn authoritative_resists_fade() {
        let auth = fade_score(&FadeInputs {
            age_ms: 365 * 86_400_000,
            storage_pressure: 0.9,
            causal_importance: 0.2,
            action_relevance: 0.2,
            risk_consequence: 0.2,
            unresolved_dependency: 0.0,
            historical_ref_importance: 0.1,
            epistemic: EpistemicClass::Authoritative,
        });
        assert!(auth < T1);
    }
}
