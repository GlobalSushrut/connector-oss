//! Rollup invariant tests (§69–§71).

#[cfg(test)]
mod invariant_tests {
    use connector_trust::{EpistemicClass, FadePolicy, FadeState, ProofLevel};
    use crate::substrate::agent_memory::rollup::fade::{
        fade_score, target_fade_state, FadeInputs, T1,
    };
    use crate::substrate::agent_memory::rollup::eligibility::default_policy;

    #[test]
    fn fade_lock_epistemic_e0_resists_fade() {
        let score = fade_score(&FadeInputs {
            age_ms: 400 * 86_400_000,
            storage_pressure: 0.95,
            causal_importance: 0.1,
            action_relevance: 0.1,
            risk_consequence: 0.1,
            unresolved_dependency: 0.0,
            historical_ref_importance: 0.1,
            epistemic: EpistemicClass::Authoritative,
        });
        assert!(score < T1, "E0 authority should resist fade");
    }

    #[test]
    fn proof_level_tracks_fade_state() {
        assert_eq!(
            ProofLevel::for_fade_state(FadeState::F1Distilled),
            ProofLevel::P1Distilled
        );
    }

    #[test]
    fn high_consequence_preserves_f0_longer() {
        let policy = default_policy();
        let low = target_fade_state(
            FadeState::F0Full,
            fade_score(&FadeInputs {
                age_ms: 60 * 86_400_000,
                storage_pressure: 0.5,
                causal_importance: 0.05,
                action_relevance: 0.05,
                risk_consequence: 0.05,
                unresolved_dependency: 0.0,
                historical_ref_importance: 0.05,
                epistemic: EpistemicClass::Observed,
            }),
            &policy,
        );
        let high = target_fade_state(
            FadeState::F0Full,
            fade_score(&FadeInputs {
                age_ms: 60 * 86_400_000,
                storage_pressure: 0.5,
                causal_importance: 0.9,
                action_relevance: 0.8,
                risk_consequence: 0.95,
                unresolved_dependency: 0.0,
                historical_ref_importance: 0.5,
                epistemic: EpistemicClass::Observed,
            }),
            &policy,
        );
        assert_eq!(low, FadeState::F1Distilled);
        assert_eq!(high, FadeState::F0Full);
    }
}
