//! Cognitive regime classification from Z_t.

use super::state::{CognitiveRegime, DynamicIntelligenceState};

/// Classify regime from current coordinates (deterministic heuristics).
pub fn classify(z: &DynamicIntelligenceState) -> CognitiveRegime {
    if z.self_continuity < 0.5 {
        return CognitiveRegime::Discontinuous;
    }
    if z.resource_potential < 0.2 {
        return CognitiveRegime::ResourceStarved;
    }
    if z.resource_potential < 0.35 && z.entropy > 0.7 {
        return CognitiveRegime::Saturated;
    }
    if z.interference > 0.65 {
        return CognitiveRegime::Conflicted;
    }
    if z.precision < 0.4 {
        return CognitiveRegime::LowPrecision;
    }
    if z.prediction_error > 0.7 && z.coherence < 0.5 {
        return CognitiveRegime::Unstable;
    }
    if z.temporal_pressure > 0.85 && z.goal_tension < 0.15 {
        return CognitiveRegime::Waiting;
    }
    if z.goal_tension < 0.1 && z.prediction_error < 0.2 {
        return CognitiveRegime::Dormant;
    }
    if z.consequence_pressure > 0.7 && z.prediction_error > 0.35 {
        return CognitiveRegime::Deliberative;
    }
    if z.cognitive_temperature > 0.65 {
        return CognitiveRegime::Exploratory;
    }
    if z.consolidation > 0.7 && z.prediction_error < 0.25 {
        return CognitiveRegime::Consolidating;
    }
    if z.goal_tension > 0.55 && z.precision >= 0.55 {
        return CognitiveRegime::Focused;
    }
    if z.prediction_error > 0.4 {
        return CognitiveRegime::Orienting;
    }
    CognitiveRegime::Observing
}

pub fn apply_regime(z: &mut DynamicIntelligenceState) {
    z.regime = classify(z);
}
