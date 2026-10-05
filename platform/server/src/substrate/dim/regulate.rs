//! Bounded regulation actions — authority-neutral only.

use serde_json::{json, Value};

use super::persist;
use super::state::{DynamicIntelligenceState, RegulationAction};
use crate::state::PlatformState;

/// Propose micro-regulation from Φ_I and regime (no authority change).
pub fn propose_regulation(z: &DynamicIntelligenceState) -> RegulationAction {
    if z.interference > 0.55 || z.precision < 0.45 {
        return RegulationAction::IncreaseVerification;
    }
    if z.prediction_error > 0.45 {
        return RegulationAction::RefreshWorldEvidence;
    }
    if z.interference > 0.4 {
        return RegulationAction::IncreaseRecallRadius;
    }
    if z.resource_potential < 0.35 || z.homeodynamic_potential > 0.4 {
        return RegulationAction::DecreaseCandidateBreadth;
    }
    if z.consequence_pressure > 0.7 {
        return RegulationAction::IncreaseCounterfactualDepth;
    }
    if z.temporal_pressure > 0.8 && z.goal_tension > 0.3 {
        return RegulationAction::WakeCognition;
    }
    if z.regime.is_degraded() && z.homeodynamic_potential > 0.5 {
        return RegulationAction::IncreaseHumanCoupling;
    }
    if z.interference > 0.35 {
        return RegulationAction::PauseConsolidation;
    }
    if z.cognitive_temperature > 0.7 {
        return RegulationAction::IncreaseCandidateBreadth;
    }
    if z.goal_tension < 0.15 && z.temporal_pressure < 0.3 {
        return RegulationAction::EnterWaiting;
    }
    RegulationAction::None
}

/// Apply regulation: record on state + journal. Does not touch grants/NF³.
pub fn apply_regulation(
    state: &PlatformState,
    z: &mut DynamicIntelligenceState,
    action: RegulationAction,
) -> Value {
    debug_assert!(action.is_authority_neutral());
    z.last_regulation = action;
    z.revision = z.revision.saturating_add(1);
    z.measured_at_ms = super::state::now_ms();
    // Soft cognitive nudges reflected in Z (still not authority).
    match action {
        RegulationAction::IncreaseVerification => {
            z.consequence_pressure = (z.consequence_pressure + 0.05).min(1.0);
        }
        RegulationAction::PauseConsolidation => {
            z.consolidation = (z.consolidation - 0.1).max(0.0);
            z.plasticity = (z.plasticity - 0.05).max(0.0);
        }
        RegulationAction::ResumeConsolidation => {
            z.consolidation = (z.consolidation + 0.05).min(1.0);
        }
        RegulationAction::DecreaseCandidateBreadth => {
            z.cognitive_temperature = (z.cognitive_temperature - 0.08).max(0.1);
        }
        RegulationAction::IncreaseCandidateBreadth => {
            z.cognitive_temperature = (z.cognitive_temperature + 0.08).min(0.95);
        }
        RegulationAction::IncreaseHumanCoupling => {
            z.consequence_pressure = (z.consequence_pressure + 0.1).min(1.0);
        }
        RegulationAction::EnterWaiting => {
            z.temporal_pressure = (z.temporal_pressure * 0.9).max(0.0);
        }
        RegulationAction::WakeCognition => {
            // Cognitive cue: lower waiting, raise temporal awareness briefly.
            z.temporal_pressure = (z.temporal_pressure * 0.7).max(0.15);
            z.metastability = (z.metastability + 0.08).min(1.0);
            z.cognitive_temperature = (z.cognitive_temperature + 0.05).min(0.95);
        }
        RegulationAction::IncreaseRecallRadius | RegulationAction::DecreaseRecallRadius => {
            // Radius applied by knot_belief_field::recall_radius_multiplier via last_regulation.
        }
        _ => {}
    }
    z.clamp_all();
    z.recompute_phi();
    let _ = persist::save(state, z);
    persist::journal(state, z, action);
    json!({
        "ok": true,
        "action": action.as_str(),
        "authority": "unchanged",
        "revision": z.revision,
        "regime": z.regime.as_str(),
        "honesty": "DIM-INV-01 — regulation is cognitive elasticity only",
    })
}
