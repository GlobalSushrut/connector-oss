//! DIM observers + estimators — deterministic v0 heuristics.

use super::persist;
use super::regime;
use super::state::DynamicIntelligenceState;
use crate::state::PlatformState;
use crate::substrate::affordance_envelope;
use crate::substrate::kecs_sot;
use crate::substrate::trajectory_budget;

/// Refresh Z_t from live Knot / KECS / affordances / trajectory — then classify.
pub fn refresh_for_agent(state: &PlatformState, agent_pid: &str) -> DynamicIntelligenceState {
    let mut z = persist::load(state, agent_pid);
    let mut evidence = Vec::new();

    // KECS / entropy → H, partial E
    let kecs = kecs_sot::live_kecs(state, agent_pid);
    if let Some(k) = kecs.get("kecs").and_then(|v| v.as_f64()) {
        // High KECS → lower entropy disorder for cognition display (invert soft)
        let disorder = (1.0 - k as f32).clamp(0.0, 1.0);
        z.entropy = 0.6 * z.entropy + 0.4 * disorder;
        evidence.push(format!("kecs:{k:.3}"));
    }
    if let Some(nodes) = kecs
        .pointer("/sources/knot_nodes")
        .and_then(|v| v.as_f64())
    {
        if nodes > 0.0 {
            z.self_continuity = (z.self_continuity * 0.7 + 0.3).min(1.0);
            evidence.push(format!("knot_nodes:{nodes}"));
        }
    }

    // Affordance density from compiled envelope
    let env = affordance_envelope::compile(state, agent_pid);
    let slots = env.slots.len() as f32;
    z.affordance_density = (slots / 16.0).clamp(0.05, 1.0);
    if !env.knot21_hint.is_empty() {
        evidence.push(format!("knot21:{}", env.knot21_hint));
    }

    // Goal / resource from trajectory budget if any open mission key
    // Use agent_pid as soft key when mission unknown
    let tb = trajectory_budget::load_or_create(state, agent_pid, agent_pid);
    if tb.max_effects > 0 {
        let used = tb.effect_count as f32 / tb.max_effects as f32;
        z.resource_potential = (1.0 - used).clamp(0.05, 1.0);
        z.goal_tension = if tb.exhausted {
            0.15
        } else {
            (0.2 + 0.5 * used).clamp(0.0, 1.0)
        };
        if tb.blast_radius > 0.0 {
            z.consequence_pressure =
                (0.5 * z.consequence_pressure + 0.5 * tb.blast_radius.clamp(0.0, 1.0)).min(1.0);
        }
    }

    // CIP inhibition → lower empowerment / higher waiting pressure
    if let Some(cip) = crate::substrate::cip_executive::load_for_agent(state, agent_pid) {
        if cip.inhibition.blocked {
            z.empowerment = (z.empowerment * 0.7).max(0.1);
            z.temporal_pressure = (z.temporal_pressure + 0.15).min(1.0);
            evidence.push("cip:inhibited".into());
        }
        z.goal_tension = (z.goal_tension * 0.5 + 0.5 * cip.uncertainty).clamp(0.0, 1.0);
    }

    // Belief coverage → coherence / precision
    let belief = crate::substrate::belief_snapshot::project_from_vac(state, "_dim", agent_pid);
    if !belief.claims.is_empty() {
        z.coherence = (0.5 * z.coherence + 0.5 * belief.coverage).clamp(0.0, 1.0);
        let contrad = belief
            .claims
            .iter()
            .filter(|c| {
                matches!(
                    c.status,
                    crate::substrate::belief_snapshot::ClaimStatus::Contradicted
                )
            })
            .count() as f32;
        let ratio = contrad / belief.claims.len() as f32;
        z.interference = (0.4 * z.interference + 0.6 * ratio).clamp(0.0, 1.0);
        z.precision = (z.precision * (1.0 - 0.3 * ratio)).clamp(0.05, 1.0);
        evidence.push(format!("belief_rev:{}", belief.revision));
    }

    // Metastability from entropy × error
    z.metastability = (1.0 - (z.entropy * z.prediction_error).sqrt()).clamp(0.0, 1.0);

    // Plasticity: conservative under high Q or weak P
    z.plasticity = (0.35 * (1.0 - z.consequence_pressure) * z.precision
        + 0.2 * z.prediction_error)
        .clamp(0.05, 0.6);

    z.evidence_refs = evidence;
    z.measured_at_ms = super::state::now_ms();
    z.revision = z.revision.saturating_add(1);
    z.recompute_temperature();
    z.recompute_phi();
    regime::apply_regime(&mut z);
    z.clamp_all();
    let _ = persist::save(state, &z);
    z
}
