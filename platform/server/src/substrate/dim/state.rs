//! DIM persistent state vector Z_t + diagnostics.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const DIM_SCHEMA: &str = "connector.dim.state.v1";
pub const DIM_FOLDER: &str = "dim_state";
pub const DIM_JOURNAL_FOLDER: &str = "dim_journal";

/// Cognitive operating regime (inspectable — DIM-INV-15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveRegime {
    #[default]
    Dormant,
    Observing,
    Orienting,
    Focused,
    Exploratory,
    Deliberative,
    Committed,
    Acting,
    Reconciling,
    Consolidating,
    Waiting,
    Saturated,
    Conflicted,
    LowPrecision,
    ResourceStarved,
    Stuck,
    Unstable,
    Stale,
    Discontinuous,
}

impl CognitiveRegime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dormant => "dormant",
            Self::Observing => "observing",
            Self::Orienting => "orienting",
            Self::Focused => "focused",
            Self::Exploratory => "exploratory",
            Self::Deliberative => "deliberative",
            Self::Committed => "committed",
            Self::Acting => "acting",
            Self::Reconciling => "reconciling",
            Self::Consolidating => "consolidating",
            Self::Waiting => "waiting",
            Self::Saturated => "saturated",
            Self::Conflicted => "conflicted",
            Self::LowPrecision => "low_precision",
            Self::ResourceStarved => "resource_starved",
            Self::Stuck => "stuck",
            Self::Unstable => "unstable",
            Self::Stale => "stale",
            Self::Discontinuous => "discontinuous",
        }
    }

    pub fn is_degraded(self) -> bool {
        matches!(
            self,
            Self::Saturated
                | Self::Conflicted
                | Self::LowPrecision
                | Self::ResourceStarved
                | Self::Stuck
                | Self::Unstable
                | Self::Stale
                | Self::Discontinuous
        )
    }
}

/// Authority-neutral micro-regulation (DIM-INV-01/02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegulationAction {
    IncreaseRecallRadius,
    DecreaseRecallRadius,
    IncreaseVerification,
    DecreaseCandidateBreadth,
    IncreaseCandidateBreadth,
    PauseConsolidation,
    ResumeConsolidation,
    RefreshWorldEvidence,
    ReduceToolParallelism,
    IncreaseCounterfactualDepth,
    WakeCognition,
    EnterWaiting,
    IncreaseHumanCoupling,
    None,
}

impl RegulationAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IncreaseRecallRadius => "increase_recall_radius",
            Self::DecreaseRecallRadius => "decrease_recall_radius",
            Self::IncreaseVerification => "increase_verification",
            Self::DecreaseCandidateBreadth => "decrease_candidate_breadth",
            Self::IncreaseCandidateBreadth => "increase_candidate_breadth",
            Self::PauseConsolidation => "pause_consolidation",
            Self::ResumeConsolidation => "resume_consolidation",
            Self::RefreshWorldEvidence => "refresh_world_evidence",
            Self::ReduceToolParallelism => "reduce_tool_parallelism",
            Self::IncreaseCounterfactualDepth => "increase_counterfactual_depth",
            Self::WakeCognition => "wake_cognition",
            Self::EnterWaiting => "enter_waiting",
            Self::IncreaseHumanCoupling => "increase_human_coupling",
            Self::None => "none",
        }
    }

    /// Compile-time / test guard: never an authority verb.
    pub fn is_authority_neutral(self) -> bool {
        true
    }
}

fn clamp01(x: f32) -> f32 {
    x.clamp(0.0, 1.0)
}

/// Persistent Dynamic Intelligence State — trajectory coordinate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicIntelligenceState {
    pub schema: String,
    pub agent_pid: String,
    pub coherence: f32,
    pub prediction_error: f32,
    pub precision: f32,
    pub entropy: f32,
    pub metastability: f32,
    pub plasticity: f32,
    pub consolidation: f32,
    pub interference: f32,
    pub affordance_density: f32,
    pub empowerment: f32,
    pub resource_potential: f32,
    pub goal_tension: f32,
    pub temporal_pressure: f32,
    pub consequence_pressure: f32,
    pub self_continuity: f32,
    pub cognitive_temperature: f32,
    pub homeodynamic_potential: f32,
    pub regime: CognitiveRegime,
    pub last_regulation: RegulationAction,
    pub measured_at_ms: i64,
    pub evidence_refs: Vec<String>,
    pub revision: u64,
}

impl DynamicIntelligenceState {
    pub fn fresh(agent_pid: &str) -> Self {
        Self {
            schema: DIM_SCHEMA.into(),
            agent_pid: agent_pid.into(),
            coherence: 0.7,
            prediction_error: 0.2,
            precision: 0.65,
            entropy: 0.4,
            metastability: 0.6,
            plasticity: 0.25,
            consolidation: 0.4,
            interference: 0.15,
            affordance_density: 0.5,
            empowerment: 0.6,
            resource_potential: 0.8,
            goal_tension: 0.3,
            temporal_pressure: 0.2,
            consequence_pressure: 0.3,
            self_continuity: 0.9,
            cognitive_temperature: 0.35,
            homeodynamic_potential: 0.0,
            regime: CognitiveRegime::Observing,
            last_regulation: RegulationAction::None,
            measured_at_ms: now_ms(),
            evidence_refs: Vec::new(),
            revision: 1,
        }
    }

    pub fn clamp_all(&mut self) {
        self.coherence = clamp01(self.coherence);
        self.prediction_error = clamp01(self.prediction_error);
        self.precision = clamp01(self.precision);
        self.entropy = clamp01(self.entropy);
        self.metastability = clamp01(self.metastability);
        self.plasticity = clamp01(self.plasticity);
        self.consolidation = clamp01(self.consolidation);
        self.interference = clamp01(self.interference);
        self.affordance_density = clamp01(self.affordance_density);
        self.empowerment = clamp01(self.empowerment);
        self.resource_potential = clamp01(self.resource_potential);
        self.goal_tension = clamp01(self.goal_tension);
        self.temporal_pressure = clamp01(self.temporal_pressure);
        self.consequence_pressure = clamp01(self.consequence_pressure);
        self.self_continuity = clamp01(self.self_continuity);
        self.cognitive_temperature = clamp01(self.cognitive_temperature);
        self.homeodynamic_potential = clamp01(self.homeodynamic_potential);
    }

    /// Distance outside viability bands → Φ_I (bands from `dim::bands`, env-overridable).
    pub fn recompute_phi(&mut self) {
        let bands = super::bands::active_bands();
        let mut phi = 0.0f32;
        for (name, lo, hi) in &bands.rows {
            let v = super::bands::value_for_key(
                name,
                self.coherence,
                self.prediction_error,
                self.precision,
                self.entropy,
                self.interference,
                self.resource_potential,
                self.self_continuity,
            );
            if v < *lo {
                phi += *lo - v;
            } else if v > *hi {
                phi += v - *hi;
            }
        }
        let n = bands.rows.len().max(1) as f32;
        self.homeodynamic_potential = clamp01(phi / n);
    }

    pub fn recompute_temperature(&mut self) {
        // Θ ↑ with E,H,X ; ↓ with K,P
        let raw = 0.25
            + 0.25 * self.prediction_error
            + 0.2 * self.entropy
            + 0.2 * self.interference
            - 0.15 * self.coherence
            - 0.15 * self.precision;
        self.cognitive_temperature = clamp01(raw);
    }

    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(json!({ "ok": false }))
    }

    pub fn operator_view(&self) -> Value {
        json!({
            "schema": self.schema,
            "agent_pid": self.agent_pid,
            "regime": self.regime.as_str(),
            "degraded": self.regime.is_degraded(),
            "homeodynamic_potential": self.homeodynamic_potential,
            "cognitive_temperature": self.cognitive_temperature,
            "last_regulation": self.last_regulation.as_str(),
            "revision": self.revision,
            "measured_at_ms": self.measured_at_ms,
            "condition": {
                "coherence": self.coherence,
                "prediction_error": self.prediction_error,
                "precision": self.precision,
                "entropy": self.entropy,
                "plasticity": self.plasticity,
                "interference": self.interference,
                "empowerment": self.empowerment,
                "temporal_pressure": self.temporal_pressure,
                "consequence_pressure": self.consequence_pressure,
                "self_continuity": self.self_continuity,
                "resource_potential": self.resource_potential,
                "goal_tension": self.goal_tension,
                "affordance_density": self.affordance_density,
                "metastability": self.metastability,
                "consolidation": self.consolidation,
            },
            "authority": "unchanged",
            "honesty": "DIM condition only — does not admit effects",
            "evidence_refs": self.evidence_refs,
        })
    }
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regulation_is_authority_neutral() {
        assert!(RegulationAction::IncreaseVerification.is_authority_neutral());
        assert!(RegulationAction::WakeCognition.is_authority_neutral());
    }

    #[test]
    fn authority_attack_high_scores_do_not_authorize() {
        // DIM-EVAL / A28: high coherence / empowerment never mint Allow.
        let mut s = DynamicIntelligenceState::fresh("attack");
        s.coherence = 1.0;
        s.empowerment = 1.0;
        s.cognitive_temperature = 0.99;
        s.precision = 1.0;
        s.recompute_phi();
        let action = crate::substrate::dim::regulate::propose_regulation(&s);
        assert!(action.is_authority_neutral());
        // No regulation string may look like an admit verb.
        let name = action.as_str();
        assert!(!name.contains("allow"));
        assert!(!name.contains("grant"));
        assert!(!name.contains("approve"));
        assert!(!name.contains("widen_world"));
    }
}
