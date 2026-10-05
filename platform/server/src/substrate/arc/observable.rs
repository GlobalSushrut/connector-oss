//! Observable cognitive state (hat Z) — never claimed complete latent LLM state.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::governor_input::hex_sha256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ObservableState {
    pub schema: String,
    /// Digests of recent model/tool proposals (not raw CoT).
    pub proposal_digests: Vec<String>,
    pub memory_mutation_digests: Vec<String>,
    pub knowledge_digests: Vec<String>,
    pub policy_entropy_est: Option<f64>,
    pub commitment_digests: Vec<String>,
    pub effect_history_head: Option<String>,
    pub denial_count: u64,
    pub budget_remaining_hint: Option<u64>,
    pub posture_label: Option<String>,
    pub ifc_provenance_digests: Vec<String>,
    /// Control-relevant DIM/Knot digests only — not private activation state.
    pub dim_operator_digest: Option<String>,
    pub knot_digest: Option<String>,
}

impl ObservableState {
    pub const SCHEMA: &'static str = "connector.arc.observable.v1";

    pub fn empty_placeholder() -> Self {
        Self {
            schema: Self::SCHEMA.into(),
            ..Default::default()
        }
    }

    pub fn digest(&self) -> String {
        let body = json!({
            "proposal_digests": self.proposal_digests,
            "memory_mutation_digests": self.memory_mutation_digests,
            "knowledge_digests": self.knowledge_digests,
            "policy_entropy_est": self.policy_entropy_est,
            "commitment_digests": self.commitment_digests,
            "effect_history_head": self.effect_history_head,
            "denial_count": self.denial_count,
            "budget_remaining_hint": self.budget_remaining_hint,
            "posture_label": self.posture_label,
            "ifc_provenance_digests": self.ifc_provenance_digests,
            "dim_operator_digest": self.dim_operator_digest,
            "knot_digest": self.knot_digest,
        });
        hex_sha256(&body)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema": self.schema,
            "digest": self.digest(),
            "denial_count": self.denial_count,
            "honesty": "hat Z only — latent LLM state is unobservable and never used as Allow",
        })
    }
}
