//! EffectProposal — intelligence proposes; governor evaluates.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::governor_input::hex_sha256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EffectProposal {
    pub schema: String,
    pub agent_id: String,
    pub capability: String,
    pub target: String,
    pub operation: String,
    pub information_labels: Value,
    pub state_digest: String,
    pub consequence_estimate: Option<String>,
    pub digest: String,
}

impl EffectProposal {
    pub const SCHEMA: &'static str = "connector.arc.effect_proposal.v1";

    pub fn new(
        agent_id: impl Into<String>,
        capability: impl Into<String>,
        target: impl Into<String>,
        operation: impl Into<String>,
        state_digest: impl Into<String>,
    ) -> Self {
        let mut p = Self {
            schema: Self::SCHEMA.into(),
            agent_id: agent_id.into(),
            capability: capability.into(),
            target: target.into(),
            operation: operation.into(),
            information_labels: json!({}),
            state_digest: state_digest.into(),
            consequence_estimate: None,
            digest: String::new(),
        };
        p.digest = p.compute_digest();
        p
    }

    pub fn compute_digest(&self) -> String {
        let body = json!({
            "agent_id": self.agent_id,
            "capability": self.capability,
            "target": self.target,
            "operation": self.operation,
            "information_labels": self.information_labels,
            "state_digest": self.state_digest,
            "consequence_estimate": self.consequence_estimate,
        });
        hex_sha256(&body)
    }
}
