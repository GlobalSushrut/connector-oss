//! Typed governor input — hat Z only. Latent / private DIM blobs are unrepresentable.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::observable::ObservableState;

/// Closed set of observations the Agency Governor may use.
///
/// Compile-time fence: do not add free-form `serde_json::Value` “dim_private” fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GovernorInput {
    pub schema: String,
    pub agent_id: String,
    pub observable: ObservableState,
    pub proposal_digest: Option<String>,
    pub authority_epoch: u64,
    pub autonomy_volume_digest: String,
    pub body_id: Option<String>,
}

impl GovernorInput {
    pub const SCHEMA: &'static str = "connector.arc.governor_input.v1";

    pub fn from_observable(
        agent_id: impl Into<String>,
        observable: ObservableState,
        authority_epoch: u64,
        autonomy_volume_digest: impl Into<String>,
        body_id: Option<String>,
        proposal_digest: Option<String>,
    ) -> Self {
        Self {
            schema: Self::SCHEMA.into(),
            agent_id: agent_id.into(),
            observable,
            proposal_digest,
            authority_epoch,
            autonomy_volume_digest: autonomy_volume_digest.into(),
            body_id,
        }
    }

    pub fn digest(&self) -> String {
        let body = json!({
            "agent_id": self.agent_id,
            "observable": self.observable.digest(),
            "proposal_digest": self.proposal_digest,
            "authority_epoch": self.authority_epoch,
            "autonomy_volume_digest": self.autonomy_volume_digest,
            "body_id": self.body_id,
        });
        hex_sha256(&body)
    }
}

pub(crate) fn hex_sha256(v: &Value) -> String {
    let bytes = serde_json::to_vec(v).unwrap_or_default();
    format!("{:x}", Sha256::digest(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::substrate::arc::observable::ObservableState;

    #[test]
    fn governor_input_has_no_latent_slot() {
        let gi = GovernorInput::from_observable(
            "a1",
            ObservableState::empty_placeholder(),
            0,
            "vol",
            None,
            None,
        );
        let s = serde_json::to_string(&gi).unwrap();
        assert!(!s.contains("latent"));
        assert!(!s.contains("dim_private"));
        assert_eq!(gi.schema, GovernorInput::SCHEMA);
    }
}
