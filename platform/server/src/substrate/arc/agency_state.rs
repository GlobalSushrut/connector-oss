//! Persistent AgencyState — reconstructed from WorldlineCommit (Phase E), not body RAM.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::autonomy_volume::AutonomyVolume;
use super::governor_input::hex_sha256;
use super::observable::ObservableState;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgencyState {
    pub schema: String,
    pub agent_id: String,
    pub hat_z_digest: String,
    pub autonomy_volume_digest: String,
    pub authority_epoch: u64,
    pub body_id: Option<String>,
    pub body_type: Option<String>,
    pub cognitive_epoch: u64,
    pub worldline_head: Option<String>,
    pub transition_fsm_head: Option<String>,
    pub digest: String,
}

impl AgencyState {
    pub const SCHEMA: &'static str = "connector.arc.agency_state.v1";

    pub fn placeholder(
        agent_id: impl Into<String>,
        obs: &ObservableState,
        volume: &AutonomyVolume,
        authority_epoch: u64,
        body_id: Option<String>,
    ) -> Self {
        let mut s = Self {
            schema: Self::SCHEMA.into(),
            agent_id: agent_id.into(),
            hat_z_digest: obs.digest(),
            autonomy_volume_digest: volume.digest().to_string(),
            authority_epoch,
            body_id,
            body_type: None,
            cognitive_epoch: 0,
            worldline_head: None,
            transition_fsm_head: None,
            digest: String::new(),
        };
        s.digest = s.compute_digest();
        s
    }

    pub fn compute_digest(&self) -> String {
        let body = json!({
            "agent_id": self.agent_id,
            "hat_z_digest": self.hat_z_digest,
            "autonomy_volume_digest": self.autonomy_volume_digest,
            "authority_epoch": self.authority_epoch,
            "body_id": self.body_id,
            "body_type": self.body_type,
            "cognitive_epoch": self.cognitive_epoch,
            "worldline_head": self.worldline_head,
            "transition_fsm_head": self.transition_fsm_head,
        });
        hex_sha256(&body)
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema": self.schema,
            "agent_id": self.agent_id,
            "digest": self.digest,
            "hat_z_digest": self.hat_z_digest,
            "autonomy_volume_digest": self.autonomy_volume_digest,
            "authority_epoch": self.authority_epoch,
            "body_id": self.body_id,
            "honesty": "WorldlineCommit is authoritative; reconstruct via arc::worldline::reconstruct_agency_state after body/process death",
        })
    }
}
