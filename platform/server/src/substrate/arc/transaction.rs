//! AgencyTransaction kernel FSM (Phase B0).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxState {
    Proposed,
    Validated,
    Reserved,
    WaitingHitl,
    Leased,
    Redeeming,
    EffectStarted,
    Settled,
    Committed,
    Denied,
    Expired,
    Revoked,
    Failed,
    EffectUnknown,
    Compensating,
    Quarantined,
    Aborted,
}

impl TxState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "PROPOSED",
            Self::Validated => "VALIDATED",
            Self::Reserved => "RESERVED",
            Self::WaitingHitl => "WAITING_HITL",
            Self::Leased => "LEASED",
            Self::Redeeming => "REDEEMING",
            Self::EffectStarted => "EFFECT_STARTED",
            Self::Settled => "SETTLED",
            Self::Committed => "COMMITTED",
            Self::Denied => "DENIED",
            Self::Expired => "EXPIRED",
            Self::Revoked => "REVOKED",
            Self::Failed => "FAILED",
            Self::EffectUnknown => "EFFECT_UNKNOWN",
            Self::Compensating => "COMPENSATING",
            Self::Quarantined => "QUARANTINED",
            Self::Aborted => "ABORTED",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Committed
                | Self::Denied
                | Self::Expired
                | Self::Revoked
                | Self::Failed
                | Self::Quarantined
                | Self::Aborted
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionError {
    Illegal { from: TxState, to: TxState },
    Terminal(TxState),
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Illegal { from, to } => {
                write!(f, "illegal AgencyTransaction edge {} → {}", from.as_str(), to.as_str())
            }
            Self::Terminal(s) => write!(f, "transaction already terminal: {}", s.as_str()),
        }
    }
}

impl std::error::Error for TransitionError {}

/// Who may cause an edge (documented in edge table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeActor {
    Cognition,
    Governor,
    Sink,
    Operator,
    Sweeper,
    Recovery,
    Aapi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeSpec {
    pub from: TxState,
    pub to: TxState,
    pub who: EdgeActor,
}

/// Legal edges — AgencyTransaction kernel algebra (B0.1).
pub fn legal_edges() -> &'static [EdgeSpec] {
    use EdgeActor::*;
    use TxState::*;
    &[
        EdgeSpec { from: Proposed, to: Validated, who: Governor },
        EdgeSpec { from: Proposed, to: Denied, who: Governor },
        EdgeSpec { from: Proposed, to: WaitingHitl, who: Governor },
        EdgeSpec { from: Proposed, to: Aborted, who: Operator },
        EdgeSpec { from: Proposed, to: Quarantined, who: Operator },
        EdgeSpec { from: Validated, to: Reserved, who: Governor },
        EdgeSpec { from: Validated, to: Denied, who: Governor },
        EdgeSpec { from: Validated, to: WaitingHitl, who: Governor },
        EdgeSpec { from: Validated, to: Aborted, who: Operator },
        EdgeSpec { from: Validated, to: Quarantined, who: Operator },
        EdgeSpec { from: Reserved, to: Leased, who: Governor },
        EdgeSpec { from: Reserved, to: Denied, who: Governor },
        EdgeSpec { from: Reserved, to: WaitingHitl, who: Governor },
        EdgeSpec { from: Reserved, to: Aborted, who: Operator },
        EdgeSpec { from: Reserved, to: Quarantined, who: Operator },
        EdgeSpec { from: Reserved, to: Expired, who: Sweeper },
        EdgeSpec { from: WaitingHitl, to: Reserved, who: Governor },
        EdgeSpec { from: WaitingHitl, to: Denied, who: Governor },
        EdgeSpec { from: WaitingHitl, to: Aborted, who: Operator },
        EdgeSpec { from: WaitingHitl, to: Quarantined, who: Operator },
        EdgeSpec { from: Leased, to: Redeeming, who: Sink },
        EdgeSpec { from: Leased, to: Expired, who: Sweeper },
        EdgeSpec { from: Leased, to: Revoked, who: Operator },
        EdgeSpec { from: Leased, to: Quarantined, who: Operator },
        EdgeSpec { from: Leased, to: Aborted, who: Operator },
        EdgeSpec { from: Redeeming, to: EffectStarted, who: Sink },
        EdgeSpec { from: Redeeming, to: Failed, who: Sink },
        EdgeSpec { from: Redeeming, to: Revoked, who: Operator },
        EdgeSpec { from: Redeeming, to: Quarantined, who: Operator },
        EdgeSpec { from: EffectStarted, to: Settled, who: Sink },
        EdgeSpec { from: EffectStarted, to: Failed, who: Sink },
        EdgeSpec { from: EffectStarted, to: EffectUnknown, who: Recovery },
        EdgeSpec { from: EffectStarted, to: Quarantined, who: Operator },
        EdgeSpec { from: Settled, to: Committed, who: Governor },
        EdgeSpec { from: Settled, to: Compensating, who: Aapi },
        EdgeSpec { from: Failed, to: Compensating, who: Aapi },
        EdgeSpec { from: EffectUnknown, to: Compensating, who: Aapi },
        EdgeSpec { from: EffectUnknown, to: Failed, who: Operator },
        EdgeSpec { from: EffectUnknown, to: Quarantined, who: Operator },
        EdgeSpec { from: Compensating, to: Committed, who: Governor },
        EdgeSpec { from: Compensating, to: Failed, who: Sink },
        // Quarantine preempt from non-terminals already listed; Revoked terminal.
    ]
}

pub fn is_legal(from: TxState, to: TxState) -> bool {
    legal_edges().iter().any(|e| e.from == from && e.to == to)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgencyTransaction {
    pub schema: String,
    pub tx_id: String,
    pub agent_id: String,
    pub state: TxState,
    pub authority_epoch_at_start: u64,
    pub proposal_digest: Option<String>,
    pub lease_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub worldline_edges: Vec<String>,
}

impl AgencyTransaction {
    pub const SCHEMA: &'static str = "connector.arc.agency_transaction.v1";

    pub fn new(agent_id: impl Into<String>, authority_epoch: u64, proposal_digest: Option<String>) -> Self {
        Self {
            schema: Self::SCHEMA.into(),
            tx_id: Uuid::new_v4().to_string(),
            agent_id: agent_id.into(),
            state: TxState::Proposed,
            authority_epoch_at_start: authority_epoch,
            proposal_digest,
            lease_id: None,
            idempotency_key: None,
            worldline_edges: Vec::new(),
        }
    }

    pub fn transition(&mut self, to: TxState) -> Result<(), TransitionError> {
        if !is_legal(self.state, to) {
            if self.state.is_terminal() {
                return Err(TransitionError::Terminal(self.state));
            }
            return Err(TransitionError::Illegal {
                from: self.state,
                to,
            });
        }
        self.worldline_edges
            .push(format!("{}→{}", self.state.as_str(), to.as_str()));
        self.state = to;
        Ok(())
    }

    /// Crash recovery: EFFECT_STARTED without SETTLED → EFFECT_UNKNOWN.
    pub fn mark_effect_unknown_after_crash(&mut self) -> Result<(), TransitionError> {
        self.transition(TxState::EffectUnknown)
    }

    pub fn digest(&self) -> String {
        let body = json!({
            "tx_id": self.tx_id,
            "agent_id": self.agent_id,
            "state": self.state.as_str(),
            "authority_epoch_at_start": self.authority_epoch_at_start,
            "proposal_digest": self.proposal_digest,
            "lease_id": self.lease_id,
            "idempotency_key": self.idempotency_key,
            "worldline_edges": self.worldline_edges,
        });
        format!("{:x}", Sha256::digest(serde_json::to_vec(&body).unwrap_or_default()))
    }

    /// B5: admit/settlement proof fragment — epoch + tx id/state for export.
    pub fn proof_export(&self) -> Value {
        json!({
            "schema": "connector.arc.admit_proof.v1",
            "tx_id": self.tx_id,
            "agent_id": self.agent_id,
            "authority_epoch": self.authority_epoch_at_start,
            "state": self.state.as_str(),
            "proposal_digest": self.proposal_digest,
            "idempotency_key": self.idempotency_key,
            "digest": self.digest(),
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema": self.schema,
            "tx_id": self.tx_id,
            "agent_id": self.agent_id,
            "state": self.state.as_str(),
            "authority_epoch_at_start": self.authority_epoch_at_start,
            "digest": self.digest(),
            "worldline_edges": self.worldline_edges,
            "proof": self.proof_export(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_to_committed() {
        let mut tx = AgencyTransaction::new("a1", 1, Some("p".into()));
        for s in [
            TxState::Validated,
            TxState::Reserved,
            TxState::Leased,
            TxState::Redeeming,
            TxState::EffectStarted,
            TxState::Settled,
            TxState::Committed,
        ] {
            tx.transition(s).unwrap();
        }
        assert_eq!(tx.state, TxState::Committed);
    }

    #[test]
    fn proposing_to_redeeming_illegal() {
        let mut tx = AgencyTransaction::new("a1", 0, None);
        let err = tx.transition(TxState::Redeeming).unwrap_err();
        assert!(matches!(err, TransitionError::Illegal { .. }));
    }

    #[test]
    fn leased_to_committed_skip_illegal() {
        let mut tx = AgencyTransaction::new("a1", 0, None);
        tx.transition(TxState::Validated).unwrap();
        tx.transition(TxState::Reserved).unwrap();
        tx.transition(TxState::Leased).unwrap();
        assert!(tx.transition(TxState::Committed).is_err());
    }

    #[test]
    fn effect_started_crash_to_unknown() {
        let mut tx = AgencyTransaction::new("a1", 0, None);
        for s in [
            TxState::Validated,
            TxState::Reserved,
            TxState::Leased,
            TxState::Redeeming,
            TxState::EffectStarted,
        ] {
            tx.transition(s).unwrap();
        }
        tx.mark_effect_unknown_after_crash().unwrap();
        assert_eq!(tx.state, TxState::EffectUnknown);
        // no blind jump to Committed
        assert!(tx.transition(TxState::Committed).is_err());
    }

    #[test]
    fn no_blind_retry_from_unknown_to_effect_started() {
        let mut tx = AgencyTransaction::new("a1", 0, None);
        for s in [
            TxState::Validated,
            TxState::Reserved,
            TxState::Leased,
            TxState::Redeeming,
            TxState::EffectStarted,
            TxState::EffectUnknown,
        ] {
            tx.transition(s).unwrap();
        }
        assert!(tx.transition(TxState::EffectStarted).is_err());
        assert!(tx.transition(TxState::Redeeming).is_err());
    }
}
