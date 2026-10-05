//! Consensus Layer (Layer 3) — HotStuff BFT, Raft, TSN-inspired scheduling.
//!
//! Provides three ordering guarantees selectable per-message:
//! Unordered (<1ms), Causal (<10ms), Total (<100ms via BFT consensus).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::envelope::OrderingMode;
use crate::identity::EntityId;
use crate::error::{ProtocolError, ProtoResult};

// ── Time Slot (TSN-inspired) ────────────────────────────────────────

/// A time slot for deterministic message scheduling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSlot {
    pub slot_id: u64,
    /// Start time in nanoseconds (IEEE 1588 PTP synchronized).
    pub start_ns: u64,
    /// Duration in nanoseconds.
    pub duration_ns: u64,
    /// Priority level (0 = emergency, highest).
    pub priority: u8,
    /// Entity that owns this slot.
    pub entity_id: EntityId,
}

// ── Consensus Round ─────────────────────────────────────────────────

/// Phase of a HotStuff BFT consensus round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusPhase {
    Propose,
    Prepare,
    PreCommit,
    Commit,
    Decide,
}

/// A proposal for BFT consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub proposal_id: String,
    pub proposer: EntityId,
    pub payload_cid: String,
    pub round: u64,
    pub phase: ConsensusPhase,
    pub timestamp: i64,
}

/// A vote on a proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub proposal_id: String,
    pub voter: EntityId,
    pub phase: ConsensusPhase,
    pub approve: bool,
    pub signature: Vec<u8>,
}

/// Decision outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusDecision {
    Committed,
    Aborted,
    Pending,
}

// ── Consensus Manager ───────────────────────────────────────────────

/// Manages BFT consensus rounds.
pub struct ConsensusManager {
    /// Known validators.
    validators: Vec<EntityId>,
    /// Active proposals.
    proposals: HashMap<String, Proposal>,
    /// Votes per proposal per phase.
    votes: HashMap<String, Vec<Vote>>,
    /// Decided proposals.
    decisions: HashMap<String, ConsensusDecision>,
    /// Current round number.
    round: u64,
}

impl ConsensusManager {
    pub fn new(validators: Vec<EntityId>) -> Self {
        Self {
            validators,
            proposals: HashMap::new(),
            votes: HashMap::new(),
            decisions: HashMap::new(),
            round: 0,
        }
    }

    /// Number of validators.
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Maximum Byzantine faults tolerated: f < n/3.
    pub fn max_faults(&self) -> usize {
        if self.validators.is_empty() { return 0; }
        (self.validators.len() - 1) / 3
    }

    /// Quorum size: 2f + 1.
    pub fn quorum_size(&self) -> usize {
        let f = self.max_faults();
        2 * f + 1
    }

    /// Submit a proposal.
    pub fn propose(&mut self, proposer: EntityId, payload_cid: String) -> ProtoResult<Proposal> {
        if !self.validators.contains(&proposer) {
            return Err(ProtocolError::Consensus("Proposer is not a validator".into()));
        }

        self.round += 1;
        let proposal = Proposal {
            proposal_id: format!("prop-{}", self.round),
            proposer,
            payload_cid,
            round: self.round,
            phase: ConsensusPhase::Propose,
            timestamp: chrono::Utc::now().timestamp_millis(),
        };

        self.proposals.insert(proposal.proposal_id.clone(), proposal.clone());
        self.votes.insert(proposal.proposal_id.clone(), Vec::new());
        self.decisions.insert(proposal.proposal_id.clone(), ConsensusDecision::Pending);

        Ok(proposal)
    }

    /// Submit a vote on a proposal.
    pub fn vote(&mut self, vote: Vote) -> ProtoResult<ConsensusDecision> {
        if !self.validators.contains(&vote.voter) {
            return Err(ProtocolError::Consensus("Voter is not a validator".into()));
        }

        if !self.proposals.contains_key(&vote.proposal_id) {
            return Err(ProtocolError::Consensus("Unknown proposal".into()));
        }

        let votes = self.votes.entry(vote.proposal_id.clone()).or_default();
        // Prevent double voting per phase
        if votes.iter().any(|v| v.voter == vote.voter && v.phase == vote.phase) {
            return Err(ProtocolError::Consensus("Already voted in this phase".into()));
        }

        let proposal_id = vote.proposal_id.clone();
        votes.push(vote);

        // Check if we have quorum for Commit phase
        let commit_approvals = self.votes.get(&proposal_id)
            .map(|vs| vs.iter()
                .filter(|v| v.phase == ConsensusPhase::Commit && v.approve)
                .count())
            .unwrap_or(0);

        if commit_approvals >= self.quorum_size() {
            self.decisions.insert(proposal_id.clone(), ConsensusDecision::Committed);
            return Ok(ConsensusDecision::Committed);
        }

        // Check if abort (too many rejections)
        let commit_rejects = self.votes.get(&proposal_id)
            .map(|vs| vs.iter()
                .filter(|v| v.phase == ConsensusPhase::Commit && !v.approve)
                .count())
            .unwrap_or(0);

        if commit_rejects > self.max_faults() {
            self.decisions.insert(proposal_id.clone(), ConsensusDecision::Aborted);
            return Ok(ConsensusDecision::Aborted);
        }

        Ok(ConsensusDecision::Pending)
    }

    /// Get the decision for a proposal.
    pub fn decision(&self, proposal_id: &str) -> ConsensusDecision {
        self.decisions.get(proposal_id).cloned().unwrap_or(ConsensusDecision::Pending)
    }

    /// Determine the required ordering mode based on SIL.
    pub fn required_ordering(sil: &crate::safety::SafetyIntegrityLevel) -> OrderingMode {
        if sil.requires_total_ordering() {
            OrderingMode::Total
        } else {
            OrderingMode::Causal
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::EntityClass;

    fn vid(n: &str) -> EntityId { EntityId::new(EntityClass::Agent, n) }

    fn make_mgr(n: usize) -> (ConsensusManager, Vec<EntityId>) {
        let validators: Vec<EntityId> = (0..n).map(|i| vid(&format!("v{}", i))).collect();
        (ConsensusManager::new(validators.clone()), validators)
    }

    #[test]
    fn test_quorum_calculation() {
        let (mgr, _) = make_mgr(4);
        assert_eq!(mgr.validator_count(), 4);
        assert_eq!(mgr.max_faults(), 1); // f < 4/3 → f = 1
        assert_eq!(mgr.quorum_size(), 3); // 2f+1 = 3
    }

    #[test]
    fn test_quorum_7_validators() {
        let (mgr, _) = make_mgr(7);
        assert_eq!(mgr.max_faults(), 2); // f < 7/3 → f = 2
        assert_eq!(mgr.quorum_size(), 5); // 2*2+1 = 5
    }

    #[test]
    fn test_propose() {
        let (mut mgr, vs) = make_mgr(4);
        let prop = mgr.propose(vs[0].clone(), "cid:abc".into()).unwrap();
        assert_eq!(prop.round, 1);
        assert_eq!(prop.phase, ConsensusPhase::Propose);
    }

    #[test]
    fn test_non_validator_cannot_propose() {
        let (mut mgr, _) = make_mgr(4);
        assert!(mgr.propose(vid("outsider"), "cid:x".into()).is_err());
    }

    #[test]
    fn test_consensus_commit_with_quorum() {
        let (mut mgr, vs) = make_mgr(4);
        let prop = mgr.propose(vs[0].clone(), "cid:payload".into()).unwrap();

        // 3 commit votes (= quorum of 3)
        for i in 0..3 {
            let result = mgr.vote(Vote {
                proposal_id: prop.proposal_id.clone(),
                voter: vs[i].clone(),
                phase: ConsensusPhase::Commit,
                approve: true,
                signature: vec![],
            }).unwrap();

            if i < 2 {
                assert_eq!(result, ConsensusDecision::Pending);
            } else {
                assert_eq!(result, ConsensusDecision::Committed);
            }
        }

        assert_eq!(mgr.decision(&prop.proposal_id), ConsensusDecision::Committed);
    }

    #[test]
    fn test_consensus_abort() {
        let (mut mgr, vs) = make_mgr(4);
        let prop = mgr.propose(vs[0].clone(), "cid:p".into()).unwrap();

        // 2 reject votes (> max_faults=1)
        for i in 0..2 {
            let _ = mgr.vote(Vote {
                proposal_id: prop.proposal_id.clone(),
                voter: vs[i].clone(),
                phase: ConsensusPhase::Commit,
                approve: false,
                signature: vec![],
            }).unwrap();
        }

        assert_eq!(mgr.decision(&prop.proposal_id), ConsensusDecision::Aborted);
    }

    #[test]
    fn test_double_vote_rejected() {
        let (mut mgr, vs) = make_mgr(4);
        let prop = mgr.propose(vs[0].clone(), "cid:x".into()).unwrap();

        mgr.vote(Vote {
            proposal_id: prop.proposal_id.clone(),
            voter: vs[0].clone(),
            phase: ConsensusPhase::Commit,
            approve: true,
            signature: vec![],
        }).unwrap();

        assert!(mgr.vote(Vote {
            proposal_id: prop.proposal_id.clone(),
            voter: vs[0].clone(),
            phase: ConsensusPhase::Commit,
            approve: true,
            signature: vec![],
        }).is_err());
    }

    #[test]
    fn test_required_ordering_by_sil() {
        use crate::safety::SafetyIntegrityLevel;
        assert_eq!(ConsensusManager::required_ordering(&SafetyIntegrityLevel::SIL0), OrderingMode::Causal);
        assert_eq!(ConsensusManager::required_ordering(&SafetyIntegrityLevel::SIL2), OrderingMode::Total);
        assert_eq!(ConsensusManager::required_ordering(&SafetyIntegrityLevel::SIL4), OrderingMode::Total);
    }
}
