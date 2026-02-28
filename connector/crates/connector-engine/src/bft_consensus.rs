//! BFT Consensus — lightweight Byzantine Fault Tolerant agreement for cells.
//!
//! Implements a simplified PBFT-style consensus round for cell state agreement.
//! Cells must agree on state transitions (agent migrations, namespace merges,
//! configuration changes) even when f < n/3 cells are Byzantine.
//!
//! Round phases: Propose → PreVote → PreCommit → Commit
//!
//! Research: PBFT (Castro & Liskov 1999), Tendermint BFT, AlephBFT,
//! bft-core crate, Hyperledger Fabric SmartBFT, HotStuff.
//!
//! This is a state machine only — transport is external (plug into vac-bus).

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};

// ═══════════════════════════════════════════════════════════════
// Round Phase
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundPhase {
    /// Waiting for a proposal
    Idle,
    /// Leader has proposed a value
    Propose,
    /// Collecting pre-votes (2/3 needed to advance)
    PreVote,
    /// Collecting pre-commits (2/3 needed to commit)
    PreCommit,
    /// Value committed (consensus reached)
    Committed,
    /// Round failed (timeout or conflicting proposals)
    Failed,
}

// ═══════════════════════════════════════════════════════════════
// Proposal & Votes
// ═══════════════════════════════════════════════════════════════

/// A proposal for consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub round: u64,
    pub proposer: String,
    pub value_hash: String,
    pub value: serde_json::Value,
    pub timestamp_ms: u64,
}

impl Proposal {
    pub fn new(round: u64, proposer: impl Into<String>, value: serde_json::Value, timestamp_ms: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(value.to_string().as_bytes());
        let hash = hex::encode(&hasher.finalize()[..16]);
        Self {
            round,
            proposer: proposer.into(),
            value_hash: hash,
            value,
            timestamp_ms,
        }
    }
}

/// A vote (pre-vote or pre-commit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub round: u64,
    pub voter: String,
    pub value_hash: String,
    pub approve: bool,
}

// ═══════════════════════════════════════════════════════════════
// BFT Round
// ═══════════════════════════════════════════════════════════════

/// A single BFT consensus round.
pub struct BftRound {
    pub round: u64,
    pub phase: RoundPhase,
    pub proposal: Option<Proposal>,
    pub pre_votes: HashMap<String, Vote>,
    pub pre_commits: HashMap<String, Vote>,
    /// Total number of validators (cells)
    pub validator_count: usize,
    /// Required votes for quorum: floor(2n/3) + 1
    pub quorum: usize,
    /// Maximum Byzantine faults tolerated: floor((n-1)/3)
    pub max_faults: usize,
    /// Set of known validators
    pub validators: HashSet<String>,
}

impl BftRound {
    pub fn new(round: u64, validators: HashSet<String>) -> Self {
        let n = validators.len();
        let quorum = (2 * n / 3) + 1;
        let max_faults = (n.saturating_sub(1)) / 3;
        Self {
            round,
            phase: RoundPhase::Idle,
            proposal: None,
            pre_votes: HashMap::new(),
            pre_commits: HashMap::new(),
            validator_count: n,
            quorum,
            max_faults,
            validators,
        }
    }

    /// Submit a proposal (only valid in Idle phase).
    pub fn propose(&mut self, proposal: Proposal) -> Result<(), String> {
        if self.phase != RoundPhase::Idle {
            return Err(format!("Cannot propose in phase {:?}", self.phase));
        }
        if !self.validators.contains(&proposal.proposer) {
            return Err(format!("Unknown proposer: {}", proposal.proposer));
        }
        if proposal.round != self.round {
            return Err(format!("Wrong round: expected {}, got {}", self.round, proposal.round));
        }
        self.proposal = Some(proposal);
        self.phase = RoundPhase::Propose;
        Ok(())
    }

    /// Cast a pre-vote.
    pub fn pre_vote(&mut self, vote: Vote) -> Result<(), String> {
        if self.phase != RoundPhase::Propose && self.phase != RoundPhase::PreVote && self.phase != RoundPhase::PreCommit {
            return Err(format!("Cannot pre-vote in phase {:?}", self.phase));
        }
        if !self.validators.contains(&vote.voter) {
            return Err(format!("Unknown voter: {}", vote.voter));
        }
        if vote.round != self.round {
            return Err(format!("Wrong round: expected {}, got {}", self.round, vote.round));
        }
        self.pre_votes.insert(vote.voter.clone(), vote);
        // Only advance phase forward, never backward
        if self.phase == RoundPhase::Propose {
            self.phase = RoundPhase::PreVote;
        }

        // Check quorum — advance to PreCommit if enough approvals
        if self.phase == RoundPhase::PreVote && self.count_approvals(&self.pre_votes) >= self.quorum {
            self.phase = RoundPhase::PreCommit;
        }
        Ok(())
    }

    /// Cast a pre-commit vote.
    pub fn pre_commit(&mut self, vote: Vote) -> Result<(), String> {
        if self.phase != RoundPhase::PreCommit {
            return Err(format!("Cannot pre-commit in phase {:?}", self.phase));
        }
        if !self.validators.contains(&vote.voter) {
            return Err(format!("Unknown voter: {}", vote.voter));
        }
        self.pre_commits.insert(vote.voter.clone(), vote);

        // Check quorum
        if self.count_approvals(&self.pre_commits) >= self.quorum {
            self.phase = RoundPhase::Committed;
        }
        Ok(())
    }

    /// Mark round as failed (timeout).
    pub fn fail(&mut self) {
        self.phase = RoundPhase::Failed;
    }

    /// Is consensus reached?
    pub fn is_committed(&self) -> bool {
        self.phase == RoundPhase::Committed
    }

    /// Get the committed value (if committed).
    pub fn committed_value(&self) -> Option<&serde_json::Value> {
        if self.is_committed() {
            self.proposal.as_ref().map(|p| &p.value)
        } else {
            None
        }
    }

    fn count_approvals(&self, votes: &HashMap<String, Vote>) -> usize {
        votes.values().filter(|v| v.approve).count()
    }
}

// ═══════════════════════════════════════════════════════════════
// BFT Engine — manages multiple rounds
// ═══════════════════════════════════════════════════════════════

/// BFT consensus engine managing sequential rounds.
pub struct BftEngine {
    pub validators: HashSet<String>,
    pub current_round: u64,
    pub committed_values: Vec<(u64, serde_json::Value)>,
    round: Option<BftRound>,
}

impl BftEngine {
    pub fn new(validators: HashSet<String>) -> Self {
        Self {
            validators: validators.clone(),
            current_round: 0,
            committed_values: Vec::new(),
            round: None,
        }
    }

    /// Start a new round.
    pub fn new_round(&mut self) -> &mut BftRound {
        self.current_round += 1;
        self.round = Some(BftRound::new(self.current_round, self.validators.clone()));
        self.round.as_mut().unwrap()
    }

    /// Get the current round.
    pub fn current(&self) -> Option<&BftRound> {
        self.round.as_ref()
    }

    /// Get the current round mutably.
    pub fn current_mut(&mut self) -> Option<&mut BftRound> {
        self.round.as_mut()
    }

    /// Finalize current round if committed, archive the value.
    pub fn finalize(&mut self) -> Option<serde_json::Value> {
        if let Some(round) = &self.round {
            if round.is_committed() {
                if let Some(val) = round.committed_value().cloned() {
                    self.committed_values.push((round.round, val.clone()));
                    self.round = None;
                    return Some(val);
                }
            }
        }
        None
    }

    pub fn committed_count(&self) -> usize {
        self.committed_values.len()
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn validators(n: usize) -> HashSet<String> {
        (0..n).map(|i| format!("cell:{}", i)).collect()
    }

    fn make_vote(round: u64, voter: &str, hash: &str, approve: bool) -> Vote {
        Vote { round, voter: voter.to_string(), value_hash: hash.to_string(), approve }
    }

    #[test]
    fn test_quorum_calculation() {
        // 4 validators: quorum = floor(8/3) + 1 = 3
        let round = BftRound::new(1, validators(4));
        assert_eq!(round.quorum, 3);
        assert_eq!(round.max_faults, 1);

        // 7 validators: quorum = floor(14/3) + 1 = 5
        let round = BftRound::new(1, validators(7));
        assert_eq!(round.quorum, 5);
        assert_eq!(round.max_faults, 2);
    }

    #[test]
    fn test_full_consensus_round() {
        let vals = validators(4);
        let mut round = BftRound::new(1, vals);

        // Propose
        let proposal = Proposal::new(1, "cell:0", serde_json::json!({"action": "migrate"}), 1000);
        let hash = proposal.value_hash.clone();
        round.propose(proposal).unwrap();
        assert_eq!(round.phase, RoundPhase::Propose);

        // Pre-vote (need 3/4 approvals)
        round.pre_vote(make_vote(1, "cell:0", &hash, true)).unwrap();
        round.pre_vote(make_vote(1, "cell:1", &hash, true)).unwrap();
        assert_eq!(round.phase, RoundPhase::PreVote); // Not yet quorum
        round.pre_vote(make_vote(1, "cell:2", &hash, true)).unwrap();
        assert_eq!(round.phase, RoundPhase::PreCommit); // Quorum reached

        // Pre-commit (need 3/4 approvals)
        round.pre_commit(make_vote(1, "cell:0", &hash, true)).unwrap();
        round.pre_commit(make_vote(1, "cell:1", &hash, true)).unwrap();
        assert!(!round.is_committed());
        round.pre_commit(make_vote(1, "cell:2", &hash, true)).unwrap();
        assert!(round.is_committed());

        let val = round.committed_value().unwrap();
        assert_eq!(val["action"], "migrate");
    }

    #[test]
    fn test_unknown_proposer_rejected() {
        let vals = validators(3);
        let mut round = BftRound::new(1, vals);
        let proposal = Proposal::new(1, "unknown:cell", serde_json::json!({}), 1000);
        assert!(round.propose(proposal).is_err());
    }

    #[test]
    fn test_wrong_round_rejected() {
        let vals = validators(3);
        let mut round = BftRound::new(1, vals);
        let proposal = Proposal::new(99, "cell:0", serde_json::json!({}), 1000);
        assert!(round.propose(proposal).is_err());
    }

    #[test]
    fn test_double_propose_rejected() {
        let vals = validators(3);
        let mut round = BftRound::new(1, vals);
        round.propose(Proposal::new(1, "cell:0", serde_json::json!({"a": 1}), 1000)).unwrap();
        assert!(round.propose(Proposal::new(1, "cell:1", serde_json::json!({"b": 2}), 1001)).is_err());
    }

    #[test]
    fn test_fail_round() {
        let vals = validators(3);
        let mut round = BftRound::new(1, vals);
        round.fail();
        assert_eq!(round.phase, RoundPhase::Failed);
        assert!(!round.is_committed());
    }

    #[test]
    fn test_reject_votes_not_enough_for_quorum() {
        let vals = validators(4);
        let mut round = BftRound::new(1, vals);
        let proposal = Proposal::new(1, "cell:0", serde_json::json!({}), 1000);
        let hash = proposal.value_hash.clone();
        round.propose(proposal).unwrap();

        // 2 approve, 2 reject — no quorum
        round.pre_vote(make_vote(1, "cell:0", &hash, true)).unwrap();
        round.pre_vote(make_vote(1, "cell:1", &hash, true)).unwrap();
        round.pre_vote(make_vote(1, "cell:2", &hash, false)).unwrap();
        round.pre_vote(make_vote(1, "cell:3", &hash, false)).unwrap();
        assert_eq!(round.phase, RoundPhase::PreVote); // Stuck at PreVote
    }

    #[test]
    fn test_engine_multiple_rounds() {
        let vals = validators(3);
        let mut engine = BftEngine::new(vals);

        // Round 1 (3 validators, quorum=3 — all must agree)
        let round = engine.new_round();
        let p = Proposal::new(1, "cell:0", serde_json::json!({"round": 1}), 1000);
        let h = p.value_hash.clone();
        round.propose(p).unwrap();
        round.pre_vote(make_vote(1, "cell:0", &h, true)).unwrap();
        round.pre_vote(make_vote(1, "cell:1", &h, true)).unwrap();
        round.pre_vote(make_vote(1, "cell:2", &h, true)).unwrap();
        round.pre_commit(make_vote(1, "cell:0", &h, true)).unwrap();
        round.pre_commit(make_vote(1, "cell:1", &h, true)).unwrap();
        round.pre_commit(make_vote(1, "cell:2", &h, true)).unwrap();
        assert!(round.is_committed());
        let val = engine.finalize().unwrap();
        assert_eq!(val["round"], 1);

        // Round 2
        let round = engine.new_round();
        let p = Proposal::new(2, "cell:1", serde_json::json!({"round": 2}), 2000);
        let h = p.value_hash.clone();
        round.propose(p).unwrap();
        round.pre_vote(make_vote(2, "cell:0", &h, true)).unwrap();
        round.pre_vote(make_vote(2, "cell:1", &h, true)).unwrap();
        round.pre_vote(make_vote(2, "cell:2", &h, true)).unwrap();
        round.pre_commit(make_vote(2, "cell:0", &h, true)).unwrap();
        round.pre_commit(make_vote(2, "cell:1", &h, true)).unwrap();
        round.pre_commit(make_vote(2, "cell:2", &h, true)).unwrap();
        engine.finalize().unwrap();

        assert_eq!(engine.committed_count(), 2);
    }

    #[test]
    fn test_seven_validators_tolerates_two_byzantine() {
        let vals = validators(7); // quorum=5, max_faults=2
        let mut round = BftRound::new(1, vals);
        let p = Proposal::new(1, "cell:0", serde_json::json!({"test": true}), 1000);
        let h = p.value_hash.clone();
        round.propose(p).unwrap();

        // 5 approve (quorum=5), 2 Byzantine don't pre-vote
        for i in 0..5 {
            round.pre_vote(make_vote(1, &format!("cell:{}", i), &h, true)).unwrap();
        }
        assert_eq!(round.phase, RoundPhase::PreCommit); // Quorum reached

        // 2 Byzantine send reject pre-votes (late, still accepted)
        for i in 5..7 {
            round.pre_vote(make_vote(1, &format!("cell:{}", i), &h, false)).unwrap();
        }

        // 5 honest validators pre-commit
        for i in 0..5 {
            round.pre_commit(make_vote(1, &format!("cell:{}", i), &h, true)).unwrap();
        }
        assert!(round.is_committed());
    }

    #[test]
    fn test_proposal_hash_deterministic() {
        let p1 = Proposal::new(1, "cell:0", serde_json::json!({"x": 1}), 1000);
        let p2 = Proposal::new(1, "cell:0", serde_json::json!({"x": 1}), 2000);
        assert_eq!(p1.value_hash, p2.value_hash); // Same value → same hash
    }
}
