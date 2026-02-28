//! Negotiation Protocol — structured agent-to-agent contract negotiation.
//!
//! Agents propose, counter-propose, accept, or reject service contracts.
//! Each negotiation has a bounded number of rounds to prevent infinite loops.
//!
//! Research: Contract Net Protocol (Smith 1980), FIPA ACL, Akash reverse auction,
//! multi-party negotiation theory (Nash bargaining)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Negotiation State Machine
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NegotiationState {
    Open,
    CounterProposed,
    Accepted,
    Rejected,
    Expired,
    Withdrawn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationTerms {
    pub max_latency_ms: u64,
    pub availability_pct: f64,
    pub cost_per_call: u64,
    pub stake_amount: u64,
    pub ttl_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationRound {
    pub round: u32,
    pub from: String,
    pub terms: NegotiationTerms,
    pub message: Option<String>,
    pub timestamp_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Negotiation {
    pub negotiation_id: String,
    pub requester_pid: String,
    pub provider_pid: String,
    pub capability_key: String,
    pub state: NegotiationState,
    pub rounds: Vec<NegotiationRound>,
    pub max_rounds: u32,
    pub created_at: i64,
    pub expires_at: i64,
    pub resolved_at: Option<i64>,
    pub final_terms: Option<NegotiationTerms>,
}

// ═══════════════════════════════════════════════════════════════
// Negotiation Manager
// ═══════════════════════════════════════════════════════════════

pub struct NegotiationManager {
    negotiations: HashMap<String, Negotiation>,
    next_id: u64,
    default_max_rounds: u32,
    default_ttl_ms: i64,
}

impl NegotiationManager {
    pub fn new(default_max_rounds: u32, default_ttl_ms: i64) -> Self {
        Self {
            negotiations: HashMap::new(),
            next_id: 1,
            default_max_rounds,
            default_ttl_ms,
        }
    }

    /// Requester proposes terms to a provider.
    pub fn propose(
        &mut self,
        requester: &str,
        provider: &str,
        capability_key: &str,
        terms: NegotiationTerms,
        now_ms: i64,
    ) -> String {
        let id = format!("neg_{}", self.next_id);
        self.next_id += 1;

        let round = NegotiationRound {
            round: 1, from: requester.to_string(),
            terms: terms.clone(), message: None, timestamp_ms: now_ms,
        };

        let neg = Negotiation {
            negotiation_id: id.clone(),
            requester_pid: requester.to_string(),
            provider_pid: provider.to_string(),
            capability_key: capability_key.to_string(),
            state: NegotiationState::Open,
            rounds: vec![round],
            max_rounds: self.default_max_rounds,
            created_at: now_ms,
            expires_at: now_ms + self.default_ttl_ms,
            resolved_at: None,
            final_terms: None,
        };
        self.negotiations.insert(id.clone(), neg);
        id
    }

    /// Counter-propose with modified terms.
    pub fn counter_propose(
        &mut self,
        negotiation_id: &str,
        from: &str,
        terms: NegotiationTerms,
        message: Option<String>,
        now_ms: i64,
    ) -> Result<(), String> {
        let neg = self.negotiations.get_mut(negotiation_id)
            .ok_or_else(|| format!("Negotiation {} not found", negotiation_id))?;

        if neg.state != NegotiationState::Open && neg.state != NegotiationState::CounterProposed {
            return Err(format!("Cannot counter-propose in state {:?}", neg.state));
        }
        if now_ms > neg.expires_at {
            neg.state = NegotiationState::Expired;
            return Err("Negotiation expired".into());
        }
        if neg.rounds.len() as u32 >= neg.max_rounds {
            return Err(format!("Max rounds ({}) exceeded", neg.max_rounds));
        }
        // Verify the counter-proposer is a participant
        if from != neg.requester_pid && from != neg.provider_pid {
            return Err("Only participants can counter-propose".into());
        }
        // Can't counter your own last proposal
        if let Some(last) = neg.rounds.last() {
            if last.from == from {
                return Err("Cannot counter-propose your own terms".into());
            }
        }

        let round = NegotiationRound {
            round: neg.rounds.len() as u32 + 1,
            from: from.to_string(),
            terms,
            message,
            timestamp_ms: now_ms,
        };
        neg.rounds.push(round);
        neg.state = NegotiationState::CounterProposed;
        Ok(())
    }

    /// Accept the current terms.
    pub fn accept(
        &mut self,
        negotiation_id: &str,
        from: &str,
        now_ms: i64,
    ) -> Result<NegotiationTerms, String> {
        let neg = self.negotiations.get_mut(negotiation_id)
            .ok_or_else(|| format!("Negotiation {} not found", negotiation_id))?;

        if neg.state != NegotiationState::Open && neg.state != NegotiationState::CounterProposed {
            return Err(format!("Cannot accept in state {:?}", neg.state));
        }
        if now_ms > neg.expires_at {
            neg.state = NegotiationState::Expired;
            return Err("Negotiation expired".into());
        }
        if from != neg.requester_pid && from != neg.provider_pid {
            return Err("Only participants can accept".into());
        }

        let final_terms = neg.rounds.last()
            .map(|r| r.terms.clone())
            .ok_or("No terms to accept")?;

        neg.state = NegotiationState::Accepted;
        neg.resolved_at = Some(now_ms);
        neg.final_terms = Some(final_terms.clone());
        Ok(final_terms)
    }

    /// Reject the negotiation entirely.
    pub fn reject(
        &mut self,
        negotiation_id: &str,
        from: &str,
        reason: Option<String>,
        now_ms: i64,
    ) -> Result<(), String> {
        let neg = self.negotiations.get_mut(negotiation_id)
            .ok_or_else(|| format!("Negotiation {} not found", negotiation_id))?;

        if neg.state == NegotiationState::Accepted || neg.state == NegotiationState::Rejected {
            return Err(format!("Cannot reject in state {:?}", neg.state));
        }
        if from != neg.requester_pid && from != neg.provider_pid {
            return Err("Only participants can reject".into());
        }

        neg.state = NegotiationState::Rejected;
        neg.resolved_at = Some(now_ms);
        if let Some(msg) = reason {
            neg.rounds.push(NegotiationRound {
                round: neg.rounds.len() as u32 + 1,
                from: from.to_string(),
                terms: neg.rounds.last().unwrap().terms.clone(),
                message: Some(msg),
                timestamp_ms: now_ms,
            });
        }
        Ok(())
    }

    /// Withdraw a negotiation (only by requester).
    pub fn withdraw(&mut self, negotiation_id: &str, from: &str, now_ms: i64) -> Result<(), String> {
        let neg = self.negotiations.get_mut(negotiation_id)
            .ok_or_else(|| format!("Negotiation {} not found", negotiation_id))?;
        if from != neg.requester_pid {
            return Err("Only requester can withdraw".into());
        }
        if neg.state == NegotiationState::Accepted {
            return Err("Cannot withdraw accepted negotiation".into());
        }
        neg.state = NegotiationState::Withdrawn;
        neg.resolved_at = Some(now_ms);
        Ok(())
    }

    /// Expire all stale negotiations.
    pub fn expire_stale(&mut self, now_ms: i64) -> Vec<String> {
        let expired: Vec<String> = self.negotiations.iter()
            .filter(|(_, n)| {
                (n.state == NegotiationState::Open || n.state == NegotiationState::CounterProposed)
                    && now_ms > n.expires_at
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            if let Some(n) = self.negotiations.get_mut(id) {
                n.state = NegotiationState::Expired;
                n.resolved_at = Some(now_ms);
            }
        }
        expired
    }

    // ── Accessors ───────────────────────────────────────────
    pub fn get(&self, id: &str) -> Option<&Negotiation> { self.negotiations.get(id) }
    pub fn active_count(&self) -> usize {
        self.negotiations.values()
            .filter(|n| n.state == NegotiationState::Open || n.state == NegotiationState::CounterProposed)
            .count()
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_terms(cost: u64) -> NegotiationTerms {
        NegotiationTerms {
            max_latency_ms: 500, availability_pct: 99.0,
            cost_per_call: cost, stake_amount: 100, ttl_ms: 86_400_000,
        }
    }

    fn make_manager() -> NegotiationManager {
        NegotiationManager::new(5, 300_000) // 5 rounds, 5min TTL
    }

    #[test]
    fn test_propose_and_accept() {
        let mut mgr = make_manager();
        let id = mgr.propose("req", "prov", "translation:translate", make_terms(100), 1000);
        assert_eq!(mgr.active_count(), 1);
        let terms = mgr.accept(&id, "prov", 2000).unwrap();
        assert_eq!(terms.cost_per_call, 100);
        assert_eq!(mgr.get(&id).unwrap().state, NegotiationState::Accepted);
    }

    #[test]
    fn test_counter_propose() {
        let mut mgr = make_manager();
        let id = mgr.propose("req", "prov", "t:a", make_terms(100), 1000);
        // Provider counters with higher price
        mgr.counter_propose(&id, "prov", make_terms(150), Some("Need more".into()), 2000).unwrap();
        assert_eq!(mgr.get(&id).unwrap().state, NegotiationState::CounterProposed);
        assert_eq!(mgr.get(&id).unwrap().rounds.len(), 2);
        // Requester counters back
        mgr.counter_propose(&id, "req", make_terms(125), None, 3000).unwrap();
        assert_eq!(mgr.get(&id).unwrap().rounds.len(), 3);
        // Provider accepts
        let terms = mgr.accept(&id, "prov", 4000).unwrap();
        assert_eq!(terms.cost_per_call, 125);
    }

    #[test]
    fn test_cannot_counter_own_terms() {
        let mut mgr = make_manager();
        let id = mgr.propose("req", "prov", "t:a", make_terms(100), 1000);
        // Requester tries to counter their own proposal
        let result = mgr.counter_propose(&id, "req", make_terms(90), None, 2000);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_rounds_enforced() {
        let mut mgr = NegotiationManager::new(3, 300_000);
        let id = mgr.propose("req", "prov", "t:a", make_terms(100), 1000);
        mgr.counter_propose(&id, "prov", make_terms(200), None, 2000).unwrap();
        mgr.counter_propose(&id, "req", make_terms(150), None, 3000).unwrap();
        // Round 4 should fail (max_rounds = 3, already have 3 rounds)
        let result = mgr.counter_propose(&id, "prov", make_terms(175), None, 4000);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject() {
        let mut mgr = make_manager();
        let id = mgr.propose("req", "prov", "t:a", make_terms(100), 1000);
        mgr.reject(&id, "prov", Some("Too expensive".into()), 2000).unwrap();
        assert_eq!(mgr.get(&id).unwrap().state, NegotiationState::Rejected);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_withdraw() {
        let mut mgr = make_manager();
        let id = mgr.propose("req", "prov", "t:a", make_terms(100), 1000);
        mgr.withdraw(&id, "req", 2000).unwrap();
        assert_eq!(mgr.get(&id).unwrap().state, NegotiationState::Withdrawn);
        // Provider cannot withdraw
        let id2 = mgr.propose("req", "prov", "t:a", make_terms(100), 3000);
        assert!(mgr.withdraw(&id2, "prov", 4000).is_err());
    }

    #[test]
    fn test_expiry() {
        let mut mgr = make_manager();
        let id = mgr.propose("req", "prov", "t:a", make_terms(100), 1000);
        assert_eq!(mgr.active_count(), 1);
        let expired = mgr.expire_stale(400_000); // After 5min TTL
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], id);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_outsider_cannot_participate() {
        let mut mgr = make_manager();
        let id = mgr.propose("req", "prov", "t:a", make_terms(100), 1000);
        let result = mgr.counter_propose(&id, "outsider", make_terms(50), None, 2000);
        assert!(result.is_err());
        let result = mgr.accept(&id, "outsider", 2000);
        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_accept_after_reject() {
        let mut mgr = make_manager();
        let id = mgr.propose("req", "prov", "t:a", make_terms(100), 1000);
        mgr.reject(&id, "prov", None, 2000).unwrap();
        let result = mgr.accept(&id, "req", 3000);
        assert!(result.is_err());
    }
}
