//! EigenTrust Reputation — stake-weighted, transitive trust with Sybil resistance.
//!
//! Agents earn reputation through successful invocations. Trust is transitive:
//! if A trusts B and B trusts C, A transitively trusts C (attenuated).
//!
//! Research: EigenTrust (Kamvar et al. 2003), Sybil resistance via stake,
//! time-decay (recent interactions weighted higher), slashing on SLA violation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Feedback
// ═══════════════════════════════════════════════════════════════

/// A single piece of feedback from one agent about another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feedback {
    pub from: String,
    pub to: String,
    pub score: f64,        // 0.0 = terrible, 1.0 = perfect
    pub weight: f64,       // stake-weighted importance
    pub timestamp_ms: i64,
    pub invocation_id: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
// Reputation Engine
// ═══════════════════════════════════════════════════════════════

/// Configuration for the reputation engine.
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    /// Number of EigenTrust iterations (convergence).
    pub iterations: usize,
    /// Time decay half-life in milliseconds. Feedback older than this is halved.
    pub decay_half_life_ms: i64,
    /// Minimum stake required to submit feedback (Sybil resistance).
    pub min_stake_to_vote: u64,
    /// Pre-trusted agents that anchor the trust graph.
    pub pre_trusted: Vec<String>,
    /// Weight given to pre-trusted agents in each iteration.
    pub pre_trust_weight: f64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            iterations: 20,
            decay_half_life_ms: 86_400_000, // 24 hours
            min_stake_to_vote: 10,
            pre_trusted: vec![],
            pre_trust_weight: 0.1,
        }
    }
}

/// Per-agent reputation data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentReputation {
    pub agent_pid: String,
    pub global_score: f64,
    pub feedback_count: usize,
    pub stake: u64,
    pub slashed_count: u32,
    pub last_updated_ms: i64,
}

/// The EigenTrust-based reputation engine.
pub struct ReputationEngine {
    config: ReputationConfig,
    feedback: Vec<Feedback>,
    stakes: HashMap<String, u64>,
    slash_counts: HashMap<String, u32>,
}

impl ReputationEngine {
    pub fn new(config: ReputationConfig) -> Self {
        Self {
            config,
            feedback: Vec::new(),
            stakes: HashMap::new(),
            slash_counts: HashMap::new(),
        }
    }

    /// Register an agent's stake.
    pub fn register_stake(&mut self, agent_pid: &str, stake: u64) {
        self.stakes.insert(agent_pid.to_string(), stake);
    }

    /// Submit feedback (must have minimum stake).
    pub fn submit_feedback(&mut self, fb: Feedback) -> Result<(), String> {
        let sender_stake = self.stakes.get(&fb.from).copied().unwrap_or(0);
        if sender_stake < self.config.min_stake_to_vote {
            return Err(format!(
                "Agent {} has stake {} < minimum {} required to vote",
                fb.from, sender_stake, self.config.min_stake_to_vote
            ));
        }
        if fb.score < 0.0 || fb.score > 1.0 {
            return Err("Score must be in [0.0, 1.0]".into());
        }
        if fb.from == fb.to {
            return Err("Self-feedback not allowed".into());
        }
        self.feedback.push(fb);
        Ok(())
    }

    /// Slash an agent's reputation (SLA violation).
    pub fn slash(&mut self, agent_pid: &str, slash_amount: u64) -> u64 {
        let count = self.slash_counts.entry(agent_pid.to_string()).or_insert(0);
        *count += 1;
        let mut zero = 0u64;
        let stake = self.stakes.get_mut(agent_pid).unwrap_or(&mut zero);
        let actual_slash = slash_amount.min(*stake);
        *stake = stake.saturating_sub(slash_amount);
        actual_slash
    }

    /// Compute global reputation scores using EigenTrust iteration.
    /// Returns sorted Vec of (agent_pid, score).
    pub fn compute(&self, now_ms: i64) -> Vec<AgentReputation> {
        // Collect all agents
        let mut agents: Vec<String> = self.stakes.keys().cloned().collect();
        for fb in &self.feedback {
            if !agents.contains(&fb.to) { agents.push(fb.to.clone()); }
            if !agents.contains(&fb.from) { agents.push(fb.from.clone()); }
        }
        if agents.is_empty() {
            return vec![];
        }

        let n = agents.len();
        let agent_idx: HashMap<&str, usize> = agents.iter()
            .enumerate().map(|(i, a)| (a.as_str(), i)).collect();

        // Build normalized local trust matrix C[i][j]
        // C[i][j] = (stake-weighted, time-decayed feedback from i about j) / sum_k(...)
        let mut c = vec![vec![0.0f64; n]; n];
        for fb in &self.feedback {
            let Some(&i) = agent_idx.get(fb.from.as_str()) else { continue };
            let Some(&j) = agent_idx.get(fb.to.as_str()) else { continue };
            let decay = self.time_decay(fb.timestamp_ms, now_ms);
            let stake_w = (self.stakes.get(&fb.from).copied().unwrap_or(1) as f64).sqrt();
            c[i][j] += fb.score * fb.weight * decay * stake_w;
        }
        // Row-normalize
        for i in 0..n {
            let row_sum: f64 = c[i].iter().sum();
            if row_sum > 0.0 {
                for j in 0..n { c[i][j] /= row_sum; }
            }
        }

        // Pre-trusted distribution p
        let mut p = vec![1.0 / n as f64; n];
        if !self.config.pre_trusted.is_empty() {
            p = vec![0.0; n];
            for pt in &self.config.pre_trusted {
                if let Some(&idx) = agent_idx.get(pt.as_str()) {
                    p[idx] = 1.0 / self.config.pre_trusted.len() as f64;
                }
            }
        }

        // EigenTrust iteration: t(k+1) = (1-a)*C^T*t(k) + a*p
        let a = self.config.pre_trust_weight;
        let mut t = p.clone();
        for _ in 0..self.config.iterations {
            let mut t_new = vec![0.0; n];
            for j in 0..n {
                let mut sum = 0.0;
                for i in 0..n {
                    sum += c[i][j] * t[i];
                }
                t_new[j] = (1.0 - a) * sum + a * p[j];
            }
            // Normalize
            let total: f64 = t_new.iter().sum();
            if total > 0.0 {
                for v in &mut t_new { *v /= total; }
            }
            t = t_new;
        }

        // Convert to 0..1 scale (relative to max)
        let max_t = t.iter().cloned().fold(0.0f64, f64::max);
        let scale = if max_t > 0.0 { 1.0 / max_t } else { 1.0 };

        let mut results: Vec<AgentReputation> = agents.iter().enumerate().map(|(i, pid)| {
            let fb_count = self.feedback.iter().filter(|f| f.to == *pid).count();
            AgentReputation {
                agent_pid: pid.clone(),
                global_score: (t[i] * scale).min(1.0),
                feedback_count: fb_count,
                stake: self.stakes.get(pid).copied().unwrap_or(0),
                slashed_count: self.slash_counts.get(pid).copied().unwrap_or(0),
                last_updated_ms: now_ms,
            }
        }).collect();

        results.sort_by(|a, b| b.global_score.partial_cmp(&a.global_score).unwrap());
        results
    }

    /// Get reputation for a single agent.
    pub fn score_for(&self, agent_pid: &str, now_ms: i64) -> f64 {
        let results = self.compute(now_ms);
        results.iter()
            .find(|r| r.agent_pid == agent_pid)
            .map(|r| r.global_score)
            .unwrap_or(0.0)
    }

    /// Time decay factor: exponential decay with configurable half-life.
    fn time_decay(&self, event_ms: i64, now_ms: i64) -> f64 {
        let age = (now_ms - event_ms).max(0) as f64;
        let half_life = self.config.decay_half_life_ms as f64;
        if half_life <= 0.0 { return 1.0; }
        (-age * (2.0f64.ln()) / half_life).exp()
    }

    // ── Accessors ───────────────────────────────────────────
    pub fn feedback_count(&self) -> usize { self.feedback.len() }
    pub fn agent_count(&self) -> usize { self.stakes.len() }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> ReputationEngine {
        let mut config = ReputationConfig::default();
        config.pre_trusted = vec!["trusted_root".into()];
        let mut engine = ReputationEngine::new(config);
        engine.register_stake("trusted_root", 1000);
        engine.register_stake("agent_a", 500);
        engine.register_stake("agent_b", 200);
        engine.register_stake("agent_c", 100);
        engine
    }

    #[test]
    fn test_submit_feedback() {
        let mut e = make_engine();
        let fb = Feedback {
            from: "trusted_root".into(), to: "agent_a".into(),
            score: 0.9, weight: 1.0, timestamp_ms: 1000,
            invocation_id: None,
        };
        assert!(e.submit_feedback(fb).is_ok());
        assert_eq!(e.feedback_count(), 1);
    }

    #[test]
    fn test_sybil_resistance_min_stake() {
        let mut e = make_engine();
        // Unregistered agent has 0 stake
        let fb = Feedback {
            from: "sybil_node".into(), to: "agent_a".into(),
            score: 1.0, weight: 1.0, timestamp_ms: 1000,
            invocation_id: None,
        };
        assert!(e.submit_feedback(fb).is_err());
    }

    #[test]
    fn test_self_feedback_rejected() {
        let mut e = make_engine();
        let fb = Feedback {
            from: "agent_a".into(), to: "agent_a".into(),
            score: 1.0, weight: 1.0, timestamp_ms: 1000,
            invocation_id: None,
        };
        assert!(e.submit_feedback(fb).is_err());
    }

    #[test]
    fn test_eigentrust_converges() {
        let mut e = make_engine();
        // trusted_root → agent_a (high), agent_a → agent_b (high)
        e.submit_feedback(Feedback {
            from: "trusted_root".into(), to: "agent_a".into(),
            score: 0.95, weight: 1.0, timestamp_ms: 1000, invocation_id: None,
        }).unwrap();
        e.submit_feedback(Feedback {
            from: "agent_a".into(), to: "agent_b".into(),
            score: 0.9, weight: 1.0, timestamp_ms: 1000, invocation_id: None,
        }).unwrap();
        let results = e.compute(1000);
        let a_score = results.iter().find(|r| r.agent_pid == "agent_a").unwrap().global_score;
        let b_score = results.iter().find(|r| r.agent_pid == "agent_b").unwrap().global_score;
        // Both should have positive scores (trust propagates)
        assert!(a_score > 0.0, "agent_a should have positive trust");
        assert!(b_score > 0.0, "agent_b should have positive trust via transitive chain");
        // Agents with feedback should score meaningfully (above zero-feedback agents)
        let c_score = results.iter().find(|r| r.agent_pid == "agent_c").unwrap().global_score;
        assert!(a_score > c_score, "agent_a (with feedback) should rank above agent_c (no feedback): a={} c={}", a_score, c_score);
    }

    #[test]
    fn test_transitive_trust() {
        let mut e = make_engine();
        // Chain: root → A → B → C
        e.submit_feedback(Feedback {
            from: "trusted_root".into(), to: "agent_a".into(),
            score: 1.0, weight: 1.0, timestamp_ms: 1000, invocation_id: None,
        }).unwrap();
        e.submit_feedback(Feedback {
            from: "agent_a".into(), to: "agent_b".into(),
            score: 1.0, weight: 1.0, timestamp_ms: 1000, invocation_id: None,
        }).unwrap();
        e.submit_feedback(Feedback {
            from: "agent_b".into(), to: "agent_c".into(),
            score: 1.0, weight: 1.0, timestamp_ms: 1000, invocation_id: None,
        }).unwrap();
        let results = e.compute(1000);
        let c_score = results.iter().find(|r| r.agent_pid == "agent_c").unwrap().global_score;
        assert!(c_score > 0.0, "Transitive trust should propagate to C");
    }

    #[test]
    fn test_time_decay() {
        // Put both agents in the SAME engine so normalization is relative
        let mut e = make_engine();
        // Old feedback for agent_a (from 24h ago — half-life)
        e.submit_feedback(Feedback {
            from: "trusted_root".into(), to: "agent_a".into(),
            score: 1.0, weight: 1.0, timestamp_ms: 0, invocation_id: None,
        }).unwrap();
        // Fresh feedback for agent_b (at query time)
        e.submit_feedback(Feedback {
            from: "trusted_root".into(), to: "agent_b".into(),
            score: 1.0, weight: 1.0, timestamp_ms: 86_400_000, invocation_id: None,
        }).unwrap();
        let results = e.compute(86_400_000);
        let a_score = results.iter().find(|r| r.agent_pid == "agent_a").unwrap().global_score;
        let b_score = results.iter().find(|r| r.agent_pid == "agent_b").unwrap().global_score;
        assert!(b_score > a_score, "Fresh feedback should yield higher score: fresh={} old={}", b_score, a_score);
    }

    #[test]
    fn test_slash_reduces_stake() {
        let mut e = make_engine();
        assert_eq!(e.stakes.get("agent_a").copied().unwrap(), 500);
        let slashed = e.slash("agent_a", 200);
        assert_eq!(slashed, 200);
        assert_eq!(e.stakes.get("agent_a").copied().unwrap(), 300);
        assert_eq!(e.slash_counts.get("agent_a").copied().unwrap(), 1);
    }

    #[test]
    fn test_slash_cannot_exceed_stake() {
        let mut e = make_engine();
        let slashed = e.slash("agent_c", 999);
        assert_eq!(slashed, 100); // Only had 100 stake
        assert_eq!(e.stakes.get("agent_c").copied().unwrap(), 0);
    }

    #[test]
    fn test_empty_engine() {
        let e = ReputationEngine::new(ReputationConfig::default());
        let results = e.compute(1000);
        assert!(results.is_empty());
    }

    #[test]
    fn test_score_range() {
        let mut e = make_engine();
        e.submit_feedback(Feedback {
            from: "trusted_root".into(), to: "agent_a".into(),
            score: 0.8, weight: 1.0, timestamp_ms: 1000, invocation_id: None,
        }).unwrap();
        let results = e.compute(1000);
        for r in &results {
            assert!(r.global_score >= 0.0 && r.global_score <= 1.0,
                "Score out of range: {} = {}", r.agent_pid, r.global_score);
        }
    }
}
