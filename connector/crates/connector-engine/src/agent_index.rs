//! Agent Index + Indexer Agent — capability graph with inverted index.
//!
//! The indexer is a system-level agent that crawls, catalogs, ranks, and
//! maintains a live index of all agents and their capabilities.
//! NOT a passive catalog — an active, intelligent indexing system.
//!
//! Research: Google search index (inverted index), PageRank ranking,
//! EigenTrust (Kamvar 2003), Google A2A Agent Cards (2025)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::service_contract::ServiceContract;

// ═══════════════════════════════════════════════════════════════
// Agent Health
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Down,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealth {
    pub status: HealthStatus,
    pub uptime_pct: f64,
    pub avg_latency_ms: u64,
    pub error_rate_pct: f64,
    pub last_check_at: i64,
    pub consecutive_failures: u32,
}

impl Default for AgentHealth {
    fn default() -> Self {
        Self {
            status: HealthStatus::Unknown,
            uptime_pct: 100.0,
            avg_latency_ms: 0,
            error_rate_pct: 0.0,
            last_check_at: 0,
            consecutive_failures: 0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Index Entry + Ranked Provider
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIndexEntry {
    pub agent_pid: String,
    pub contract: ServiceContract,
    pub health: AgentHealth,
    pub reputation_score: f64,
    pub last_indexed_at: i64,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedProvider {
    pub agent_pid: String,
    pub composite_score: f64,
}

// ═══════════════════════════════════════════════════════════════
// Agent Index — Capability Graph
// ═══════════════════════════════════════════════════════════════

/// Forward + inverted index for fast capability lookup.
pub struct AgentIndex {
    /// Forward: agent_pid → entry
    agents: HashMap<String, AgentIndexEntry>,
    /// Inverted: capability_key → Vec<agent_pid>
    capability_index: HashMap<String, Vec<String>>,
}

impl AgentIndex {
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
            capability_index: HashMap::new(),
        }
    }

    /// Index an agent with its service contract.
    pub fn index_agent(&mut self, pid: &str, contract: ServiceContract, reputation: f64, now_ms: i64) {
        let entry = AgentIndexEntry {
            agent_pid: pid.to_string(),
            contract: contract.clone(),
            health: AgentHealth::default(),
            reputation_score: reputation,
            last_indexed_at: now_ms,
            is_active: true,
        };

        // Update inverted index
        for key in contract.capability_keys() {
            let providers = self.capability_index.entry(key).or_default();
            if !providers.contains(&pid.to_string()) {
                providers.push(pid.to_string());
            }
        }

        self.agents.insert(pid.to_string(), entry);
    }

    /// Deindex an agent (mark inactive, remove from inverted index).
    pub fn deindex_agent(&mut self, pid: &str) {
        if let Some(entry) = self.agents.get_mut(pid) {
            entry.is_active = false;
            // Remove from inverted index
            for key in entry.contract.capability_keys() {
                if let Some(providers) = self.capability_index.get_mut(&key) {
                    providers.retain(|p| p != pid);
                }
            }
        }
    }

    /// Look up agents by capability key.
    pub fn lookup_capability(&self, domain: &str, action: &str) -> Vec<&AgentIndexEntry> {
        let key = format!("{}:{}", domain, action);
        match self.capability_index.get(&key) {
            Some(pids) => pids.iter()
                .filter_map(|pid| self.agents.get(pid))
                .filter(|e| e.is_active)
                .collect(),
            None => Vec::new(),
        }
    }

    /// Get ranked providers for a capability, sorted by composite score (descending).
    pub fn ranked_providers(&self, domain: &str, action: &str) -> Vec<RankedProvider> {
        let entries = self.lookup_capability(domain, action);
        let mut ranked: Vec<RankedProvider> = entries.iter().map(|e| {
            let trust_score = e.reputation_score;
            let health_score = match e.health.status {
                HealthStatus::Healthy => 1.0,
                HealthStatus::Degraded => 0.5,
                HealthStatus::Down => 0.0,
                HealthStatus::Unknown => 0.3,
            };
            let price_score = {
                let cost = e.contract.pricing.estimated_cost_per_call();
                if cost == 0 { 0.5 } else { 1.0 / (1.0 + cost as f64 / 1000.0) }
            };
            let composite = 0.4 * trust_score + 0.3 * health_score + 0.3 * price_score;
            RankedProvider {
                agent_pid: e.agent_pid.clone(),
                composite_score: composite,
            }
        }).collect();
        ranked.sort_by(|a, b| b.composite_score.partial_cmp(&a.composite_score).unwrap());
        ranked
    }

    /// Update health for an agent.
    pub fn update_health(&mut self, pid: &str, health: AgentHealth) {
        if let Some(entry) = self.agents.get_mut(pid) {
            entry.health = health;
        }
    }

    /// Update reputation score for an agent.
    pub fn update_reputation(&mut self, pid: &str, score: f64) {
        if let Some(entry) = self.agents.get_mut(pid) {
            entry.reputation_score = score;
        }
    }

    /// Purge stale entries (contracts expired or not indexed recently).
    pub fn purge_stale(&mut self, now_ms: i64, staleness_threshold_ms: i64) -> Vec<String> {
        let stale: Vec<String> = self.agents.iter()
            .filter(|(_, e)| {
                e.is_active && (
                    e.contract.is_expired(now_ms) ||
                    (now_ms - e.last_indexed_at > staleness_threshold_ms)
                )
            })
            .map(|(pid, _)| pid.clone())
            .collect();

        for pid in &stale {
            self.deindex_agent(pid);
        }
        stale
    }

    /// Run health checks — mark agents as degraded/down based on consecutive failures.
    pub fn run_health_checks(&mut self, now_ms: i64) {
        let pids: Vec<String> = self.agents.keys().cloned().collect();
        for pid in pids {
            if let Some(entry) = self.agents.get_mut(&pid) {
                if !entry.is_active { continue; }
                entry.health.last_check_at = now_ms;
                // Simulated: in production, would probe the agent
                // For now, status derived from consecutive_failures
                entry.health.status = match entry.health.consecutive_failures {
                    0 => HealthStatus::Healthy,
                    1..=2 => HealthStatus::Degraded,
                    _ => HealthStatus::Down,
                };
            }
        }
    }

    // ── Accessors ───────────────────────────────────────────

    pub fn get_entry(&self, pid: &str) -> Option<&AgentIndexEntry> { self.agents.get(pid) }
    pub fn active_count(&self) -> usize { self.agents.values().filter(|e| e.is_active).count() }
    pub fn total_count(&self) -> usize { self.agents.len() }
    pub fn capability_count(&self) -> usize { self.capability_index.len() }

    pub fn all_capability_keys(&self) -> Vec<String> {
        self.capability_index.keys().cloned().collect()
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_contract::*;

    fn make_contract(domain: &str, action: &str, cost: u64, now: i64) -> ServiceContract {
        ServiceContract {
            contract_id: format!("sc_{}_{}", domain, action),
            provider_pid: "".into(), // set per agent
            provider_did: None,
            capabilities: vec![CapabilitySpec {
                domain: domain.into(), action: action.into(),
                version: "1.0".into(), parameters: vec![],
            }],
            input_schema: vec![], output_schema: vec![],
            sla: ServiceLevelAgreement {
                max_latency_ms: 500, availability_pct: 99.0,
                max_error_rate_pct: 1.0, max_concurrent: 10,
            },
            pricing: PricingModel::PerInvocation { cost_per_call: cost },
            stake_amount: 100, published_at: now,
            expires_at: now + 86_400_000, attestation: None,
        }
    }

    #[test]
    fn test_index_and_lookup() {
        let mut idx = AgentIndex::new();
        let c = make_contract("translation", "translate", 100, 1000);
        idx.index_agent("agent_a", c, 0.8, 1000);
        let results = idx.lookup_capability("translation", "translate");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_pid, "agent_a");
    }

    #[test]
    fn test_inverted_index_multiple_providers() {
        let mut idx = AgentIndex::new();
        idx.index_agent("a1", make_contract("translation", "translate", 100, 1000), 0.9, 1000);
        idx.index_agent("a2", make_contract("translation", "translate", 200, 1000), 0.7, 1000);
        idx.index_agent("a3", make_contract("analysis", "summarize", 50, 1000), 0.8, 1000);
        assert_eq!(idx.lookup_capability("translation", "translate").len(), 2);
        assert_eq!(idx.lookup_capability("analysis", "summarize").len(), 1);
        assert_eq!(idx.lookup_capability("unknown", "action").len(), 0);
    }

    #[test]
    fn test_deindex_removes_from_inverted() {
        let mut idx = AgentIndex::new();
        idx.index_agent("a1", make_contract("translation", "translate", 100, 1000), 0.8, 1000);
        assert_eq!(idx.lookup_capability("translation", "translate").len(), 1);
        idx.deindex_agent("a1");
        assert_eq!(idx.lookup_capability("translation", "translate").len(), 0);
        assert_eq!(idx.active_count(), 0);
        assert_eq!(idx.total_count(), 1); // Still exists, just inactive
    }

    #[test]
    fn test_health_update() {
        let mut idx = AgentIndex::new();
        idx.index_agent("a1", make_contract("t", "a", 100, 1000), 0.8, 1000);
        assert_eq!(idx.get_entry("a1").unwrap().health.status, HealthStatus::Unknown);
        idx.update_health("a1", AgentHealth {
            status: HealthStatus::Healthy, uptime_pct: 99.9,
            avg_latency_ms: 50, error_rate_pct: 0.1,
            last_check_at: 2000, consecutive_failures: 0,
        });
        assert_eq!(idx.get_entry("a1").unwrap().health.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_staleness_purge() {
        let mut idx = AgentIndex::new();
        idx.index_agent("a1", make_contract("t", "a", 100, 1000), 0.8, 1000);
        // 2 hours later, staleness threshold is 1 hour
        let purged = idx.purge_stale(1000 + 7_200_000, 3_600_000);
        assert_eq!(purged.len(), 1);
        assert_eq!(purged[0], "a1");
        assert_eq!(idx.active_count(), 0);
    }

    #[test]
    fn test_expired_contract_purged() {
        let mut idx = AgentIndex::new();
        let mut c = make_contract("t", "a", 100, 1000);
        c.expires_at = 5000; // Expires very soon
        idx.index_agent("a1", c, 0.8, 1000);
        let purged = idx.purge_stale(6000, 999_999_999);
        assert_eq!(purged.len(), 1);
    }

    #[test]
    fn test_ranked_providers_order() {
        let mut idx = AgentIndex::new();
        idx.index_agent("cheap_low_trust", make_contract("t", "a", 10, 1000), 0.3, 1000);
        idx.index_agent("expensive_high_trust", make_contract("t", "a", 500, 1000), 0.95, 1000);
        idx.index_agent("mid_mid_trust", make_contract("t", "a", 100, 1000), 0.6, 1000);
        let ranked = idx.ranked_providers("t", "a");
        assert_eq!(ranked.len(), 3);
        // High trust should rank higher despite higher price
        assert_eq!(ranked[0].agent_pid, "expensive_high_trust");
    }

    #[test]
    fn test_capability_key_format() {
        let mut idx = AgentIndex::new();
        idx.index_agent("a1", make_contract("translation", "translate", 100, 1000), 0.8, 1000);
        let keys = idx.all_capability_keys();
        assert!(keys.contains(&"translation:translate".to_string()));
    }

    #[test]
    fn test_run_health_checks() {
        let mut idx = AgentIndex::new();
        idx.index_agent("a1", make_contract("t", "a", 100, 1000), 0.8, 1000);
        idx.agents.get_mut("a1").unwrap().health.consecutive_failures = 3;
        idx.run_health_checks(2000);
        assert_eq!(idx.get_entry("a1").unwrap().health.status, HealthStatus::Down);
    }

    #[test]
    fn test_reputation_update() {
        let mut idx = AgentIndex::new();
        idx.index_agent("a1", make_contract("t", "a", 100, 1000), 0.5, 1000);
        assert!((idx.get_entry("a1").unwrap().reputation_score - 0.5).abs() < 0.01);
        idx.update_reputation("a1", 0.9);
        assert!((idx.get_entry("a1").unwrap().reputation_score - 0.9).abs() < 0.01);
    }
}
