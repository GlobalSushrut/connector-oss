//! Intent-Based Discovery — agents declare what they need, not what to search for.
//!
//! Queries the AgentIndex with multi-criteria filtering and deterministic ranking.
//!
//! Research: Akash Network reverse auction matching, Google A2A Agent Cards,
//! Service mesh discovery (Istio/Envoy)

use serde::{Deserialize, Serialize};

use crate::agent_index::{AgentIndex, AgentIndexEntry, RankedProvider, HealthStatus};

// ═══════════════════════════════════════════════════════════════
// Intent Query
// ═══════════════════════════════════════════════════════════════

/// An agent declares what it needs — the query engine finds matching providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentQuery {
    pub requester_pid: String,
    pub domain: String,
    pub action: String,
    pub max_latency_ms: Option<u64>,
    pub min_availability_pct: Option<f64>,
    pub max_cost_per_call: Option<u64>,
    pub min_trust_score: Option<f64>,
    pub max_results: usize,
}

/// Result of a discovery query.
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    pub providers: Vec<RankedProvider>,
    pub total_indexed: usize,
    pub matched: usize,
}

// ═══════════════════════════════════════════════════════════════
// Query Engine
// ═══════════════════════════════════════════════════════════════

/// Multi-criteria query engine that searches the AgentIndex.
pub struct QueryEngine;

impl QueryEngine {
    /// Execute an intent query against the agent index.
    pub fn search(index: &AgentIndex, query: &IntentQuery) -> DiscoveryResult {
        let candidates = index.lookup_capability(&query.domain, &query.action);
        let total_indexed = index.active_count();

        // Filter by SLA, price, trust
        let filtered: Vec<&AgentIndexEntry> = candidates.into_iter()
            .filter(|e| {
                // SLA filter
                if let Some(max_lat) = query.max_latency_ms {
                    if e.contract.sla.max_latency_ms > max_lat { return false; }
                }
                if let Some(min_avail) = query.min_availability_pct {
                    if e.contract.sla.availability_pct < min_avail { return false; }
                }
                // Price filter
                if let Some(max_cost) = query.max_cost_per_call {
                    let cost = e.contract.pricing.estimated_cost_per_call();
                    if cost > max_cost { return false; }
                }
                // Trust filter
                if let Some(min_trust) = query.min_trust_score {
                    if e.reputation_score < min_trust { return false; }
                }
                // Must be healthy or degraded (not down)
                if e.health.status == HealthStatus::Down { return false; }
                true
            })
            .collect();

        let matched = filtered.len();

        // Rank by composite score
        let mut ranked: Vec<RankedProvider> = filtered.iter().map(|e| {
            let trust = e.reputation_score;
            let health = match e.health.status {
                HealthStatus::Healthy => 1.0,
                HealthStatus::Degraded => 0.5,
                _ => 0.3,
            };
            let cost = e.contract.pricing.estimated_cost_per_call();
            let price = if cost == 0 { 0.5 } else { 1.0 / (1.0 + cost as f64 / 1000.0) };
            let sla_fit = {
                let lat_score = if let Some(max_lat) = query.max_latency_ms {
                    1.0 - (e.contract.sla.max_latency_ms as f64 / max_lat as f64)
                } else { 0.5 };
                lat_score.max(0.0)
            };
            let composite = 0.35 * trust + 0.25 * health + 0.20 * price + 0.20 * sla_fit;
            RankedProvider { agent_pid: e.agent_pid.clone(), composite_score: composite }
        }).collect();

        ranked.sort_by(|a, b| b.composite_score.partial_cmp(&a.composite_score).unwrap());
        ranked.truncate(query.max_results);

        DiscoveryResult { providers: ranked, total_indexed, matched }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_contract::*;
    use crate::agent_index::AgentHealth;

    fn make_contract(lat: u64, avail: f64, cost: u64, now: i64) -> ServiceContract {
        ServiceContract {
            contract_id: "sc".into(), provider_pid: "".into(), provider_did: None,
            capabilities: vec![CapabilitySpec {
                domain: "translation".into(), action: "translate".into(),
                version: "1.0".into(), parameters: vec![],
            }],
            input_schema: vec![], output_schema: vec![],
            sla: ServiceLevelAgreement {
                max_latency_ms: lat, availability_pct: avail,
                max_error_rate_pct: 1.0, max_concurrent: 10,
            },
            pricing: PricingModel::PerInvocation { cost_per_call: cost },
            stake_amount: 100, published_at: now,
            expires_at: now + 86_400_000, attestation: None,
        }
    }

    fn build_index() -> AgentIndex {
        let mut idx = AgentIndex::new();
        idx.index_agent("fast_expensive", make_contract(100, 99.9, 500, 1000), 0.9, 1000);
        idx.index_agent("slow_cheap", make_contract(2000, 95.0, 10, 1000), 0.6, 1000);
        idx.index_agent("mid_mid", make_contract(500, 99.0, 100, 1000), 0.75, 1000);
        idx.update_health("fast_expensive", AgentHealth {
            status: HealthStatus::Healthy, uptime_pct: 99.9,
            avg_latency_ms: 80, error_rate_pct: 0.05,
            last_check_at: 1000, consecutive_failures: 0,
        });
        idx.update_health("slow_cheap", AgentHealth {
            status: HealthStatus::Healthy, ..AgentHealth::default()
        });
        idx.update_health("mid_mid", AgentHealth {
            status: HealthStatus::Healthy, ..AgentHealth::default()
        });
        idx
    }

    #[test]
    fn test_basic_intent_query() {
        let idx = build_index();
        let q = IntentQuery {
            requester_pid: "req".into(), domain: "translation".into(),
            action: "translate".into(), max_latency_ms: None,
            min_availability_pct: None, max_cost_per_call: None,
            min_trust_score: None, max_results: 10,
        };
        let result = QueryEngine::search(&idx, &q);
        assert_eq!(result.matched, 3);
        assert_eq!(result.providers.len(), 3);
    }

    #[test]
    fn test_sla_latency_filter() {
        let idx = build_index();
        let q = IntentQuery {
            requester_pid: "req".into(), domain: "translation".into(),
            action: "translate".into(), max_latency_ms: Some(500),
            min_availability_pct: None, max_cost_per_call: None,
            min_trust_score: None, max_results: 10,
        };
        let result = QueryEngine::search(&idx, &q);
        assert_eq!(result.matched, 2); // fast_expensive (100ms) + mid_mid (500ms)
        assert!(result.providers.iter().all(|p| p.agent_pid != "slow_cheap"));
    }

    #[test]
    fn test_price_filter() {
        let idx = build_index();
        let q = IntentQuery {
            requester_pid: "req".into(), domain: "translation".into(),
            action: "translate".into(), max_latency_ms: None,
            min_availability_pct: None, max_cost_per_call: Some(200),
            min_trust_score: None, max_results: 10,
        };
        let result = QueryEngine::search(&idx, &q);
        assert_eq!(result.matched, 2); // slow_cheap (10) + mid_mid (100)
    }

    #[test]
    fn test_trust_filter() {
        let idx = build_index();
        let q = IntentQuery {
            requester_pid: "req".into(), domain: "translation".into(),
            action: "translate".into(), max_latency_ms: None,
            min_availability_pct: None, max_cost_per_call: None,
            min_trust_score: Some(0.8), max_results: 10,
        };
        let result = QueryEngine::search(&idx, &q);
        assert_eq!(result.matched, 1); // Only fast_expensive (0.9)
    }

    #[test]
    fn test_ranking_order() {
        let idx = build_index();
        let q = IntentQuery {
            requester_pid: "req".into(), domain: "translation".into(),
            action: "translate".into(), max_latency_ms: None,
            min_availability_pct: None, max_cost_per_call: None,
            min_trust_score: None, max_results: 10,
        };
        let result = QueryEngine::search(&idx, &q);
        // High trust agent should be first
        assert_eq!(result.providers[0].agent_pid, "fast_expensive");
    }

    #[test]
    fn test_no_results() {
        let idx = build_index();
        let q = IntentQuery {
            requester_pid: "req".into(), domain: "unknown".into(),
            action: "action".into(), max_latency_ms: None,
            min_availability_pct: None, max_cost_per_call: None,
            min_trust_score: None, max_results: 10,
        };
        let result = QueryEngine::search(&idx, &q);
        assert_eq!(result.matched, 0);
        assert!(result.providers.is_empty());
    }

    #[test]
    fn test_max_results_truncation() {
        let idx = build_index();
        let q = IntentQuery {
            requester_pid: "req".into(), domain: "translation".into(),
            action: "translate".into(), max_latency_ms: None,
            min_availability_pct: None, max_cost_per_call: None,
            min_trust_score: None, max_results: 2,
        };
        let result = QueryEngine::search(&idx, &q);
        assert_eq!(result.providers.len(), 2);
    }

    #[test]
    fn test_down_agents_excluded() {
        let mut idx = build_index();
        idx.update_health("mid_mid", AgentHealth {
            status: HealthStatus::Down, consecutive_failures: 5,
            ..AgentHealth::default()
        });
        let q = IntentQuery {
            requester_pid: "req".into(), domain: "translation".into(),
            action: "translate".into(), max_latency_ms: None,
            min_availability_pct: None, max_cost_per_call: None,
            min_trust_score: None, max_results: 10,
        };
        let result = QueryEngine::search(&idx, &q);
        assert_eq!(result.matched, 2); // mid_mid excluded (Down)
    }
}
