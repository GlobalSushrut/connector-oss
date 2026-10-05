//! Dynamic Pricing — surge pricing, volume discounts, budget gates.
//!
//! Prices adjust based on demand (surge), usage history (volume discounts),
//! and hard budget limits (gates). Creates economic backpressure on overuse.
//!
//! Research: AWS spot pricing, Uber surge, Akash reverse auction,
//! cloud GPU pricing (Lambda Labs, RunPod)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Price Quote
// ═══════════════════════════════════════════════════════════════

/// A computed price for a specific invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceQuote {
    pub base_cost: u64,
    pub surge_multiplier: f64,
    pub volume_discount_pct: f64,
    pub final_cost: u64,
    pub budget_remaining: Option<u64>,
    pub budget_exceeded: bool,
}

// ═══════════════════════════════════════════════════════════════
// Budget Gate
// ═══════════════════════════════════════════════════════════════

/// Hard spending limit for an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetGate {
    pub agent_pid: String,
    pub max_spend: u64,
    pub spent: u64,
    pub window_start_ms: i64,
    pub window_duration_ms: i64,
}

impl BudgetGate {
    pub fn remaining(&self) -> u64 {
        self.max_spend.saturating_sub(self.spent)
    }

    pub fn is_exceeded(&self) -> bool {
        self.spent >= self.max_spend
    }

    pub fn is_window_expired(&self, now_ms: i64) -> bool {
        now_ms > self.window_start_ms + self.window_duration_ms
    }

    pub fn reset(&mut self, now_ms: i64) {
        self.spent = 0;
        self.window_start_ms = now_ms;
    }
}

// ═══════════════════════════════════════════════════════════════
// Dynamic Pricer
// ═══════════════════════════════════════════════════════════════

/// Configuration for dynamic pricing.
#[derive(Debug, Clone)]
pub struct PricingConfig {
    /// Maximum surge multiplier (e.g., 3.0 = 3x base price).
    pub max_surge: f64,
    /// Demand window in milliseconds for computing surge.
    pub surge_window_ms: i64,
    /// Number of requests in window that triggers max surge.
    pub surge_threshold: u64,
    /// Volume discount tiers: (min_invocations, discount_pct).
    pub volume_tiers: Vec<(u64, f64)>,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            max_surge: 3.0,
            surge_window_ms: 60_000, // 1 minute
            surge_threshold: 100,
            volume_tiers: vec![
                (10, 5.0),    // 5% off after 10 calls
                (100, 10.0),  // 10% off after 100
                (1000, 20.0), // 20% off after 1000
            ],
        }
    }
}

/// Dynamic pricing engine with surge, volume discounts, and budget gates.
pub struct DynamicPricer {
    config: PricingConfig,
    /// Per-provider demand tracking: provider_pid → Vec<timestamp_ms>
    demand: HashMap<String, Vec<i64>>,
    /// Per-(requester, provider) invocation counts for volume discounts.
    invocation_counts: HashMap<(String, String), u64>,
    /// Per-agent budget gates.
    budgets: HashMap<String, BudgetGate>,
}

impl DynamicPricer {
    pub fn new(config: PricingConfig) -> Self {
        Self {
            config,
            demand: HashMap::new(),
            invocation_counts: HashMap::new(),
            budgets: HashMap::new(),
        }
    }

    /// Record a request to a provider (for surge calculation).
    pub fn record_request(&mut self, provider_pid: &str, now_ms: i64) {
        let timestamps = self.demand.entry(provider_pid.to_string()).or_default();
        timestamps.push(now_ms);
        // Prune old entries outside window
        let cutoff = now_ms - self.config.surge_window_ms;
        timestamps.retain(|t| *t >= cutoff);
    }

    /// Record a completed invocation (for volume discounts).
    pub fn record_invocation(&mut self, requester: &str, provider: &str) {
        let key = (requester.to_string(), provider.to_string());
        *self.invocation_counts.entry(key).or_insert(0) += 1;
    }

    /// Set a budget gate for an agent.
    pub fn set_budget(&mut self, agent_pid: &str, max_spend: u64, window_ms: i64, now_ms: i64) {
        self.budgets.insert(agent_pid.to_string(), BudgetGate {
            agent_pid: agent_pid.to_string(),
            max_spend,
            spent: 0,
            window_start_ms: now_ms,
            window_duration_ms: window_ms,
        });
    }

    /// Compute price quote for an invocation.
    pub fn quote(
        &mut self,
        requester: &str,
        provider: &str,
        base_cost: u64,
        now_ms: i64,
    ) -> PriceQuote {
        // 1. Surge multiplier
        let surge = self.compute_surge(provider, now_ms);

        // 2. Volume discount
        let key = (requester.to_string(), provider.to_string());
        let count = self.invocation_counts.get(&key).copied().unwrap_or(0);
        let discount = self.compute_volume_discount(count);

        // 3. Apply pricing
        let surged = (base_cost as f64 * surge) as u64;
        let discount_amount = (surged as f64 * discount / 100.0) as u64;
        let final_cost = surged.saturating_sub(discount_amount).max(1);

        // 4. Budget gate check
        let (budget_remaining, budget_exceeded) = self.check_budget(requester, final_cost, now_ms);

        PriceQuote {
            base_cost,
            surge_multiplier: surge,
            volume_discount_pct: discount,
            final_cost,
            budget_remaining,
            budget_exceeded,
        }
    }

    /// Charge an agent's budget (call after successful invocation).
    pub fn charge(&mut self, agent_pid: &str, amount: u64, now_ms: i64) -> Result<(), String> {
        if let Some(gate) = self.budgets.get_mut(agent_pid) {
            if gate.is_window_expired(now_ms) {
                gate.reset(now_ms);
            }
            if gate.spent + amount > gate.max_spend {
                return Err(format!(
                    "Budget exceeded: {} spent {} + {} > max {}",
                    agent_pid, gate.spent, amount, gate.max_spend
                ));
            }
            gate.spent += amount;
        }
        Ok(())
    }

    fn compute_surge(&self, provider: &str, now_ms: i64) -> f64 {
        let cutoff = now_ms - self.config.surge_window_ms;
        let recent_count = self.demand.get(provider)
            .map(|ts| ts.iter().filter(|t| **t >= cutoff).count() as u64)
            .unwrap_or(0);
        if self.config.surge_threshold == 0 {
            return 1.0;
        }
        let ratio = recent_count as f64 / self.config.surge_threshold as f64;
        let surge = 1.0 + (self.config.max_surge - 1.0) * ratio.min(1.0);
        surge.min(self.config.max_surge)
    }

    fn compute_volume_discount(&self, invocation_count: u64) -> f64 {
        let mut best_discount = 0.0;
        for (min_count, discount) in &self.config.volume_tiers {
            if invocation_count >= *min_count && *discount > best_discount {
                best_discount = *discount;
            }
        }
        best_discount
    }

    fn check_budget(&mut self, agent_pid: &str, cost: u64, now_ms: i64) -> (Option<u64>, bool) {
        match self.budgets.get_mut(agent_pid) {
            Some(gate) => {
                if gate.is_window_expired(now_ms) {
                    gate.reset(now_ms);
                }
                let remaining = gate.remaining();
                let exceeded = cost > remaining;
                (Some(remaining), exceeded)
            }
            None => (None, false),
        }
    }

    // ── Accessors ───────────────────────────────────────────
    pub fn get_budget(&self, agent_pid: &str) -> Option<&BudgetGate> {
        self.budgets.get(agent_pid)
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_price_no_surge() {
        let mut pricer = DynamicPricer::new(PricingConfig::default());
        let quote = pricer.quote("req", "prov", 100, 1000);
        assert_eq!(quote.base_cost, 100);
        assert!((quote.surge_multiplier - 1.0).abs() < 0.01);
        assert_eq!(quote.final_cost, 100);
        assert!(!quote.budget_exceeded);
    }

    #[test]
    fn test_surge_pricing() {
        let mut pricer = DynamicPricer::new(PricingConfig {
            max_surge: 3.0,
            surge_window_ms: 60_000,
            surge_threshold: 10,
            volume_tiers: vec![],
        });
        // Record 10 requests (= threshold) → should hit max surge
        for i in 0..10 {
            pricer.record_request("prov", 1000 + i);
        }
        let quote = pricer.quote("req", "prov", 100, 1005);
        assert!(quote.surge_multiplier > 2.5, "Surge should be near max: {}", quote.surge_multiplier);
        assert!(quote.final_cost > 250);
    }

    #[test]
    fn test_volume_discount() {
        let mut pricer = DynamicPricer::new(PricingConfig::default());
        // Simulate 100 invocations
        for _ in 0..100 {
            pricer.record_invocation("req", "prov");
        }
        let quote = pricer.quote("req", "prov", 1000, 1000);
        assert!((quote.volume_discount_pct - 10.0).abs() < 0.01); // 10% at 100 calls
        assert!(quote.final_cost < 1000);
    }

    #[test]
    fn test_budget_gate_allows() {
        let mut pricer = DynamicPricer::new(PricingConfig::default());
        pricer.set_budget("req", 5000, 3600_000, 0);
        let quote = pricer.quote("req", "prov", 100, 1000);
        assert!(!quote.budget_exceeded);
        assert_eq!(quote.budget_remaining, Some(5000));
    }

    #[test]
    fn test_budget_gate_blocks() {
        let mut pricer = DynamicPricer::new(PricingConfig::default());
        pricer.set_budget("req", 50, 3600_000, 0);
        let quote = pricer.quote("req", "prov", 100, 1000);
        assert!(quote.budget_exceeded);
    }

    #[test]
    fn test_budget_charge_and_track() {
        let mut pricer = DynamicPricer::new(PricingConfig::default());
        pricer.set_budget("req", 500, 3600_000, 0);
        assert!(pricer.charge("req", 200, 1000).is_ok());
        assert_eq!(pricer.get_budget("req").unwrap().remaining(), 300);
        assert!(pricer.charge("req", 400, 2000).is_err()); // Would exceed
    }

    #[test]
    fn test_budget_window_reset() {
        let mut pricer = DynamicPricer::new(PricingConfig::default());
        pricer.set_budget("req", 100, 60_000, 0);
        assert!(pricer.charge("req", 90, 1000).is_ok());
        assert_eq!(pricer.get_budget("req").unwrap().remaining(), 10);
        // Window expires → resets
        assert!(pricer.charge("req", 50, 70_000).is_ok());
        assert_eq!(pricer.get_budget("req").unwrap().remaining(), 50);
    }

    #[test]
    fn test_surge_decays_outside_window() {
        let mut pricer = DynamicPricer::new(PricingConfig {
            max_surge: 3.0,
            surge_window_ms: 1000,
            surge_threshold: 5,
            volume_tiers: vec![],
        });
        for i in 0..5 {
            pricer.record_request("prov", i);
        }
        // Way after the surge window
        let quote = pricer.quote("req", "prov", 100, 100_000);
        assert!((quote.surge_multiplier - 1.0).abs() < 0.01, "Surge should have decayed");
    }
}
