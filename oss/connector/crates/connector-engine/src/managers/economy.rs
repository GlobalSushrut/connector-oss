//! EconomyManager — Payments and pricing subsystem.
//!
//! Groups economy-related engines:
//! - `EscrowManager` — Trustless payment between agents
//! - `DynamicPricer` — Dynamic pricing for agent services
//! - `GlobalQuotaTracker` — Cross-agent rate/resource limits

use crate::escrow::EscrowManager;
use crate::pricing::{DynamicPricer, PricingConfig};
use crate::global_quota::GlobalQuotaTracker;

/// EconomyManager — unified payments and pricing layer.
///
/// Consolidates all economy-related engines into a single manager,
/// providing a cohesive API for escrow, pricing, and quota management.
pub struct EconomyManager {
    /// EscrowManager — trustless payment between agents
    pub escrow: EscrowManager,
    /// DynamicPricer — dynamic pricing for agent services
    pub pricer: DynamicPricer,
    /// GlobalQuotaTracker — cross-agent rate/resource limits
    pub global_quota: GlobalQuotaTracker,
}

impl EconomyManager {
    /// Create a new EconomyManager with default configurations.
    pub fn new() -> Self {
        Self {
            escrow: EscrowManager::new(),
            pricer: DynamicPricer::new(PricingConfig::default()),
            global_quota: GlobalQuotaTracker::new(),
        }
    }

    /// Create with custom pricing configuration.
    pub fn with_pricing_config(mut self, config: PricingConfig) -> Self {
        self.pricer = DynamicPricer::new(config);
        self
    }

    /// Check if a write should emit a quota warning.
    pub fn check_quota_write(&mut self, namespace: &str, local_count: u64) -> Option<crate::global_quota::QuotaWarning> {
        self.global_quota.check_write(namespace, local_count)
    }

    /// Set global quota limit for a namespace.
    pub fn set_quota_limit(&mut self, namespace: &str, limit: u64) {
        self.global_quota.set_limit(namespace, limit);
    }

    /// Update quota from cell heartbeat.
    pub fn update_quota_heartbeat(&mut self, namespace: &str, cell_id: &str, packet_count: u64) {
        self.global_quota.update_from_heartbeat(namespace, cell_id, packet_count);
    }

    /// Get estimated global count for a namespace.
    pub fn estimated_global_count(&self, namespace: &str) -> u64 {
        self.global_quota.estimated_global(namespace)
    }

    /// Get escrow manager reference.
    pub fn escrow(&self) -> &EscrowManager {
        &self.escrow
    }

    /// Get mutable escrow manager reference.
    pub fn escrow_mut(&mut self) -> &mut EscrowManager {
        &mut self.escrow
    }

    /// Get pricer reference.
    pub fn pricer(&self) -> &DynamicPricer {
        &self.pricer
    }

    /// Get mutable pricer reference.
    pub fn pricer_mut(&mut self) -> &mut DynamicPricer {
        &mut self.pricer
    }

    /// Get global quota tracker reference.
    pub fn global_quota(&self) -> &GlobalQuotaTracker {
        &self.global_quota
    }

    /// Get mutable global quota tracker reference.
    pub fn global_quota_mut(&mut self) -> &mut GlobalQuotaTracker {
        &mut self.global_quota
    }
}

impl Default for EconomyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_economy_manager_creation() {
        let mut manager = EconomyManager::new();
        manager.set_quota_limit("tokens", 1000);
        // Verify quota was set
        assert_eq!(manager.estimated_global_count("tokens"), 0);
    }

    #[test]
    fn test_quota_heartbeat() {
        let mut manager = EconomyManager::new();
        manager.set_quota_limit("tokens", 1000);
        manager.update_quota_heartbeat("tokens", "cell-1", 100);
        assert_eq!(manager.estimated_global_count("tokens"), 100);
    }
}
