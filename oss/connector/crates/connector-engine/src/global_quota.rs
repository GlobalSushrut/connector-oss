//! Distributed Namespace Quota Enforcement — tracks global quota across cells.
//!
//! Military-grade properties:
//! - Soft enforcement: allows write but emits warning if estimated global > 80%
//! - Aggregates heartbeat data from all cells
//! - Local enforcement still works independently
//! - Audit trail for all quota warnings

use std::collections::HashMap;

// ── Quota Warning ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct QuotaWarning {
    pub namespace: String,
    pub local_count: u64,
    pub estimated_global: u64,
    pub global_limit: u64,
    pub usage_pct: f64,
    pub timestamp: i64,
}

// ── Cell Heartbeat Data ─────────────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CellNamespaceCount {
    cell_id: String,
    packet_count: u64,
    last_heartbeat: i64,
}

// ── Global Quota Tracker ────────────────────────────────────────────

pub struct GlobalQuotaTracker {
    /// namespace → global limit
    limits: HashMap<String, u64>,
    /// namespace → cell_id → packet count
    cell_counts: HashMap<String, HashMap<String, CellNamespaceCount>>,
    /// Warning threshold (0.0 - 1.0, default 0.8 = 80%)
    pub warning_threshold: f64,
    /// Heartbeat staleness threshold (ms) — ignore stale heartbeats
    pub heartbeat_staleness_ms: i64,
    /// Emitted warnings
    warnings: Vec<QuotaWarning>,
}

impl GlobalQuotaTracker {
    pub fn new() -> Self {
        Self {
            limits: HashMap::new(),
            cell_counts: HashMap::new(),
            warning_threshold: 0.80,
            heartbeat_staleness_ms: 60_000, // 1 minute
            warnings: Vec::new(),
        }
    }

    fn now_ms() -> i64 { chrono::Utc::now().timestamp_millis() }

    /// Set global quota for a namespace.
    pub fn set_limit(&mut self, namespace: &str, limit: u64) {
        self.limits.insert(namespace.to_string(), limit);
    }

    /// Update packet count from a cell heartbeat.
    pub fn update_from_heartbeat(&mut self, namespace: &str, cell_id: &str, packet_count: u64) {
        let cells = self.cell_counts.entry(namespace.to_string()).or_default();
        cells.insert(cell_id.to_string(), CellNamespaceCount {
            cell_id: cell_id.to_string(),
            packet_count,
            last_heartbeat: Self::now_ms(),
        });
    }

    /// Estimate global packet count for a namespace (sum of non-stale cell counts).
    pub fn estimated_global(&self, namespace: &str) -> u64 {
        let now = Self::now_ms();
        let staleness = self.heartbeat_staleness_ms;
        self.cell_counts.get(namespace)
            .map(|cells| cells.values()
                .filter(|c| now - c.last_heartbeat <= staleness)
                .map(|c| c.packet_count)
                .sum())
            .unwrap_or(0)
    }

    /// Check if a write should emit a quota warning.
    /// Returns Some(warning) if estimated global exceeds threshold, None otherwise.
    /// The write is always ALLOWED (soft enforcement).
    pub fn check_write(&mut self, namespace: &str, local_count: u64) -> Option<QuotaWarning> {
        let limit = match self.limits.get(namespace) {
            Some(&l) => l,
            None => return None, // no limit set
        };

        let estimated = self.estimated_global(namespace) + local_count;
        let usage_pct = estimated as f64 / limit.max(1) as f64;

        if usage_pct >= self.warning_threshold {
            let warning = QuotaWarning {
                namespace: namespace.to_string(),
                local_count,
                estimated_global: estimated,
                global_limit: limit,
                usage_pct,
                timestamp: Self::now_ms(),
            };
            self.warnings.push(warning.clone());
            Some(warning)
        } else {
            None
        }
    }

    pub fn warnings(&self) -> &[QuotaWarning] { &self.warnings }
    pub fn warning_count(&self) -> usize { self.warnings.len() }
}

impl Default for GlobalQuotaTracker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_limit_no_warning() {
        let mut tracker = GlobalQuotaTracker::new();
        let result = tracker.check_write("ns:test", 100);
        assert!(result.is_none());
    }

    #[test]
    fn test_under_threshold_no_warning() {
        let mut tracker = GlobalQuotaTracker::new();
        tracker.set_limit("ns:test", 1000);
        tracker.update_from_heartbeat("ns:test", "cell-1", 100);

        let result = tracker.check_write("ns:test", 50);
        assert!(result.is_none()); // 150/1000 = 15% < 80%
    }

    #[test]
    fn test_over_threshold_warning() {
        let mut tracker = GlobalQuotaTracker::new();
        tracker.set_limit("ns:test", 1000);
        tracker.update_from_heartbeat("ns:test", "cell-1", 500);
        tracker.update_from_heartbeat("ns:test", "cell-2", 350);

        let result = tracker.check_write("ns:test", 10);
        assert!(result.is_some()); // (500+350+10)/1000 = 86% > 80%

        let warning = result.unwrap();
        assert!(warning.usage_pct > 0.8);
    }

    #[test]
    fn test_multi_cell_aggregation() {
        let mut tracker = GlobalQuotaTracker::new();
        tracker.set_limit("ns:app", 500);
        tracker.update_from_heartbeat("ns:app", "cell-1", 100);
        tracker.update_from_heartbeat("ns:app", "cell-2", 200);
        tracker.update_from_heartbeat("ns:app", "cell-3", 150);

        assert_eq!(tracker.estimated_global("ns:app"), 450);
    }

    #[test]
    fn test_stale_heartbeat_ignored() {
        let mut tracker = GlobalQuotaTracker::new();
        tracker.heartbeat_staleness_ms = 100; // very short
        tracker.set_limit("ns:test", 100);
        tracker.update_from_heartbeat("ns:test", "cell-1", 90);

        // Backdate the heartbeat
        tracker.cell_counts.get_mut("ns:test").unwrap()
            .get_mut("cell-1").unwrap().last_heartbeat -= 200;

        // Stale heartbeat ignored — estimated is 0
        assert_eq!(tracker.estimated_global("ns:test"), 0);
    }

    #[test]
    fn test_warning_count() {
        let mut tracker = GlobalQuotaTracker::new();
        tracker.set_limit("ns:test", 100);
        tracker.update_from_heartbeat("ns:test", "cell-1", 85);

        tracker.check_write("ns:test", 1);
        tracker.check_write("ns:test", 1);

        assert_eq!(tracker.warning_count(), 2);
    }
}
