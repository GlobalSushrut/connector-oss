//! Adaptive Router — workload-aware routing for distributed cells.
//!
//! Routes agent requests to the optimal cell based on workload type and
//! real-time cell metrics. Falls back to consistent hash ring when no
//! metrics are available.
//!
//! Analogous to Linux's CFS scheduler + NUMA-aware memory placement.
//!
//! Research: SchedCP (arXiv:2509.01245), Confluent event-driven patterns,
//! Kubernetes scheduler framework

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Workload Types
// ═══════════════════════════════════════════════════════════════

/// Workload classification — determines routing strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadType {
    /// Chat, Q&A — optimize for lowest latency
    Interactive,
    /// Bulk processing — optimize for highest throughput
    Batch,
    /// Non-urgent — can be preempted by Interactive/Realtime
    Background,
    /// Safety-critical — preempts everything, deadline-enforced
    Realtime,
}

/// Workload profile attached to a routing request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadProfile {
    pub workload_type: WorkloadType,
    pub agent_pid: String,
    /// Estimated tokens for this request
    pub estimated_tokens: u64,
    /// Hard deadline in ms (0 = no deadline)
    pub deadline_ms: u64,
}

// ═══════════════════════════════════════════════════════════════
// Cell Metrics
// ═══════════════════════════════════════════════════════════════

/// Real-time health/load metrics for a single cell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellLoad {
    pub cell_id: String,
    pub active_agents: usize,
    pub queue_depth: usize,
    pub avg_latency_ms: f64,
    pub token_throughput: f64,
    pub load_pct: f64,
    /// Timestamp of last metric update (ms epoch)
    pub updated_at_ms: u64,
}

impl CellLoad {
    pub fn new(cell_id: impl Into<String>) -> Self {
        Self {
            cell_id: cell_id.into(),
            active_agents: 0,
            queue_depth: 0,
            avg_latency_ms: 0.0,
            token_throughput: 0.0,
            load_pct: 0.0,
            updated_at_ms: 0,
        }
    }

    /// Check if metrics are stale (no update for > staleness_threshold_ms).
    pub fn is_stale(&self, now_ms: u64, staleness_threshold_ms: u64) -> bool {
        self.updated_at_ms == 0 || now_ms.saturating_sub(self.updated_at_ms) > staleness_threshold_ms
    }
}

// ═══════════════════════════════════════════════════════════════
// Routing Decision
// ═══════════════════════════════════════════════════════════════

/// Result of a routing decision.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteDecision {
    pub cell_id: String,
    pub reason: RouteReason,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RouteReason {
    /// Chosen by workload-aware adaptive routing
    Adaptive(String),
    /// Fell back to hash ring (no metrics or all stale)
    HashFallback,
    /// Only one cell available
    OnlyCell,
    /// No cells available
    NoCells,
}

// ═══════════════════════════════════════════════════════════════
// Adaptive Router
// ═══════════════════════════════════════════════════════════════

/// Adaptive router that selects cells based on workload type and metrics.
pub struct AdaptiveRouter {
    metrics: HashMap<String, CellLoad>,
    /// Max load percentage before a cell is excluded (default: 90%)
    max_load_pct: f64,
    /// Staleness threshold in ms (default: 90s)
    staleness_threshold_ms: u64,
}

impl AdaptiveRouter {
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
            max_load_pct: 90.0,
            staleness_threshold_ms: 90_000,
        }
    }

    pub fn with_config(max_load_pct: f64, staleness_threshold_ms: u64) -> Self {
        Self {
            metrics: HashMap::new(),
            max_load_pct,
            staleness_threshold_ms,
        }
    }

    /// Update metrics for a cell (typically from heartbeat events).
    pub fn update_metrics(&mut self, load: CellLoad) {
        self.metrics.insert(load.cell_id.clone(), load);
    }

    /// Remove a cell from the routing table (e.g., on shutdown).
    pub fn remove_cell(&mut self, cell_id: &str) {
        self.metrics.remove(cell_id);
    }

    /// Get current cell count.
    pub fn cell_count(&self) -> usize {
        self.metrics.len()
    }

    /// Get metrics for a specific cell.
    pub fn get_metrics(&self, cell_id: &str) -> Option<&CellLoad> {
        self.metrics.get(cell_id)
    }

    /// Route a workload to the best cell.
    pub fn route(&self, profile: &WorkloadProfile, now_ms: u64) -> RouteDecision {
        if self.metrics.is_empty() {
            return RouteDecision { cell_id: String::new(), reason: RouteReason::NoCells };
        }

        // Filter to healthy, non-stale, non-overloaded cells
        let eligible: Vec<&CellLoad> = self.metrics.values()
            .filter(|c| !c.is_stale(now_ms, self.staleness_threshold_ms))
            .filter(|c| c.load_pct < self.max_load_pct)
            .collect();

        if eligible.is_empty() {
            // Fall back to hash-based selection among ALL cells (even stale)
            return self.hash_fallback(&profile.agent_pid);
        }

        if eligible.len() == 1 {
            return RouteDecision {
                cell_id: eligible[0].cell_id.clone(),
                reason: RouteReason::OnlyCell,
            };
        }

        match profile.workload_type {
            WorkloadType::Interactive | WorkloadType::Realtime => {
                // Pick cell with lowest latency
                let best = eligible.iter()
                    .min_by(|a, b| a.avg_latency_ms.partial_cmp(&b.avg_latency_ms).unwrap_or(std::cmp::Ordering::Equal))
                    .unwrap();
                RouteDecision {
                    cell_id: best.cell_id.clone(),
                    reason: RouteReason::Adaptive("lowest_latency".into()),
                }
            }
            WorkloadType::Batch => {
                // Pick cell with highest throughput
                let best = eligible.iter()
                    .max_by(|a, b| a.token_throughput.partial_cmp(&b.token_throughput).unwrap_or(std::cmp::Ordering::Equal))
                    .unwrap();
                RouteDecision {
                    cell_id: best.cell_id.clone(),
                    reason: RouteReason::Adaptive("highest_throughput".into()),
                }
            }
            WorkloadType::Background => {
                // Pick cell with lowest load (least busy)
                let best = eligible.iter()
                    .min_by(|a, b| a.load_pct.partial_cmp(&b.load_pct).unwrap_or(std::cmp::Ordering::Equal))
                    .unwrap();
                RouteDecision {
                    cell_id: best.cell_id.clone(),
                    reason: RouteReason::Adaptive("lowest_load".into()),
                }
            }
        }
    }

    /// Hash-based fallback when no metrics are available.
    fn hash_fallback(&self, agent_pid: &str) -> RouteDecision {
        let cells: Vec<&str> = self.metrics.keys().map(|s| s.as_str()).collect();
        if cells.is_empty() {
            return RouteDecision { cell_id: String::new(), reason: RouteReason::NoCells };
        }
        // Simple hash: sum of bytes mod cell count
        let hash: usize = agent_pid.bytes().map(|b| b as usize).sum::<usize>() % cells.len();
        // Sort for determinism
        let mut sorted: Vec<&str> = cells;
        sorted.sort();
        RouteDecision {
            cell_id: sorted[hash].to_string(),
            reason: RouteReason::HashFallback,
        }
    }

    /// Check which cells have stale metrics.
    pub fn stale_cells(&self, now_ms: u64) -> Vec<String> {
        self.metrics.values()
            .filter(|c| c.is_stale(now_ms, self.staleness_threshold_ms))
            .map(|c| c.cell_id.clone())
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(id: &str, latency: f64, throughput: f64, load: f64, updated_ms: u64) -> CellLoad {
        CellLoad {
            cell_id: id.to_string(),
            active_agents: 10,
            queue_depth: 5,
            avg_latency_ms: latency,
            token_throughput: throughput,
            load_pct: load,
            updated_at_ms: updated_ms,
        }
    }

    fn profile(wtype: WorkloadType) -> WorkloadProfile {
        WorkloadProfile {
            workload_type: wtype,
            agent_pid: "pid:test".into(),
            estimated_tokens: 1000,
            deadline_ms: 0,
        }
    }

    #[test]
    fn test_interactive_routes_to_lowest_latency() {
        let mut router = AdaptiveRouter::new();
        router.update_metrics(cell("cell-a", 50.0, 1000.0, 40.0, 9000));
        router.update_metrics(cell("cell-b", 20.0, 800.0, 60.0, 9000));
        router.update_metrics(cell("cell-c", 80.0, 1200.0, 30.0, 9000));

        let decision = router.route(&profile(WorkloadType::Interactive), 10_000);
        assert_eq!(decision.cell_id, "cell-b"); // Lowest latency
        assert_eq!(decision.reason, RouteReason::Adaptive("lowest_latency".into()));
    }

    #[test]
    fn test_batch_routes_to_highest_throughput() {
        let mut router = AdaptiveRouter::new();
        router.update_metrics(cell("cell-a", 50.0, 1000.0, 40.0, 9000));
        router.update_metrics(cell("cell-b", 20.0, 800.0, 60.0, 9000));
        router.update_metrics(cell("cell-c", 80.0, 1500.0, 30.0, 9000));

        let decision = router.route(&profile(WorkloadType::Batch), 10_000);
        assert_eq!(decision.cell_id, "cell-c"); // Highest throughput
        assert_eq!(decision.reason, RouteReason::Adaptive("highest_throughput".into()));
    }

    #[test]
    fn test_background_routes_to_lowest_load() {
        let mut router = AdaptiveRouter::new();
        router.update_metrics(cell("cell-a", 50.0, 1000.0, 40.0, 9000));
        router.update_metrics(cell("cell-b", 20.0, 800.0, 60.0, 9000));
        router.update_metrics(cell("cell-c", 80.0, 1200.0, 20.0, 9000));

        let decision = router.route(&profile(WorkloadType::Background), 10_000);
        assert_eq!(decision.cell_id, "cell-c"); // Lowest load
        assert_eq!(decision.reason, RouteReason::Adaptive("lowest_load".into()));
    }

    #[test]
    fn test_realtime_routes_to_lowest_latency() {
        let mut router = AdaptiveRouter::new();
        router.update_metrics(cell("cell-a", 10.0, 500.0, 70.0, 9000));
        router.update_metrics(cell("cell-b", 30.0, 1000.0, 50.0, 9000));

        let decision = router.route(&profile(WorkloadType::Realtime), 10_000);
        assert_eq!(decision.cell_id, "cell-a");
        assert_eq!(decision.reason, RouteReason::Adaptive("lowest_latency".into()));
    }

    #[test]
    fn test_no_metrics_falls_back_to_hash() {
        let mut router = AdaptiveRouter::new();
        // Add cells with stale metrics (updated_at = 0)
        router.update_metrics(CellLoad::new("cell-a"));
        router.update_metrics(CellLoad::new("cell-b"));

        let decision = router.route(&profile(WorkloadType::Interactive), 100_000);
        assert_eq!(decision.reason, RouteReason::HashFallback);
        // Should pick one of the cells
        assert!(decision.cell_id == "cell-a" || decision.cell_id == "cell-b");
    }

    #[test]
    fn test_overloaded_cell_excluded() {
        let mut router = AdaptiveRouter::new();
        router.update_metrics(cell("cell-a", 10.0, 2000.0, 95.0, 9000)); // >90% load
        router.update_metrics(cell("cell-b", 50.0, 800.0, 40.0, 9000));

        let decision = router.route(&profile(WorkloadType::Interactive), 10_000);
        assert_eq!(decision.cell_id, "cell-b"); // cell-a excluded for load
    }

    #[test]
    fn test_stale_metrics_detected() {
        let mut router = AdaptiveRouter::with_config(90.0, 5000); // 5s staleness
        router.update_metrics(cell("cell-a", 10.0, 1000.0, 40.0, 1000));
        router.update_metrics(cell("cell-b", 20.0, 800.0, 50.0, 8000));

        let stale = router.stale_cells(10_000);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0], "cell-a"); // 1000 → 10000 = 9s > 5s threshold
    }

    #[test]
    fn test_all_stale_falls_back_to_hash() {
        let mut router = AdaptiveRouter::with_config(90.0, 5000);
        router.update_metrics(cell("cell-a", 10.0, 1000.0, 40.0, 1000));
        router.update_metrics(cell("cell-b", 20.0, 800.0, 50.0, 2000));

        // At t=20000, both are stale (>5s)
        let decision = router.route(&profile(WorkloadType::Batch), 20_000);
        assert_eq!(decision.reason, RouteReason::HashFallback);
    }

    #[test]
    fn test_empty_router_returns_no_cells() {
        let router = AdaptiveRouter::new();
        let decision = router.route(&profile(WorkloadType::Interactive), 10_000);
        assert_eq!(decision.reason, RouteReason::NoCells);
        assert!(decision.cell_id.is_empty());
    }

    #[test]
    fn test_single_eligible_cell_returns_only_cell() {
        let mut router = AdaptiveRouter::new();
        router.update_metrics(cell("cell-only", 50.0, 1000.0, 30.0, 9000));

        let decision = router.route(&profile(WorkloadType::Interactive), 10_000);
        assert_eq!(decision.cell_id, "cell-only");
        assert_eq!(decision.reason, RouteReason::OnlyCell);
    }
}
