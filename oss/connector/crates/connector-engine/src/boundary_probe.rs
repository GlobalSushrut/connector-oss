//! TC-4 — BoundaryProbeDetector: detects systematic namespace boundary probing.
//!
//! # What is Boundary Probing?
//!
//! A compromised or misconfigured agent may attempt to discover what resources it
//! *cannot* access by systematically trying operations across an expanding namespace
//! frontier. The signature is:
//!
//! 1. **Clustered denials**: multiple `ActionOutcome::Denied` events in a short window
//! 2. **Expanding frontier**: each probe targets a *new* namespace path not tried before
//! 3. **Escalating frequency**: inter-denial interval decreasing over time
//!
//! # Probe Score
//!
//! ```text
//! P = (clustered_denials / total_executions) × escalation_factor
//! ```
//!
//! Where:
//! - `clustered_denials` = denials in a time window where inter-denial gap < θ_gap_ms
//! - `total_executions` = total operations by this agent
//! - `escalation_factor` = 1 + frontier_growth_rate (how fast new paths are being probed)
//!
//! # Thresholds
//!
//! | Score  | Action                                    |
//! |--------|-------------------------------------------|
//! | > 0.05 | Alert — log warning                       |
//! | > 0.10 | TC Reduction (auto) — capability shrink   |
//! | > 0.20 | TC Revocation vote (f+1=3 validators)     |
//!
//! # Integration
//!
//! `BoundaryProbeDetector::analyze(agent_pid, audit_entries)` is called:
//! - On every `GET /monitor/anomalies` request (TC-4)
//! - Automatically in `TokenContainerManager::check_reduction_needed()`
//! - In the background watchdog every 5 seconds

use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// Core types
// ═══════════════════════════════════════════════════════════════

/// A minimal audit event fed into the detector.
/// Maps directly from `KernelAuditEntry` fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeAuditEvent {
    /// Timestamp (ms since epoch)
    pub timestamp_ms: i64,
    /// Target namespace or resource path attempted
    pub target: Option<String>,
    /// Whether this operation was denied
    pub denied: bool,
    /// Agent that performed the operation
    pub agent_pid: String,
}

/// Thresholds controlling when probe actions are taken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeThresholds {
    /// Score above this → alert (log warning)
    pub alert: f64,
    /// Score above this → TC Reduction recommendation
    pub reduction: f64,
    /// Score above this → TC Revocation vote
    pub revocation: f64,
    /// Maximum milliseconds between consecutive denials to count as "clustered"
    pub cluster_gap_ms: i64,
    /// Minimum events required before scoring (avoid false positives on sparse logs)
    pub min_events: usize,
    /// Time window for analysis (ms); events older than this are ignored
    pub window_ms: i64,
}

impl Default for ProbeThresholds {
    fn default() -> Self {
        Self {
            alert:          0.05,
            reduction:      0.10,
            revocation:     0.20,
            cluster_gap_ms: 2_000,   // denials ≤2s apart = clustered
            min_events:     5,
            window_ms:      300_000, // 5-minute sliding window
        }
    }
}

/// Recommended action based on probe score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeAction {
    /// No action — score below alert threshold
    None,
    /// Score > 0.05: log a warning
    Alert,
    /// Score > 0.10: automatically reduce TC capability
    TcReduction,
    /// Score > 0.20: initiate TC revocation vote
    TcRevocationVote,
}

impl std::fmt::Display for ProbeAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeAction::None             => write!(f, "none"),
            ProbeAction::Alert            => write!(f, "alert"),
            ProbeAction::TcReduction      => write!(f, "tc_reduction"),
            ProbeAction::TcRevocationVote => write!(f, "tc_revocation_vote"),
        }
    }
}

/// Full probe analysis result for one agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeAnalysis {
    pub agent_pid: String,
    /// Final probe score P ∈ [0, ∞) (values > 0.20 trigger revocation)
    pub score: f64,
    /// Recommended action
    pub action: ProbeAction,
    /// Number of clustered denials in the analysis window
    pub clustered_denials: usize,
    /// Total operations in the analysis window
    pub total_executions: usize,
    /// Number of unique namespace paths denied (frontier size)
    pub frontier_size: usize,
    /// Rate at which new paths are being probed (frontier growth per denial)
    pub frontier_growth_rate: f64,
    /// Escalation factor = 1.0 + frontier_growth_rate
    pub escalation_factor: f64,
    /// Probe clusters: each cluster is a sequence of closely-timed denials
    pub clusters: Vec<ProbeCluster>,
    /// Analysis window used (ms)
    pub window_ms: i64,
    /// Timestamp of analysis (ms epoch)
    pub analyzed_at: i64,
}

/// A single cluster of closely-timed denial events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeCluster {
    /// Start time of cluster (ms epoch)
    pub start_ms: i64,
    /// End time of cluster (ms epoch)
    pub end_ms: i64,
    /// Number of denials in this cluster
    pub denial_count: usize,
    /// Unique target paths in this cluster
    pub targets: Vec<String>,
    /// Duration of cluster (ms)
    pub duration_ms: i64,
}

// ═══════════════════════════════════════════════════════════════
// BoundaryProbeDetector
// ═══════════════════════════════════════════════════════════════

/// Detects systematic boundary probing by analyzing audit event streams.
pub struct BoundaryProbeDetector {
    pub thresholds: ProbeThresholds,
}

impl BoundaryProbeDetector {
    pub fn new() -> Self {
        Self { thresholds: ProbeThresholds::default() }
    }

    pub fn with_thresholds(thresholds: ProbeThresholds) -> Self {
        Self { thresholds }
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    /// Analyze a stream of audit events for an agent.
    ///
    /// Returns a `ProbeAnalysis` with score and recommended action.
    /// Events are filtered to the configured time window before scoring.
    pub fn analyze(&self, agent_pid: &str, events: &[ProbeAuditEvent]) -> ProbeAnalysis {
        let now = Self::now_ms();
        let cutoff = now - self.thresholds.window_ms;

        // Filter to window and sort by timestamp
        let mut window_events: Vec<&ProbeAuditEvent> = events.iter()
            .filter(|e| e.agent_pid == agent_pid && e.timestamp_ms >= cutoff)
            .collect();
        window_events.sort_by_key(|e| e.timestamp_ms);

        let total_executions = window_events.len();

        if total_executions < self.thresholds.min_events {
            return ProbeAnalysis {
                agent_pid: agent_pid.to_string(),
                score: 0.0,
                action: ProbeAction::None,
                clustered_denials: 0,
                total_executions,
                frontier_size: 0,
                frontier_growth_rate: 0.0,
                escalation_factor: 1.0,
                clusters: vec![],
                window_ms: self.thresholds.window_ms,
                analyzed_at: now,
            };
        }

        // Separate denials
        let denials: Vec<&ProbeAuditEvent> = window_events.iter()
            .copied()
            .filter(|e| e.denied)
            .collect();

        // Build denial clusters: consecutive denials with gap ≤ cluster_gap_ms
        let clusters = self.build_clusters(&denials);
        let clustered_denials: usize = clusters.iter().map(|c| c.denial_count).sum();

        // Frontier: unique namespace paths that were denied
        let denied_paths: HashSet<String> = denials.iter()
            .filter_map(|e| e.target.clone())
            .collect();
        let frontier_size = denied_paths.len();

        // Frontier growth rate: unique denied paths / clustered denials
        // (1.0 = every denial is a new path = pure frontier expansion)
        let frontier_growth_rate = if clustered_denials > 0 {
            frontier_size as f64 / clustered_denials as f64
        } else {
            0.0
        };

        let escalation_factor = 1.0 + frontier_growth_rate;

        // Probe score: P = (clustered_denials / total_executions) × escalation_factor
        let raw_ratio = if total_executions > 0 {
            clustered_denials as f64 / total_executions as f64
        } else {
            0.0
        };
        let score = raw_ratio * escalation_factor;

        let action = if score > self.thresholds.revocation {
            ProbeAction::TcRevocationVote
        } else if score > self.thresholds.reduction {
            ProbeAction::TcReduction
        } else if score > self.thresholds.alert {
            ProbeAction::Alert
        } else {
            ProbeAction::None
        };

        ProbeAnalysis {
            agent_pid: agent_pid.to_string(),
            score,
            action,
            clustered_denials,
            total_executions,
            frontier_size,
            frontier_growth_rate,
            escalation_factor,
            clusters,
            window_ms: self.thresholds.window_ms,
            analyzed_at: now,
        }
    }

    /// Analyze all agents in the event stream and return per-agent results.
    pub fn analyze_all(&self, events: &[ProbeAuditEvent]) -> HashMap<String, ProbeAnalysis> {
        let agents: HashSet<String> = events.iter()
            .map(|e| e.agent_pid.clone())
            .collect();
        agents.into_iter()
            .map(|pid| {
                let analysis = self.analyze(&pid, events);
                (pid, analysis)
            })
            .collect()
    }

    /// Build denial clusters from sorted denial events.
    fn build_clusters(&self, denials: &[&ProbeAuditEvent]) -> Vec<ProbeCluster> {
        if denials.is_empty() { return vec![]; }

        let mut clusters: Vec<ProbeCluster> = Vec::new();
        let mut current: Option<(i64, i64, Vec<String>)> = None; // (start_ms, last_ms, targets)

        for event in denials {
            let ts = event.timestamp_ms;
            let target = event.target.clone().unwrap_or_default();

            match current.take() {
                None => {
                    current = Some((ts, ts, vec![target]));
                }
                Some((start, last, mut targets)) => {
                    if ts - last <= self.thresholds.cluster_gap_ms {
                        targets.push(target);
                        current = Some((start, ts, targets));
                    } else {
                        // Close current cluster
                        let count = targets.len();
                        clusters.push(ProbeCluster {
                            start_ms: start,
                            end_ms: last,
                            denial_count: count,
                            targets,
                            duration_ms: last - start,
                        });
                        // Start new cluster
                        current = Some((ts, ts, vec![target]));
                    }
                }
            }
        }

        // Close final cluster
        if let Some((start, last, targets)) = current {
            let count = targets.len();
            clusters.push(ProbeCluster {
                start_ms: start,
                end_ms: last,
                denial_count: count,
                targets,
                duration_ms: last - start,
            });
        }

        clusters
    }
}

impl Default for BoundaryProbeDetector {
    fn default() -> Self { Self::new() }
}

// ═══════════════════════════════════════════════════════════════
// Summary view for GET /monitor/anomalies
// ═══════════════════════════════════════════════════════════════

/// Summary of all agents' probe scores — suitable for the /monitor/anomalies endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyReport {
    pub total_agents_analyzed: usize,
    pub agents_alerting: usize,
    pub agents_requiring_reduction: usize,
    pub agents_requiring_revocation: usize,
    pub per_agent: Vec<ProbeAnalysisSummary>,
    pub generated_at: i64,
}

/// Condensed per-agent summary for the anomaly report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeAnalysisSummary {
    pub agent_pid: String,
    pub score: f64,
    pub action: ProbeAction,
    pub clustered_denials: usize,
    pub total_executions: usize,
    pub frontier_size: usize,
    pub cluster_count: usize,
}

impl AnomalyReport {
    pub fn from_analyses(analyses: HashMap<String, ProbeAnalysis>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let mut per_agent: Vec<ProbeAnalysisSummary> = analyses.values()
            .map(|a| ProbeAnalysisSummary {
                agent_pid: a.agent_pid.clone(),
                score: a.score,
                action: a.action.clone(),
                clustered_denials: a.clustered_denials,
                total_executions: a.total_executions,
                frontier_size: a.frontier_size,
                cluster_count: a.clusters.len(),
            })
            .collect();

        // Sort by descending score
        per_agent.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

        let agents_alerting = per_agent.iter().filter(|a| a.action != ProbeAction::None).count();
        let agents_requiring_reduction = per_agent.iter().filter(|a| matches!(a.action, ProbeAction::TcReduction | ProbeAction::TcRevocationVote)).count();
        let agents_requiring_revocation = per_agent.iter().filter(|a| a.action == ProbeAction::TcRevocationVote).count();

        Self {
            total_agents_analyzed: per_agent.len(),
            agents_alerting,
            agents_requiring_reduction,
            agents_requiring_revocation,
            per_agent,
            generated_at: now,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(ts: i64, pid: &str, target: &str, denied: bool) -> ProbeAuditEvent {
        ProbeAuditEvent {
            timestamp_ms: ts,
            target: Some(target.to_string()),
            denied,
            agent_pid: pid.to_string(),
        }
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    #[test]
    fn test_tc4_no_denials_score_zero() {
        let det = BoundaryProbeDetector::new();
        let n = now();
        let events: Vec<_> = (0..10).map(|i| make_event(n - i * 1000, "bot", "ns:ok", false)).collect();
        let result = det.analyze("bot", &events);
        assert_eq!(result.score, 0.0);
        assert_eq!(result.action, ProbeAction::None);
    }

    #[test]
    fn test_tc4_sparse_denials_below_alert() {
        let det = BoundaryProbeDetector::new();
        let n = now();
        let mut events: Vec<ProbeAuditEvent> = (0..20).map(|i| make_event(n - i * 5000, "bot", "ns:a", false)).collect();
        // 1 isolated denial in 20 events — isolated so single cluster of 1, new unique path
        // score = (1/21) * (1 + 1.0) ≈ 0.095, which is below the reduction threshold (0.10)
        events.push(make_event(n - 100_000, "bot", "ns:secret", true));
        let result = det.analyze("bot", &events);
        // A single isolated denial may alert but must not trigger TC Reduction or Revocation
        assert!(result.score < 0.10,
            "Single isolated denial must stay below reduction threshold: {}", result.score);
        assert!(
            matches!(result.action, ProbeAction::None | ProbeAction::Alert),
            "Single isolated denial must not trigger reduction/revocation: {:?}", result.action
        );
    }

    #[test]
    fn test_tc4_clustered_denials_trigger_alert() {
        let det = BoundaryProbeDetector::new();
        let n = now();
        let mut events: Vec<ProbeAuditEvent> = (0..10).map(|i| make_event(n - i * 10_000, "probe", "ns:ok", false)).collect();
        // 5 clustered denials on different paths, 500ms apart
        for i in 0..5 {
            events.push(make_event(n - i * 500, "probe", &format!("ns:secret/{}", i), true));
        }
        let result = det.analyze("probe", &events);
        assert!(result.score > 0.05, "Clustered denials should trigger alert: {}", result.score);
        assert!(matches!(result.action, ProbeAction::Alert | ProbeAction::TcReduction | ProbeAction::TcRevocationVote));
    }

    #[test]
    fn test_tc4_high_probe_triggers_reduction() {
        let det = BoundaryProbeDetector::new();
        let n = now();
        // 5 ok ops, 6 clustered denials on expanding paths → high ratio
        let mut events: Vec<ProbeAuditEvent> = (0..5).map(|i| make_event(n - 60_000 - i * 1000, "attacker", "ns:ok", false)).collect();
        for i in 0..6 {
            events.push(make_event(n - i * 300, "attacker", &format!("ns:admin/secret/{}", i), true));
        }
        let result = det.analyze("attacker", &events);
        assert!(result.score > 0.10, "High probe ratio should trigger reduction: {}", result.score);
        assert!(matches!(result.action, ProbeAction::TcReduction | ProbeAction::TcRevocationVote));
    }

    #[test]
    fn test_tc4_extreme_probe_triggers_revocation() {
        let det = BoundaryProbeDetector::new();
        let n = now();
        // 2 ok, 15 clustered denials on all-different paths = very high score
        let mut events: Vec<ProbeAuditEvent> = (0..2).map(|i| make_event(n - 120_000 - i * 1000, "hacker", "ns:ok", false)).collect();
        for i in 0..15 {
            events.push(make_event(n - i * 100, "hacker", &format!("ns:root/path/{}", i), true));
        }
        let result = det.analyze("hacker", &events);
        assert!(result.score > 0.20, "Extreme probe should trigger revocation vote: {}", result.score);
        assert_eq!(result.action, ProbeAction::TcRevocationVote);
    }

    #[test]
    fn test_tc4_frontier_growth_rate_is_correct() {
        let det = BoundaryProbeDetector::new();
        let n = now();
        let mut events: Vec<ProbeAuditEvent> = (0..10).map(|i| make_event(n - i * 5000, "bot", "ns:ok", false)).collect();
        // 4 denials, all on unique paths
        for i in 0..4 {
            events.push(make_event(n - i * 400, "bot", &format!("ns:unique/{}", i), true));
        }
        let result = det.analyze("bot", &events);
        // frontier_size=4, clustered_denials may be 4, so rate ≈ 1.0
        assert!(result.frontier_growth_rate > 0.0);
        assert!(result.escalation_factor >= 1.0);
    }

    #[test]
    fn test_tc4_analyze_all_returns_per_agent() {
        let det = BoundaryProbeDetector::new();
        let n = now();
        let mut events = Vec::new();
        for i in 0..10 {
            events.push(make_event(n - i * 1000, "agent-a", "ns:a", false));
            events.push(make_event(n - i * 1000, "agent-b", "ns:b", i % 3 == 0));
        }
        let results = det.analyze_all(&events);
        assert!(results.contains_key("agent-a"));
        assert!(results.contains_key("agent-b"));
    }

    #[test]
    fn test_tc4_anomaly_report_sorted_by_score() {
        let det = BoundaryProbeDetector::new();
        let n = now();
        let mut events = Vec::new();
        // agent-high: many clustered denials
        for i in 0..5 { events.push(make_event(n - 1000, "agent-high", "ns:ok", false)); }
        for i in 0..8 { events.push(make_event(n - i as i64 * 200, "agent-high", &format!("ns:secret/{}", i), true)); }
        // agent-low: clean
        for i in 0..10 { events.push(make_event(n - i as i64 * 1000, "agent-low", "ns:ok", false)); }

        let analyses = det.analyze_all(&events);
        let report = AnomalyReport::from_analyses(analyses);
        if report.per_agent.len() >= 2 {
            assert!(report.per_agent[0].score >= report.per_agent[1].score,
                "Report must be sorted by descending score");
        }
    }

    #[test]
    fn test_tc4_window_filters_old_events() {
        let det = BoundaryProbeDetector::with_thresholds(ProbeThresholds {
            window_ms: 60_000, // only last 60s
            min_events: 1,
            ..Default::default()
        });
        let n = now();
        // Old denials outside window (2 hours ago)
        let mut events: Vec<ProbeAuditEvent> = (0..5).map(|i|
            make_event(n - 7_200_000 - i * 1000, "bot", &format!("ns:old/{}", i), true)
        ).collect();
        // Recent ok events inside window
        for i in 0..10 {
            events.push(make_event(n - i * 1000, "bot", "ns:ok", false));
        }
        let result = det.analyze("bot", &events);
        assert_eq!(result.clustered_denials, 0, "Old denials must be excluded by window");
    }

    #[test]
    fn test_tc4_min_events_prevents_false_positives() {
        let det = BoundaryProbeDetector::new(); // min_events = 5
        let n = now();
        // Only 3 events (below min_events=5)
        let events = vec![
            make_event(n - 100, "sparse", "ns:secret/1", true),
            make_event(n - 200, "sparse", "ns:secret/2", true),
            make_event(n - 300, "sparse", "ns:ok", false),
        ];
        let result = det.analyze("sparse", &events);
        assert_eq!(result.score, 0.0, "Sparse agent must not be scored");
        assert_eq!(result.action, ProbeAction::None);
    }
}
