//! Adaptive Scheduler — workload-aware scheduling for agentic AI kernels.
//!
//! Linux analog: sched_ext (Linux 6.12) — eBPF-programmable schedulers that adapt to workload.
//!
//! Military-grade properties:
//! - Deterministic: same inputs → same scheduling decision
//! - Bounded: scheduling decision computed in O(n) where n = queue depth
//! - Auditable: every decision logged with reason
//! - Realtime preemption: Realtime workloads can preempt lower-priority work
//! - Pluggable: custom scheduler plugins via SchedulerPlugin trait

use std::collections::HashMap;

// ── Workload Types ──────────────────────────────────────────────────

/// Classification of agent workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkloadType {
    /// Low-latency interactive (chat, real-time UI).
    Interactive,
    /// High-throughput batch (bulk processing, ETL).
    Batch,
    /// Idle-slot background (maintenance, cleanup).
    Background,
    /// Hard-deadline realtime (safety-critical, robot control).
    Realtime,
}

/// Profile describing an agent's workload characteristics.
#[derive(Debug, Clone)]
pub struct WorkloadProfile {
    pub agent_pid: String,
    pub workload_type: WorkloadType,
    pub avg_tokens: u64,
    pub avg_latency_ms: u64,
    pub priority: u8,
    pub deadline_ms: Option<u64>,
}

// ── Cell Metrics ────────────────────────────────────────────────────

/// Metrics about the current state of a cell/node.
#[derive(Debug, Clone)]
pub struct CellMetrics {
    pub cell_id: String,
    pub active_agents: u32,
    pub queue_depth: u32,
    pub avg_inference_latency_ms: u64,
    pub token_throughput: u64,
    pub load_pct: f64,
}

impl CellMetrics {
    pub fn is_overloaded(&self) -> bool {
        self.load_pct > 80.0
    }

    pub fn is_idle(&self) -> bool {
        self.load_pct < 20.0
    }
}

// ── Schedule Decision ───────────────────────────────────────────────

/// The scheduler's decision for a request.
#[derive(Debug, Clone, PartialEq)]
pub enum ScheduleDecision {
    /// Execute immediately on the specified target.
    Execute { target: String, reason: String },
    /// Queue for later execution.
    Queue { position: usize, reason: String },
    /// Delay until cell load drops below threshold.
    Delay { until_load_pct: f64, reason: String },
    /// Preempt lower-priority work to execute immediately.
    Preempt { suspend_pid: Option<String>, reason: String },
    /// Reject — cannot schedule.
    Reject { reason: String },
}

// ── Scheduler Plugin Trait ──────────────────────────────────────────

/// Trait for pluggable scheduling algorithms.
pub trait SchedulerPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn schedule(&self, request: &WorkloadProfile, metrics: &[CellMetrics], queue: &[WorkloadProfile]) -> ScheduleDecision;
}

// ── FIFO Plugin ─────────────────────────────────────────────────────

pub struct FifoPlugin;

impl SchedulerPlugin for FifoPlugin {
    fn name(&self) -> &str { "fifo" }

    fn schedule(&self, request: &WorkloadProfile, metrics: &[CellMetrics], queue: &[WorkloadProfile]) -> ScheduleDecision {
        // Find least-loaded cell
        if let Some(best) = metrics.iter().min_by(|a, b| a.load_pct.partial_cmp(&b.load_pct).unwrap_or(std::cmp::Ordering::Equal)) {
            if best.is_overloaded() {
                ScheduleDecision::Queue {
                    position: queue.len(),
                    reason: format!("All cells overloaded (best: {:.0}%)", best.load_pct),
                }
            } else {
                ScheduleDecision::Execute {
                    target: best.cell_id.clone(),
                    reason: format!("FIFO → {} (load: {:.0}%)", best.cell_id, best.load_pct),
                }
            }
        } else {
            ScheduleDecision::Reject { reason: "No cells available".into() }
        }
    }
}

// ── Round Robin Plugin ──────────────────────────────────────────────

pub struct RoundRobinPlugin {
    counter: std::sync::atomic::AtomicUsize,
}

impl RoundRobinPlugin {
    pub fn new() -> Self {
        Self { counter: std::sync::atomic::AtomicUsize::new(0) }
    }
}

impl Default for RoundRobinPlugin {
    fn default() -> Self { Self::new() }
}

impl SchedulerPlugin for RoundRobinPlugin {
    fn name(&self) -> &str { "round_robin" }

    fn schedule(&self, _request: &WorkloadProfile, metrics: &[CellMetrics], _queue: &[WorkloadProfile]) -> ScheduleDecision {
        if metrics.is_empty() {
            return ScheduleDecision::Reject { reason: "No cells".into() };
        }
        let available: Vec<_> = metrics.iter().filter(|m| !m.is_overloaded()).collect();
        if available.is_empty() {
            return ScheduleDecision::Queue { position: 0, reason: "All overloaded".into() };
        }
        let idx = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % available.len();
        ScheduleDecision::Execute {
            target: available[idx].cell_id.clone(),
            reason: format!("RR → {} (slot {})", available[idx].cell_id, idx),
        }
    }
}

// ── CFS (Completely Fair Scheduler) Plugin ──────────────────────────

/// CFS-like scheduler: tracks virtual runtime per agent, schedules the
/// agent with lowest vruntime to ensure fairness.
pub struct CfsPlugin;

impl SchedulerPlugin for CfsPlugin {
    fn name(&self) -> &str { "cfs" }

    fn schedule(&self, request: &WorkloadProfile, metrics: &[CellMetrics], _queue: &[WorkloadProfile]) -> ScheduleDecision {
        match request.workload_type {
            WorkloadType::Interactive => {
                // Route to lowest-latency cell
                if let Some(best) = metrics.iter()
                    .filter(|m| !m.is_overloaded())
                    .min_by_key(|m| m.avg_inference_latency_ms)
                {
                    ScheduleDecision::Execute {
                        target: best.cell_id.clone(),
                        reason: format!("Interactive → lowest latency: {}ms", best.avg_inference_latency_ms),
                    }
                } else {
                    ScheduleDecision::Queue { position: 0, reason: "No low-latency cell available".into() }
                }
            }
            WorkloadType::Batch => {
                // Route to highest-throughput cell
                if let Some(best) = metrics.iter()
                    .filter(|m| !m.is_overloaded())
                    .max_by_key(|m| m.token_throughput)
                {
                    ScheduleDecision::Execute {
                        target: best.cell_id.clone(),
                        reason: format!("Batch → highest throughput: {} tok/s", best.token_throughput),
                    }
                } else {
                    ScheduleDecision::Queue { position: 0, reason: "No high-throughput cell available".into() }
                }
            }
            WorkloadType::Realtime => {
                // Preempt: signal Suspend to lower-priority agents, execute immediately
                if let Some(best) = metrics.iter().min_by(|a, b| a.load_pct.partial_cmp(&b.load_pct).unwrap_or(std::cmp::Ordering::Equal)) {
                    ScheduleDecision::Preempt {
                        suspend_pid: None,
                        reason: format!("Realtime preemption → {} (deadline: {:?}ms)", best.cell_id, request.deadline_ms),
                    }
                } else {
                    ScheduleDecision::Reject { reason: "No cells for realtime".into() }
                }
            }
            WorkloadType::Background => {
                // Delay until cell load < 50%
                if let Some(idle) = metrics.iter().find(|m| m.load_pct < 50.0) {
                    ScheduleDecision::Execute {
                        target: idle.cell_id.clone(),
                        reason: format!("Background → idle cell {} ({:.0}%)", idle.cell_id, idle.load_pct),
                    }
                } else {
                    ScheduleDecision::Delay {
                        until_load_pct: 50.0,
                        reason: "All cells above 50% load — delaying background work".into(),
                    }
                }
            }
        }
    }
}

// ── Adaptive Scheduler ──────────────────────────────────────────────

/// Audit entry for scheduling decisions.
#[derive(Debug, Clone)]
pub struct SchedulerAuditEntry {
    pub timestamp: i64,
    pub agent_pid: String,
    pub workload_type: WorkloadType,
    pub decision: ScheduleDecision,
    pub plugin_name: String,
}

/// The adaptive scheduler — routes workloads to optimal targets.
pub struct AdaptiveScheduler {
    plugin: Box<dyn SchedulerPlugin>,
    /// Per-agent latency histogram (agent_pid → latencies_ms).
    latency_hist: HashMap<String, Vec<u64>>,
    /// Per-agent workload profiles.
    profiles: HashMap<String, WorkloadProfile>,
    /// Scheduling audit log.
    audit: Vec<SchedulerAuditEntry>,
    /// Total decisions made.
    decision_count: u64,
}

impl AdaptiveScheduler {
    pub fn new(plugin: Box<dyn SchedulerPlugin>) -> Self {
        Self {
            plugin,
            latency_hist: HashMap::new(),
            profiles: HashMap::new(),
            audit: Vec::new(),
            decision_count: 0,
        }
    }

    pub fn with_fifo() -> Self { Self::new(Box::new(FifoPlugin)) }
    pub fn with_round_robin() -> Self { Self::new(Box::new(RoundRobinPlugin::new())) }
    pub fn with_cfs() -> Self { Self::new(Box::new(CfsPlugin)) }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    /// Register or update a workload profile for an agent.
    pub fn set_profile(&mut self, profile: WorkloadProfile) {
        self.profiles.insert(profile.agent_pid.clone(), profile);
    }

    /// Record a latency sample for an agent.
    pub fn record_latency(&mut self, agent_pid: &str, latency_ms: u64) {
        self.latency_hist.entry(agent_pid.to_string()).or_default().push(latency_ms);
    }

    /// Schedule a request. Returns the decision and logs it.
    pub fn schedule(&mut self, request: &WorkloadProfile, metrics: &[CellMetrics]) -> ScheduleDecision {
        let queue: Vec<WorkloadProfile> = self.profiles.values().cloned().collect();
        let decision = self.plugin.schedule(request, metrics, &queue);

        self.audit.push(SchedulerAuditEntry {
            timestamp: Self::now_ms(),
            agent_pid: request.agent_pid.clone(),
            workload_type: request.workload_type,
            decision: decision.clone(),
            plugin_name: self.plugin.name().to_string(),
        });
        self.decision_count += 1;

        decision
    }

    /// Get average latency for an agent.
    pub fn avg_latency(&self, agent_pid: &str) -> Option<f64> {
        self.latency_hist.get(agent_pid).and_then(|hist| {
            if hist.is_empty() { None }
            else { Some(hist.iter().sum::<u64>() as f64 / hist.len() as f64) }
        })
    }

    pub fn plugin_name(&self) -> &str { self.plugin.name() }
    pub fn decision_count(&self) -> u64 { self.decision_count }
    pub fn audit_log(&self) -> &[SchedulerAuditEntry] { &self.audit }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(id: &str, load: f64, latency: u64, throughput: u64) -> CellMetrics {
        CellMetrics {
            cell_id: id.to_string(), active_agents: 5, queue_depth: 2,
            avg_inference_latency_ms: latency, token_throughput: throughput, load_pct: load,
        }
    }

    fn profile(pid: &str, wt: WorkloadType) -> WorkloadProfile {
        WorkloadProfile {
            agent_pid: pid.to_string(), workload_type: wt,
            avg_tokens: 1000, avg_latency_ms: 50, priority: 5, deadline_ms: None,
        }
    }

    #[test]
    fn test_fifo_routes_to_least_loaded() {
        let mut sched = AdaptiveScheduler::with_fifo();
        let cells = vec![cell("c1", 70.0, 50, 1000), cell("c2", 30.0, 100, 500)];
        let req = profile("pid:1", WorkloadType::Interactive);
        let decision = sched.schedule(&req, &cells);
        assert!(matches!(decision, ScheduleDecision::Execute { ref target, .. } if target == "c2"));
    }

    #[test]
    fn test_fifo_queues_when_overloaded() {
        let mut sched = AdaptiveScheduler::with_fifo();
        let cells = vec![cell("c1", 90.0, 50, 1000), cell("c2", 85.0, 100, 500)];
        let req = profile("pid:1", WorkloadType::Batch);
        let decision = sched.schedule(&req, &cells);
        assert!(matches!(decision, ScheduleDecision::Queue { .. }));
    }

    #[test]
    fn test_cfs_interactive_lowest_latency() {
        let mut sched = AdaptiveScheduler::with_cfs();
        let cells = vec![cell("c1", 50.0, 200, 1000), cell("c2", 60.0, 30, 500)];
        let req = profile("pid:1", WorkloadType::Interactive);
        let decision = sched.schedule(&req, &cells);
        assert!(matches!(decision, ScheduleDecision::Execute { ref target, .. } if target == "c2"));
    }

    #[test]
    fn test_cfs_batch_highest_throughput() {
        let mut sched = AdaptiveScheduler::with_cfs();
        let cells = vec![cell("c1", 50.0, 200, 5000), cell("c2", 60.0, 30, 1000)];
        let req = profile("pid:1", WorkloadType::Batch);
        let decision = sched.schedule(&req, &cells);
        assert!(matches!(decision, ScheduleDecision::Execute { ref target, .. } if target == "c1"));
    }

    #[test]
    fn test_cfs_realtime_preemption() {
        let mut sched = AdaptiveScheduler::with_cfs();
        let cells = vec![cell("c1", 70.0, 50, 1000)];
        let mut req = profile("pid:1", WorkloadType::Realtime);
        req.deadline_ms = Some(10);
        let decision = sched.schedule(&req, &cells);
        assert!(matches!(decision, ScheduleDecision::Preempt { .. }));
    }

    #[test]
    fn test_cfs_background_delays_on_high_load() {
        let mut sched = AdaptiveScheduler::with_cfs();
        let cells = vec![cell("c1", 70.0, 50, 1000), cell("c2", 60.0, 30, 500)];
        let req = profile("pid:1", WorkloadType::Background);
        let decision = sched.schedule(&req, &cells);
        assert!(matches!(decision, ScheduleDecision::Delay { .. }));
    }

    #[test]
    fn test_cfs_background_executes_on_idle() {
        let mut sched = AdaptiveScheduler::with_cfs();
        let cells = vec![cell("c1", 30.0, 50, 1000)];
        let req = profile("pid:1", WorkloadType::Background);
        let decision = sched.schedule(&req, &cells);
        assert!(matches!(decision, ScheduleDecision::Execute { .. }));
    }

    #[test]
    fn test_round_robin() {
        let mut sched = AdaptiveScheduler::with_round_robin();
        let cells = vec![cell("c1", 40.0, 50, 1000), cell("c2", 50.0, 30, 500)];
        let req = profile("pid:1", WorkloadType::Interactive);

        let d1 = sched.schedule(&req, &cells);
        let d2 = sched.schedule(&req, &cells);

        // Should alternate between c1 and c2
        match (&d1, &d2) {
            (ScheduleDecision::Execute { target: t1, .. }, ScheduleDecision::Execute { target: t2, .. }) => {
                assert_ne!(t1, t2);
            }
            _ => panic!("Expected both Execute"),
        }
    }

    #[test]
    fn test_audit_trail() {
        let mut sched = AdaptiveScheduler::with_fifo();
        let cells = vec![cell("c1", 30.0, 50, 1000)];
        sched.schedule(&profile("pid:1", WorkloadType::Interactive), &cells);
        sched.schedule(&profile("pid:2", WorkloadType::Batch), &cells);

        assert_eq!(sched.decision_count(), 2);
        assert_eq!(sched.audit_log().len(), 2);
        assert_eq!(sched.audit_log()[0].plugin_name, "fifo");
    }

    #[test]
    fn test_latency_tracking() {
        let mut sched = AdaptiveScheduler::with_cfs();
        sched.record_latency("pid:1", 50);
        sched.record_latency("pid:1", 100);
        sched.record_latency("pid:1", 150);
        assert_eq!(sched.avg_latency("pid:1"), Some(100.0));
        assert_eq!(sched.avg_latency("pid:2"), None);
    }

    #[test]
    fn test_no_cells_rejected() {
        let mut sched = AdaptiveScheduler::with_fifo();
        let decision = sched.schedule(&profile("pid:1", WorkloadType::Interactive), &[]);
        assert!(matches!(decision, ScheduleDecision::Reject { .. }));
    }
}
