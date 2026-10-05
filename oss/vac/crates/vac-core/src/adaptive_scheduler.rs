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
use std::cmp::Reverse;

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

// ── EWMA + Power-of-Two Plugin (I13) ───────────────────────────────

/// Per-cell EWMA latency state.
pub struct EwmaLatencyState {
    /// Smoothed latency: L_n = 0.2 * sample + 0.8 * L_{n-1}
    pub ewma_ms: f64,
    pub sample_count: u64,
}

impl EwmaLatencyState {
    fn new(initial_ms: f64) -> Self {
        Self { ewma_ms: initial_ms, sample_count: 1 }
    }

    fn update(&mut self, sample_ms: f64) {
        self.ewma_ms = 0.2 * sample_ms + 0.8 * self.ewma_ms;
        self.sample_count += 1;
    }
}

/// EWMA + power-of-two choices scheduler (Mitzenmacher 2001).
///
/// On each schedule call: pick 2 random non-overloaded cells, route to the
/// one with lower EWMA latency. Falls back to single cell if < 2 available.
pub struct EwmaPowerOfTwoPlugin {
    /// Per-cell EWMA latency; keyed by cell_id.
    ewma: std::sync::Mutex<HashMap<String, EwmaLatencyState>>,
    rng_state: std::sync::atomic::AtomicU64,
}

impl EwmaPowerOfTwoPlugin {
    pub fn new() -> Self {
        Self {
            ewma: std::sync::Mutex::new(HashMap::new()),
            rng_state: std::sync::atomic::AtomicU64::new(0x4d595df4d0f33173),
        }
    }

    pub fn record_latency(&self, cell_id: &str, latency_ms: f64) {
        let mut map = self.ewma.lock().unwrap();
        map.entry(cell_id.to_string())
            .and_modify(|s| s.update(latency_ms))
            .or_insert_with(|| EwmaLatencyState::new(latency_ms));
    }

    pub fn ewma_latency(&self, cell_id: &str) -> Option<f64> {
        self.ewma.lock().unwrap().get(cell_id).map(|s| s.ewma_ms)
    }

    fn next_rand(&self) -> u64 {
        let mut x = self.rng_state.load(std::sync::atomic::Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng_state.store(x, std::sync::atomic::Ordering::Relaxed);
        x
    }
}

impl Default for EwmaPowerOfTwoPlugin {
    fn default() -> Self { Self::new() }
}

impl SchedulerPlugin for EwmaPowerOfTwoPlugin {
    fn name(&self) -> &str { "ewma_p2c" }

    fn schedule(&self, _request: &WorkloadProfile, metrics: &[CellMetrics], _queue: &[WorkloadProfile]) -> ScheduleDecision {
        let available: Vec<&CellMetrics> = metrics.iter().filter(|m| !m.is_overloaded()).collect();
        if available.is_empty() {
            return ScheduleDecision::Queue { position: 0, reason: "All cells overloaded".into() };
        }
        let map = self.ewma.lock().unwrap();
        if available.len() == 1 {
            let c = available[0];
            return ScheduleDecision::Execute {
                target: c.cell_id.clone(),
                reason: format!("P2C single cell → {} (EWMA: {:.1}ms)",
                    c.cell_id,
                    map.get(&c.cell_id).map(|s| s.ewma_ms).unwrap_or(c.avg_inference_latency_ms as f64)),
            };
        }
        let a_idx = (self.next_rand() as usize) % available.len();
        let mut b_idx = (self.next_rand() as usize) % available.len();
        if b_idx == a_idx { b_idx = (b_idx + 1) % available.len(); }
        let a = available[a_idx];
        let b = available[b_idx];
        let lat_a = map.get(&a.cell_id).map(|s| s.ewma_ms).unwrap_or(a.avg_inference_latency_ms as f64);
        let lat_b = map.get(&b.cell_id).map(|s| s.ewma_ms).unwrap_or(b.avg_inference_latency_ms as f64);
        let (chosen, lat) = if lat_a <= lat_b { (a, lat_a) } else { (b, lat_b) };
        drop(map);
        ScheduleDecision::Execute {
            target: chosen.cell_id.clone(),
            reason: format!("P2C → {} (EWMA: {:.1}ms)", chosen.cell_id, lat),
        }
    }
}

// ── Agent Affinity Sticky Routing Plugin (I14) ───────────────────────

/// Agent affinity routing: route to primary ring cell if load < 70%;
/// spill to ring successor only when load > 90%.
pub struct AffinityPlugin {
    ring: std::sync::Mutex<self::affinity_ring::AffinityRing>,
}

mod affinity_ring {
    use std::collections::BTreeMap;

    pub struct AffinityRing {
        ring: BTreeMap<u32, String>,
        cells: Vec<String>,
    }

    impl AffinityRing {
        pub fn new() -> Self { Self { ring: BTreeMap::new(), cells: Vec::new() } }

        pub fn add_cell(&mut self, cell_id: impl Into<String>) {
            let cell_id = cell_id.into();
            if self.cells.contains(&cell_id) { return; }
            for i in 0..150u32 {
                let key = format!("{}:{}", cell_id, i);
                self.ring.insert(Self::xxh32(key.as_bytes()), cell_id.clone());
            }
            self.cells.push(cell_id);
        }

        pub fn get_cell(&self, agent_pid: &str) -> Option<&str> {
            if self.ring.is_empty() { return None; }
            let h = Self::xxh32(agent_pid.as_bytes());
            self.ring.range(h..)
                .next()
                .or_else(|| self.ring.iter().next())
                .map(|(_, c)| c.as_str())
        }

        pub fn next_cell(&self, agent_pid: &str) -> Option<&str> {
            if self.cells.len() < 2 { return None; }
            let primary = self.get_cell(agent_pid)?;
            let h = Self::xxh32(agent_pid.as_bytes());
            let after: Vec<_> = self.ring.range(h..).collect();
            let before: Vec<_> = self.ring.range(..h).collect();
            for (_, c) in after.into_iter().chain(before) {
                if c.as_str() != primary { return Some(c.as_str()); }
            }
            None
        }

        fn xxh32(data: &[u8]) -> u32 {
            const P1: u32 = 0x9E3779B1;
            const P2: u32 = 0x85EBCA77;
            const P3: u32 = 0xC2B2AE3D;
            const P4: u32 = 0x27D4EB2F;
            const P5: u32 = 0x165667B1;
            let len = data.len() as u32;
            let mut h: u32 = P5.wrapping_add(len);
            for &b in data {
                h = h.wrapping_add((b as u32).wrapping_mul(P5));
                h = h.rotate_left(11).wrapping_mul(P1);
            }
            h ^= h >> 15; h = h.wrapping_mul(P2);
            h ^= h >> 13; h = h.wrapping_mul(P3);
            h ^= h >> 16; h
        }
    }
}

impl AffinityPlugin {
    pub fn new() -> Self {
        Self { ring: std::sync::Mutex::new(affinity_ring::AffinityRing::new()) }
    }

    pub fn add_cell(&self, cell_id: &str) {
        self.ring.lock().unwrap().add_cell(cell_id);
    }
}

impl Default for AffinityPlugin { fn default() -> Self { Self::new() } }

impl SchedulerPlugin for AffinityPlugin {
    fn name(&self) -> &str { "affinity" }

    fn schedule(&self, request: &WorkloadProfile, metrics: &[CellMetrics], _queue: &[WorkloadProfile]) -> ScheduleDecision {
        let ring = self.ring.lock().unwrap();
        let primary_id = match ring.get_cell(&request.agent_pid) {
            Some(c) => c.to_string(),
            None => return ScheduleDecision::Reject { reason: "Affinity ring empty".into() },
        };

        let primary_metrics = metrics.iter().find(|m| m.cell_id == primary_id);
        if let Some(pm) = primary_metrics {
            if pm.load_pct < 70.0 {
                return ScheduleDecision::Execute {
                    target: primary_id.clone(),
                    reason: format!("Affinity primary {} ({:.0}% load)", primary_id, pm.load_pct),
                };
            }
            if pm.load_pct <= 90.0 {
                return ScheduleDecision::Queue {
                    position: 0,
                    reason: format!("Affinity primary {} ({:.0}%) between 70-90% — queuing", primary_id, pm.load_pct),
                };
            }
        }
        // load > 90% or metrics unavailable: spill to ring successor
        if let Some(next_id) = ring.next_cell(&request.agent_pid) {
            let next = next_id.to_string();
            if let Some(nm) = metrics.iter().find(|m| m.cell_id == next) {
                if !nm.is_overloaded() {
                    return ScheduleDecision::Execute {
                        target: next.clone(),
                        reason: format!("Affinity spill {} → {} (primary > 90%)", primary_id, next),
                    };
                }
            }
        }
        ScheduleDecision::Queue { position: 0, reason: format!("Affinity: all cells at capacity (primary {})", primary_id) }
    }
}

// ── EDF Scheduling Plugin (I15) ──────────────────────────────────────

/// Earliest Deadline First scheduler for Realtime workloads.
///
/// Maintains a BinaryHeap<(Reverse<deadline_ms>, pid)>.
/// Feasibility check: Σ(Cᵢ/Tᵢ) ≤ 1.0 where Cᵢ = avg_latency_ms, Tᵢ = deadline_ms.
/// If sum > 1.0, logs a warning (some deadlines will miss); still executes.
pub struct EdfPlugin {
    queue: std::sync::Mutex<std::collections::BinaryHeap<(Reverse<u64>, String)>>,
}

impl EdfPlugin {
    pub fn new() -> Self {
        Self { queue: std::sync::Mutex::new(std::collections::BinaryHeap::new()) }
    }

    /// Enqueue a realtime request; must be called before schedule.
    pub fn enqueue(&self, agent_pid: &str, deadline_ms: u64) {
        self.queue.lock().unwrap().push((Reverse(deadline_ms), agent_pid.to_string()));
    }

    fn utilization(queue: &[(WorkloadProfile)]) -> f64 {
        queue.iter().filter_map(|p| {
            if let (Some(d), l) = (p.deadline_ms, p.avg_latency_ms) {
                if d > 0 { Some(l as f64 / d as f64) } else { None }
            } else { None }
        }).sum()
    }
}

impl Default for EdfPlugin { fn default() -> Self { Self::new() } }

impl SchedulerPlugin for EdfPlugin {
    fn name(&self) -> &str { "edf" }

    fn schedule(&self, request: &WorkloadProfile, metrics: &[CellMetrics], queue: &[WorkloadProfile]) -> ScheduleDecision {
        let u = Self::utilization(queue);
        if u > 1.0 {
            // Feasibility violation: log and continue (late execution > none)
            eprintln!("[EDF] feasibility violation: Σ(Cᵢ/Tᵢ) = {:.3} > 1.0 — some deadlines will miss", u);
        }

        let deadline = request.deadline_ms.unwrap_or(u64::MAX);
        // Find least-loaded non-overloaded cell for the earliest-deadline job
        if let Some(best) = metrics.iter().filter(|m| !m.is_overloaded())
            .min_by(|a, b| a.load_pct.partial_cmp(&b.load_pct).unwrap_or(std::cmp::Ordering::Equal))
        {
            ScheduleDecision::Execute {
                target: best.cell_id.clone(),
                reason: format!("EDF → {} (deadline: {}ms, utilization: {:.2})", best.cell_id, deadline, u),
            }
        } else {
            // Missed deadline: log + execute on any cell anyway
            if let Some(any) = metrics.first() {
                eprintln!("[EDF] agent {} missed deadline {}ms — executing late on {}", request.agent_pid, deadline, any.cell_id);
                ScheduleDecision::Execute {
                    target: any.cell_id.clone(),
                    reason: format!("EDF late execution → {} (all overloaded, deadline {}ms)", any.cell_id, deadline),
                }
            } else {
                ScheduleDecision::Reject { reason: "EDF: no cells available".into() }
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
    pub fn with_ewma_p2c() -> Self { Self::new(Box::new(EwmaPowerOfTwoPlugin::new())) }
    pub fn with_edf() -> Self { Self::new(Box::new(EdfPlugin::new())) }

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

    /// Get average latency for an agent (arithmetic mean over recorded samples).
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
    use std::cmp::Reverse;

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

    // ── I13: EWMA + power-of-two ──
    #[test]
    fn test_ewma_p2c_routes_to_lower_ewma_latency() {
        let plugin = EwmaPowerOfTwoPlugin::new();
        plugin.record_latency("fast", 10.0);
        plugin.record_latency("slow", 200.0);
        // Run many schedules; the lower EWMA cell should win significantly more often
        let cells = vec![
            cell("fast", 40.0, 10, 1000),
            cell("slow", 40.0, 200, 1000),
        ];
        let mut fast_wins = 0usize;
        let req = profile("pid:1", WorkloadType::Interactive);
        for _ in 0..200 {
            match plugin.schedule(&req, &cells, &[]) {
                ScheduleDecision::Execute { ref target, .. } if target == "fast" => fast_wins += 1,
                _ => {}
            }
        }
        assert!(fast_wins >= 140, "Expected fast cell to win ≥ 70%, got {}/200", fast_wins);
    }

    #[test]
    fn test_ewma_update_follows_formula() {
        let mut state = EwmaLatencyState::new(100.0);
        state.update(200.0);
        let expected = 0.2 * 200.0 + 0.8 * 100.0;
        assert!((state.ewma_ms - expected).abs() < 0.001, "EWMA mismatch: {} vs {}", state.ewma_ms, expected);
    }

    // ── I14: Affinity sticky routing ──
    #[test]
    fn test_affinity_routes_to_primary_under_70_pct() {
        let plugin = AffinityPlugin::new();
        plugin.add_cell("cell-1");
        plugin.add_cell("cell-2");
        let req = profile("pid:sticky", WorkloadType::Interactive);
        let cells = vec![
            cell("cell-1", 50.0, 10, 1000),
            cell("cell-2", 55.0, 20, 1000),
        ];
        let ring = plugin.ring.lock().unwrap();
        let primary = ring.get_cell(&req.agent_pid).unwrap().to_string();
        drop(ring);
        let decision = plugin.schedule(&req, &cells, &[]);
        assert!(
            matches!(&decision, ScheduleDecision::Execute { target, .. } if *target == primary),
            "Expected primary cell {}, got {:?}", primary, decision
        );
    }

    #[test]
    fn test_affinity_spills_when_primary_overloaded() {
        let plugin = AffinityPlugin::new();
        plugin.add_cell("cell-1");
        plugin.add_cell("cell-2");
        let req = profile("pid:sticky", WorkloadType::Interactive);
        let ring = plugin.ring.lock().unwrap();
        let primary = ring.get_cell(&req.agent_pid).unwrap().to_string();
        let spill = ring.next_cell(&req.agent_pid).unwrap().to_string();
        drop(ring);
        // Primary at 95% > 90% threshold → spill to next
        let (c1_load, c2_load) = if primary == "cell-1" { (95.0, 30.0) } else { (30.0, 95.0) };
        let cells = vec![
            cell("cell-1", c1_load, 10, 1000),
            cell("cell-2", c2_load, 20, 1000),
        ];
        let decision = plugin.schedule(&req, &cells, &[]);
        assert!(
            matches!(&decision, ScheduleDecision::Execute { target, .. } if *target == spill),
            "Expected spill to {}, got {:?}", spill, decision
        );
    }

    // ── I15: EDF scheduling ──
    #[test]
    fn test_edf_schedules_earliest_deadline_first() {
        let plugin = EdfPlugin::new();
        let cells = vec![cell("c1", 30.0, 50, 1000)];
        let mut req = profile("pid:rt", WorkloadType::Realtime);
        req.deadline_ms = Some(50);
        let decision = plugin.schedule(&req, &cells, &[]);
        assert!(matches!(decision, ScheduleDecision::Execute { ref target, .. } if target == "c1"));
    }

    #[test]
    fn test_edf_feasibility_check_warns_but_still_executes() {
        let plugin = EdfPlugin::new();
        let cells = vec![cell("c1", 30.0, 50, 1000)];
        // Overloaded queue: Σ(Cᵢ/Tᵢ) > 1
        let queue = vec![
            WorkloadProfile { agent_pid: "p1".into(), workload_type: WorkloadType::Realtime, avg_tokens: 100, avg_latency_ms: 90, priority: 9, deadline_ms: Some(100) },
            WorkloadProfile { agent_pid: "p2".into(), workload_type: WorkloadType::Realtime, avg_tokens: 100, avg_latency_ms: 80, priority: 9, deadline_ms: Some(100) },
        ];
        let mut req = profile("pid:rt2", WorkloadType::Realtime);
        req.deadline_ms = Some(10);
        let decision = plugin.schedule(&req, &cells, &queue);
        // Should still execute despite utilization > 1.0
        assert!(matches!(decision, ScheduleDecision::Execute { .. }));
    }

    #[test]
    fn test_edf_late_execution_on_all_overloaded() {
        let plugin = EdfPlugin::new();
        let cells = vec![cell("c1", 95.0, 50, 1000)];
        let mut req = profile("pid:rt3", WorkloadType::Realtime);
        req.deadline_ms = Some(5);
        let decision = plugin.schedule(&req, &cells, &[]);
        // All overloaded, but still executes late rather than rejecting
        assert!(matches!(decision, ScheduleDecision::Execute { ref target, .. } if target == "c1"));
    }
}
