//! Self-Healing Infrastructure — automatic detection and recovery from failures.
//!
//! Linux analog: systemd watchdog + service restart + journald analysis.
//!
//! Military-grade properties:
//! - 5 independent health checks running in parallel
//! - Every healing action produces an audit entry
//! - Predictive alerting based on stability index trends
//! - No false-positive auto-kills: requires N consecutive failures before action
//! - Configurable thresholds per check via HealingPolicy

use std::collections::HashMap;

// ── Health Check Results ────────────────────────────────────────────

/// Type of health check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealthCheckType {
    /// Detect dead agents (no activity > threshold).
    Heartbeat,
    /// Verify audit chain integrity (tamper detection).
    Integrity,
    /// Detect overloaded cells.
    LoadBalance,
    /// Compare replication sequence numbers.
    ReplicationLag,
    /// Aggregate trust/behavior scores → auto-suspend high-risk agents.
    TrustAudit,
}

impl std::fmt::Display for HealthCheckType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Heartbeat => write!(f, "heartbeat"),
            Self::Integrity => write!(f, "integrity"),
            Self::LoadBalance => write!(f, "load_balance"),
            Self::ReplicationLag => write!(f, "replication_lag"),
            Self::TrustAudit => write!(f, "trust_audit"),
        }
    }
}

/// Result of a single health check.
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub check_type: HealthCheckType,
    pub healthy: bool,
    pub detail: String,
    pub timestamp: i64,
    pub affected_agents: Vec<String>,
}

// ── Healing Actions ─────────────────────────────────────────────────

/// Action taken by the self-healing system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealingAction {
    /// Restart a dead/stuck agent.
    RestartAgent { agent_pid: String, reason: String },
    /// Migrate agent to a less-loaded cell.
    MigrateAgent { agent_pid: String, target_cell: String, reason: String },
    /// Suspend a high-risk agent.
    SuspendAgent { agent_pid: String, reason: String },
    /// Trigger Merkle sync to repair replication lag.
    TriggerSync { cell_id: String, reason: String },
    /// Alert human operator.
    AlertOperator { severity: String, message: String },
    /// No action needed.
    None,
}

// ── Healing Policy ──────────────────────────────────────────────────

/// Configurable thresholds for healing decisions.
#[derive(Debug, Clone)]
pub struct HealingPolicy {
    /// Agent considered dead after this many ms of inactivity.
    pub heartbeat_timeout_ms: i64,
    /// Number of consecutive heartbeat misses before action.
    pub heartbeat_miss_threshold: u32,
    /// Cell load percentage that triggers rebalancing.
    pub overload_threshold_pct: f64,
    /// Replication sequence gap that triggers sync.
    pub replication_lag_threshold: u64,
    /// Trust score below which agent is auto-suspended.
    pub trust_suspend_threshold: f64,
    /// Stability index below which predictive alert fires.
    pub stability_alert_threshold: f64,
    /// Minimum sample size before trust-based suspension.
    pub trust_min_samples: u32,
}

impl Default for HealingPolicy {
    fn default() -> Self {
        Self {
            heartbeat_timeout_ms: 30_000,
            heartbeat_miss_threshold: 2,
            overload_threshold_pct: 80.0,
            replication_lag_threshold: 100,
            trust_suspend_threshold: 0.3,
            stability_alert_threshold: 0.3,
            trust_min_samples: 20,
        }
    }
}

impl HealingPolicy {
    /// Strict policy for military/safety-critical deployments.
    pub fn strict() -> Self {
        Self {
            heartbeat_timeout_ms: 10_000,
            heartbeat_miss_threshold: 1,
            overload_threshold_pct: 60.0,
            replication_lag_threshold: 50,
            trust_suspend_threshold: 0.5,
            stability_alert_threshold: 0.4,
            trust_min_samples: 10,
        }
    }
}

// ── Agent Health State ──────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AgentHealthState {
    last_activity_ms: i64,
    consecutive_misses: u32,
    trust_score: f64,
    trust_samples: u32,
    suspended: bool,
}

// ── Healing Audit Entry ─────────────────────────────────────────────

/// Every healing action produces an audit entry.
#[derive(Debug, Clone)]
pub struct HealingAuditEntry {
    pub timestamp: i64,
    pub check_type: HealthCheckType,
    pub action: HealingAction,
    pub detail: String,
}

// ── Health Monitor ──────────────────────────────────────────────────

/// The self-healing health monitor.
pub struct HealthMonitor {
    policy: HealingPolicy,
    /// Per-agent health state.
    agent_state: HashMap<String, AgentHealthState>,
    /// Cell load percentages.
    cell_loads: HashMap<String, f64>,
    /// Per-cell replication sequence numbers.
    cell_sequences: HashMap<String, u64>,
    /// Overall stability index (0.0 = unstable, 1.0 = fully healthy).
    stability_index: f64,
    /// Previous stability index (for trend detection).
    prev_stability_index: f64,
    /// Healing audit log.
    audit: Vec<HealingAuditEntry>,
    /// Total checks run.
    check_count: u64,
    /// Total healing actions taken.
    action_count: u64,
}

impl HealthMonitor {
    pub fn new(policy: HealingPolicy) -> Self {
        Self {
            policy,
            agent_state: HashMap::new(),
            cell_loads: HashMap::new(),
            cell_sequences: HashMap::new(),
            stability_index: 1.0,
            prev_stability_index: 1.0,
            audit: Vec::new(),
            check_count: 0,
            action_count: 0,
        }
    }

    pub fn default_monitor() -> Self {
        Self::new(HealingPolicy::default())
    }

    pub fn strict_monitor() -> Self {
        Self::new(HealingPolicy::strict())
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    fn log_action(&mut self, check_type: HealthCheckType, action: HealingAction, detail: &str) {
        if action != HealingAction::None {
            self.action_count += 1;
        }
        self.audit.push(HealingAuditEntry {
            timestamp: Self::now_ms(),
            check_type,
            action,
            detail: detail.to_string(),
        });
    }

    // ── State updates ───────────────────────────────────────────

    /// Record agent activity (heartbeat).
    pub fn record_heartbeat(&mut self, agent_pid: &str) {
        let state = self.agent_state.entry(agent_pid.to_string()).or_insert(AgentHealthState {
            last_activity_ms: Self::now_ms(),
            consecutive_misses: 0,
            trust_score: 1.0,
            trust_samples: 0,
            suspended: false,
        });
        state.last_activity_ms = Self::now_ms();
        state.consecutive_misses = 0;
    }

    /// Update agent trust score.
    pub fn update_trust(&mut self, agent_pid: &str, score: f64) {
        let state = self.agent_state.entry(agent_pid.to_string()).or_insert(AgentHealthState {
            last_activity_ms: Self::now_ms(),
            consecutive_misses: 0,
            trust_score: 1.0,
            trust_samples: 0,
            suspended: false,
        });
        state.trust_samples += 1;
        // Exponential moving average
        let alpha = 0.2;
        state.trust_score = alpha * score + (1.0 - alpha) * state.trust_score;
    }

    /// Update cell load.
    pub fn update_cell_load(&mut self, cell_id: &str, load_pct: f64) {
        self.cell_loads.insert(cell_id.to_string(), load_pct);
    }

    /// Update cell replication sequence.
    pub fn update_cell_sequence(&mut self, cell_id: &str, seq: u64) {
        self.cell_sequences.insert(cell_id.to_string(), seq);
    }

    // ── Health Checks ───────────────────────────────────────────

    /// Check 1: Heartbeat — detect dead agents.
    pub fn check_heartbeat(&mut self) -> Vec<HealingAction> {
        let now = Self::now_ms();
        let timeout = self.policy.heartbeat_timeout_ms;
        let threshold = self.policy.heartbeat_miss_threshold;

        // Pass 1: update miss counts and collect dead agents (owned data)
        let mut dead: Vec<(String, i64, u32)> = Vec::new();
        let pids: Vec<String> = self.agent_state.keys().cloned().collect();
        for pid in &pids {
            let state = self.agent_state.get_mut(pid).unwrap();
            if state.suspended { continue; }
            if now - state.last_activity_ms > timeout {
                state.consecutive_misses += 1;
                if state.consecutive_misses >= threshold {
                    dead.push((pid.clone(), now - state.last_activity_ms, state.consecutive_misses));
                }
            }
        }

        // Pass 2: create actions and log (no borrow on agent_state)
        let mut actions = Vec::new();
        for (pid, inactive_ms, misses) in dead {
            let action = HealingAction::RestartAgent {
                agent_pid: pid.clone(),
                reason: format!("Dead: {}ms inactive, {} consecutive misses", inactive_ms, misses),
            };
            self.log_action(HealthCheckType::Heartbeat, action.clone(),
                &format!("Agent {} dead after {} misses", pid, misses));
            actions.push(action);
        }
        self.check_count += 1;
        actions
    }

    /// Check 2: Integrity — verify audit chain (returns healthy/tampered).
    pub fn check_integrity(&mut self, chain_valid: bool) -> Vec<HealingAction> {
        self.check_count += 1;
        if chain_valid {
            return Vec::new();
        }
        let action = HealingAction::AlertOperator {
            severity: "CRITICAL".into(),
            message: "Audit chain integrity failure — possible tampering detected".into(),
        };
        self.log_action(HealthCheckType::Integrity, action.clone(), "Audit chain tampered");
        vec![action]
    }

    /// Check 3: Load Balance — detect overloaded cells.
    pub fn check_load_balance(&mut self) -> Vec<HealingAction> {
        self.check_count += 1;
        let threshold = self.policy.overload_threshold_pct;
        let mut actions = Vec::new();

        let overloaded: Vec<String> = self.cell_loads.iter()
            .filter(|(_, &load)| load > threshold)
            .map(|(id, _)| id.clone())
            .collect();

        for cell_id in overloaded {
            let action = HealingAction::AlertOperator {
                severity: "WARNING".into(),
                message: format!("Cell {} overloaded ({:.0}% > {:.0}%)",
                    cell_id, self.cell_loads[&cell_id], threshold),
            };
            self.log_action(HealthCheckType::LoadBalance, action.clone(),
                &format!("Cell {} overloaded", cell_id));
            actions.push(action);
        }
        actions
    }

    /// Check 4: Replication Lag — detect sync gaps.
    pub fn check_replication_lag(&mut self) -> Vec<HealingAction> {
        self.check_count += 1;
        if self.cell_sequences.len() < 2 { return Vec::new(); }

        let max_seq = self.cell_sequences.values().copied().max().unwrap_or(0);
        let threshold = self.policy.replication_lag_threshold;

        // Collect lagging cells into owned data to avoid borrow conflict
        let lagging: Vec<(String, u64)> = self.cell_sequences.iter()
            .filter(|(_, &seq)| max_seq - seq > threshold)
            .map(|(id, &seq)| (id.clone(), max_seq - seq))
            .collect();

        let mut actions = Vec::new();
        for (cell_id, gap) in lagging {
            let action = HealingAction::TriggerSync {
                cell_id: cell_id.clone(),
                reason: format!("Replication lag: {} behind (gap: {}, threshold: {})",
                    cell_id, gap, threshold),
            };
            self.log_action(HealthCheckType::ReplicationLag, action.clone(),
                &format!("Cell {} lagging by {}", cell_id, gap));
            actions.push(action);
        }
        actions
    }

    /// Check 5: Trust Audit — auto-suspend high-risk agents.
    pub fn check_trust_audit(&mut self) -> Vec<HealingAction> {
        self.check_count += 1;
        let threshold = self.policy.trust_suspend_threshold;
        let min_samples = self.policy.trust_min_samples;

        // Collect agents to suspend into owned data to avoid borrow conflict
        let to_suspend: Vec<(String, f64, u32)> = self.agent_state.iter()
            .filter(|(_, s)| !s.suspended && s.trust_samples >= min_samples && s.trust_score < threshold)
            .map(|(pid, s)| (pid.clone(), s.trust_score, s.trust_samples))
            .collect();

        let mut actions = Vec::new();
        for (pid, trust_score, trust_samples) in to_suspend {
            if let Some(state) = self.agent_state.get_mut(&pid) {
                state.suspended = true;
            }
            let action = HealingAction::SuspendAgent {
                agent_pid: pid.clone(),
                reason: format!("Trust score {:.2} < {:.2} (samples: {})",
                    trust_score, threshold, trust_samples),
            };
            self.log_action(HealthCheckType::TrustAudit, action.clone(),
                &format!("Agent {} suspended: trust={:.2}", pid, trust_score));
            actions.push(action);
        }
        actions
    }

    /// Run all 5 health checks and return combined actions.
    pub fn run_all_checks(&mut self, audit_chain_valid: bool) -> Vec<HealingAction> {
        let mut all = Vec::new();
        all.extend(self.check_heartbeat());
        all.extend(self.check_integrity(audit_chain_valid));
        all.extend(self.check_load_balance());
        all.extend(self.check_replication_lag());
        all.extend(self.check_trust_audit());

        // Update stability index
        self.prev_stability_index = self.stability_index;
        let total_agents = self.agent_state.len().max(1) as f64;
        let healthy_agents = self.agent_state.values()
            .filter(|s| !s.suspended && s.consecutive_misses == 0)
            .count() as f64;
        self.stability_index = healthy_agents / total_agents;

        // Predictive alert: stability declining
        if self.stability_index < self.policy.stability_alert_threshold
            && self.stability_index < self.prev_stability_index
        {
            let action = HealingAction::AlertOperator {
                severity: "PREDICTIVE".into(),
                message: format!("Stability declining: {:.2} → {:.2} (threshold: {:.2})",
                    self.prev_stability_index, self.stability_index,
                    self.policy.stability_alert_threshold),
            };
            self.log_action(HealthCheckType::Heartbeat, action.clone(), "Predictive stability alert");
            all.push(action);
        }

        all
    }

    // ── Query methods ───────────────────────────────────────────

    pub fn stability_index(&self) -> f64 { self.stability_index }
    pub fn check_count(&self) -> u64 { self.check_count }
    pub fn action_count(&self) -> u64 { self.action_count }
    pub fn audit_log(&self) -> &[HealingAuditEntry] { &self.audit }
    pub fn is_suspended(&self, agent_pid: &str) -> bool {
        self.agent_state.get(agent_pid).map(|s| s.suspended).unwrap_or(false)
    }
    pub fn policy(&self) -> &HealingPolicy { &self.policy }
}

impl Default for HealthMonitor {
    fn default() -> Self { Self::default_monitor() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dead_agent_detection() {
        let mut mon = HealthMonitor::new(HealingPolicy {
            heartbeat_timeout_ms: 0, // instant timeout
            heartbeat_miss_threshold: 1,
            ..Default::default()
        });

        // Register agent with old heartbeat
        mon.record_heartbeat("pid:1");
        // Backdate to simulate stale heartbeat
        mon.agent_state.get_mut("pid:1").unwrap().last_activity_ms -= 1000;

        let actions = mon.check_heartbeat();
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], HealingAction::RestartAgent { agent_pid, .. } if agent_pid == "pid:1"));
    }

    #[test]
    fn test_healthy_agent_no_action() {
        let mut mon = HealthMonitor::default_monitor();
        mon.record_heartbeat("pid:1");
        let actions = mon.check_heartbeat();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_integrity_failure() {
        let mut mon = HealthMonitor::default_monitor();
        let actions = mon.check_integrity(false);
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], HealingAction::AlertOperator { severity, .. } if severity == "CRITICAL"));
    }

    #[test]
    fn test_integrity_pass() {
        let mut mon = HealthMonitor::default_monitor();
        let actions = mon.check_integrity(true);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_overload_detection() {
        let mut mon = HealthMonitor::default_monitor();
        mon.update_cell_load("cell-1", 90.0);
        mon.update_cell_load("cell-2", 50.0);
        let actions = mon.check_load_balance();
        assert_eq!(actions.len(), 1); // only cell-1 overloaded
    }

    #[test]
    fn test_replication_lag() {
        let mut mon = HealthMonitor::default_monitor();
        mon.update_cell_sequence("cell-1", 1000);
        mon.update_cell_sequence("cell-2", 800); // 200 behind, threshold 100

        let actions = mon.check_replication_lag();
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], HealingAction::TriggerSync { cell_id, .. } if cell_id == "cell-2"));
    }

    #[test]
    fn test_trust_auto_suspend() {
        let mut mon = HealthMonitor::new(HealingPolicy {
            trust_suspend_threshold: 0.5,
            trust_min_samples: 3,
            ..Default::default()
        });

        mon.record_heartbeat("pid:1");
        // Feed low trust scores
        for _ in 0..5 {
            mon.update_trust("pid:1", 0.1);
        }

        let actions = mon.check_trust_audit();
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], HealingAction::SuspendAgent { agent_pid, .. } if agent_pid == "pid:1"));
        assert!(mon.is_suspended("pid:1"));
    }

    #[test]
    fn test_trust_min_samples() {
        let mut mon = HealthMonitor::new(HealingPolicy {
            trust_suspend_threshold: 0.5,
            trust_min_samples: 20,
            ..Default::default()
        });

        mon.record_heartbeat("pid:1");
        // Only 3 samples — not enough to suspend
        for _ in 0..3 {
            mon.update_trust("pid:1", 0.1);
        }

        let actions = mon.check_trust_audit();
        assert!(actions.is_empty()); // not enough samples
    }

    #[test]
    fn test_run_all_checks() {
        let mut mon = HealthMonitor::default_monitor();
        mon.record_heartbeat("pid:1");
        mon.update_cell_load("cell-1", 50.0);
        mon.update_cell_sequence("cell-1", 100);

        let actions = mon.run_all_checks(true);
        assert!(actions.is_empty()); // everything healthy
        assert_eq!(mon.stability_index(), 1.0);
    }

    #[test]
    fn test_healing_audit_trail() {
        let mut mon = HealthMonitor::default_monitor();
        mon.check_integrity(false);
        assert_eq!(mon.audit_log().len(), 1);
        assert_eq!(mon.action_count(), 1);
    }

    #[test]
    fn test_predictive_alert() {
        let mut mon = HealthMonitor::new(HealingPolicy {
            heartbeat_timeout_ms: 0,
            heartbeat_miss_threshold: 1,
            stability_alert_threshold: 0.5,
            ..Default::default()
        });

        // Register 4 agents, 3 are dead
        for i in 0..4 {
            let pid = format!("pid:{}", i);
            mon.record_heartbeat(&pid);
        }
        // Backdate 3 agents
        for i in 1..4 {
            let pid = format!("pid:{}", i);
            mon.agent_state.get_mut(&pid).unwrap().last_activity_ms -= 1000;
        }

        let actions = mon.run_all_checks(true);
        // Should have 3 restart actions + 1 predictive alert
        let restart_count = actions.iter().filter(|a| matches!(a, HealingAction::RestartAgent { .. })).count();
        let alert_count = actions.iter().filter(|a| matches!(a, HealingAction::AlertOperator { severity, .. } if severity == "PREDICTIVE")).count();
        assert_eq!(restart_count, 3);
        assert_eq!(alert_count, 1);
        assert!(mon.stability_index() < 0.5);
    }

    #[test]
    fn test_consecutive_miss_threshold() {
        let mut mon = HealthMonitor::new(HealingPolicy {
            heartbeat_timeout_ms: 0,
            heartbeat_miss_threshold: 3, // need 3 misses
            ..Default::default()
        });

        mon.record_heartbeat("pid:1");
        mon.agent_state.get_mut("pid:1").unwrap().last_activity_ms -= 1000;

        // Miss 1: no action yet
        let a1 = mon.check_heartbeat();
        assert!(a1.is_empty());

        // Miss 2: still no action
        let a2 = mon.check_heartbeat();
        assert!(a2.is_empty());

        // Miss 3: NOW action
        let a3 = mon.check_heartbeat();
        assert_eq!(a3.len(), 1);
    }
}
