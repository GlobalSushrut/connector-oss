//! System Watchdog — self-healing monitor for agent OS health.
//!
//! Evaluates rules against system state and fires corrective actions.
//! Analogous to Linux watchdog timers + systemd restart policies.
//!
//! Default rules:
//! - MemoryQuotaExceeded → EvictToTier
//! - ThreatScoreElevated → SendSignal(SecurityAlert)
//! - TokenBudgetExhausted → SuspendAgent

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Watchdog Conditions
// ═══════════════════════════════════════════════════════════════

/// Condition that triggers a watchdog rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WatchdogCondition {
    /// No heartbeat from a cell for > threshold_ms
    CellHeartbeatMissed { cell_id: String, threshold_ms: u64 },
    /// Agent error rate exceeds threshold (0.0–1.0)
    AgentErrorRateHigh { agent_pid: String, threshold: f64 },
    /// Agent's token budget is exhausted
    TokenBudgetExhausted { agent_pid: String },
    /// Agent's memory region exceeds quota percentage (0.0–1.0)
    MemoryQuotaExceeded { agent_pid: String, threshold: f64 },
    /// Cluster partition detected (peer count dropped below minimum)
    ClusterPartitionDetected { min_peers: usize },
    /// Trust score dropped below threshold (0–100)
    TrustScoreLow { agent_pid: String, threshold: f64 },
    /// Threat score exceeds threshold (0.0–1.0)
    ThreatScoreElevated { agent_pid: String, threshold: f64 },
    /// Custom condition identified by name
    Custom { name: String },
}

// ═══════════════════════════════════════════════════════════════
// Watchdog Actions
// ═══════════════════════════════════════════════════════════════

/// Action to take when a watchdog rule fires.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WatchdogAction {
    /// Terminate and re-register the agent
    RestartAgent { agent_pid: String },
    /// Suspend the agent (send Suspend signal)
    SuspendAgent { agent_pid: String },
    /// Evict agent's cold memory to a lower tier
    EvictToTier { agent_pid: String, target_tier: String },
    /// Trigger Merkle sync with a specific cell
    TriggerMerkleSync { cell_id: String },
    /// Send a signal to an agent
    SendSignal { agent_pid: String, signal_name: String },
    /// Notify a human operator (log + flag)
    NotifyHuman { message: String, severity: String },
    /// Execute a VĀKYA action
    ExecuteVakya { vakya_description: String },
    /// Custom action identified by name
    Custom { name: String, payload: String },
}

// ═══════════════════════════════════════════════════════════════
// Watchdog Rule
// ═══════════════════════════════════════════════════════════════

/// A single watchdog rule: condition → action with cooldown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchdogRule {
    /// Human-readable rule name
    pub name: String,
    /// Condition to evaluate
    pub condition: WatchdogCondition,
    /// Action to fire if condition matches
    pub action: WatchdogAction,
    /// Minimum milliseconds between firings (prevents flapping)
    pub cooldown_ms: u64,
    /// Last time this rule fired (ms epoch), 0 = never
    pub last_triggered_ms: u64,
    /// Whether the rule is enabled
    pub enabled: bool,
}

impl WatchdogRule {
    pub fn new(name: impl Into<String>, condition: WatchdogCondition, action: WatchdogAction, cooldown_ms: u64) -> Self {
        Self {
            name: name.into(),
            condition,
            action,
            cooldown_ms,
            last_triggered_ms: 0,
            enabled: true,
        }
    }

    /// Check if the rule's cooldown has elapsed.
    pub fn is_ready(&self, now_ms: u64) -> bool {
        self.enabled && (self.last_triggered_ms == 0 || now_ms - self.last_triggered_ms >= self.cooldown_ms)
    }
}

// ═══════════════════════════════════════════════════════════════
// Watchdog State — snapshot of system health
// ═══════════════════════════════════════════════════════════════

/// Per-agent health metrics fed into watchdog evaluation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentHealth {
    pub agent_pid: String,
    pub error_rate: f64,
    pub memory_used_pct: f64,
    pub token_budget_exhausted: bool,
    pub threat_score: f64,
    pub trust_score: f64,
}

/// Per-cell health metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CellHealth {
    pub cell_id: String,
    pub last_heartbeat_ms: u64,
    pub active_agents: usize,
}

/// Complete system state snapshot for watchdog evaluation.
#[derive(Debug, Clone, Default)]
pub struct WatchdogState {
    pub agents: HashMap<String, AgentHealth>,
    pub cells: HashMap<String, CellHealth>,
    pub peer_count: usize,
    pub custom_flags: HashMap<String, bool>,
}

impl WatchdogState {
    pub fn new() -> Self { Self::default() }

    pub fn set_agent(&mut self, health: AgentHealth) {
        self.agents.insert(health.agent_pid.clone(), health);
    }

    pub fn set_cell(&mut self, health: CellHealth) {
        self.cells.insert(health.cell_id.clone(), health);
    }

    pub fn set_custom_flag(&mut self, name: impl Into<String>, value: bool) {
        self.custom_flags.insert(name.into(), value);
    }
}

// ═══════════════════════════════════════════════════════════════
// System Watchdog
// ═══════════════════════════════════════════════════════════════

/// Fired action record — returned from evaluate().
#[derive(Debug, Clone)]
pub struct FiredAction {
    pub rule_name: String,
    pub action: WatchdogAction,
}

/// System watchdog that evaluates rules against state and fires actions.
pub struct SystemWatchdog {
    rules: Vec<WatchdogRule>,
}

impl SystemWatchdog {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Create a watchdog pre-loaded with sensible default rules.
    pub fn with_defaults() -> Self {
        let mut wd = Self::new();
        // Default rule: high threat → send security alert signal
        wd.add_rule(WatchdogRule::new(
            "default_threat_alert",
            WatchdogCondition::ThreatScoreElevated { agent_pid: "*".to_string(), threshold: 0.7 },
            WatchdogAction::SendSignal { agent_pid: "*".to_string(), signal_name: "security_alert".to_string() },
            10_000,
        ));
        // Default rule: token budget exhausted → suspend agent
        wd.add_rule(WatchdogRule::new(
            "default_budget_suspend",
            WatchdogCondition::TokenBudgetExhausted { agent_pid: "*".to_string() },
            WatchdogAction::SuspendAgent { agent_pid: "*".to_string() },
            30_000,
        ));
        wd
    }

    /// Add a rule to the watchdog.
    pub fn add_rule(&mut self, rule: WatchdogRule) {
        self.rules.push(rule);
    }

    /// Get all rules (for inspection).
    pub fn rules(&self) -> &[WatchdogRule] {
        &self.rules
    }

    /// Get a mutable reference to rules.
    pub fn rules_mut(&mut self) -> &mut Vec<WatchdogRule> {
        &mut self.rules
    }

    /// Evaluate all rules against the given state. Returns fired actions.
    /// Updates `last_triggered_ms` on rules that fire.
    pub fn evaluate(&mut self, state: &WatchdogState, now_ms: u64) -> Vec<FiredAction> {
        let mut fired = Vec::new();

        for rule in &mut self.rules {
            if !rule.is_ready(now_ms) {
                continue;
            }

            let matches = match_condition(&rule.condition, state, now_ms);

            if !matches.is_empty() {
                for matched_pid in &matches {
                    let action = resolve_action(&rule.action, matched_pid);
                    fired.push(FiredAction {
                        rule_name: rule.name.clone(),
                        action,
                    });
                }
                rule.last_triggered_ms = now_ms;
            }
        }

        fired
    }

    /// Total rule count.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

// ═══════════════════════════════════════════════════════════════
// Condition Matching
// ═══════════════════════════════════════════════════════════════

/// Returns a list of matching agent/cell IDs (or vec![""] for non-agent conditions).
fn match_condition(condition: &WatchdogCondition, state: &WatchdogState, now_ms: u64) -> Vec<String> {
    match condition {
        WatchdogCondition::CellHeartbeatMissed { cell_id, threshold_ms } => {
            let check = |cid: &str| -> bool {
                state.cells.get(cid)
                    .map(|c| now_ms.saturating_sub(c.last_heartbeat_ms) > *threshold_ms)
                    .unwrap_or(true) // Missing cell = missed heartbeat
            };
            if cell_id == "*" {
                state.cells.keys().filter(|k| check(k)).cloned().collect()
            } else if check(cell_id) {
                vec![cell_id.clone()]
            } else {
                vec![]
            }
        }

        WatchdogCondition::AgentErrorRateHigh { agent_pid, threshold } => {
            match_agents(agent_pid, state, |a| a.error_rate > *threshold)
        }

        WatchdogCondition::TokenBudgetExhausted { agent_pid } => {
            match_agents(agent_pid, state, |a| a.token_budget_exhausted)
        }

        WatchdogCondition::MemoryQuotaExceeded { agent_pid, threshold } => {
            match_agents(agent_pid, state, |a| a.memory_used_pct > *threshold)
        }

        WatchdogCondition::ClusterPartitionDetected { min_peers } => {
            if state.peer_count < *min_peers {
                vec!["cluster".to_string()]
            } else {
                vec![]
            }
        }

        WatchdogCondition::TrustScoreLow { agent_pid, threshold } => {
            match_agents(agent_pid, state, |a| a.trust_score < *threshold)
        }

        WatchdogCondition::ThreatScoreElevated { agent_pid, threshold } => {
            match_agents(agent_pid, state, |a| a.threat_score > *threshold)
        }

        WatchdogCondition::Custom { name } => {
            if state.custom_flags.get(name).copied().unwrap_or(false) {
                vec![name.clone()]
            } else {
                vec![]
            }
        }
    }
}

/// Match agents by wildcard or specific pid.
fn match_agents(agent_pid: &str, state: &WatchdogState, predicate: impl Fn(&AgentHealth) -> bool) -> Vec<String> {
    if agent_pid == "*" {
        state.agents.values()
            .filter(|a| predicate(a))
            .map(|a| a.agent_pid.clone())
            .collect()
    } else {
        state.agents.get(agent_pid)
            .filter(|a| predicate(a))
            .map(|a| vec![a.agent_pid.clone()])
            .unwrap_or_default()
    }
}

/// Resolve wildcard "*" in action to a specific agent/cell pid.
fn resolve_action(action: &WatchdogAction, matched_id: &str) -> WatchdogAction {
    match action {
        WatchdogAction::RestartAgent { agent_pid } => WatchdogAction::RestartAgent {
            agent_pid: if agent_pid == "*" { matched_id.to_string() } else { agent_pid.clone() },
        },
        WatchdogAction::SuspendAgent { agent_pid } => WatchdogAction::SuspendAgent {
            agent_pid: if agent_pid == "*" { matched_id.to_string() } else { agent_pid.clone() },
        },
        WatchdogAction::EvictToTier { agent_pid, target_tier } => WatchdogAction::EvictToTier {
            agent_pid: if agent_pid == "*" { matched_id.to_string() } else { agent_pid.clone() },
            target_tier: target_tier.clone(),
        },
        WatchdogAction::SendSignal { agent_pid, signal_name } => WatchdogAction::SendSignal {
            agent_pid: if agent_pid == "*" { matched_id.to_string() } else { agent_pid.clone() },
            signal_name: signal_name.clone(),
        },
        WatchdogAction::TriggerMerkleSync { cell_id } => WatchdogAction::TriggerMerkleSync {
            cell_id: if cell_id == "*" { matched_id.to_string() } else { cell_id.clone() },
        },
        other => other.clone(),
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(pid: &str, error_rate: f64, mem_pct: f64, budget_exhausted: bool, threat: f64, trust: f64) -> AgentHealth {
        AgentHealth {
            agent_pid: pid.to_string(),
            error_rate,
            memory_used_pct: mem_pct,
            token_budget_exhausted: budget_exhausted,
            threat_score: threat,
            trust_score: trust,
        }
    }

    #[test]
    fn test_rule_added_and_stored() {
        let mut wd = SystemWatchdog::new();
        assert_eq!(wd.rule_count(), 0);
        wd.add_rule(WatchdogRule::new(
            "test", WatchdogCondition::Custom { name: "x".into() },
            WatchdogAction::NotifyHuman { message: "hi".into(), severity: "info".into() }, 1000,
        ));
        assert_eq!(wd.rule_count(), 1);
        assert_eq!(wd.rules()[0].name, "test");
    }

    #[test]
    fn test_memory_quota_exceeded_triggers_evict() {
        let mut wd = SystemWatchdog::new();
        wd.add_rule(WatchdogRule::new(
            "mem_evict",
            WatchdogCondition::MemoryQuotaExceeded { agent_pid: "pid:001".into(), threshold: 0.9 },
            WatchdogAction::EvictToTier { agent_pid: "pid:001".into(), target_tier: "cold".into() },
            1000,
        ));

        let mut state = WatchdogState::new();
        state.set_agent(agent("pid:001", 0.0, 0.95, false, 0.0, 80.0));

        let fired = wd.evaluate(&state, 5000);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule_name, "mem_evict");
        assert_eq!(fired[0].action, WatchdogAction::EvictToTier { agent_pid: "pid:001".into(), target_tier: "cold".into() });
    }

    #[test]
    fn test_threat_elevated_triggers_signal() {
        let mut wd = SystemWatchdog::new();
        wd.add_rule(WatchdogRule::new(
            "threat_alert",
            WatchdogCondition::ThreatScoreElevated { agent_pid: "pid:002".into(), threshold: 0.5 },
            WatchdogAction::SendSignal { agent_pid: "pid:002".into(), signal_name: "security_alert".into() },
            1000,
        ));

        let mut state = WatchdogState::new();
        state.set_agent(agent("pid:002", 0.0, 0.5, false, 0.8, 90.0));

        let fired = wd.evaluate(&state, 1000);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].action, WatchdogAction::SendSignal { agent_pid: "pid:002".into(), signal_name: "security_alert".into() });
    }

    #[test]
    fn test_cooldown_prevents_duplicate_firing() {
        let mut wd = SystemWatchdog::new();
        wd.add_rule(WatchdogRule::new(
            "threat",
            WatchdogCondition::ThreatScoreElevated { agent_pid: "pid:003".into(), threshold: 0.5 },
            WatchdogAction::SendSignal { agent_pid: "pid:003".into(), signal_name: "alert".into() },
            5000, // 5s cooldown
        ));

        let mut state = WatchdogState::new();
        state.set_agent(agent("pid:003", 0.0, 0.0, false, 0.9, 80.0));

        // First evaluation fires
        let fired = wd.evaluate(&state, 1000);
        assert_eq!(fired.len(), 1);

        // Second evaluation within cooldown — does NOT fire
        let fired = wd.evaluate(&state, 3000);
        assert_eq!(fired.len(), 0);

        // Third evaluation after cooldown — fires again
        let fired = wd.evaluate(&state, 7000);
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn test_token_budget_exhausted_triggers_suspend() {
        let mut wd = SystemWatchdog::new();
        wd.add_rule(WatchdogRule::new(
            "budget_suspend",
            WatchdogCondition::TokenBudgetExhausted { agent_pid: "pid:004".into() },
            WatchdogAction::SuspendAgent { agent_pid: "pid:004".into() },
            1000,
        ));

        let mut state = WatchdogState::new();
        state.set_agent(agent("pid:004", 0.0, 0.0, true, 0.0, 80.0));

        let fired = wd.evaluate(&state, 2000);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].action, WatchdogAction::SuspendAgent { agent_pid: "pid:004".into() });
    }

    #[test]
    fn test_heartbeat_missed_triggers_merkle_sync() {
        let mut wd = SystemWatchdog::new();
        wd.add_rule(WatchdogRule::new(
            "heartbeat",
            WatchdogCondition::CellHeartbeatMissed { cell_id: "cell-a".into(), threshold_ms: 5000 },
            WatchdogAction::TriggerMerkleSync { cell_id: "cell-a".into() },
            10_000,
        ));

        let mut state = WatchdogState::new();
        state.set_cell(CellHealth { cell_id: "cell-a".into(), last_heartbeat_ms: 1000, active_agents: 5 });

        // At t=3000, heartbeat was 2s ago — not missed
        let fired = wd.evaluate(&state, 3000);
        assert_eq!(fired.len(), 0);

        // At t=8000, heartbeat was 7s ago — missed (>5s threshold)
        let fired = wd.evaluate(&state, 8000);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].action, WatchdogAction::TriggerMerkleSync { cell_id: "cell-a".into() });
    }

    #[test]
    fn test_trust_score_low_triggers_notify() {
        let mut wd = SystemWatchdog::new();
        wd.add_rule(WatchdogRule::new(
            "low_trust",
            WatchdogCondition::TrustScoreLow { agent_pid: "pid:005".into(), threshold: 50.0 },
            WatchdogAction::NotifyHuman { message: "Low trust agent".into(), severity: "warning".into() },
            1000,
        ));

        let mut state = WatchdogState::new();
        state.set_agent(agent("pid:005", 0.0, 0.0, false, 0.0, 30.0));

        let fired = wd.evaluate(&state, 2000);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule_name, "low_trust");
    }

    #[test]
    fn test_custom_condition() {
        let mut wd = SystemWatchdog::new();
        wd.add_rule(WatchdogRule::new(
            "custom_check",
            WatchdogCondition::Custom { name: "disk_full".into() },
            WatchdogAction::Custom { name: "cleanup".into(), payload: "{}".into() },
            1000,
        ));

        let mut state = WatchdogState::new();
        // Not flagged — no fire
        let fired = wd.evaluate(&state, 1000);
        assert_eq!(fired.len(), 0);

        // Flagged — fires
        state.set_custom_flag("disk_full", true);
        let fired = wd.evaluate(&state, 2000);
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn test_wildcard_matches_all_agents() {
        let mut wd = SystemWatchdog::new();
        wd.add_rule(WatchdogRule::new(
            "all_threat",
            WatchdogCondition::ThreatScoreElevated { agent_pid: "*".into(), threshold: 0.5 },
            WatchdogAction::SendSignal { agent_pid: "*".into(), signal_name: "alert".into() },
            1000,
        ));

        let mut state = WatchdogState::new();
        state.set_agent(agent("pid:a", 0.0, 0.0, false, 0.8, 90.0));
        state.set_agent(agent("pid:b", 0.0, 0.0, false, 0.9, 90.0));
        state.set_agent(agent("pid:c", 0.0, 0.0, false, 0.1, 90.0)); // below threshold

        let fired = wd.evaluate(&state, 2000);
        assert_eq!(fired.len(), 2); // pid:a and pid:b, not pid:c
        // Check that wildcard was resolved to specific PIDs
        let pids: Vec<String> = fired.iter().map(|f| match &f.action {
            WatchdogAction::SendSignal { agent_pid, .. } => agent_pid.clone(),
            _ => panic!("wrong action type"),
        }).collect();
        assert!(pids.contains(&"pid:a".to_string()));
        assert!(pids.contains(&"pid:b".to_string()));
    }

    #[test]
    fn test_multiple_rules_evaluated_in_one_pass() {
        let mut wd = SystemWatchdog::new();
        wd.add_rule(WatchdogRule::new("r1", WatchdogCondition::Custom { name: "a".into() }, WatchdogAction::Custom { name: "a1".into(), payload: "{}".into() }, 0));
        wd.add_rule(WatchdogRule::new("r2", WatchdogCondition::Custom { name: "b".into() }, WatchdogAction::Custom { name: "b1".into(), payload: "{}".into() }, 0));
        wd.add_rule(WatchdogRule::new("r3", WatchdogCondition::Custom { name: "c".into() }, WatchdogAction::Custom { name: "c1".into(), payload: "{}".into() }, 0));
        wd.add_rule(WatchdogRule::new("r4", WatchdogCondition::Custom { name: "d".into() }, WatchdogAction::Custom { name: "d1".into(), payload: "{}".into() }, 0));
        wd.add_rule(WatchdogRule::new("r5", WatchdogCondition::Custom { name: "e".into() }, WatchdogAction::Custom { name: "e1".into(), payload: "{}".into() }, 0));

        let mut state = WatchdogState::new();
        state.set_custom_flag("a", true);
        state.set_custom_flag("b", false);
        state.set_custom_flag("c", true);
        state.set_custom_flag("d", true);
        // "e" not set = false

        let fired = wd.evaluate(&state, 1000);
        assert_eq!(fired.len(), 3); // a, c, d
        let names: Vec<&str> = fired.iter().map(|f| f.rule_name.as_str()).collect();
        assert!(names.contains(&"r1"));
        assert!(names.contains(&"r3"));
        assert!(names.contains(&"r4"));
    }

    #[test]
    fn test_no_match_fires_nothing() {
        let mut wd = SystemWatchdog::new();
        wd.add_rule(WatchdogRule::new(
            "nothing",
            WatchdogCondition::MemoryQuotaExceeded { agent_pid: "pid:x".into(), threshold: 0.9 },
            WatchdogAction::EvictToTier { agent_pid: "pid:x".into(), target_tier: "cold".into() },
            1000,
        ));

        let mut state = WatchdogState::new();
        state.set_agent(agent("pid:x", 0.0, 0.5, false, 0.0, 80.0)); // 50% < 90% threshold

        let fired = wd.evaluate(&state, 1000);
        assert_eq!(fired.len(), 0);
    }

    #[test]
    fn test_cluster_partition_detected() {
        let mut wd = SystemWatchdog::new();
        wd.add_rule(WatchdogRule::new(
            "partition",
            WatchdogCondition::ClusterPartitionDetected { min_peers: 3 },
            WatchdogAction::NotifyHuman { message: "Cluster partition!".into(), severity: "critical".into() },
            5000,
        ));

        let mut state = WatchdogState::new();
        state.peer_count = 5;

        // Healthy — no fire
        let fired = wd.evaluate(&state, 1000);
        assert_eq!(fired.len(), 0);

        // Partition — only 2 peers
        state.peer_count = 2;
        let fired = wd.evaluate(&state, 2000);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule_name, "partition");
    }

    #[test]
    fn test_defaults_include_threat_and_budget_rules() {
        let wd = SystemWatchdog::with_defaults();
        assert_eq!(wd.rule_count(), 2);
        assert_eq!(wd.rules()[0].name, "default_threat_alert");
        assert_eq!(wd.rules()[1].name, "default_budget_suspend");
    }
}
