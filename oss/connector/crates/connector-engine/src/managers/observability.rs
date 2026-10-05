//! ObservabilityManager — Monitoring and analysis subsystem.
//!
//! Groups observability-related engines:
//! - `SystemWatchdog` — Self-healing monitor with configurable rules
//! - `ReputationEngine` — EigenTrust-based agent reputation scoring
//! - `BehaviorAnalyzer` — Runtime behavioral analysis and anomaly detection

use crate::watchdog::{SystemWatchdog, WatchdogState, WatchdogRule, WatchdogCondition, WatchdogAction, FiredAction};
use crate::reputation::{ReputationEngine, ReputationConfig};
use crate::behavior::{BehaviorAnalyzer, BehaviorConfig};

/// ObservabilityManager — unified monitoring and analysis layer.
///
/// Consolidates all observability-related engines into a single manager,
/// providing a cohesive API for monitoring, reputation, and behavior analysis.
pub struct ObservabilityManager {
    /// SystemWatchdog — self-healing monitor with configurable rules
    pub watchdog: SystemWatchdog,
    /// ReputationEngine — EigenTrust-based agent reputation scoring
    pub reputation: ReputationEngine,
    /// BehaviorAnalyzer — runtime behavioral analysis
    pub behavior: BehaviorAnalyzer,
}

impl ObservabilityManager {
    /// Create a new ObservabilityManager with default configurations.
    pub fn new() -> Self {
        Self {
            watchdog: SystemWatchdog::with_defaults(),
            reputation: ReputationEngine::new(ReputationConfig::default()),
            behavior: BehaviorAnalyzer::default_analyzer(),
        }
    }

    /// Create with custom behavior configuration.
    pub fn with_behavior_config(mut self, config: BehaviorConfig) -> Self {
        self.behavior = BehaviorAnalyzer::new(config);
        self
    }

    /// Create with custom reputation configuration.
    pub fn with_reputation_config(mut self, config: ReputationConfig) -> Self {
        self.reputation = ReputationEngine::new(config);
        self
    }

    /// Configure watchdog with custom rules.
    pub fn with_watchdog_config(
        mut self,
        check_interval_ms: u64,
        max_memory_mb: u64,
        max_cpu_percent: u8,
    ) -> Self {
        self.watchdog = SystemWatchdog::with_defaults();
        
        // Memory limit rule
        self.watchdog.add_rule(WatchdogRule::new(
            "config_memory_limit",
            WatchdogCondition::TokenBudgetExhausted { agent_pid: "*".to_string() },
            WatchdogAction::SendSignal {
                agent_pid: "*".to_string(),
                signal_name: format!("memory_limit_{}mb", max_memory_mb),
            },
            check_interval_ms,
        ));
        
        // CPU/threat rule
        self.watchdog.add_rule(WatchdogRule::new(
            "config_cpu_limit",
            WatchdogCondition::ThreatScoreElevated {
                agent_pid: "*".to_string(),
                threshold: (max_cpu_percent as f64) / 100.0,
            },
            WatchdogAction::SendSignal {
                agent_pid: "*".to_string(),
                signal_name: "cpu_threshold_alert".to_string(),
            },
            check_interval_ms,
        ));
        
        self
    }

    /// Get the risk score for an agent (normalized 0-1).
    pub fn agent_risk_score(&self, agent_pid: &str) -> f64 {
        self.behavior.agent_risk_score(agent_pid) / 100.0
    }

    /// Record an action for behavior analysis.
    pub fn record_action(&mut self, agent_pid: &str, action_type: &str, size: u64) {
        self.behavior.record_action(agent_pid, action_type, size);
    }

    /// Record an error for behavior analysis.
    pub fn record_error(&mut self, agent_pid: &str) {
        self.behavior.record_error(agent_pid);
    }

    /// Get agent reputation score.
    pub fn get_reputation(&self, agent_pid: &str) -> f64 {
        let now_ms = chrono::Utc::now().timestamp_millis();
        self.reputation.score_for(agent_pid, now_ms)
    }

    /// Submit feedback for reputation update.
    pub fn submit_feedback(&mut self, feedback: crate::reputation::Feedback) -> Result<(), String> {
        self.reputation.submit_feedback(feedback)
    }

    /// Check watchdog rules and return any fired actions.
    pub fn check_watchdog(&mut self, state: &WatchdogState) -> Vec<FiredAction> {
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        self.watchdog.evaluate(state, now_ms)
    }

    /// Get watchdog reference.
    pub fn watchdog(&self) -> &SystemWatchdog {
        &self.watchdog
    }

    /// Get mutable watchdog reference.
    pub fn watchdog_mut(&mut self) -> &mut SystemWatchdog {
        &mut self.watchdog
    }

    /// Get reputation engine reference.
    pub fn reputation(&self) -> &ReputationEngine {
        &self.reputation
    }

    /// Get mutable reputation engine reference.
    pub fn reputation_mut(&mut self) -> &mut ReputationEngine {
        &mut self.reputation
    }

    /// Get behavior analyzer reference.
    pub fn behavior(&self) -> &BehaviorAnalyzer {
        &self.behavior
    }

    /// Get mutable behavior analyzer reference.
    pub fn behavior_mut(&mut self) -> &mut BehaviorAnalyzer {
        &mut self.behavior
    }
}

impl Default for ObservabilityManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_observability_manager_creation() {
        let manager = ObservabilityManager::new();
        assert_eq!(manager.agent_risk_score("test_agent"), 0.0);
    }

    #[test]
    fn test_behavior_recording() {
        let mut manager = ObservabilityManager::new();
        manager.record_action("agent_1", "memory.write", 1024);
        // Risk score should still be low for normal activity
        assert!(manager.agent_risk_score("agent_1") < 0.5);
    }
}
