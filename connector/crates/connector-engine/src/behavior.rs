//! Behavior Analyzer — runtime behavioral analysis for agentic AI.
//!
//! Based on: MAESTRO threat model (behavioral drift detection), OWASP Agentic Top 10
//! (memory poisoning, tool misuse, privilege escalation), NIST AI RMF MEASURE function,
//! OWASP AIVSS v1 (agent.behavior.deviation > 0.75 threshold).
//!
//! Monitors agent behavior patterns using sliding windows over action history.
//! Detects anomalies, scope drift, escalation attempts, and cross-agent contamination.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Alert Levels (NIST AI RMF MANAGE function)
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorAlert {
    pub level: AlertLevel,
    pub category: String,
    pub agent_pid: String,
    pub message: String,
    pub metric_name: String,
    pub metric_value: f64,
    pub threshold: f64,
    pub timestamp: i64,
}

// ═══════════════════════════════════════════════════════════════
// Agent Behavior Profile — baseline + current metrics
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Default)]
struct AgentProfile {
    /// Action timestamps for frequency calculation
    action_times: Vec<i64>,
    /// Unique tools used (scope tracking)
    tools_used: std::collections::HashSet<String>,
    /// Bytes read/written (exfiltration detection)
    data_volume_bytes: u64,
    /// Failed operation count (probing detection)
    error_count: u32,
    /// Successful operation count
    success_count: u32,
    /// Privilege escalation attempt count
    escalation_attempts: u32,
    /// Cross-boundary access attempts
    cross_boundary_count: u32,
    /// Baseline action frequency (actions/min, established after N actions)
    baseline_frequency: Option<f64>,
    /// Baseline tool diversity
    baseline_tool_count: Option<usize>,
    /// Number of actions used to establish baseline
    baseline_sample_size: usize,
}

// ═══════════════════════════════════════════════════════════════
// Behavior Analyzer Configuration
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorConfig {
    /// Window size in milliseconds for frequency calculation
    pub window_ms: i64,
    /// Number of actions before baseline is established
    pub baseline_sample_size: usize,
    /// Z-score threshold for anomaly detection (default 2.0 = ~95th percentile)
    pub anomaly_threshold: f64,
    /// Max actions per window before alert
    pub max_actions_per_window: u32,
    /// Max unique tools before scope drift alert
    pub max_tool_diversity: usize,
    /// Max error rate (errors / total) before probing alert
    pub max_error_rate: f64,
    /// Max data volume (bytes) per window before exfiltration alert
    pub max_data_volume: u64,
    /// Enable cross-agent contamination detection
    pub detect_contamination: bool,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            window_ms: 60_000,
            baseline_sample_size: 20,
            anomaly_threshold: 2.0,
            max_actions_per_window: 100,
            max_tool_diversity: 10,
            max_error_rate: 0.3,
            max_data_volume: 10_000_000,
            detect_contamination: true,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// BehaviorAnalyzer
// ═══════════════════════════════════════════════════════════════

pub struct BehaviorAnalyzer {
    config: BehaviorConfig,
    profiles: HashMap<String, AgentProfile>,
    alerts: Vec<BehaviorAlert>,
}

impl BehaviorAnalyzer {
    pub fn new(config: BehaviorConfig) -> Self {
        Self {
            config,
            profiles: HashMap::new(),
            alerts: Vec::new(),
        }
    }

    pub fn default_analyzer() -> Self {
        Self::new(BehaviorConfig::default())
    }

    fn now_ms() -> i64 { chrono::Utc::now().timestamp_millis() }

    fn profile(&mut self, agent_pid: &str) -> &mut AgentProfile {
        self.profiles.entry(agent_pid.to_string()).or_default()
    }

    fn alert(&mut self, level: AlertLevel, category: &str, agent_pid: &str, message: &str,
             metric_name: &str, metric_value: f64, threshold: f64) {
        self.alerts.push(BehaviorAlert {
            level,
            category: category.to_string(),
            agent_pid: agent_pid.to_string(),
            message: message.to_string(),
            metric_name: metric_name.to_string(),
            metric_value,
            threshold,
            timestamp: Self::now_ms(),
        });
    }

    // ── Record events ────────────────────────────────────────

    /// Record an action by an agent. Returns any alerts triggered.
    pub fn record_action(&mut self, agent_pid: &str, action: &str, data_bytes: u64) -> Vec<BehaviorAlert> {
        let now = Self::now_ms();
        let window_start = now - self.config.window_ms;
        let mut new_alerts = Vec::new();

        let profile = self.profiles.entry(agent_pid.to_string()).or_default();
        profile.action_times.push(now);
        profile.action_times.retain(|t| *t > window_start);
        profile.data_volume_bytes += data_bytes;
        profile.success_count += 1;

        // Action frequency check
        let current_frequency = profile.action_times.len() as u32;
        if current_frequency > self.config.max_actions_per_window {
            let a = BehaviorAlert {
                level: AlertLevel::Critical,
                category: "action_frequency".to_string(),
                agent_pid: agent_pid.to_string(),
                message: format!("Action frequency spike: {} actions in window (max: {})",
                    current_frequency, self.config.max_actions_per_window),
                metric_name: "actions_per_window".to_string(),
                metric_value: current_frequency as f64,
                threshold: self.config.max_actions_per_window as f64,
                timestamp: now,
            };
            new_alerts.push(a.clone());
            self.alerts.push(a);
        }

        // Baseline deviation check (after baseline established)
        if profile.baseline_frequency.is_none()
            && profile.action_times.len() >= self.config.baseline_sample_size
        {
            profile.baseline_frequency = Some(profile.action_times.len() as f64);
            profile.baseline_tool_count = Some(profile.tools_used.len());
            profile.baseline_sample_size = profile.action_times.len();
        }

        if let Some(baseline) = profile.baseline_frequency {
            if baseline > 0.0 {
                let deviation = (current_frequency as f64 - baseline).abs() / baseline;
                if deviation > self.config.anomaly_threshold {
                    let a = BehaviorAlert {
                        level: AlertLevel::Warning,
                        category: "behavioral_drift".to_string(),
                        agent_pid: agent_pid.to_string(),
                        message: format!("Behavioral drift: frequency deviation {:.1}x from baseline", deviation),
                        metric_name: "frequency_deviation".to_string(),
                        metric_value: deviation,
                        threshold: self.config.anomaly_threshold,
                        timestamp: now,
                    };
                    new_alerts.push(a.clone());
                    self.alerts.push(a);
                }
            }
        }

        // Data volume check (exfiltration detection)
        if profile.data_volume_bytes > self.config.max_data_volume {
            let a = BehaviorAlert {
                level: AlertLevel::Critical,
                category: "data_exfiltration".to_string(),
                agent_pid: agent_pid.to_string(),
                message: format!("Data volume anomaly: {} bytes (max: {})",
                    profile.data_volume_bytes, self.config.max_data_volume),
                metric_name: "data_volume_bytes".to_string(),
                metric_value: profile.data_volume_bytes as f64,
                threshold: self.config.max_data_volume as f64,
                timestamp: now,
            };
            new_alerts.push(a.clone());
            self.alerts.push(a);
        }

        new_alerts
    }

    /// Record a tool usage by an agent.
    pub fn record_tool_use(&mut self, agent_pid: &str, tool_id: &str) -> Vec<BehaviorAlert> {
        let mut new_alerts = Vec::new();
        let profile = self.profiles.entry(agent_pid.to_string()).or_default();
        profile.tools_used.insert(tool_id.to_string());

        // Scope drift detection
        if profile.tools_used.len() > self.config.max_tool_diversity {
            let a = BehaviorAlert {
                level: AlertLevel::Warning,
                category: "scope_drift".to_string(),
                agent_pid: agent_pid.to_string(),
                message: format!("Scope drift: {} unique tools used (max: {})",
                    profile.tools_used.len(), self.config.max_tool_diversity),
                metric_name: "tool_diversity".to_string(),
                metric_value: profile.tools_used.len() as f64,
                threshold: self.config.max_tool_diversity as f64,
                timestamp: Self::now_ms(),
            };
            new_alerts.push(a.clone());
            self.alerts.push(a);
        }

        new_alerts
    }

    /// Record a failed operation (probing detection).
    pub fn record_error(&mut self, agent_pid: &str) -> Vec<BehaviorAlert> {
        let mut new_alerts = Vec::new();
        let profile = self.profiles.entry(agent_pid.to_string()).or_default();
        profile.error_count += 1;

        let total = profile.success_count + profile.error_count;
        if total >= 5 {
            let error_rate = profile.error_count as f64 / total as f64;
            if error_rate > self.config.max_error_rate {
                let a = BehaviorAlert {
                    level: AlertLevel::Warning,
                    category: "probing".to_string(),
                    agent_pid: agent_pid.to_string(),
                    message: format!("High error rate: {:.0}% ({}/{} failed) — possible probing",
                        error_rate * 100.0, profile.error_count, total),
                    metric_name: "error_rate".to_string(),
                    metric_value: error_rate,
                    threshold: self.config.max_error_rate,
                    timestamp: Self::now_ms(),
                };
                new_alerts.push(a.clone());
                self.alerts.push(a);
            }
        }

        new_alerts
    }

    /// Record a privilege escalation attempt.
    pub fn record_escalation_attempt(&mut self, agent_pid: &str, detail: &str) {
        let profile = self.profiles.entry(agent_pid.to_string()).or_default();
        profile.escalation_attempts += 1;

        let a = BehaviorAlert {
            level: if profile.escalation_attempts >= 3 { AlertLevel::Block } else { AlertLevel::Critical },
            category: "privilege_escalation".to_string(),
            agent_pid: agent_pid.to_string(),
            message: format!("Privilege escalation attempt #{}: {}", profile.escalation_attempts, detail),
            metric_name: "escalation_attempts".to_string(),
            metric_value: profile.escalation_attempts as f64,
            threshold: 3.0,
            timestamp: Self::now_ms(),
        };
        self.alerts.push(a);
    }

    /// Record a cross-boundary access.
    pub fn record_cross_boundary(&mut self, agent_pid: &str, target: &str) {
        if !self.config.detect_contamination { return; }
        let profile = self.profiles.entry(agent_pid.to_string()).or_default();
        profile.cross_boundary_count += 1;

        let a = BehaviorAlert {
            level: AlertLevel::Warning,
            category: "cross_boundary".to_string(),
            agent_pid: agent_pid.to_string(),
            message: format!("Cross-boundary access #{}: target={}", profile.cross_boundary_count, target),
            metric_name: "cross_boundary_count".to_string(),
            metric_value: profile.cross_boundary_count as f64,
            threshold: 5.0,
            timestamp: Self::now_ms(),
        };
        self.alerts.push(a);
    }

    // ── Query methods ────────────────────────────────────────

    pub fn alerts(&self) -> &[BehaviorAlert] { &self.alerts }
    pub fn alert_count(&self) -> usize { self.alerts.len() }

    pub fn alerts_by_level(&self, level: AlertLevel) -> Vec<&BehaviorAlert> {
        self.alerts.iter().filter(|a| a.level == level).collect()
    }

    pub fn alerts_by_agent(&self, agent_pid: &str) -> Vec<&BehaviorAlert> {
        self.alerts.iter().filter(|a| a.agent_pid == agent_pid).collect()
    }

    pub fn has_blocking_alerts(&self) -> bool {
        self.alerts.iter().any(|a| a.level == AlertLevel::Block)
    }

    pub fn agent_risk_score(&self, agent_pid: &str) -> f64 {
        let agent_alerts = self.alerts_by_agent(agent_pid);
        let mut score: f64 = 0.0;
        for alert in agent_alerts {
            score += match alert.level {
                AlertLevel::Info => 0.0,
                AlertLevel::Warning => 1.0,
                AlertLevel::Critical => 3.0,
                AlertLevel::Block => 10.0,
            };
        }
        score.min(100.0)
    }

    pub fn config(&self) -> &BehaviorConfig { &self.config }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_behavior_no_alerts() {
        let mut ba = BehaviorAnalyzer::default_analyzer();
        let alerts = ba.record_action("pid:bot", "memory.write", 100);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_action_frequency_spike() {
        let mut ba = BehaviorAnalyzer::new(BehaviorConfig {
            max_actions_per_window: 5,
            ..Default::default()
        });
        for i in 0..6 {
            let alerts = ba.record_action("pid:bot", &format!("action.{}", i), 10);
            if i >= 5 {
                assert!(!alerts.is_empty(), "Should alert on spike");
                assert_eq!(alerts[0].category, "action_frequency");
            }
        }
    }

    #[test]
    fn test_scope_drift_detection() {
        let mut ba = BehaviorAnalyzer::new(BehaviorConfig {
            max_tool_diversity: 3,
            ..Default::default()
        });
        ba.record_tool_use("pid:bot", "tool_a");
        ba.record_tool_use("pid:bot", "tool_b");
        ba.record_tool_use("pid:bot", "tool_c");
        let alerts = ba.record_tool_use("pid:bot", "tool_d");
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].category, "scope_drift");
    }

    #[test]
    fn test_error_rate_probing_detection() {
        let mut ba = BehaviorAnalyzer::new(BehaviorConfig {
            max_error_rate: 0.3,
            ..Default::default()
        });
        // 2 successes, 4 errors = 66% error rate
        ba.record_action("pid:bot", "a", 0);
        ba.record_action("pid:bot", "b", 0);
        ba.record_error("pid:bot");
        ba.record_error("pid:bot");
        ba.record_error("pid:bot");
        let alerts = ba.record_error("pid:bot");
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].category, "probing");
    }

    #[test]
    fn test_data_exfiltration_detection() {
        let mut ba = BehaviorAnalyzer::new(BehaviorConfig {
            max_data_volume: 1000,
            ..Default::default()
        });
        ba.record_action("pid:bot", "read", 500);
        let alerts = ba.record_action("pid:bot", "read", 600);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].category, "data_exfiltration");
    }

    #[test]
    fn test_privilege_escalation_tracking() {
        let mut ba = BehaviorAnalyzer::default_analyzer();
        ba.record_escalation_attempt("pid:bot", "tried to access admin namespace");
        ba.record_escalation_attempt("pid:bot", "tried to modify policies");
        ba.record_escalation_attempt("pid:bot", "tried to delete audit log");
        assert!(ba.has_blocking_alerts());
    }

    #[test]
    fn test_cross_boundary_detection() {
        let mut ba = BehaviorAnalyzer::default_analyzer();
        ba.record_cross_boundary("pid:bot", "ns:pipe/admin");
        assert_eq!(ba.alert_count(), 1);
        assert_eq!(ba.alerts()[0].category, "cross_boundary");
    }

    #[test]
    fn test_agent_risk_score() {
        let mut ba = BehaviorAnalyzer::default_analyzer();
        ba.record_escalation_attempt("pid:bot", "attempt 1"); // Critical = 3
        ba.record_cross_boundary("pid:bot", "admin"); // Warning = 1
        let score = ba.agent_risk_score("pid:bot");
        assert!(score >= 4.0);
    }

    #[test]
    fn test_multi_agent_isolation() {
        let mut ba = BehaviorAnalyzer::default_analyzer();
        ba.record_action("pid:bot1", "action", 100);
        ba.record_escalation_attempt("pid:bot2", "bad thing");
        assert_eq!(ba.alerts_by_agent("pid:bot1").len(), 0);
        assert_eq!(ba.alerts_by_agent("pid:bot2").len(), 1);
    }
}
