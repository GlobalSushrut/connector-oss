//! Adaptive Firewall Thresholds — per-agent dynamic adjustment based on behavioral baselines.
//!
//! Military-grade properties:
//! - No adjustment until baseline established (min_sample_size actions)
//! - Tighten for low-baseline agents (catch anomalies earlier)
//! - Loosen for high-baseline agents handling PHI (reduce false positives)
//! - All threshold changes logged for audit

use std::collections::HashMap;

use crate::firewall::VerdictThresholds;

// ── Config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AdaptiveThresholdConfig {
    pub enabled: bool,
    /// Minimum actions before adapting thresholds.
    pub min_sample_size: usize,
    /// Factor to tighten thresholds for low-baseline agents (< 1.0 = tighter).
    pub tighten_factor: f64,
    /// Factor to loosen thresholds for high-baseline agents (> 1.0 = looser).
    pub loosen_factor: f64,
    /// Score below which agent is "low-baseline".
    pub low_baseline_cutoff: f64,
    /// Score above which agent is "high-baseline".
    pub high_baseline_cutoff: f64,
}

impl Default for AdaptiveThresholdConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_sample_size: 20,
            tighten_factor: 0.75,
            loosen_factor: 1.25,
            low_baseline_cutoff: 0.15,
            high_baseline_cutoff: 0.40,
        }
    }
}

// ── Per-Agent Baseline ──────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AgentBaseline {
    scores: Vec<f64>,
    avg_score: f64,
    adapted_thresholds: Option<VerdictThresholds>,
}

impl AgentBaseline {
    fn new() -> Self {
        Self { scores: Vec::new(), avg_score: 0.0, adapted_thresholds: None }
    }

    fn record(&mut self, score: f64) {
        self.scores.push(score);
        self.avg_score = self.scores.iter().sum::<f64>() / self.scores.len() as f64;
    }
}

// ── Threshold Adjustment Log ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ThresholdAdjustment {
    pub timestamp: i64,
    pub agent_pid: String,
    pub direction: String,
    pub old_block: f64,
    pub new_block: f64,
    pub avg_score: f64,
}

// ── Adaptive Threshold Manager ──────────────────────────────────────

pub struct AdaptiveThresholdManager {
    config: AdaptiveThresholdConfig,
    baselines: HashMap<String, AgentBaseline>,
    default_thresholds: VerdictThresholds,
    adjustments: Vec<ThresholdAdjustment>,
}

impl AdaptiveThresholdManager {
    pub fn new(config: AdaptiveThresholdConfig, defaults: VerdictThresholds) -> Self {
        Self {
            config,
            baselines: HashMap::new(),
            default_thresholds: defaults,
            adjustments: Vec::new(),
        }
    }

    fn now_ms() -> i64 { chrono::Utc::now().timestamp_millis() }

    /// Record a threat score for an agent. Returns adapted thresholds if baseline is established.
    pub fn record_score(&mut self, agent_pid: &str, score: f64) -> VerdictThresholds {
        if !self.config.enabled {
            return self.default_thresholds.clone();
        }

        let baseline = self.baselines.entry(agent_pid.to_string())
            .or_insert_with(AgentBaseline::new);
        baseline.record(score);

        // Not enough samples yet — use defaults
        if baseline.scores.len() < self.config.min_sample_size {
            return self.default_thresholds.clone();
        }

        // Already adapted for this baseline level
        if let Some(ref adapted) = baseline.adapted_thresholds {
            return adapted.clone();
        }

        // Compute adapted thresholds
        let avg = baseline.avg_score;
        let defaults = &self.default_thresholds;

        let adapted = if avg < self.config.low_baseline_cutoff {
            // Low-baseline agent: tighten (catch anomalies earlier)
            let t = VerdictThresholds {
                warn: defaults.warn * self.config.tighten_factor,
                review: defaults.review * self.config.tighten_factor,
                block: defaults.block * self.config.tighten_factor,
            };
            self.adjustments.push(ThresholdAdjustment {
                timestamp: Self::now_ms(),
                agent_pid: agent_pid.to_string(),
                direction: "tighten".into(),
                old_block: defaults.block,
                new_block: t.block,
                avg_score: avg,
            });
            t
        } else if avg > self.config.high_baseline_cutoff {
            // High-baseline agent (handles PHI): loosen to reduce false positives
            let t = VerdictThresholds {
                warn: defaults.warn * self.config.loosen_factor,
                review: defaults.review * self.config.loosen_factor,
                block: (defaults.block * self.config.loosen_factor).min(0.95),
            };
            self.adjustments.push(ThresholdAdjustment {
                timestamp: Self::now_ms(),
                agent_pid: agent_pid.to_string(),
                direction: "loosen".into(),
                old_block: defaults.block,
                new_block: t.block,
                avg_score: avg,
            });
            t
        } else {
            // Normal baseline — keep defaults
            defaults.clone()
        };

        baseline.adapted_thresholds = Some(adapted.clone());
        adapted
    }

    /// Get current thresholds for an agent.
    pub fn thresholds_for(&self, agent_pid: &str) -> VerdictThresholds {
        self.baselines.get(agent_pid)
            .and_then(|b| b.adapted_thresholds.clone())
            .unwrap_or_else(|| self.default_thresholds.clone())
    }

    pub fn adjustment_log(&self) -> &[ThresholdAdjustment] { &self.adjustments }
    pub fn agent_avg_score(&self, agent_pid: &str) -> Option<f64> {
        self.baselines.get(agent_pid).map(|b| b.avg_score)
    }
}

impl Default for AdaptiveThresholdManager {
    fn default() -> Self {
        Self::new(AdaptiveThresholdConfig::default(), VerdictThresholds::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_before_baseline() {
        let mut mgr = AdaptiveThresholdManager::default();
        // Only 5 samples — not enough
        for _ in 0..5 {
            let t = mgr.record_score("pid:1", 0.1);
            assert_eq!(t.block, 0.8); // default
        }
    }

    #[test]
    fn test_tighten_for_low_baseline() {
        let mut mgr = AdaptiveThresholdManager::new(
            AdaptiveThresholdConfig { min_sample_size: 5, ..Default::default() },
            VerdictThresholds::default(),
        );

        // Low-baseline agent (avg = 0.1)
        for _ in 0..5 {
            mgr.record_score("pid:low", 0.10);
        }

        let t = mgr.thresholds_for("pid:low");
        assert!(t.block < 0.8, "Expected tighter block, got {}", t.block);
        assert_eq!(mgr.adjustment_log().len(), 1);
        assert_eq!(mgr.adjustment_log()[0].direction, "tighten");
    }

    #[test]
    fn test_loosen_for_high_baseline() {
        let mut mgr = AdaptiveThresholdManager::new(
            AdaptiveThresholdConfig { min_sample_size: 5, ..Default::default() },
            VerdictThresholds::default(),
        );

        // High-baseline agent handling PHI (avg = 0.45)
        for _ in 0..5 {
            mgr.record_score("pid:phi", 0.45);
        }

        let t = mgr.thresholds_for("pid:phi");
        assert!(t.block > 0.8, "Expected looser block, got {}", t.block);
    }

    #[test]
    fn test_normal_baseline_keeps_defaults() {
        let mut mgr = AdaptiveThresholdManager::new(
            AdaptiveThresholdConfig { min_sample_size: 5, ..Default::default() },
            VerdictThresholds::default(),
        );

        for _ in 0..5 {
            mgr.record_score("pid:normal", 0.25);
        }

        let t = mgr.thresholds_for("pid:normal");
        assert_eq!(t.block, 0.8); // unchanged
    }

    #[test]
    fn test_disabled() {
        let mut mgr = AdaptiveThresholdManager::new(
            AdaptiveThresholdConfig { enabled: false, min_sample_size: 1, ..Default::default() },
            VerdictThresholds::default(),
        );

        for _ in 0..20 {
            mgr.record_score("pid:1", 0.05);
        }

        let t = mgr.thresholds_for("pid:1");
        assert_eq!(t.block, 0.8); // always default when disabled
    }
}
