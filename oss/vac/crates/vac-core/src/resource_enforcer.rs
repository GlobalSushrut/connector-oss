//! Resource Enforcer — OOM killer, execution limits, throttling
//!
//! This module implements resource enforcement mechanisms:
//! - OOM (Out-of-Memory) killer for agents exceeding memory limits
//! - Execution time limits with timeout enforcement
//! - Gradual throttling based on resource usage
//! - Resource violation tracking and reporting
//!
//! Design sources: Linux OOM killer, cgroups v2, Kubernetes resource limits

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::hardware_contract::{AgentHardwareContract, LimitAction, ResourceUsage, ViolationSeverity};
use crate::process::Pid;

// =============================================================================
// OOM Killer
// =============================================================================

/// OOM score for an agent (higher = more likely to be killed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OomScore {
    /// Agent PID
    pub pid: Pid,
    /// Base score (0-1000)
    pub score: i32,
    /// Adjustment from contract (-1000 to 1000)
    pub adj: i16,
    /// Final score (score + adj, clamped to 0-1000)
    pub final_score: i32,
    /// Memory usage in bytes
    pub memory_bytes: u64,
    /// Memory limit in bytes
    pub memory_limit: u64,
    /// Usage percentage
    pub usage_percent: f32,
    /// Is protected (score_adj <= -900)
    pub protected: bool,
}

impl OomScore {
    pub fn compute(
        pid: Pid,
        memory_bytes: u64,
        memory_limit: u64,
        oom_score_adj: i16,
    ) -> Self {
        // Base score: percentage of limit used (0-1000)
        let usage_percent = if memory_limit > 0 {
            (memory_bytes as f64 / memory_limit as f64 * 100.0) as f32
        } else {
            0.0
        };
        
        let base_score = (usage_percent * 10.0).min(1000.0) as i32;
        let final_score = (base_score + oom_score_adj as i32).clamp(0, 1000);
        let protected = oom_score_adj <= -900;

        Self {
            pid,
            score: base_score,
            adj: oom_score_adj,
            final_score,
            memory_bytes,
            memory_limit,
            usage_percent,
            protected,
        }
    }
}

/// OOM kill reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OomKillReason {
    /// System-wide memory pressure
    SystemPressure { available_bytes: u64, threshold_bytes: u64 },
    /// Agent exceeded hard limit
    HardLimitExceeded { used: u64, limit: u64 },
    /// Manual trigger
    Manual { reason: String },
}

/// OOM kill event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OomKillEvent {
    /// Timestamp (epoch ms)
    pub timestamp: i64,
    /// Killed agent PID
    pub pid: Pid,
    /// OOM score at time of kill
    pub oom_score: i32,
    /// Memory used at time of kill
    pub memory_bytes: u64,
    /// Kill reason
    pub reason: OomKillReason,
    /// Signal sent (SIGKILL = 9)
    pub signal: i32,
}

/// OOM Killer — selects and kills agents when memory is exhausted
#[derive(Debug, Default)]
pub struct OomKiller {
    /// OOM scores by PID
    scores: HashMap<Pid, OomScore>,
    /// Kill history
    kill_history: Vec<OomKillEvent>,
    /// System memory threshold (bytes)
    system_threshold: u64,
    /// Enabled flag
    enabled: bool,
}

impl OomKiller {
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            kill_history: Vec::new(),
            system_threshold: 1_073_741_824, // 1GB default
            enabled: true,
        }
    }

    /// Update OOM score for an agent
    pub fn update_score(&mut self, pid: Pid, usage: &ResourceUsage, contract: &AgentHardwareContract) {
        let memory_limit = contract.resource_limits.memory_bytes.hard.value().unwrap_or(u64::MAX);
        let score = OomScore::compute(
            pid.clone(),
            usage.memory_bytes,
            memory_limit,
            contract.oom_score_adj,
        );
        self.scores.insert(pid, score);
    }

    /// Remove agent from tracking
    pub fn remove(&mut self, pid: &Pid) {
        self.scores.remove(pid);
    }

    /// Get OOM score for an agent
    pub fn get_score(&self, pid: &Pid) -> Option<&OomScore> {
        self.scores.get(pid)
    }

    /// Select victim for OOM kill (highest score, not protected)
    pub fn select_victim(&self) -> Option<&OomScore> {
        self.scores.values()
            .filter(|s| !s.protected && s.final_score > 0)
            .max_by_key(|s| s.final_score)
    }

    /// Check if agent should be killed (exceeded hard limit)
    pub fn should_kill(&self, pid: &Pid) -> Option<OomKillReason> {
        let score = self.scores.get(pid)?;
        if score.usage_percent > 100.0 && !score.protected {
            Some(OomKillReason::HardLimitExceeded {
                used: score.memory_bytes,
                limit: score.memory_limit,
            })
        } else {
            None
        }
    }

    /// Record a kill event
    pub fn record_kill(&mut self, pid: Pid, reason: OomKillReason) -> OomKillEvent {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let oom_score = self.scores.get(&pid).map(|s| s.final_score).unwrap_or(0);
        let memory_bytes = self.scores.get(&pid).map(|s| s.memory_bytes).unwrap_or(0);

        let event = OomKillEvent {
            timestamp: now,
            pid: pid.clone(),
            oom_score,
            memory_bytes,
            reason,
            signal: 9, // SIGKILL
        };

        self.kill_history.push(event.clone());
        self.scores.remove(&pid);
        event
    }

    /// Get kill history
    pub fn history(&self) -> &[OomKillEvent] {
        &self.kill_history
    }

    /// Enable/disable OOM killer
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

// =============================================================================
// Execution Time Limiter
// =============================================================================

/// Execution timeout configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTimeout {
    /// Soft timeout (warning)
    pub soft_ms: u64,
    /// Hard timeout (kill)
    pub hard_ms: u64,
    /// Grace period after soft timeout
    pub grace_ms: u64,
}

impl Default for ExecutionTimeout {
    fn default() -> Self {
        Self {
            soft_ms: 30_000,   // 30 seconds
            hard_ms: 300_000,  // 5 minutes
            grace_ms: 5_000,   // 5 seconds grace
        }
    }
}

/// Execution state
#[derive(Debug, Clone)]
pub struct ExecutionState {
    /// Agent PID
    pub pid: Pid,
    /// Operation ID
    pub operation_id: String,
    /// Start time
    pub started_at: Instant,
    /// Timeout configuration
    pub timeout: ExecutionTimeout,
    /// Soft timeout triggered
    pub soft_triggered: bool,
    /// Hard timeout triggered
    pub hard_triggered: bool,
}

impl ExecutionState {
    pub fn new(pid: Pid, operation_id: String, timeout: ExecutionTimeout) -> Self {
        Self {
            pid,
            operation_id,
            started_at: Instant::now(),
            timeout,
            soft_triggered: false,
            hard_triggered: false,
        }
    }

    /// Get elapsed time in milliseconds
    pub fn elapsed_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis() as u64
    }

    /// Check timeout status
    pub fn check_timeout(&mut self) -> TimeoutStatus {
        let elapsed = self.elapsed_ms();

        if elapsed >= self.timeout.hard_ms {
            self.hard_triggered = true;
            TimeoutStatus::HardTimeout
        } else if elapsed >= self.timeout.soft_ms && !self.soft_triggered {
            self.soft_triggered = true;
            TimeoutStatus::SoftTimeout
        } else if self.soft_triggered && elapsed >= self.timeout.soft_ms + self.timeout.grace_ms {
            self.hard_triggered = true;
            TimeoutStatus::GracePeriodExpired
        } else {
            TimeoutStatus::Running
        }
    }

    /// Get remaining time until hard timeout
    pub fn remaining_ms(&self) -> u64 {
        let elapsed = self.elapsed_ms();
        if elapsed >= self.timeout.hard_ms {
            0
        } else {
            self.timeout.hard_ms - elapsed
        }
    }
}

/// Timeout status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutStatus {
    /// Still running within limits
    Running,
    /// Soft timeout reached (warning)
    SoftTimeout,
    /// Grace period after soft timeout expired
    GracePeriodExpired,
    /// Hard timeout reached (kill)
    HardTimeout,
}

/// Execution Time Limiter — tracks and enforces execution time limits
#[derive(Debug, Default)]
pub struct ExecutionLimiter {
    /// Active executions by operation ID
    executions: HashMap<String, ExecutionState>,
    /// Timeout events
    timeout_events: Vec<TimeoutEvent>,
}

/// Timeout event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutEvent {
    pub timestamp: i64,
    pub pid: String,
    pub operation_id: String,
    pub elapsed_ms: u64,
    pub timeout_type: String, // "soft" or "hard"
    pub action_taken: String,
}

impl ExecutionLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start tracking an execution
    pub fn start(&mut self, pid: Pid, operation_id: String, timeout: ExecutionTimeout) {
        let state = ExecutionState::new(pid, operation_id.clone(), timeout);
        self.executions.insert(operation_id, state);
    }

    /// Complete an execution (remove from tracking)
    pub fn complete(&mut self, operation_id: &str) -> Option<Duration> {
        self.executions.remove(operation_id).map(|s| s.started_at.elapsed())
    }

    /// Check all executions for timeouts
    pub fn check_all(&mut self) -> Vec<(String, TimeoutStatus)> {
        let mut results = vec![];
        for (op_id, state) in self.executions.iter_mut() {
            let status = state.check_timeout();
            if status != TimeoutStatus::Running {
                results.push((op_id.clone(), status));
            }
        }
        results
    }

    /// Get execution state
    pub fn get(&self, operation_id: &str) -> Option<&ExecutionState> {
        self.executions.get(operation_id)
    }

    /// Record timeout event
    pub fn record_timeout(&mut self, operation_id: &str, timeout_type: &str, action: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        if let Some(state) = self.executions.get(operation_id) {
            self.timeout_events.push(TimeoutEvent {
                timestamp: now,
                pid: state.pid.clone(),
                operation_id: operation_id.to_string(),
                elapsed_ms: state.elapsed_ms(),
                timeout_type: timeout_type.to_string(),
                action_taken: action.to_string(),
            });
        }
    }

    /// Get timeout history
    pub fn history(&self) -> &[TimeoutEvent] {
        &self.timeout_events
    }

    /// Get active execution count
    pub fn active_count(&self) -> usize {
        self.executions.len()
    }
}

// =============================================================================
// Throttler
// =============================================================================

/// Throttle level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThrottleLevel {
    /// No throttling
    None,
    /// Light throttling (10% slowdown)
    Light,
    /// Medium throttling (50% slowdown)
    Medium,
    /// Heavy throttling (90% slowdown)
    Heavy,
    /// Blocked (100% - no operations allowed)
    Blocked,
}

impl ThrottleLevel {
    /// Get delay multiplier (1.0 = no delay)
    pub fn delay_multiplier(&self) -> f32 {
        match self {
            Self::None => 1.0,
            Self::Light => 1.1,
            Self::Medium => 2.0,
            Self::Heavy => 10.0,
            Self::Blocked => f32::INFINITY,
        }
    }

    /// Get delay in milliseconds for a base operation time
    pub fn delay_ms(&self, base_ms: u64) -> u64 {
        match self {
            Self::None => 0,
            Self::Light => base_ms / 10,
            Self::Medium => base_ms,
            Self::Heavy => base_ms * 9,
            Self::Blocked => u64::MAX,
        }
    }
}

/// Throttle state for an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleState {
    pub pid: Pid,
    pub level: ThrottleLevel,
    pub reason: String,
    pub started_at: i64,
    pub expires_at: Option<i64>,
    pub operations_delayed: u64,
    pub total_delay_ms: u64,
}

impl ThrottleState {
    pub fn new(pid: Pid, level: ThrottleLevel, reason: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            pid,
            level,
            reason,
            started_at: now,
            expires_at: None,
            operations_delayed: 0,
            total_delay_ms: 0,
        }
    }

    pub fn with_expiry(mut self, duration_ms: i64) -> Self {
        self.expires_at = Some(self.started_at + duration_ms);
        self
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            now > expires
        } else {
            false
        }
    }
}

/// Throttler — implements gradual throttling based on resource usage
#[derive(Debug, Default)]
pub struct Throttler {
    /// Throttle states by PID
    states: HashMap<Pid, ThrottleState>,
    /// Thresholds for auto-throttling (usage percent -> level)
    thresholds: ThrottleThresholds,
}

/// Throttle thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleThresholds {
    /// Light throttle at this usage percent
    pub light: f32,
    /// Medium throttle at this usage percent
    pub medium: f32,
    /// Heavy throttle at this usage percent
    pub heavy: f32,
    /// Block at this usage percent
    pub block: f32,
}

impl Default for ThrottleThresholds {
    fn default() -> Self {
        Self {
            light: 70.0,
            medium: 85.0,
            heavy: 95.0,
            block: 100.0,
        }
    }
}

impl Throttler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_thresholds(thresholds: ThrottleThresholds) -> Self {
        Self {
            states: HashMap::new(),
            thresholds,
        }
    }

    /// Compute throttle level based on usage
    pub fn compute_level(&self, usage_percent: f32) -> ThrottleLevel {
        if usage_percent >= self.thresholds.block {
            ThrottleLevel::Blocked
        } else if usage_percent >= self.thresholds.heavy {
            ThrottleLevel::Heavy
        } else if usage_percent >= self.thresholds.medium {
            ThrottleLevel::Medium
        } else if usage_percent >= self.thresholds.light {
            ThrottleLevel::Light
        } else {
            ThrottleLevel::None
        }
    }

    /// Update throttle state for an agent
    pub fn update(&mut self, pid: Pid, usage: &ResourceUsage, contract: &AgentHardwareContract) {
        let soft_limit = contract.resource_limits.memory_bytes.soft.value().unwrap_or(u64::MAX);
        let usage_percent = if soft_limit > 0 {
            (usage.memory_bytes as f64 / soft_limit as f64 * 100.0) as f32
        } else {
            0.0
        };

        let level = self.compute_level(usage_percent);
        
        if level == ThrottleLevel::None {
            self.states.remove(&pid);
        } else {
            let reason = format!("Memory usage at {:.1}% of soft limit", usage_percent);
            let state = ThrottleState::new(pid.clone(), level, reason);
            self.states.insert(pid, state);
        }
    }

    /// Set manual throttle
    pub fn set_throttle(&mut self, pid: Pid, level: ThrottleLevel, reason: String, duration_ms: Option<i64>) {
        let mut state = ThrottleState::new(pid.clone(), level, reason);
        if let Some(dur) = duration_ms {
            state = state.with_expiry(dur);
        }
        self.states.insert(pid, state);
    }

    /// Remove throttle
    pub fn remove(&mut self, pid: &Pid) {
        self.states.remove(pid);
    }

    /// Get throttle state
    pub fn get(&self, pid: &Pid) -> Option<&ThrottleState> {
        self.states.get(pid)
    }

    /// Get throttle level
    pub fn level(&self, pid: &Pid) -> ThrottleLevel {
        self.states.get(pid).map(|s| s.level).unwrap_or(ThrottleLevel::None)
    }

    /// Check if operation should proceed (returns delay in ms, or None if blocked)
    pub fn check_operation(&mut self, pid: &Pid, base_delay_ms: u64) -> Option<u64> {
        // Clean up expired throttles
        if let Some(state) = self.states.get(pid) {
            if state.is_expired() {
                self.states.remove(pid);
                return Some(0);
            }
        }

        match self.states.get_mut(pid) {
            None => Some(0),
            Some(state) => {
                if state.level == ThrottleLevel::Blocked {
                    None
                } else {
                    let delay = state.level.delay_ms(base_delay_ms);
                    state.operations_delayed += 1;
                    state.total_delay_ms += delay;
                    Some(delay)
                }
            }
        }
    }

    /// Get all throttled agents
    pub fn throttled_agents(&self) -> Vec<&ThrottleState> {
        self.states.values().collect()
    }
}

// =============================================================================
// Resource Enforcer (Combined)
// =============================================================================

/// Resource Enforcer — combines OOM killer, execution limiter, and throttler
#[derive(Debug, Default)]
pub struct ResourceEnforcer {
    pub oom_killer: OomKiller,
    pub execution_limiter: ExecutionLimiter,
    pub throttler: Throttler,
}

impl ResourceEnforcer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update all enforcement state for an agent
    pub fn update(&mut self, pid: Pid, usage: &ResourceUsage, contract: &AgentHardwareContract) {
        self.oom_killer.update_score(pid.clone(), usage, contract);
        self.throttler.update(pid, usage, contract);
    }

    /// Check all limits and return required actions
    pub fn check_limits(&mut self, pid: &Pid, usage: &ResourceUsage, contract: &AgentHardwareContract) -> Vec<EnforcementAction> {
        let mut actions = vec![];

        // Check OOM
        if contract.oom_killer_enabled {
            if let Some(reason) = self.oom_killer.should_kill(pid) {
                actions.push(EnforcementAction::Kill {
                    pid: pid.clone(),
                    reason: format!("{:?}", reason),
                    signal: 9,
                });
            }
        }

        // Check resource limit violations
        let violations = usage.check_limits(contract);
        for v in violations {
            let action = match v.severity {
                ViolationSeverity::Soft => match contract.soft_limit_action {
                    LimitAction::Warn => EnforcementAction::Warn {
                        pid: pid.clone(),
                        resource: v.resource,
                        message: format!("Soft limit exceeded: {} / {:?}", v.current, v.soft_limit),
                    },
                    LimitAction::Throttle => EnforcementAction::Throttle {
                        pid: pid.clone(),
                        level: ThrottleLevel::Light,
                        reason: v.resource,
                    },
                    LimitAction::Suspend => EnforcementAction::Suspend { pid: pid.clone() },
                    LimitAction::Terminate => EnforcementAction::Terminate { pid: pid.clone() },
                    LimitAction::Signal => EnforcementAction::Signal { pid: pid.clone(), signal: 15 },
                },
                ViolationSeverity::Hard => match contract.hard_limit_action {
                    LimitAction::Warn => EnforcementAction::Warn {
                        pid: pid.clone(),
                        resource: v.resource,
                        message: format!("Hard limit exceeded: {} / {:?}", v.current, v.hard_limit),
                    },
                    LimitAction::Throttle => EnforcementAction::Throttle {
                        pid: pid.clone(),
                        level: ThrottleLevel::Heavy,
                        reason: v.resource,
                    },
                    LimitAction::Suspend => EnforcementAction::Suspend { pid: pid.clone() },
                    LimitAction::Terminate => EnforcementAction::Terminate { pid: pid.clone() },
                    LimitAction::Signal => EnforcementAction::Signal { pid: pid.clone(), signal: 9 },
                },
            };
            actions.push(action);
        }

        actions
    }

    /// Remove agent from all tracking
    pub fn remove(&mut self, pid: &Pid) {
        self.oom_killer.remove(pid);
        self.throttler.remove(pid);
    }
}

/// Enforcement action to take
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnforcementAction {
    /// Log warning
    Warn { pid: Pid, resource: String, message: String },
    /// Apply throttling
    Throttle { pid: Pid, level: ThrottleLevel, reason: String },
    /// Suspend agent
    Suspend { pid: Pid },
    /// Terminate agent gracefully
    Terminate { pid: Pid },
    /// Send signal
    Signal { pid: Pid, signal: i32 },
    /// Kill agent immediately
    Kill { pid: Pid, reason: String, signal: i32 },
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oom_score() {
        let score = OomScore::compute(
            "pid:001".to_string(),
            800_000_000, // 800MB
            1_000_000_000, // 1GB limit
            0,
        );
        assert_eq!(score.usage_percent, 80.0);
        assert_eq!(score.score, 800);
        assert!(!score.protected);
    }

    #[test]
    fn test_oom_protected() {
        let score = OomScore::compute(
            "pid:001".to_string(),
            800_000_000,
            1_000_000_000,
            -950, // Protected
        );
        assert!(score.protected);
        assert!(score.final_score < 0 || score.final_score == 0);
    }

    #[test]
    fn test_throttle_levels() {
        let throttler = Throttler::new();
        
        assert_eq!(throttler.compute_level(50.0), ThrottleLevel::None);
        assert_eq!(throttler.compute_level(75.0), ThrottleLevel::Light);
        assert_eq!(throttler.compute_level(90.0), ThrottleLevel::Medium);
        assert_eq!(throttler.compute_level(97.0), ThrottleLevel::Heavy);
        assert_eq!(throttler.compute_level(100.0), ThrottleLevel::Blocked);
    }

    #[test]
    fn test_execution_timeout() {
        let timeout = ExecutionTimeout {
            soft_ms: 100,
            hard_ms: 200,
            grace_ms: 50,
        };
        let mut state = ExecutionState::new(
            "pid:001".to_string(),
            "op:001".to_string(),
            timeout,
        );

        // Initially running
        assert_eq!(state.check_timeout(), TimeoutStatus::Running);
    }

    #[test]
    fn test_throttle_delay() {
        assert_eq!(ThrottleLevel::None.delay_ms(100), 0);
        assert_eq!(ThrottleLevel::Light.delay_ms(100), 10);
        assert_eq!(ThrottleLevel::Medium.delay_ms(100), 100);
        assert_eq!(ThrottleLevel::Heavy.delay_ms(100), 900);
    }
}
