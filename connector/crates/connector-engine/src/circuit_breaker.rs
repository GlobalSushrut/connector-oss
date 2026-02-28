//! Circuit Breaker — Layer 4 Rate & State Guard for the 5-Layer Guard Pipeline.
//!
//! Per-agent deterministic state machine: Closed → Open → HalfOpen.
//! Prevents cascading failures across agents (OWASP ASI08).
//!
//! Research: Netflix Hystrix pattern, OWASP ASI08 (Cascading Failures),
//! NIST AI RMF MANAGE, Resilience4j

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Circuit State
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    /// Normal — all requests evaluated by full pipeline
    Closed,
    /// Tripped — all requests IMMEDIATELY DENIED (no pipeline evaluation)
    Open,
    /// Recovery — limited probe requests allowed
    HalfOpen,
}

/// Per-agent circuit breaker with deterministic state transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreaker {
    pub state: CircuitState,
    pub failure_count: u32,
    pub failure_threshold: u32,
    pub reset_timeout_ms: i64,
    pub half_open_max_probes: u32,
    pub half_open_success_count: u32,
    pub half_open_probe_count: u32,
    pub last_failure_ms: i64,
    pub last_state_change_ms: i64,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, reset_timeout_ms: i64, half_open_max_probes: u32) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            failure_threshold,
            reset_timeout_ms,
            half_open_max_probes,
            half_open_success_count: 0,
            half_open_probe_count: 0,
            last_failure_ms: 0,
            last_state_change_ms: 0,
        }
    }

    /// Check if a request should be allowed through the circuit breaker.
    /// Returns true if allowed, false if circuit is Open and request should be denied.
    pub fn should_allow(&mut self, now_ms: i64) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if reset timeout has elapsed → transition to HalfOpen
                if now_ms - self.last_failure_ms >= self.reset_timeout_ms {
                    self.state = CircuitState::HalfOpen;
                    self.half_open_success_count = 0;
                    self.half_open_probe_count = 0;
                    self.last_state_change_ms = now_ms;
                    true // Allow first probe
                } else {
                    false // Still open, deny
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited probe requests
                self.half_open_probe_count < self.half_open_max_probes
            }
        }
    }

    /// Record a successful request outcome.
    pub fn record_success(&mut self, now_ms: i64) {
        match self.state {
            CircuitState::Closed => {
                self.failure_count = 0; // Reset on success
            }
            CircuitState::HalfOpen => {
                self.half_open_success_count += 1;
                self.half_open_probe_count += 1;
                // All probes passed → close circuit
                if self.half_open_success_count >= self.half_open_max_probes {
                    self.state = CircuitState::Closed;
                    self.failure_count = 0;
                    self.last_state_change_ms = now_ms;
                }
            }
            CircuitState::Open => {} // Shouldn't happen, but safe to ignore
        }
    }

    /// Record a failed request outcome (guard denial).
    pub fn record_failure(&mut self, now_ms: i64) {
        self.last_failure_ms = now_ms;
        match self.state {
            CircuitState::Closed => {
                self.failure_count += 1;
                if self.failure_count >= self.failure_threshold {
                    self.state = CircuitState::Open;
                    self.last_state_change_ms = now_ms;
                }
            }
            CircuitState::HalfOpen => {
                // Any failure during HalfOpen → re-open
                self.state = CircuitState::Open;
                self.last_state_change_ms = now_ms;
            }
            CircuitState::Open => {} // Already open
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Circuit Breaker Manager — per-agent breakers
// ═══════════════════════════════════════════════════════════════

/// Manages per-agent circuit breakers.
pub struct CircuitBreakerManager {
    breakers: HashMap<String, CircuitBreaker>,
    default_failure_threshold: u32,
    default_reset_timeout_ms: i64,
    default_half_open_probes: u32,
}

impl CircuitBreakerManager {
    pub fn new() -> Self {
        Self {
            breakers: HashMap::new(),
            default_failure_threshold: 5,
            default_reset_timeout_ms: 30_000,
            default_half_open_probes: 3,
        }
    }

    pub fn with_defaults(failure_threshold: u32, reset_timeout_ms: i64, half_open_probes: u32) -> Self {
        Self {
            breakers: HashMap::new(),
            default_failure_threshold: failure_threshold,
            default_reset_timeout_ms: reset_timeout_ms,
            default_half_open_probes: half_open_probes,
        }
    }

    /// Check if a request from agent_pid should be allowed.
    pub fn should_allow(&mut self, agent_pid: &str, now_ms: i64) -> bool {
        let breaker = self.breakers.entry(agent_pid.to_string()).or_insert_with(|| {
            CircuitBreaker::new(
                self.default_failure_threshold,
                self.default_reset_timeout_ms,
                self.default_half_open_probes,
            )
        });
        breaker.should_allow(now_ms)
    }

    /// Record a successful outcome for an agent.
    pub fn record_success(&mut self, agent_pid: &str, now_ms: i64) {
        if let Some(breaker) = self.breakers.get_mut(agent_pid) {
            breaker.record_success(now_ms);
        }
    }

    /// Record a failure (guard denial) for an agent.
    pub fn record_failure(&mut self, agent_pid: &str, now_ms: i64) {
        let breaker = self.breakers.entry(agent_pid.to_string()).or_insert_with(|| {
            CircuitBreaker::new(
                self.default_failure_threshold,
                self.default_reset_timeout_ms,
                self.default_half_open_probes,
            )
        });
        breaker.record_failure(now_ms);
    }

    /// Get the current state of an agent's circuit breaker.
    pub fn get_state(&self, agent_pid: &str) -> Option<CircuitState> {
        self.breakers.get(agent_pid).map(|b| b.state)
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_closed_allows_requests() {
        let mut cb = CircuitBreaker::new(5, 30_000, 3);
        assert!(cb.should_allow(1000));
        assert_eq!(cb.state, CircuitState::Closed);
    }

    #[test]
    fn test_closed_to_open_on_threshold() {
        let mut cb = CircuitBreaker::new(3, 30_000, 3);
        for i in 0..3 {
            cb.record_failure(1000 + i);
        }
        assert_eq!(cb.state, CircuitState::Open);
        assert!(!cb.should_allow(1005));
    }

    #[test]
    fn test_open_to_half_open_after_timeout() {
        let mut cb = CircuitBreaker::new(3, 1000, 3);
        for i in 0..3 { cb.record_failure(100 + i); }
        assert_eq!(cb.state, CircuitState::Open);
        // After timeout, should transition to HalfOpen
        assert!(cb.should_allow(1200));
        assert_eq!(cb.state, CircuitState::HalfOpen);
    }

    #[test]
    fn test_half_open_to_closed_on_success() {
        let mut cb = CircuitBreaker::new(3, 100, 2);
        for i in 0..3 { cb.record_failure(100 + i); }
        // Transition to HalfOpen
        cb.should_allow(300);
        assert_eq!(cb.state, CircuitState::HalfOpen);
        // Two successful probes → Closed
        cb.record_success(301);
        assert_eq!(cb.state, CircuitState::HalfOpen); // Not yet, need 2
        cb.record_success(302);
        assert_eq!(cb.state, CircuitState::Closed);
    }

    #[test]
    fn test_half_open_to_open_on_failure() {
        let mut cb = CircuitBreaker::new(3, 100, 3);
        for i in 0..3 { cb.record_failure(100 + i); }
        cb.should_allow(300); // → HalfOpen
        assert_eq!(cb.state, CircuitState::HalfOpen);
        cb.record_failure(301); // Any failure → re-Open
        assert_eq!(cb.state, CircuitState::Open);
    }

    #[test]
    fn test_success_resets_failure_count() {
        let mut cb = CircuitBreaker::new(5, 30_000, 3);
        cb.record_failure(100);
        cb.record_failure(101);
        assert_eq!(cb.failure_count, 2);
        cb.record_success(102); // Reset
        assert_eq!(cb.failure_count, 0);
    }

    #[test]
    fn test_manager_per_agent_isolation() {
        let mut mgr = CircuitBreakerManager::with_defaults(2, 1000, 2);
        // Agent A failures
        mgr.record_failure("agent_a", 100);
        mgr.record_failure("agent_a", 101);
        // Agent A circuit should be open
        assert!(!mgr.should_allow("agent_a", 102));
        // Agent B should be unaffected
        assert!(mgr.should_allow("agent_b", 102));
    }
}
