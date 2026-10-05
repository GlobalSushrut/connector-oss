//! Policy Gate — authorization for every capability request.
//!
//! Risk escalation: Low → rate-limit only, Medium → token required,
//! High → explicit token + logged, Critical → HITL + SCITT.

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::capability::RiskLevel;

/// Policy decision for a capability request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
    RequireApproval { reason: String },
    Defer { reason: String },
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }
}

/// A capability request to be evaluated by policy.
#[derive(Debug, Clone)]
pub struct CapRequest {
    pub agent_pid: String,
    pub capability_id: String,
    pub risk: RiskLevel,
    pub has_token: bool,
    pub token_expired: bool,
}

/// Trait for policy evaluation.
pub trait Policy: Send + Sync {
    fn evaluate(&self, request: &CapRequest) -> PolicyDecision;
}

/// Default policy implementing risk escalation.
pub struct DefaultPolicy {
    /// Rate limiters: (agent_pid, capability_id) → (count, window_start)
    rate_limits: std::sync::Mutex<HashMap<(String, String), (u32, Instant)>>,
    /// Max requests per minute per (agent, capability) pair
    rate_limit_per_minute: u32,
}

impl DefaultPolicy {
    pub fn new() -> Self {
        Self {
            rate_limits: std::sync::Mutex::new(HashMap::new()),
            rate_limit_per_minute: 60,
        }
    }

    pub fn with_rate_limit(mut self, per_minute: u32) -> Self {
        self.rate_limit_per_minute = per_minute;
        self
    }

    fn check_rate_limit(&self, agent_pid: &str, capability_id: &str) -> bool {
        let key = (agent_pid.to_string(), capability_id.to_string());
        let mut limits = self.rate_limits.lock().unwrap();
        let now = Instant::now();

        let entry = limits.entry(key).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() >= 60 {
            *entry = (1, now);
            return true;
        }
        entry.0 += 1;
        entry.0 <= self.rate_limit_per_minute
    }
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl Policy for DefaultPolicy {
    fn evaluate(&self, request: &CapRequest) -> PolicyDecision {
        // Check expired tokens
        if request.has_token && request.token_expired {
            return PolicyDecision::Deny {
                reason: "Token expired".to_string(),
            };
        }

        // Risk escalation
        match request.risk {
            RiskLevel::Low => {
                // Rate limit only
                if !self.check_rate_limit(&request.agent_pid, &request.capability_id) {
                    return PolicyDecision::Deny {
                        reason: "Rate limit exceeded".to_string(),
                    };
                }
                PolicyDecision::Allow
            }
            RiskLevel::Medium => {
                if !request.has_token {
                    return PolicyDecision::Deny {
                        reason: "Token required for medium-risk capability".to_string(),
                    };
                }
                if !self.check_rate_limit(&request.agent_pid, &request.capability_id) {
                    return PolicyDecision::Deny {
                        reason: "Rate limit exceeded".to_string(),
                    };
                }
                PolicyDecision::Allow
            }
            RiskLevel::High => {
                if !request.has_token {
                    return PolicyDecision::Deny {
                        reason: "Explicit token required for high-risk capability".to_string(),
                    };
                }
                PolicyDecision::Allow
            }
            RiskLevel::Critical => {
                PolicyDecision::RequireApproval {
                    reason: "Critical-risk capability requires human-in-the-loop approval".to_string(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(risk: RiskLevel, has_token: bool) -> CapRequest {
        CapRequest {
            agent_pid: "agent-1".to_string(),
            capability_id: "test.cap".to_string(),
            risk,
            has_token,
            token_expired: false,
        }
    }

    #[test]
    fn test_policy_low_risk_allowed() {
        let policy = DefaultPolicy::new();
        let decision = policy.evaluate(&make_request(RiskLevel::Low, false));
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_policy_medium_without_token_denied() {
        let policy = DefaultPolicy::new();
        let decision = policy.evaluate(&make_request(RiskLevel::Medium, false));
        assert!(!decision.is_allowed());
    }

    #[test]
    fn test_policy_medium_with_token_allowed() {
        let policy = DefaultPolicy::new();
        let decision = policy.evaluate(&make_request(RiskLevel::Medium, true));
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_policy_high_without_token_denied() {
        let policy = DefaultPolicy::new();
        let decision = policy.evaluate(&make_request(RiskLevel::High, false));
        assert!(!decision.is_allowed());
    }

    #[test]
    fn test_policy_high_with_token_allowed() {
        let policy = DefaultPolicy::new();
        let decision = policy.evaluate(&make_request(RiskLevel::High, true));
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_policy_critical_requires_approval() {
        let policy = DefaultPolicy::new();
        let decision = policy.evaluate(&make_request(RiskLevel::Critical, true));
        assert!(matches!(decision, PolicyDecision::RequireApproval { .. }));
    }

    #[test]
    fn test_policy_expired_token_denied() {
        let policy = DefaultPolicy::new();
        let mut req = make_request(RiskLevel::Medium, true);
        req.token_expired = true;
        let decision = policy.evaluate(&req);
        assert!(!decision.is_allowed());
    }

    #[test]
    fn test_policy_rate_limit() {
        let policy = DefaultPolicy::new().with_rate_limit(3);
        let req = make_request(RiskLevel::Low, false);

        assert!(policy.evaluate(&req).is_allowed());
        assert!(policy.evaluate(&req).is_allowed());
        assert!(policy.evaluate(&req).is_allowed());
        // 4th should be denied
        assert!(!policy.evaluate(&req).is_allowed());
    }
}
