//! Policy decision types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result of policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Whether the action is allowed
    pub allowed: bool,
    /// Decision type
    pub decision: DecisionType,
    /// Reason for the decision
    pub reason: String,
    /// Rules that matched
    pub matched_rules: Vec<MatchedRule>,
    /// Required approvals (if any)
    pub required_approvals: Vec<ApprovalRequirement>,
    /// Obligations to fulfill
    pub obligations: Vec<Obligation>,
    /// Advice/recommendations
    pub advice: Vec<String>,
    /// Decision timestamp
    pub timestamp: DateTime<Utc>,
    /// Decision ID for audit
    pub decision_id: String,
}

impl PolicyDecision {
    /// Create an allow decision
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            allowed: true,
            decision: DecisionType::Allow,
            reason: reason.into(),
            matched_rules: vec![],
            required_approvals: vec![],
            obligations: vec![],
            advice: vec![],
            timestamp: Utc::now(),
            decision_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Create a deny decision
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            decision: DecisionType::Deny,
            reason: reason.into(),
            matched_rules: vec![],
            required_approvals: vec![],
            obligations: vec![],
            advice: vec![],
            timestamp: Utc::now(),
            decision_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Create a pending approval decision
    pub fn pending_approval(reason: impl Into<String>, approvals: Vec<ApprovalRequirement>) -> Self {
        Self {
            allowed: false,
            decision: DecisionType::PendingApproval,
            reason: reason.into(),
            matched_rules: vec![],
            required_approvals: approvals,
            obligations: vec![],
            advice: vec![],
            timestamp: Utc::now(),
            decision_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Add a matched rule
    pub fn with_matched_rule(mut self, rule: MatchedRule) -> Self {
        self.matched_rules.push(rule);
        self
    }

    /// Add an obligation
    pub fn with_obligation(mut self, obligation: Obligation) -> Self {
        self.obligations.push(obligation);
        self
    }

    /// Add advice
    pub fn with_advice(mut self, advice: impl Into<String>) -> Self {
        self.advice.push(advice.into());
        self
    }

    /// Check if approval is required
    pub fn requires_approval(&self) -> bool {
        !self.required_approvals.is_empty()
    }

    /// Check if there are obligations
    pub fn has_obligations(&self) -> bool {
        !self.obligations.is_empty()
    }
}

/// Type of decision
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionType {
    /// Action is allowed
    Allow,
    /// Action is denied
    Deny,
    /// Action requires approval
    PendingApproval,
    /// No applicable policy (default deny)
    NotApplicable,
    /// Error during evaluation
    Error,
}

/// A rule that matched during evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRule {
    /// Rule ID
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Rule effect (allow/deny)
    pub effect: RuleEffect,
    /// Priority
    pub priority: i32,
    /// Conditions that matched
    pub matched_conditions: Vec<String>,
}

/// Rule effect
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleEffect {
    Allow,
    Deny,
    RequireApproval,
}

/// Approval requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequirement {
    /// Approval ID
    pub approval_id: String,
    /// Type of approval
    pub approval_type: ApprovalType,
    /// Required approvers
    pub approvers: Vec<String>,
    /// Minimum approvals needed
    pub min_approvals: u32,
    /// Approval timeout in seconds
    pub timeout_secs: Option<u64>,
    /// Reason for requiring approval
    pub reason: String,
}

impl ApprovalRequirement {
    pub fn new(approval_type: ApprovalType, reason: impl Into<String>) -> Self {
        Self {
            approval_id: uuid::Uuid::new_v4().to_string(),
            approval_type,
            approvers: vec![],
            min_approvals: 1,
            timeout_secs: None,
            reason: reason.into(),
        }
    }

    pub fn with_approvers(mut self, approvers: Vec<String>) -> Self {
        self.approvers = approvers;
        self
    }

    pub fn with_min_approvals(mut self, min: u32) -> Self {
        self.min_approvals = min;
        self
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = Some(timeout_secs);
        self
    }
}

/// Type of approval
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalType {
    /// Human approval required
    Human,
    /// Manager approval required
    Manager,
    /// Security team approval
    Security,
    /// Multi-party approval
    MultiParty,
    /// Automated approval (e.g., based on risk score)
    Automated,
}

/// Obligation to fulfill after action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Obligation {
    /// Obligation ID
    pub obligation_id: String,
    /// Obligation type
    pub obligation_type: ObligationType,
    /// Obligation parameters
    pub parameters: HashMap<String, serde_json::Value>,
    /// When to fulfill (before/after action)
    pub timing: ObligationTiming,
    /// Whether obligation is mandatory
    pub mandatory: bool,
}

impl Obligation {
    pub fn new(obligation_type: ObligationType, timing: ObligationTiming) -> Self {
        Self {
            obligation_id: uuid::Uuid::new_v4().to_string(),
            obligation_type,
            parameters: HashMap::new(),
            timing,
            mandatory: true,
        }
    }

    pub fn with_parameter(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.parameters.insert(key.into(), value);
        self
    }

    pub fn optional(mut self) -> Self {
        self.mandatory = false;
        self
    }
}

/// Type of obligation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationType {
    /// Log the action
    Log,
    /// Notify someone
    Notify,
    /// Encrypt data
    Encrypt,
    /// Redact sensitive data
    Redact,
    /// Rate limit
    RateLimit,
    /// Custom obligation
    Custom(String),
}

/// When to fulfill obligation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObligationTiming {
    Before,
    After,
    Both,
}

/// Approval status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalStatus {
    /// Approval requirement ID
    pub approval_id: String,
    /// Current status
    pub status: ApprovalState,
    /// Approvals received
    pub approvals: Vec<Approval>,
    /// Rejections received
    pub rejections: Vec<Rejection>,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Expires at
    pub expires_at: Option<DateTime<Utc>>,
}

/// Approval state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Approved,
    Rejected,
    Expired,
    Cancelled,
}

/// An approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// Approver ID
    pub approver: String,
    /// Approval timestamp
    pub approved_at: DateTime<Utc>,
    /// Optional comment
    pub comment: Option<String>,
}

/// A rejection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rejection {
    /// Rejector ID
    pub rejector: String,
    /// Rejection timestamp
    pub rejected_at: DateTime<Utc>,
    /// Reason for rejection
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_decision() {
        let decision = PolicyDecision::allow("Action permitted by default policy");
        assert!(decision.allowed);
        assert_eq!(decision.decision, DecisionType::Allow);
    }

    #[test]
    fn test_deny_decision() {
        let decision = PolicyDecision::deny("Action denied by security policy");
        assert!(!decision.allowed);
        assert_eq!(decision.decision, DecisionType::Deny);
    }

    #[test]
    fn test_pending_approval() {
        let approval = ApprovalRequirement::new(
            ApprovalType::Human,
            "High-risk action requires approval",
        )
        .with_approvers(vec!["manager@example.com".to_string()])
        .with_timeout(3600);

        let decision = PolicyDecision::pending_approval(
            "Approval required",
            vec![approval],
        );

        assert!(!decision.allowed);
        assert!(decision.requires_approval());
        assert_eq!(decision.required_approvals.len(), 1);
    }

    #[test]
    fn test_obligation() {
        let obligation = Obligation::new(ObligationType::Log, ObligationTiming::After)
            .with_parameter("level", serde_json::json!("info"));

        let decision = PolicyDecision::allow("Allowed with logging")
            .with_obligation(obligation);

        assert!(decision.has_obligations());
    }
}
