//! Rule definitions for MetaRules

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::decision::{RuleEffect, ApprovalType, ApprovalRequirement};

/// A policy containing multiple rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy ID
    pub id: String,
    /// Policy name
    pub name: String,
    /// Policy description
    pub description: Option<String>,
    /// Policy version
    pub version: String,
    /// Rules in this policy
    pub rules: Vec<Rule>,
    /// Default effect if no rules match
    pub default_effect: RuleEffect,
    /// Policy priority (higher = evaluated first)
    pub priority: i32,
    /// Whether policy is enabled
    pub enabled: bool,
}

impl Policy {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            version: "1.0.0".to_string(),
            rules: vec![],
            default_effect: RuleEffect::Deny,
            priority: 0,
            enabled: true,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn with_rule(mut self, rule: Rule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn with_default_allow(mut self) -> Self {
        self.default_effect = RuleEffect::Allow;
        self
    }

    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// A single rule in a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Rule ID
    pub id: String,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: Option<String>,
    /// Conditions that must match
    pub conditions: Vec<Condition>,
    /// Effect if conditions match
    pub effect: RuleEffect,
    /// Rule priority within policy
    pub priority: i32,
    /// Approval requirements (if effect is RequireApproval)
    pub approval_config: Option<ApprovalConfig>,
    /// Whether rule is enabled
    pub enabled: bool,
}

impl Rule {
    pub fn new(id: impl Into<String>, name: impl Into<String>, effect: RuleEffect) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            conditions: vec![],
            effect,
            priority: 0,
            approval_config: None,
            enabled: true,
        }
    }

    pub fn allow(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(id, name, RuleEffect::Allow)
    }

    pub fn deny(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(id, name, RuleEffect::Deny)
    }

    pub fn require_approval(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(id, name, RuleEffect::RequireApproval)
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.conditions.push(condition);
        self
    }

    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_approval_config(mut self, config: ApprovalConfig) -> Self {
        self.approval_config = Some(config);
        self
    }

    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// Approval configuration for rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalConfig {
    /// Type of approval
    pub approval_type: ApprovalType,
    /// Required approvers (principals or roles)
    pub approvers: Vec<String>,
    /// Minimum approvals needed
    pub min_approvals: u32,
    /// Timeout in seconds
    pub timeout_secs: u64,
    /// Reason template
    pub reason_template: String,
}

impl ApprovalConfig {
    pub fn new(approval_type: ApprovalType) -> Self {
        Self {
            approval_type,
            approvers: vec![],
            min_approvals: 1,
            timeout_secs: 3600,
            reason_template: "Approval required".to_string(),
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
        self.timeout_secs = timeout_secs;
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason_template = reason.into();
        self
    }

    /// Convert to ApprovalRequirement
    pub fn to_requirement(&self) -> ApprovalRequirement {
        ApprovalRequirement::new(self.approval_type, &self.reason_template)
            .with_approvers(self.approvers.clone())
            .with_min_approvals(self.min_approvals)
            .with_timeout(self.timeout_secs)
    }
}

/// A condition to evaluate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    /// Condition type
    pub condition_type: ConditionType,
    /// Field to evaluate
    pub field: String,
    /// Operator
    pub operator: Operator,
    /// Value to compare against
    pub value: serde_json::Value,
}

impl Condition {
    pub fn new(condition_type: ConditionType, field: impl Into<String>, operator: Operator, value: serde_json::Value) -> Self {
        Self {
            condition_type,
            field: field.into(),
            operator,
            value,
        }
    }

    /// Actor condition
    pub fn actor(operator: Operator, value: impl Into<String>) -> Self {
        Self::new(
            ConditionType::Actor,
            "pid",
            operator,
            serde_json::json!(value.into()),
        )
    }

    /// Action condition
    pub fn action(operator: Operator, value: impl Into<String>) -> Self {
        Self::new(
            ConditionType::Action,
            "action",
            operator,
            serde_json::json!(value.into()),
        )
    }

    /// Resource condition
    pub fn resource(operator: Operator, value: impl Into<String>) -> Self {
        Self::new(
            ConditionType::Resource,
            "rid",
            operator,
            serde_json::json!(value.into()),
        )
    }

    /// Time condition
    pub fn time(field: impl Into<String>, operator: Operator, value: impl Into<String>) -> Self {
        Self::new(
            ConditionType::Time,
            field,
            operator,
            serde_json::json!(value.into()),
        )
    }

    /// Environment condition
    pub fn environment(operator: Operator, value: impl Into<String>) -> Self {
        Self::new(
            ConditionType::Environment,
            "environment",
            operator,
            serde_json::json!(value.into()),
        )
    }

    /// Custom attribute condition
    pub fn attribute(field: impl Into<String>, operator: Operator, value: serde_json::Value) -> Self {
        Self::new(ConditionType::Attribute, field, operator, value)
    }
}

/// Type of condition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionType {
    /// Condition on actor
    Actor,
    /// Condition on action
    Action,
    /// Condition on resource
    Resource,
    /// Condition on time
    Time,
    /// Condition on environment
    Environment,
    /// Condition on geographic location
    Geo,
    /// Condition on session
    Session,
    /// Condition on custom attribute
    Attribute,
}

/// Comparison operator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    /// Equals
    Eq,
    /// Not equals
    Ne,
    /// Greater than
    Gt,
    /// Greater than or equal
    Gte,
    /// Less than
    Lt,
    /// Less than or equal
    Lte,
    /// Contains (for strings/arrays)
    Contains,
    /// Starts with
    StartsWith,
    /// Ends with
    EndsWith,
    /// Matches regex
    Matches,
    /// In list
    In,
    /// Not in list
    NotIn,
    /// Exists (field is present)
    Exists,
    /// Not exists
    NotExists,
}

/// Predefined rule templates
pub mod templates {
    use super::*;

    /// Deny all actions in production without MFA
    pub fn require_mfa_in_production() -> Rule {
        Rule::deny("require-mfa-prod", "Require MFA in Production")
            .with_description("Deny actions in production environment without MFA verification")
            .with_condition(Condition::environment(Operator::Eq, "production"))
            .with_condition(Condition::new(
                ConditionType::Session,
                "mfa_verified",
                Operator::Eq,
                serde_json::json!(false),
            ))
    }

    /// Require approval for delete actions
    pub fn require_approval_for_delete() -> Rule {
        Rule::require_approval("approve-delete", "Require Approval for Delete")
            .with_description("Require human approval for all delete actions")
            .with_condition(Condition::action(Operator::EndsWith, ".delete"))
            .with_approval_config(
                ApprovalConfig::new(ApprovalType::Human)
                    .with_min_approvals(1)
                    .with_timeout(3600)
                    .with_reason("Delete actions require approval"),
            )
    }

    /// Deny actions outside business hours
    pub fn business_hours_only() -> Rule {
        Rule::deny("business-hours", "Business Hours Only")
            .with_description("Deny actions outside business hours (9 AM - 6 PM)")
            .with_condition(Condition::time("hour", Operator::Lt, "9"))
            .with_condition(Condition::time("hour", Operator::Gte, "18"))
    }

    /// Allow read-only actions for all users
    pub fn allow_read_actions() -> Rule {
        Rule::allow("allow-read", "Allow Read Actions")
            .with_description("Allow all read actions")
            .with_condition(Condition::action(Operator::EndsWith, ".read"))
            .with_priority(10)
    }

    /// Deny access to sensitive resources
    pub fn deny_sensitive_resources() -> Rule {
        Rule::deny("deny-sensitive", "Deny Sensitive Resources")
            .with_description("Deny access to resources marked as sensitive")
            .with_condition(Condition::resource(Operator::Contains, "/sensitive/"))
            .with_priority(100)
    }

    /// Rate limit per actor
    pub fn rate_limit_rule(requests_per_minute: u64) -> Rule {
        Rule::deny("rate-limit", "Rate Limit")
            .with_description(format!("Limit to {} requests per minute", requests_per_minute))
            .with_condition(Condition::attribute(
                "rate_limit_exceeded",
                Operator::Eq,
                serde_json::json!(true),
            ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_builder() {
        let policy = Policy::new("test-policy", "Test Policy")
            .with_description("A test policy")
            .with_rule(Rule::allow("r1", "Allow all").with_priority(10))
            .with_default_allow();

        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.default_effect, RuleEffect::Allow);
    }

    #[test]
    fn test_rule_builder() {
        let rule = Rule::deny("test-rule", "Test Rule")
            .with_description("Deny test actions")
            .with_condition(Condition::action(Operator::StartsWith, "test."))
            .with_priority(50);

        assert_eq!(rule.effect, RuleEffect::Deny);
        assert_eq!(rule.conditions.len(), 1);
        assert_eq!(rule.priority, 50);
    }

    #[test]
    fn test_condition_builders() {
        let actor_cond = Condition::actor(Operator::Eq, "user:admin");
        assert_eq!(actor_cond.condition_type, ConditionType::Actor);

        let action_cond = Condition::action(Operator::StartsWith, "file.");
        assert_eq!(action_cond.condition_type, ConditionType::Action);

        let resource_cond = Condition::resource(Operator::Contains, "/secret/");
        assert_eq!(resource_cond.condition_type, ConditionType::Resource);
    }

    #[test]
    fn test_approval_config() {
        let config = ApprovalConfig::new(ApprovalType::Manager)
            .with_approvers(vec!["manager@example.com".to_string()])
            .with_min_approvals(2)
            .with_timeout(7200);

        let requirement = config.to_requirement();
        assert_eq!(requirement.min_approvals, 2);
        assert_eq!(requirement.timeout_secs, Some(7200));
    }

    #[test]
    fn test_rule_templates() {
        let mfa_rule = templates::require_mfa_in_production();
        assert_eq!(mfa_rule.effect, RuleEffect::Deny);

        let delete_rule = templates::require_approval_for_delete();
        assert_eq!(delete_rule.effect, RuleEffect::RequireApproval);
        assert!(delete_rule.approval_config.is_some());
    }
}
