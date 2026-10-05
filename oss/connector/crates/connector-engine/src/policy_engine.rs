//! Policy Guard — Layer 2 of the 5-Layer Guard Pipeline.
//!
//! Cedar/XACML-inspired deterministic rule engine with **deny-overrides** combining.
//! Context-aware: PII permitted in `/k/medical/`, blocked in `/p/public/`.
//!
//! Research: Amazon Cedar (formally verified, 2023), XACML 3.0 combining algorithms,
//! OPA/Rego (CNCF), NIST SP 800-53 AC-3

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// Policy Types
// ═══════════════════════════════════════════════════════════════

/// Effect of a policy rule — deterministic, no weights.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyEffect {
    Permit,
    Deny,
    RequireApproval,
}

/// A single policy rule with conditions and effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub description: String,
    pub priority: u32,
    pub effect: PolicyEffect,
    pub conditions: Vec<PolicyCondition>,
}

/// Conditions that must ALL be true for a rule to apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyCondition {
    /// Subject's security level must be >= this value
    MinClearance(u8),
    /// Object namespace must match this type prefix
    NamespacePrefix(String),
    /// Operation type must match
    OperationIs(String),
    /// Agent must own the target namespace
    AgentOwnsNamespace,
    /// Agent must have an explicit grant
    AgentHasGrant,
    /// Content type tag must match (e.g., "medical", "financial")
    ContentTypeIs(String),
    /// Namespace path must contain this substring
    NamespaceContains(String),
    /// Negation of another condition
    Not(Box<PolicyCondition>),
}

/// Context for evaluating policy rules against a request.
#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub agent_pid: String,
    pub agent_clearance: u8,
    pub operation: String,
    pub namespace: String,
    pub namespace_prefix: String,
    pub is_owner: bool,
    pub has_grant: bool,
    pub content_type: Option<String>,
}

/// Result of policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecisionResult {
    Permit { matched_rule: String },
    Deny { matched_rule: String, reason: String },
    RequireApproval { matched_rule: String, reason: String },
    DefaultDeny,
}

impl PolicyDecisionResult {
    pub fn is_deny(&self) -> bool {
        matches!(self, PolicyDecisionResult::Deny { .. } | PolicyDecisionResult::DefaultDeny)
    }
}

// ═══════════════════════════════════════════════════════════════
// Policy Engine
// ═══════════════════════════════════════════════════════════════

/// Deterministic policy decision point with deny-overrides combining.
///
/// Formal properties:
/// - **Monotonicity**: Adding a Deny rule can ONLY make the system MORE restrictive
/// - **Determinism**: Same context → ALWAYS same decision
/// - **Fail-closed**: No matching rules → DEFAULT DENY
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Evaluate all rules against the context using deny-overrides combining.
    ///
    /// 1. Evaluate ALL applicable rules
    /// 2. If ANY returns Deny → DENY (immediate, no override)
    /// 3. If ANY returns RequireApproval → HOLD (unless Deny found)
    /// 4. If at least one Permit and no Deny → PERMIT
    /// 5. If NO rules match → DEFAULT DENY (fail-closed)
    pub fn evaluate(&self, ctx: &PolicyContext) -> PolicyDecisionResult {
        let mut has_permit = false;
        let mut permit_rule = String::new();
        let mut has_approval = false;
        let mut approval_rule = String::new();

        for rule in &self.rules {
            if self.rule_applies(rule, ctx) {
                match &rule.effect {
                    PolicyEffect::Deny => {
                        return PolicyDecisionResult::Deny {
                            matched_rule: rule.id.clone(),
                            reason: rule.description.clone(),
                        };
                    }
                    PolicyEffect::RequireApproval => {
                        if !has_approval {
                            has_approval = true;
                            approval_rule = rule.id.clone();
                        }
                    }
                    PolicyEffect::Permit => {
                        if !has_permit {
                            has_permit = true;
                            permit_rule = rule.id.clone();
                        }
                    }
                }
            }
        }

        if has_approval {
            return PolicyDecisionResult::RequireApproval {
                matched_rule: approval_rule,
                reason: "Human approval required".into(),
            };
        }

        if has_permit {
            return PolicyDecisionResult::Permit { matched_rule: permit_rule };
        }

        PolicyDecisionResult::DefaultDeny
    }

    /// Check if all conditions of a rule match the context.
    fn rule_applies(&self, rule: &PolicyRule, ctx: &PolicyContext) -> bool {
        rule.conditions.iter().all(|c| self.condition_matches(c, ctx))
    }

    fn condition_matches(&self, cond: &PolicyCondition, ctx: &PolicyContext) -> bool {
        match cond {
            PolicyCondition::MinClearance(level) => ctx.agent_clearance >= *level,
            PolicyCondition::NamespacePrefix(prefix) => ctx.namespace_prefix == *prefix,
            PolicyCondition::OperationIs(op) => ctx.operation == *op,
            PolicyCondition::AgentOwnsNamespace => ctx.is_owner,
            PolicyCondition::AgentHasGrant => ctx.has_grant,
            PolicyCondition::ContentTypeIs(ct) => ctx.content_type.as_deref() == Some(ct.as_str()),
            PolicyCondition::NamespaceContains(sub) => ctx.namespace.contains(sub.as_str()),
            PolicyCondition::Not(inner) => !self.condition_matches(inner, ctx),
        }
    }

    pub fn rule_count(&self) -> usize { self.rules.len() }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn medical_ctx() -> PolicyContext {
        PolicyContext {
            agent_pid: "doctor_ai".into(),
            agent_clearance: 3,
            operation: "MemWrite".into(),
            namespace: "k/medical/patients".into(),
            namespace_prefix: "k".into(),
            is_owner: true,
            has_grant: true,
            content_type: Some("medical".into()),
        }
    }

    fn public_ctx() -> PolicyContext {
        PolicyContext {
            agent_pid: "rogue_ai".into(),
            agent_clearance: 2,
            operation: "MemWrite".into(),
            namespace: "p/public/data".into(),
            namespace_prefix: "p".into(),
            is_owner: false,
            has_grant: false,
            content_type: None,
        }
    }

    #[test]
    fn test_deny_overrides_permit() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            id: "permit_owner".into(), description: "Permit owner writes".into(),
            priority: 10, effect: PolicyEffect::Permit,
            conditions: vec![PolicyCondition::AgentOwnsNamespace],
        });
        engine.add_rule(PolicyRule {
            id: "deny_public_write".into(), description: "Deny writes to public by non-admins".into(),
            priority: 1, effect: PolicyEffect::Deny,
            conditions: vec![
                PolicyCondition::NamespacePrefix("p".into()),
                PolicyCondition::Not(Box::new(PolicyCondition::MinClearance(4))),
            ],
        });
        // Public context: Deny rule matches (prefix=p, clearance<4) → DENY even though owner permit exists
        let result = engine.evaluate(&public_ctx());
        assert!(result.is_deny());
    }

    #[test]
    fn test_default_deny_no_rules() {
        let engine = PolicyEngine::new();
        let result = engine.evaluate(&medical_ctx());
        assert_eq!(result, PolicyDecisionResult::DefaultDeny);
    }

    #[test]
    fn test_permit_medical_pii() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            id: "permit_medical_pii".into(),
            description: "Medical agents may write PII to knowledge bases".into(),
            priority: 5, effect: PolicyEffect::Permit,
            conditions: vec![
                PolicyCondition::ContentTypeIs("medical".into()),
                PolicyCondition::NamespacePrefix("k".into()),
                PolicyCondition::AgentHasGrant,
            ],
        });
        let result = engine.evaluate(&medical_ctx());
        assert_eq!(result, PolicyDecisionResult::Permit { matched_rule: "permit_medical_pii".into() });
    }

    #[test]
    fn test_deny_pii_in_public() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            id: "deny_pii_public".into(),
            description: "Block PII writes to public namespaces".into(),
            priority: 1, effect: PolicyEffect::Deny,
            conditions: vec![PolicyCondition::NamespacePrefix("p".into())],
        });
        let result = engine.evaluate(&public_ctx());
        assert!(result.is_deny());
    }

    #[test]
    fn test_require_approval() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            id: "hitl_system_write".into(),
            description: "Require approval for system namespace writes".into(),
            priority: 5, effect: PolicyEffect::RequireApproval,
            conditions: vec![PolicyCondition::NamespacePrefix("s".into())],
        });
        let ctx = PolicyContext {
            agent_pid: "admin".into(), agent_clearance: 5,
            operation: "MemWrite".into(), namespace: "s/audit/config".into(),
            namespace_prefix: "s".into(), is_owner: false, has_grant: true,
            content_type: None,
        };
        let result = engine.evaluate(&ctx);
        match result {
            PolicyDecisionResult::RequireApproval { matched_rule, .. } => {
                assert_eq!(matched_rule, "hitl_system_write");
            }
            _ => panic!("Expected RequireApproval, got {:?}", result),
        }
    }

    #[test]
    fn test_role_based_medical_only() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            id: "permit_medical_agents".into(),
            description: "Only medical content type can access medical NS".into(),
            priority: 5, effect: PolicyEffect::Permit,
            conditions: vec![
                PolicyCondition::ContentTypeIs("medical".into()),
                PolicyCondition::NamespaceContains("medical".into()),
            ],
        });
        engine.add_rule(PolicyRule {
            id: "deny_non_medical".into(),
            description: "Deny non-medical access to medical NS".into(),
            priority: 1, effect: PolicyEffect::Deny,
            conditions: vec![
                PolicyCondition::NamespaceContains("medical".into()),
                PolicyCondition::Not(Box::new(PolicyCondition::ContentTypeIs("medical".into()))),
            ],
        });
        // Medical agent → Permit
        let result = engine.evaluate(&medical_ctx());
        assert!(!result.is_deny());
        // Non-medical agent trying medical namespace → Deny
        let billing_ctx = PolicyContext {
            agent_pid: "billing_ai".into(), agent_clearance: 2,
            operation: "MemRead".into(), namespace: "k/medical/patients".into(),
            namespace_prefix: "k".into(), is_owner: false, has_grant: false,
            content_type: Some("billing".into()),
        };
        let result = engine.evaluate(&billing_ctx);
        assert!(result.is_deny());
    }

    #[test]
    fn test_monotonicity_adding_deny_only_restricts() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            id: "permit_all".into(), description: "Permit everything".into(),
            priority: 100, effect: PolicyEffect::Permit,
            conditions: vec![], // Always matches
        });
        let ctx = medical_ctx();
        assert!(!engine.evaluate(&ctx).is_deny()); // Permitted

        // Adding a Deny rule can only restrict
        engine.add_rule(PolicyRule {
            id: "deny_specific".into(), description: "Deny medical writes".into(),
            priority: 1, effect: PolicyEffect::Deny,
            conditions: vec![PolicyCondition::ContentTypeIs("medical".into())],
        });
        assert!(engine.evaluate(&ctx).is_deny()); // Now denied
    }

    #[test]
    fn test_priority_ordering() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            id: "low_priority".into(), description: "".into(),
            priority: 100, effect: PolicyEffect::Permit, conditions: vec![],
        });
        engine.add_rule(PolicyRule {
            id: "high_priority".into(), description: "Deny all".into(),
            priority: 1, effect: PolicyEffect::Deny, conditions: vec![],
        });
        // Deny-overrides regardless of priority order
        assert!(engine.evaluate(&medical_ctx()).is_deny());
    }
}
