//! Policy evaluation engine

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::context::EvaluationContext;
use crate::decision::{PolicyDecision, DecisionType, MatchedRule, RuleEffect};
use crate::error::{MetaRulesError, MetaRulesResult};
use crate::rules::{Policy, Rule, Condition, ConditionType, Operator};

/// Policy evaluation engine
pub struct PolicyEngine {
    policies: Arc<RwLock<HashMap<String, Policy>>>,
    /// Default decision when no policies match
    default_decision: DecisionType,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            default_decision: DecisionType::Deny,
        }
    }

    pub fn with_default_allow(mut self) -> Self {
        self.default_decision = DecisionType::Allow;
        self
    }

    /// Add a policy
    pub async fn add_policy(&self, policy: Policy) {
        let mut policies = self.policies.write().await;
        info!(policy_id = %policy.id, policy_name = %policy.name, "Adding policy");
        policies.insert(policy.id.clone(), policy);
    }

    /// Remove a policy
    pub async fn remove_policy(&self, policy_id: &str) -> Option<Policy> {
        let mut policies = self.policies.write().await;
        policies.remove(policy_id)
    }

    /// Get a policy by ID
    pub async fn get_policy(&self, policy_id: &str) -> Option<Policy> {
        let policies = self.policies.read().await;
        policies.get(policy_id).cloned()
    }

    /// List all policies
    pub async fn list_policies(&self) -> Vec<Policy> {
        let policies = self.policies.read().await;
        policies.values().cloned().collect()
    }

    /// Evaluate a context against all policies
    pub async fn evaluate(&self, context: &EvaluationContext) -> MetaRulesResult<PolicyDecision> {
        let policies = self.policies.read().await;
        
        // Sort policies by priority (higher first)
        let mut sorted_policies: Vec<&Policy> = policies.values()
            .filter(|p| p.enabled)
            .collect();
        sorted_policies.sort_by(|a, b| b.priority.cmp(&a.priority));

        let mut matched_rules = Vec::new();
        let mut final_decision: Option<PolicyDecision> = None;

        for policy in sorted_policies {
            debug!(policy_id = %policy.id, "Evaluating policy");

            // Sort rules by priority within policy
            let mut sorted_rules: Vec<&Rule> = policy.rules.iter()
                .filter(|r| r.enabled)
                .collect();
            sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

            for rule in sorted_rules {
                if self.evaluate_rule(rule, context)? {
                    debug!(rule_id = %rule.id, effect = ?rule.effect, "Rule matched");
                    
                    matched_rules.push(MatchedRule {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        effect: rule.effect,
                        priority: rule.priority,
                        matched_conditions: rule.conditions.iter()
                            .map(|c| format!("{:?}", c.condition_type))
                            .collect(),
                    });

                    // First matching rule with Deny or RequireApproval takes precedence
                    if rule.effect == RuleEffect::Deny {
                        final_decision = Some(PolicyDecision::deny(format!(
                            "Denied by rule: {}",
                            rule.name
                        )).with_matched_rule(matched_rules.last().unwrap().clone()));
                        break;
                    } else if rule.effect == RuleEffect::RequireApproval {
                        let approvals = rule.approval_config.as_ref()
                            .map(|c| vec![c.to_requirement()])
                            .unwrap_or_default();
                        
                        final_decision = Some(PolicyDecision::pending_approval(
                            format!("Approval required by rule: {}", rule.name),
                            approvals,
                        ).with_matched_rule(matched_rules.last().unwrap().clone()));
                        break;
                    } else if final_decision.is_none() {
                        // Allow - but continue checking for denies
                        final_decision = Some(PolicyDecision::allow(format!(
                            "Allowed by rule: {}",
                            rule.name
                        )).with_matched_rule(matched_rules.last().unwrap().clone()));
                    }
                }
            }

            // If we got a deny or require approval, stop evaluating
            if let Some(ref decision) = final_decision {
                if !decision.allowed || decision.requires_approval() {
                    break;
                }
            }
        }

        // Return final decision or default
        Ok(final_decision.unwrap_or_else(|| {
            match self.default_decision {
                DecisionType::Allow => PolicyDecision::allow("No matching rules, default allow"),
                _ => PolicyDecision::deny("No matching rules, default deny"),
            }
        }))
    }

    /// Evaluate a single rule against context
    fn evaluate_rule(&self, rule: &Rule, context: &EvaluationContext) -> MetaRulesResult<bool> {
        // All conditions must match (AND logic)
        for condition in &rule.conditions {
            if !self.evaluate_condition(condition, context)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Evaluate a single condition
    fn evaluate_condition(&self, condition: &Condition, context: &EvaluationContext) -> MetaRulesResult<bool> {
        let actual_value = self.get_field_value(condition, context)?;
        
        match condition.operator {
            Operator::Eq => Ok(actual_value == condition.value),
            Operator::Ne => Ok(actual_value != condition.value),
            Operator::Gt => self.compare_values(&actual_value, &condition.value, |a, b| a > b),
            Operator::Gte => self.compare_values(&actual_value, &condition.value, |a, b| a >= b),
            Operator::Lt => self.compare_values(&actual_value, &condition.value, |a, b| a < b),
            Operator::Lte => self.compare_values(&actual_value, &condition.value, |a, b| a <= b),
            Operator::Contains => {
                if let (Some(haystack), Some(needle)) = (actual_value.as_str(), condition.value.as_str()) {
                    Ok(haystack.contains(needle))
                } else if let Some(arr) = actual_value.as_array() {
                    Ok(arr.contains(&condition.value))
                } else {
                    Ok(false)
                }
            }
            Operator::StartsWith => {
                if let (Some(s), Some(prefix)) = (actual_value.as_str(), condition.value.as_str()) {
                    Ok(s.starts_with(prefix))
                } else {
                    Ok(false)
                }
            }
            Operator::EndsWith => {
                if let (Some(s), Some(suffix)) = (actual_value.as_str(), condition.value.as_str()) {
                    Ok(s.ends_with(suffix))
                } else {
                    Ok(false)
                }
            }
            Operator::Matches => {
                if let (Some(s), Some(pattern)) = (actual_value.as_str(), condition.value.as_str()) {
                    // Simple glob matching
                    Ok(glob_match(pattern, s))
                } else {
                    Ok(false)
                }
            }
            Operator::In => {
                if let Some(arr) = condition.value.as_array() {
                    Ok(arr.contains(&actual_value))
                } else {
                    Ok(false)
                }
            }
            Operator::NotIn => {
                if let Some(arr) = condition.value.as_array() {
                    Ok(!arr.contains(&actual_value))
                } else {
                    Ok(true)
                }
            }
            Operator::Exists => Ok(!actual_value.is_null()),
            Operator::NotExists => Ok(actual_value.is_null()),
        }
    }

    /// Get field value from context
    fn get_field_value(&self, condition: &Condition, context: &EvaluationContext) -> MetaRulesResult<serde_json::Value> {
        match condition.condition_type {
            ConditionType::Actor => {
                match condition.field.as_str() {
                    "pid" => Ok(serde_json::json!(context.vakya.v1_karta.pid.0)),
                    "role" => Ok(serde_json::json!(context.vakya.v1_karta.role)),
                    "realm" => Ok(serde_json::json!(context.vakya.v1_karta.realm)),
                    "actor_type" => Ok(serde_json::json!(format!("{:?}", context.vakya.v1_karta.actor_type))),
                    _ => Ok(serde_json::Value::Null),
                }
            }
            ConditionType::Action => {
                match condition.field.as_str() {
                    "action" => Ok(serde_json::json!(context.vakya.v3_kriya.action)),
                    "domain" => Ok(serde_json::json!(context.vakya.v3_kriya.domain)),
                    "verb" => Ok(serde_json::json!(context.vakya.v3_kriya.verb)),
                    _ => Ok(serde_json::Value::Null),
                }
            }
            ConditionType::Resource => {
                match condition.field.as_str() {
                    "rid" => Ok(serde_json::json!(context.vakya.v2_karma.rid.0)),
                    "kind" => Ok(serde_json::json!(context.vakya.v2_karma.kind)),
                    "ns" => Ok(serde_json::json!(context.vakya.v2_karma.ns.as_ref().map(|n| &n.0))),
                    _ => Ok(serde_json::Value::Null),
                }
            }
            ConditionType::Time => {
                let now = context.timestamp;
                match condition.field.as_str() {
                    "hour" => Ok(serde_json::json!(now.format("%H").to_string())),
                    "minute" => Ok(serde_json::json!(now.format("%M").to_string())),
                    "day_of_week" => Ok(serde_json::json!(now.format("%u").to_string())),
                    "date" => Ok(serde_json::json!(now.format("%Y-%m-%d").to_string())),
                    _ => Ok(serde_json::Value::Null),
                }
            }
            ConditionType::Environment => {
                match condition.field.as_str() {
                    "environment" => Ok(serde_json::json!(context.environment)),
                    _ => Ok(serde_json::Value::Null),
                }
            }
            ConditionType::Geo => {
                if let Some(ref geo) = context.geo {
                    match condition.field.as_str() {
                        "country" => Ok(serde_json::json!(geo.country)),
                        "region" => Ok(serde_json::json!(geo.region)),
                        "city" => Ok(serde_json::json!(geo.city)),
                        _ => Ok(serde_json::Value::Null),
                    }
                } else {
                    Ok(serde_json::Value::Null)
                }
            }
            ConditionType::Session => {
                if let Some(ref session) = context.session {
                    match condition.field.as_str() {
                        "mfa_verified" => Ok(serde_json::json!(session.mfa_verified)),
                        "auth_method" => Ok(serde_json::json!(session.auth_method)),
                        "duration_secs" => Ok(serde_json::json!(session.duration_secs())),
                        "idle_secs" => Ok(serde_json::json!(session.idle_secs())),
                        _ => Ok(serde_json::Value::Null),
                    }
                } else {
                    Ok(serde_json::Value::Null)
                }
            }
            ConditionType::Attribute => {
                Ok(context.attributes.get(&condition.field)
                    .cloned()
                    .unwrap_or(serde_json::Value::Null))
            }
        }
    }

    /// Compare two values with a comparison function
    fn compare_values<F>(&self, a: &serde_json::Value, b: &serde_json::Value, cmp: F) -> MetaRulesResult<bool>
    where
        F: Fn(f64, f64) -> bool,
    {
        match (a.as_f64(), b.as_f64()) {
            (Some(a_num), Some(b_num)) => Ok(cmp(a_num, b_num)),
            _ => {
                // Try string comparison
                match (a.as_str(), b.as_str()) {
                    (Some(a_str), Some(b_str)) => Ok(cmp(
                        a_str.parse::<f64>().unwrap_or(0.0),
                        b_str.parse::<f64>().unwrap_or(0.0),
                    )),
                    _ => Ok(false),
                }
            }
        }
    }
}

/// Simple glob matching
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    
    if pattern == "**" {
        return true;
    }

    // Handle simple wildcards
    if pattern.starts_with('*') && pattern.ends_with('*') {
        let middle = &pattern[1..pattern.len()-1];
        return value.contains(middle);
    }
    
    if pattern.starts_with('*') {
        let suffix = &pattern[1..];
        return value.ends_with(suffix);
    }
    
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len()-1];
        return value.starts_with(prefix);
    }

    pattern == value
}

/// Builder for creating a policy engine with predefined policies
pub struct PolicyEngineBuilder {
    engine: PolicyEngine,
    policies: Vec<Policy>,
}

impl Default for PolicyEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngineBuilder {
    pub fn new() -> Self {
        Self {
            engine: PolicyEngine::new(),
            policies: vec![],
        }
    }

    pub fn with_default_allow(mut self) -> Self {
        self.engine = self.engine.with_default_allow();
        self
    }

    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policies.push(policy);
        self
    }

    pub async fn build(self) -> PolicyEngine {
        for policy in self.policies {
            self.engine.add_policy(policy).await;
        }
        self.engine
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Rule, Condition, Operator};
    use aapi_core::*;

    fn create_test_vakya(action: &str) -> Vakya {
        Vakya::builder()
            .karta(Karta {
                pid: PrincipalId::new("user:test"),
                role: Some("admin".to_string()),
                realm: None,
                key_id: None,
                actor_type: ActorType::Human,
                delegation_chain: vec![],
            })
            .karma(Karma {
                rid: ResourceId::new("file:/test.txt"),
                kind: Some("file".to_string()),
                ns: None,
                version: None,
                labels: std::collections::HashMap::new(),
            })
            .kriya(Kriya::new(
                action.split('.').next().unwrap_or("test"),
                action.split('.').last().unwrap_or("action"),
            ))
            .adhikarana(Adhikarana {
                cap: CapabilityRef::Reference { cap_ref: "cap:test".to_string() },
                policy_ref: None,
                ttl: Some(TtlConstraint {
                    expires_at: Timestamp(chrono::Utc::now() + chrono::Duration::hours(1)),
                    max_duration_ms: None,
                }),
                budgets: vec![],
                approval_lane: ApprovalLane::None,
                scopes: vec![],
                context: None,
            })
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_allow_rule() {
        let engine = PolicyEngine::new();
        
        let policy = Policy::new("test", "Test Policy")
            .with_rule(
                Rule::allow("allow-read", "Allow Read")
                    .with_condition(Condition::action(Operator::EndsWith, ".read"))
            );
        
        engine.add_policy(policy).await;

        let vakya = create_test_vakya("file.read");
        let context = EvaluationContext::new(vakya);
        
        let decision = engine.evaluate(&context).await.unwrap();
        assert!(decision.allowed);
    }

    #[tokio::test]
    async fn test_deny_rule() {
        let engine = PolicyEngine::new();
        
        let policy = Policy::new("test", "Test Policy")
            .with_rule(
                Rule::deny("deny-delete", "Deny Delete")
                    .with_condition(Condition::action(Operator::EndsWith, ".delete"))
            );
        
        engine.add_policy(policy).await;

        let vakya = create_test_vakya("file.delete");
        let context = EvaluationContext::new(vakya);
        
        let decision = engine.evaluate(&context).await.unwrap();
        assert!(!decision.allowed);
    }

    #[tokio::test]
    async fn test_default_deny() {
        let engine = PolicyEngine::new();
        
        let vakya = create_test_vakya("unknown.action");
        let context = EvaluationContext::new(vakya);
        
        let decision = engine.evaluate(&context).await.unwrap();
        assert!(!decision.allowed);
    }

    #[tokio::test]
    async fn test_default_allow() {
        let engine = PolicyEngine::new().with_default_allow();
        
        let vakya = create_test_vakya("unknown.action");
        let context = EvaluationContext::new(vakya);
        
        let decision = engine.evaluate(&context).await.unwrap();
        assert!(decision.allowed);
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("file.*", "file.read"));
        assert!(glob_match("*.delete", "file.delete"));
        assert!(glob_match("*admin*", "super_admin_user"));
        assert!(!glob_match("file.*", "database.read"));
    }
}
