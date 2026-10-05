//! Data Handling Policies — Policy Enforcement for Data Processing
//!
//! FIX BUG-031/032/033: Data handling policies

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};

use crate::data::ledger::{Cid, DataType, SensitivityLevel, DataControlLedger};

// =============================================================================
// Policy Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataHandlingPolicy {
    pub policy_id: String,
    pub name: String,
    pub description: String,
    pub applies_to: PolicyScope,
    pub rules: Vec<PolicyRule>,
    pub default_action: PolicyAction,
    pub created_at: i64,
    pub updated_at: i64,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyScope {
    AllData,
    BySensitivity(Vec<SensitivityLevel>),
    ByDataType(Vec<DataType>),
    BySubject(Vec<String>), // subject IDs
    ByCid(Vec<Cid>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_id: String,
    pub condition: PolicyCondition,
    pub action: PolicyAction,
    pub priority: u32, // higher = evaluated first
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyCondition {
    Always,
    SensitivityAtLeast(SensitivityLevel),
    DataTypeIs(DataType),
    SubjectIs(String),
    HasTag(String),
    AgeExceedsDays(u32),
    AccessCountExceeds(u64),
    PurposeIs(String),
    And(Box<PolicyCondition>, Box<PolicyCondition>),
    Or(Box<PolicyCondition>, Box<PolicyCondition>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Deny { reason: String },
    RequireApproval { approvers: Vec<String> },
    Anonymize,
    Encrypt { algorithm: String },
    Delete,
    Archive,
    Mask { pattern: String },
    AuditLog,
    Notify { recipients: Vec<String> },
}

// =============================================================================
// Policy Engine
// =============================================================================

pub struct PolicyEngine {
    policies: Arc<RwLock<HashMap<String, DataHandlingPolicy>>>,
    /// Active policy versions
    active_versions: Arc<RwLock<HashMap<String, u32>>>,
    /// Policy evaluation cache
    evaluation_cache: Arc<RwLock<HashMap<String, PolicyAction>>>,
    /// Compliance violations
    violations: Arc<RwLock<Vec<PolicyViolation>>>,
    ledger: Arc<DataControlLedger>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub violation_id: String,
    pub timestamp: i64,
    pub policy_id: String,
    pub cid: Cid,
    pub operation: String,
    pub severity: ViolationSeverity,
    pub message: String,
    pub resolved: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Info,
    Warning,
    Critical,
    Blocker,
}

#[derive(Debug, Clone)]
pub struct PolicyEvaluation {
    pub cid: Cid,
    pub operation: String,
    pub context: EvaluationContext,
    pub matched_policies: Vec<String>,
    pub final_action: PolicyAction,
    pub violations: Vec<PolicyViolation>,
    pub processing_time_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationContext {
    pub purpose: String,
    pub requester: String,
    pub timestamp: i64,
    pub access_count: u64,
    pub previous_actions: Vec<String>,
    pub tags: HashSet<String>,
}

impl PolicyEngine {
    pub fn new(ledger: Arc<DataControlLedger>) -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            active_versions: Arc::new(RwLock::new(HashMap::new())),
            evaluation_cache: Arc::new(RwLock::new(HashMap::new())),
            violations: Arc::new(RwLock::new(Vec::new())),
            ledger,
        }
    }

    /// Register new policy
    pub fn register_policy(&self, mut policy: DataHandlingPolicy) {
        policy.version += 1;
        policy.updated_at = chrono::Utc::now().timestamp_millis();
        
        let id = policy.policy_id.clone();
        self.policies.write().unwrap().insert(id.clone(), policy);
        self.active_versions.write().unwrap().insert(id.clone(), 1);
        
        // Clear cache for this policy
        self.evaluation_cache.write().unwrap().retain(|k, _| !k.starts_with(&id));
        
        println!("[POLICY] Registered {} v{}", id, self.active_versions.read().unwrap().get(&id).unwrap_or(&1));
    }

    /// Evaluate policy for operation on data
    pub fn evaluate(&self, cid: &Cid, operation: &str, context: &EvaluationContext) -> PolicyEvaluation {
        let start = std::time::Instant::now();
        
        // Get segment info
        let segment = self.ledger.get(cid);
        
        // Find matching policies
        let policies = self.policies.read().unwrap();
        let mut matched = Vec::new();
        let mut final_action = PolicyAction::Allow;
        let mut violations = Vec::new();
        
        for (id, policy) in policies.iter() {
            if self.policy_applies(policy, cid, &segment) {
                matched.push(id.clone());
                
                // Evaluate rules in priority order
                let mut rules = policy.rules.clone();
                rules.sort_by(|a, b| b.priority.cmp(&a.priority));
                
                for rule in rules {
                    if self.evaluate_condition(&rule.condition, cid, &segment, context) {
                        final_action = rule.action.clone();
                        
                        // Check for violations
                        if let PolicyAction::Deny { ref reason } = final_action {
                            violations.push(PolicyViolation {
                                violation_id: format!("vln-{}", uuid::Uuid::new_v4()),
                                timestamp: chrono::Utc::now().timestamp_millis(),
                                policy_id: id.clone(),
                                cid: cid.clone(),
                                operation: operation.to_string(),
                                severity: ViolationSeverity::Critical,
                                message: reason.clone(),
                                resolved: false,
                            });
                        }
                        
                        break; // First matching rule wins
                    }
                }
            }
        }

        PolicyEvaluation {
            cid: cid.clone(),
            operation: operation.to_string(),
            context: context.clone(),
            matched_policies: matched,
            final_action,
            violations,
            processing_time_ms: start.elapsed().as_millis() as u32,
        }
    }

    fn policy_applies(&self, policy: &DataHandlingPolicy, cid: &Cid, segment: &Option<crate::data::ledger::DataSegment>) -> bool {
        match &policy.applies_to {
            PolicyScope::AllData => true,
            PolicyScope::BySensitivity(levels) => {
                segment.as_ref()
                    .map(|s| levels.contains(&s.sensitivity_level))
                    .unwrap_or(false)
            }
            PolicyScope::ByDataType(types) => {
                segment.as_ref()
                    .map(|s| types.contains(&s.data_type))
                    .unwrap_or(false)
            }
            PolicyScope::BySubject(subjects) => {
                segment.as_ref()
                    .map(|s| s.subject_ids.iter().any(|subj| subjects.contains(subj)))
                    .unwrap_or(false)
            }
            PolicyScope::ByCid(cids) => cids.contains(cid),
        }
    }

    fn evaluate_condition(&self, condition: &PolicyCondition, cid: &Cid, segment: &Option<crate::data::ledger::DataSegment>, context: &EvaluationContext) -> bool {
        match condition {
            PolicyCondition::Always => true,
            PolicyCondition::SensitivityAtLeast(level) => {
                segment.as_ref()
                    .map(|s| s.sensitivity_level >= *level)
                    .unwrap_or(false)
            }
            PolicyCondition::DataTypeIs(dtype) => {
                segment.as_ref()
                    .map(|s| s.data_type == *dtype)
                    .unwrap_or(false)
            }
            PolicyCondition::SubjectIs(subject) => {
                segment.as_ref()
                    .map(|s| s.subject_ids.contains(subject))
                    .unwrap_or(false)
            }
            PolicyCondition::HasTag(tag) => context.tags.contains(tag),
            PolicyCondition::AgeExceedsDays(days) => {
                segment.as_ref()
                    .map(|s| {
                        let age_days = (chrono::Utc::now().timestamp_millis() - s.created_at) / (24 * 3600 * 1000);
                        age_days > *days as i64
                    })
                    .unwrap_or(false)
            }
            PolicyCondition::AccessCountExceeds(count) => context.access_count > *count,
            PolicyCondition::PurposeIs(purpose) => context.purpose == *purpose,
            PolicyCondition::And(left, right) => {
                self.evaluate_condition(left, cid, segment, context) &&
                self.evaluate_condition(right, cid, segment, context)
            }
            PolicyCondition::Or(left, right) => {
                self.evaluate_condition(left, cid, segment, context) ||
                self.evaluate_condition(right, cid, segment, context)
            }
        }
    }

    /// Record violation
    pub fn record_violation(&self, violation: PolicyViolation) {
        self.violations.write().unwrap().push(violation);
    }

    /// Get violations
    pub fn get_violations(&self, unresolved_only: bool) -> Vec<PolicyViolation> {
        if unresolved_only {
            self.violations.read().unwrap()
                .iter()
                .filter(|v| !v.resolved)
                .cloned()
                .collect()
        } else {
            self.violations.read().unwrap().clone()
        }
    }

    /// Resolve violation
    pub fn resolve_violation(&self, violation_id: &str) -> Result<(), String> {
        let mut violations = self.violations.write().unwrap();
        
        if let Some(v) = violations.iter_mut().find(|v| v.violation_id == violation_id) {
            v.resolved = true;
            Ok(())
        } else {
            Err("Violation not found".to_string())
        }
    }

    /// Get policy statistics
    pub fn get_stats(&self) -> PolicyStats {
        PolicyStats {
            total_policies: self.policies.read().unwrap().len(),
            active_versions: self.active_versions.read().unwrap().len(),
            total_violations: self.violations.read().unwrap().len(),
            unresolved_violations: self.violations.read().unwrap().iter().filter(|v| !v.resolved).count(),
        }
    }

    /// Create default PII policy
    pub fn default_pii_policy() -> DataHandlingPolicy {
        DataHandlingPolicy {
            policy_id: "default-pii".to_string(),
            name: "Default PII Protection".to_string(),
            description: "Protects PII data with encryption and access controls".to_string(),
            applies_to: PolicyScope::BySensitivity(vec![
                SensitivityLevel::Pii,
                SensitivityLevel::SensitivePii,
            ]),
            rules: vec![
                PolicyRule {
                    rule_id: "encrypt-pii".to_string(),
                    condition: PolicyCondition::Always,
                    action: PolicyAction::Encrypt { algorithm: "AES-256-GCM".to_string() },
                    priority: 100,
                },
                PolicyRule {
                    rule_id: "audit-access".to_string(),
                    condition: PolicyCondition::SensitivityAtLeast(SensitivityLevel::Pii),
                    action: PolicyAction::AuditLog,
                    priority: 50,
                },
            ],
            default_action: PolicyAction::Allow,
            created_at: chrono::Utc::now().timestamp_millis(),
            updated_at: chrono::Utc::now().timestamp_millis(),
            version: 1,
        }
    }

    /// Create data retention policy
    pub fn retention_policy(retention_days: u32) -> DataHandlingPolicy {
        DataHandlingPolicy {
            policy_id: format!("retention-{}d", retention_days),
            name: format!("{}-Day Data Retention", retention_days),
            description: format!("Automatically deletes data older than {} days", retention_days),
            applies_to: PolicyScope::AllData,
            rules: vec![
                PolicyRule {
                    rule_id: "auto-delete".to_string(),
                    condition: PolicyCondition::AgeExceedsDays(retention_days),
                    action: PolicyAction::Delete,
                    priority: 10,
                },
            ],
            default_action: PolicyAction::Allow,
            created_at: chrono::Utc::now().timestamp_millis(),
            updated_at: chrono::Utc::now().timestamp_millis(),
            version: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyStats {
    pub total_policies: usize,
    pub active_versions: usize,
    pub total_violations: usize,
    pub unresolved_violations: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_policy_registration() {
        let ledger = Arc::new(DataControlLedger::new());
        let engine = PolicyEngine::new(ledger);
        
        let policy = PolicyEngine::default_pii_policy();
        engine.register_policy(policy);
        
        assert_eq!(engine.get_stats().total_policies, 1);
    }

    #[test]
    fn test_policy_evaluation() {
        let ledger = Arc::new(DataControlLedger::new());
        let engine = PolicyEngine::new(ledger.clone());
        
        // Register PII data
        let cid = ledger.register(b"pii", DataType::Raw, SensitivityLevel::Pii, vec!["user-123".to_string()]);
        
        // Register policy
        engine.register_policy(PolicyEngine::default_pii_policy());
        
        let context = EvaluationContext {
            purpose: "analytics".to_string(),
            requester: "agent-1".to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            access_count: 0,
            previous_actions: vec![],
            tags: HashSet::new(),
        };
        
        let eval = engine.evaluate(&cid, "read", &context);
        assert!(!eval.matched_policies.is_empty());
    }

    #[test]
    fn test_age_based_policy() {
        let ledger = Arc::new(DataControlLedger::new());
        let engine = PolicyEngine::new(ledger.clone());
        
        // Register old data
        let cid = ledger.register(b"old data", DataType::Raw, SensitivityLevel::Internal, vec![]);
        
        // Register retention policy
        engine.register_policy(PolicyEngine::retention_policy(0)); // 0 days
        
        let context = EvaluationContext {
            purpose: "check".to_string(),
            requester: "system".to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            access_count: 0,
            previous_actions: vec![],
            tags: HashSet::new(),
        };
        
        let eval = engine.evaluate(&cid, "check", &context);
        // Should match delete action due to age
        assert!(matches!(eval.final_action, PolicyAction::Delete));
    }
}
