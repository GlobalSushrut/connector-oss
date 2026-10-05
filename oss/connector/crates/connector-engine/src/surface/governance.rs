//! Governance Hooks — Policy enforcement for surface access
//!
//! Following CLS patterns: surfaces are governed by policies.

use super::document::{SurfaceType, SurfaceView};
use super::roles::Role;
use serde::{Deserialize, Serialize};

/// Policy decision for surface access
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow,
    Deny,
    AllowWithRedaction,
    RequireApproval,
    RateLimit,
}

/// Policy violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub policy_id: String,
    pub rule: String,
    pub reason: String,
    pub severity: ViolationSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Info, Warning, Error, Critical,
}

/// Surface access request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceAccessRequest {
    pub actor: String,
    pub role: Role,
    pub surface_type: SurfaceType,
    pub view: SurfaceView,
    pub subject_id: String,
    pub namespace: Option<String>,
    pub time_travel: bool,
    pub export_format: Option<String>,
}

/// Policy rule for surface access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfacePolicy {
    pub id: String,
    pub name: String,
    pub rules: Vec<PolicyRule>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub condition: PolicyCondition,
    pub action: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyCondition {
    RoleIs(Role),
    RoleNot(Role),
    ViewIs(SurfaceView),
    ViewNot(SurfaceView),
    SurfaceTypeIs(SurfaceType),
    NamespaceIs(String),
    IsTimeTravel,
    IsExport,
    And(Vec<PolicyCondition>),
    Or(Vec<PolicyCondition>),
    Not(Box<PolicyCondition>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Deny { reason: String },
    Redact { level: String },
    RequireApproval { approver: String },
    RateLimit { requests_per_minute: u32 },
    Log { level: String },
}

impl PolicyCondition {
    pub fn evaluate(&self, req: &SurfaceAccessRequest) -> bool {
        match self {
            Self::RoleIs(r) => req.role == *r,
            Self::RoleNot(r) => req.role != *r,
            Self::ViewIs(v) => req.view == *v,
            Self::ViewNot(v) => req.view != *v,
            Self::SurfaceTypeIs(t) => req.surface_type == *t,
            Self::NamespaceIs(ns) => req.namespace.as_deref() == Some(ns),
            Self::IsTimeTravel => req.time_travel,
            Self::IsExport => req.export_format.is_some(),
            Self::And(conds) => conds.iter().all(|c| c.evaluate(req)),
            Self::Or(conds) => conds.iter().any(|c| c.evaluate(req)),
            Self::Not(c) => !c.evaluate(req),
        }
    }
}

/// Policy engine for surface governance
pub struct SurfaceGovernance {
    policies: Vec<SurfacePolicy>,
    default_decision: PolicyDecision,
}

impl Default for SurfaceGovernance {
    fn default() -> Self {
        Self::new()
    }
}

impl SurfaceGovernance {
    pub fn new() -> Self {
        Self {
            policies: Self::default_policies(),
            default_decision: PolicyDecision::Allow,
        }
    }

    fn default_policies() -> Vec<SurfacePolicy> {
        vec![
            // Operators cannot access Forensic view
            SurfacePolicy {
                id: "operator-forensic-deny".into(),
                name: "Deny Forensic to Operators".into(),
                enabled: true,
                rules: vec![PolicyRule {
                    id: "r1".into(),
                    condition: PolicyCondition::And(vec![
                        PolicyCondition::RoleIs(Role::Operator),
                        PolicyCondition::ViewIs(SurfaceView::Forensic),
                    ]),
                    action: PolicyAction::Deny { reason: "Operators cannot access Forensic view".into() },
                }],
            },
            // Executives cannot access Ops view
            SurfacePolicy {
                id: "exec-ops-deny".into(),
                name: "Deny Ops to Executives".into(),
                enabled: true,
                rules: vec![PolicyRule {
                    id: "r1".into(),
                    condition: PolicyCondition::And(vec![
                        PolicyCondition::RoleIs(Role::Executive),
                        PolicyCondition::ViewIs(SurfaceView::Ops),
                    ]),
                    action: PolicyAction::Deny { reason: "Executives should use Exec view".into() },
                }],
            },
            // Time travel requires audit logging
            SurfacePolicy {
                id: "time-travel-log".into(),
                name: "Log Time Travel Access".into(),
                enabled: true,
                rules: vec![PolicyRule {
                    id: "r1".into(),
                    condition: PolicyCondition::IsTimeTravel,
                    action: PolicyAction::Log { level: "info".into() },
                }],
            },
            // Export requires approval for non-auditors
            SurfacePolicy {
                id: "export-approval".into(),
                name: "Export Requires Approval".into(),
                enabled: true,
                rules: vec![PolicyRule {
                    id: "r1".into(),
                    condition: PolicyCondition::And(vec![
                        PolicyCondition::IsExport,
                        PolicyCondition::RoleNot(Role::Auditor),
                    ]),
                    action: PolicyAction::RequireApproval { approver: "compliance-officer".into() },
                }],
            },
        ]
    }

    /// Evaluate access request against policies
    pub fn evaluate(&self, req: &SurfaceAccessRequest) -> GovernanceResult {
        let mut violations = Vec::new();
        let mut decision = self.default_decision;
        let mut redaction_level = None;
        let mut requires_approval = false;
        let mut approver = None;

        for policy in &self.policies {
            if !policy.enabled { continue; }
            
            for rule in &policy.rules {
                if rule.condition.evaluate(req) {
                    match &rule.action {
                        PolicyAction::Allow => {},
                        PolicyAction::Deny { reason } => {
                            decision = PolicyDecision::Deny;
                            violations.push(PolicyViolation {
                                policy_id: policy.id.clone(),
                                rule: rule.id.clone(),
                                reason: reason.clone(),
                                severity: ViolationSeverity::Error,
                            });
                        },
                        PolicyAction::Redact { level } => {
                            if decision != PolicyDecision::Deny {
                                decision = PolicyDecision::AllowWithRedaction;
                                redaction_level = Some(level.clone());
                            }
                        },
                        PolicyAction::RequireApproval { approver: a } => {
                            if decision != PolicyDecision::Deny {
                                decision = PolicyDecision::RequireApproval;
                                requires_approval = true;
                                approver = Some(a.clone());
                            }
                        },
                        PolicyAction::RateLimit { .. } => {
                            if decision == PolicyDecision::Allow {
                                decision = PolicyDecision::RateLimit;
                            }
                        },
                        PolicyAction::Log { .. } => {
                            // Logging doesn't change decision
                        },
                    }
                }
            }
        }

        GovernanceResult {
            decision,
            violations,
            redaction_level,
            requires_approval,
            approver,
        }
    }

    /// Add custom policy
    pub fn add_policy(&mut self, policy: SurfacePolicy) {
        self.policies.push(policy);
    }
}

/// Result of governance evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceResult {
    pub decision: PolicyDecision,
    pub violations: Vec<PolicyViolation>,
    pub redaction_level: Option<String>,
    pub requires_approval: bool,
    pub approver: Option<String>,
}

impl GovernanceResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self.decision, PolicyDecision::Allow | PolicyDecision::AllowWithRedaction | PolicyDecision::RateLimit)
    }

    pub fn is_denied(&self) -> bool {
        matches!(self.decision, PolicyDecision::Deny)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operator_forensic_denied() {
        let gov = SurfaceGovernance::new();
        let req = SurfaceAccessRequest {
            actor: "user-1".into(),
            role: Role::Operator,
            surface_type: SurfaceType::Agent,
            view: SurfaceView::Forensic,
            subject_id: "agent-001".into(),
            namespace: None,
            time_travel: false,
            export_format: None,
        };
        let result = gov.evaluate(&req);
        assert!(result.is_denied());
    }

    #[test]
    fn test_developer_forensic_allowed() {
        let gov = SurfaceGovernance::new();
        let req = SurfaceAccessRequest {
            actor: "user-1".into(),
            role: Role::Developer,
            surface_type: SurfaceType::Agent,
            view: SurfaceView::Forensic,
            subject_id: "agent-001".into(),
            namespace: None,
            time_travel: false,
            export_format: None,
        };
        let result = gov.evaluate(&req);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_export_requires_approval() {
        let gov = SurfaceGovernance::new();
        let req = SurfaceAccessRequest {
            actor: "user-1".into(),
            role: Role::Developer,
            surface_type: SurfaceType::Agent,
            view: SurfaceView::Summary,
            subject_id: "agent-001".into(),
            namespace: None,
            time_travel: false,
            export_format: Some("pdf".into()),
        };
        let result = gov.evaluate(&req);
        assert!(result.requires_approval);
    }
}
