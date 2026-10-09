//! Approval Engine — state machine for actions that need human sign-off.
//!
//! Approvals are persisted to Connector via the audit/store API.
//! The workflow: Action held → Approval created → Approver notified →
//! Approver approves/rejects → Action released/discarded.

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use crate::action::{RiskLevel, CanonicalAction};
use crate::connector_client::ConnectorClient;
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub session_id: String,
    pub identity: String,
    pub role: String,
    pub action_summary: String,
    pub action_detail: serde_json::Value,
    pub risk_level: RiskLevel,
    pub risk_score: u8,
    pub required_from: Vec<String>,
    pub quorum: u32,
    pub timeout_minutes: u32,
    pub escalation_to: Vec<String>,
    pub status: ApprovalStatus,
    pub decisions: Vec<ApprovalDecision>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub approver: String,
    pub decision: ApprovalVerdict,
    pub reason: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalVerdict {
    Approve,
    Reject,
}

impl Approval {
    /// Create a new pending approval.
    pub fn new(
        session_id: &str,
        identity: &str,
        role: &str,
        action: &CanonicalAction,
        risk_level: RiskLevel,
        risk_score: u8,
        required_from: Vec<String>,
        quorum: u32,
    ) -> Self {
        let id = format!("apr_{}", &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]);
        let summary = summarize_action(action);
        let detail = serde_json::to_value(action).unwrap_or_default();

        Self {
            id,
            session_id: session_id.into(),
            identity: identity.into(),
            role: role.into(),
            action_summary: summary,
            action_detail: detail,
            risk_level,
            risk_score,
            required_from,
            quorum: quorum.max(1),
            timeout_minutes: 30,
            escalation_to: vec!["security_lead".into()],
            status: ApprovalStatus::Pending,
            decisions: vec![],
            created_at: Utc::now(),
            resolved_at: None,
        }
    }

    /// Record an approval decision. Returns true if quorum is met.
    pub fn record_decision(&mut self, approver: &str, verdict: ApprovalVerdict, reason: Option<&str>) -> bool {
        self.decisions.push(ApprovalDecision {
            approver: approver.into(),
            decision: verdict.clone(),
            reason: reason.map(|s| s.into()),
            timestamp: Utc::now(),
        });

        match verdict {
            ApprovalVerdict::Reject => {
                self.status = ApprovalStatus::Rejected;
                self.resolved_at = Some(Utc::now());
                false
            }
            ApprovalVerdict::Approve => {
                let approve_count = self.decisions.iter()
                    .filter(|d| d.decision == ApprovalVerdict::Approve)
                    .count() as u32;
                if approve_count >= self.quorum {
                    self.status = ApprovalStatus::Approved;
                    self.resolved_at = Some(Utc::now());
                    true
                } else {
                    false
                }
            }
        }
    }

    pub fn is_resolved(&self) -> bool {
        self.status != ApprovalStatus::Pending
    }
}

/// Persist an approval to Connector store.
pub async fn create_approval(client: &ConnectorClient, approval: &Approval) -> Result<()> {
    // Use audit_record as a generic store endpoint
    client.audit_record(&approval.session_id, &serde_json::json!({
        "type": "approval.created",
        "approval_id": &approval.id,
        "summary": &approval.action_summary,
        "risk": format!("{}", approval.risk_level),
        "required_from": &approval.required_from,
        "timeout_minutes": approval.timeout_minutes,
        "escalation_to": &approval.escalation_to,
        "approval": serde_json::to_value(approval)?,
    })).await?;
    Ok(())
}

/// List pending approvals for a session.
pub async fn list_approvals(client: &ConnectorClient, session_id: Option<&str>) -> Result<Vec<Approval>> {
    // Query via audit trail and filter for approval entries
    let session = session_id.unwrap_or("*");
    let trail = client.audit_trail(session).await?;
    let entries = trail.get("entries").and_then(|v| v.as_array()).cloned().unwrap_or_default();

    let approvals: Vec<Approval> = entries.iter()
        .filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("approval.created"))
        .filter_map(|e| e.get("approval").and_then(|v| serde_json::from_value(v.clone()).ok()))
        .collect();

    Ok(approvals)
}

fn summarize_action(action: &CanonicalAction) -> String {
    match action {
        CanonicalAction::FileWrite { path, lines_changed, .. } =>
            format!("Write {} ({} lines)", path.display(), lines_changed),
        CanonicalAction::FileDelete { path } => format!("Delete {}", path.display()),
        CanonicalAction::CommandExec { command, .. } => format!("Exec: {}", command),
        CanonicalAction::GitOp { operation, args } =>
            format!("Git {:?} {}", operation, args.join(" ")),
        CanonicalAction::DeployAction { command, target, .. } =>
            format!("Deploy: {} → {}", command, target),
        CanonicalAction::PackageInstall { package, manager, .. } =>
            format!("Install {} ({})", package, manager),
        CanonicalAction::SecretAccess { key_name, .. } =>
            format!("Secret access: {}", key_name),
        _ => format!("{:?}", action),
    }
}
