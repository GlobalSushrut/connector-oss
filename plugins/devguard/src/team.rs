//! DevGuard Team Management — Multi-user team governance with role-based access.
//!
//! Team = Tenant. Each team has:
//! - Members with roles (senior, junior, admin)
//! - Projects with isolated data
//! - Agentic capability tracking (who did what, when, with what access)
//! - Central command dashboard

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Unique team identifier (acts as tenant_id)
pub type TeamId = String;

/// Unique member identifier within a team
pub type MemberId = String;

/// Unique project identifier within a team
pub type ProjectId = String;

/// Team roles with different capability levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TeamRole {
    /// Team admin - can manage members, roles, view all activity
    Admin,
    /// Senior member - full access, can approve junior actions
    Senior,
    /// Junior member - restricted access, requires approval for sensitive ops
    Junior,
    /// Observer - read-only access to team activity
    Observer,
}

impl TeamRole {
    /// Role clearance level (higher = more access)
    pub fn clearance(&self) -> u32 {
        match self {
            TeamRole::Admin => 100,
            TeamRole::Senior => 75,
            TeamRole::Junior => 50,
            TeamRole::Observer => 25,
        }
    }

    /// Check if this role can perform an action requiring target clearance
    pub fn can_access(&self, required_clearance: u32) -> bool {
        self.clearance() >= required_clearance
    }

    /// Whether this role can approve actions from other roles
    pub fn can_approve(&self, other: &TeamRole) -> bool {
        self.clearance() > other.clearance()
    }
}

impl Default for TeamRole {
    fn default() -> Self {
        TeamRole::Junior
    }
}

/// Team member with identity and role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    pub id: MemberId,
    pub email: String,
    pub name: String,
    pub role: TeamRole,
    pub joined_at: DateTime<Utc>,
    pub last_active: Option<DateTime<Utc>>,
    /// Identity provider (github, gitlab, okta, local)
    pub provider: String,
    /// External ID from provider
    pub external_id: Option<String>,
    /// Whether member is currently active
    pub active: bool,
    /// API key prefix for audit trails
    pub api_key_prefix: Option<String>,
}

/// Project within a team - isolates data and agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamProject {
    pub id: ProjectId,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: MemberId,
    /// Default role for new members joining this project
    pub default_role: TeamRole,
    /// Project-specific policy overrides
    pub policy_config: Option<serde_json::Value>,
    /// Active agents in this project
    pub active_agents: Vec<String>,
    /// Total actions performed in this project
    pub total_actions: u64,
}

/// Team with members, projects, and settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: TeamId,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub created_by: MemberId,
    pub members: HashMap<MemberId, TeamMember>,
    pub projects: HashMap<ProjectId, TeamProject>,
    /// Default role for new members
    pub default_role: TeamRole,
    /// Whether team requires MFA
    pub require_mfa: bool,
    /// Allowed identity providers
    pub allowed_providers: Vec<String>,
    /// Team-wide budget limit (USD)
    pub budget_limit_usd: Option<f64>,
    /// Data retention days
    pub retention_days: u32,
    /// Custom policy template
    pub policy_template: Option<String>,
}

/// Agentic action performed by a team member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticAction {
    pub id: String,
    pub team_id: TeamId,
    pub project_id: ProjectId,
    pub member_id: MemberId,
    pub member_role: TeamRole,
    pub action_type: ActionType,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    /// Resources accessed (files, commands, etc.)
    pub resources_accessed: Vec<String>,
    /// Whether action was approved (for junior actions requiring approval)
    pub approved: bool,
    pub approved_by: Option<MemberId>,
    /// Policy violations detected
    pub violations: Vec<String>,
    /// Cost in USD
    pub cost_usd: Option<f64>,
    /// Tokens consumed
    pub tokens: Option<u64>,
    /// Session ID for audit trail
    pub session_id: String,
}

/// Types of agentic actions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    FileRead,
    FileWrite,
    FileDelete,
    ShellExecute,
    GitCommit,
    GitPush,
    GitBranch,
    LlmPrompt,
    ToolUse,
    SecretAccess,
    ConfigChange,
    MemberInvite,
    RoleChange,
}

/// Team activity summary for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamActivitySummary {
    pub team_id: TeamId,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_actions: u64,
    pub actions_by_role: HashMap<String, u64>,
    pub actions_by_type: HashMap<String, u64>,
    pub members_active: u32,
    pub projects_active: u32,
    pub violations_detected: u32,
    pub approvals_required: u32,
    pub approvals_given: u32,
    pub cost_usd_total: f64,
    pub top_resources: Vec<(String, u64)>,
}

/// Member capability report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberCapabilityReport {
    pub member_id: MemberId,
    pub member_name: String,
    pub role: TeamRole,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_actions: u64,
    pub actions_by_type: HashMap<String, u64>,
    pub files_accessed: Vec<String>,
    pub commands_executed: Vec<String>,
    pub llm_prompts: u64,
    pub tokens_consumed: u64,
    pub cost_attributed: f64,
    pub violations: Vec<String>,
    pub pending_approvals: Vec<String>,
    pub capabilities_used: Vec<String>,
}

/// Team settings for new teams
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamSettings {
    pub default_role: TeamRole,
    pub require_mfa: bool,
    pub allowed_providers: Vec<String>,
    pub budget_limit_usd: Option<f64>,
    pub retention_days: u32,
    pub auto_approve_senior: bool,
    pub require_approval_for: Vec<String>, // shell, git_push, file_delete, etc.
}

impl Default for TeamSettings {
    fn default() -> Self {
        Self {
            default_role: TeamRole::Junior,
            require_mfa: false,
            allowed_providers: vec!["local".to_string(), "github".to_string()],
            budget_limit_usd: None,
            retention_days: 30,
            auto_approve_senior: true,
            require_approval_for: vec![
                "shell_execute".to_string(),
                "git_push".to_string(),
                "file_delete".to_string(),
            ],
        }
    }
}

/// Command center view for team admins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamCommandCenter {
    pub team: Team,
    pub active_now: Vec<ActiveSessionView>,
    pub recent_actions: Vec<AgenticAction>,
    pub pending_approvals: Vec<PendingApprovalView>,
    pub violations_today: Vec<ViolationView>,
    pub budget_remaining: Option<f64>,
    pub period_summary: TeamActivitySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSessionView {
    pub session_id: String,
    pub member_name: String,
    pub member_role: TeamRole,
    pub project_name: String,
    pub tool: String,
    pub started_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub actions_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApprovalView {
    pub request_id: String,
    pub requested_by: String,
    pub requester_role: TeamRole,
    pub action_type: ActionType,
    pub description: String,
    pub requested_at: DateTime<Utc>,
    pub can_approve: Vec<String>, // member IDs who can approve
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationView {
    pub violation_id: String,
    pub member_name: String,
    pub action_type: ActionType,
    pub violation_type: String,
    pub timestamp: DateTime<Utc>,
    pub severity: String,
    pub auto_blocked: bool,
}

/// Create a new team with initial admin
pub fn create_team(name: &str, admin_email: &str, admin_name: &str) -> (Team, TeamMember) {
    let team_id = uuid::Uuid::new_v4().to_string();
    let admin_id = uuid::Uuid::new_v4().to_string();
    
    let admin = TeamMember {
        id: admin_id.clone(),
        email: admin_email.to_string(),
        name: admin_name.to_string(),
        role: TeamRole::Admin,
        joined_at: Utc::now(),
        last_active: Some(Utc::now()),
        provider: "local".to_string(),
        external_id: None,
        active: true,
        api_key_prefix: None,
    };
    
    let team = Team {
        id: team_id,
        name: name.to_string(),
        created_at: Utc::now(),
        created_by: admin_id.clone(),
        members: {
            let mut m = HashMap::new();
            m.insert(admin_id, admin.clone());
            m
        },
        projects: HashMap::new(),
        default_role: TeamRole::Junior,
        require_mfa: false,
        allowed_providers: vec!["local".to_string()],
        budget_limit_usd: None,
        retention_days: 30,
        policy_template: None,
    };
    
    (team, admin)
}

/// Check if member can perform action based on role and policy
pub fn can_perform_action(
    member: &TeamMember,
    action: &ActionType,
    settings: &TeamSettings,
) -> (bool, Option<String>) {
    // Observers can only read
    if member.role == TeamRole::Observer {
        match action {
            ActionType::FileRead | ActionType::LlmPrompt => return (true, None),
            _ => return (false, Some("Observers have read-only access".to_string())),
        }
    }
    
    // Juniors need approval for sensitive actions
    if member.role == TeamRole::Junior {
        let action_str = format!("{:?}", action).to_lowercase();
        if settings.require_approval_for.iter().any(|s| action_str.contains(s)) {
            return (false, Some("This action requires senior/admin approval".to_string()));
        }
    }
    
    // Check if member is active
    if !member.active {
        return (false, Some("Member account is inactive".to_string()));
    }
    
    (true, None)
}

/// Get capabilities description for a role
pub fn role_capabilities(role: &TeamRole) -> Vec<String> {
    match role {
        TeamRole::Admin => vec![
            "Manage team members and roles".to_string(),
            "View all team activity".to_string(),
            "Configure policies".to_string(),
            "Approve any action".to_string(),
            "Manage projects".to_string(),
            "Full file access".to_string(),
            "Full shell access".to_string(),
        ],
        TeamRole::Senior => vec![
            "Full file access".to_string(),
            "Full shell access".to_string(),
            "Approve junior actions".to_string(),
            "View team activity".to_string(),
            "Create projects".to_string(),
        ],
        TeamRole::Junior => vec![
            "Read files".to_string(),
            "Write files (reviewed)".to_string(),
            "Basic shell commands".to_string(),
            "LLM assistance".to_string(),
            "Request approval for sensitive ops".to_string(),
        ],
        TeamRole::Observer => vec![
            "View files".to_string(),
            "View activity logs".to_string(),
            "Read-only access".to_string(),
        ],
    }
}
