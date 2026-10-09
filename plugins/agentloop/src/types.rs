//! Domain types for AgentLoop — shared across all four modules.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

// ── Shared: Agent ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id:           Uuid,
    pub connector_id: Option<String>,
    pub name:         String,
    pub description:  Option<String>,
    pub team:         Option<String>,
    pub tags:         Vec<String>,
    pub status:       AgentStatus,
    pub metadata:     Value,
    pub created_at:   DateTime<Utc>,
    pub updated_at:   DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus { Active, Archived, Quarantined }

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentStatus::Active      => write!(f, "active"),
            AgentStatus::Archived    => write!(f, "archived"),
            AgentStatus::Quarantined => write!(f, "quarantined"),
        }
    }
}

// ── Shared: Run ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub id:                 Uuid,
    pub connector_run_id:   String,
    pub agent_id:           Option<Uuid>,
    pub prompt_id:          Option<Uuid>,
    pub prompt_version:     Option<i32>,
    pub experiment_id:      Option<Uuid>,
    pub status:             RunStatus,
    pub inputs:             Value,
    pub outputs:            Option<Value>,
    pub model:              Option<String>,
    pub provider:           Option<String>,
    pub total_tokens:       i32,
    pub prompt_tokens:      i32,
    pub completion_tokens:  i32,
    pub cost_usd:           f64,
    pub latency_ms:         i32,
    pub error_message:      Option<String>,
    pub cid:                Option<String>,
    pub started_at:         DateTime<Utc>,
    pub ended_at:           Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RunStatus { Unknown, Running, Completed, Failed, Aborted }

impl std::fmt::Display for RunStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunStatus::Unknown   => write!(f, "unknown"),
            RunStatus::Running   => write!(f, "running"),
            RunStatus::Completed => write!(f, "completed"),
            RunStatus::Failed    => write!(f, "failed"),
            RunStatus::Aborted   => write!(f, "aborted"),
        }
    }
}

// ── Shared: Step ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub id:            Uuid,
    pub run_id:        Uuid,
    pub step_index:    i32,
    pub step_type:     String,
    pub name:          Option<String>,
    pub inputs:        Value,
    pub outputs:       Option<Value>,
    pub model:         Option<String>,
    pub tokens:        i32,
    pub cost_usd:      f64,
    pub latency_ms:    i32,
    pub error_message: Option<String>,
    pub started_at:    Option<DateTime<Utc>>,
    pub ended_at:      Option<DateTime<Utc>>,
}

// ── Module: Design ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prompt {
    pub id:              Uuid,
    pub agent_id:        Option<Uuid>,
    pub name:            String,
    pub description:     Option<String>,
    pub tags:            Vec<String>,
    pub status:          PromptStatus,
    pub current_version: i32,
    pub created_at:      DateTime<Utc>,
    pub updated_at:      DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PromptStatus { Active, Archived, Deprecated }

impl std::fmt::Display for PromptStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { PromptStatus::Active => write!(f, "active"), PromptStatus::Archived => write!(f, "archived"), PromptStatus::Deprecated => write!(f, "deprecated") }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptVersion {
    pub id:              Uuid,
    pub prompt_id:       Uuid,
    pub version:         i32,
    pub system_prompt:   Option<String>,
    pub user_template:   Option<String>,
    pub variables:       Value,
    pub model_config:    Value,
    pub lint_score:      Option<i32>,
    pub lint_issues:     Value,
    pub fingerprint:     String,
    pub author:          Option<String>,
    pub commit_message:  Option<String>,
    pub approval_status: ApprovalStatus,
    pub approved_by:     Option<String>,
    pub approved_at:     Option<DateTime<Utc>>,
    pub created_at:      DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus { Draft, Pending, Approved, Rejected }

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { ApprovalStatus::Draft => write!(f, "draft"), ApprovalStatus::Pending => write!(f, "pending"), ApprovalStatus::Approved => write!(f, "approved"), ApprovalStatus::Rejected => write!(f, "rejected") }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    pub id:          Uuid,
    pub agent_id:    Option<Uuid>,
    pub name:        String,
    pub description: Option<String>,
    pub tags:        Vec<String>,
    pub row_count:   i32,
    pub created_at:  DateTime<Utc>,
    pub updated_at:  DateTime<Utc>,
}

// ── Module: Ship ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Experiment {
    pub id:                      Uuid,
    pub agent_id:                Option<Uuid>,
    pub name:                    String,
    pub description:             Option<String>,
    pub status:                  ExperimentStatus,
    pub variant_control_id:      Option<Uuid>,
    pub variant_treatment_id:    Option<Uuid>,
    pub traffic_split_pct:       i32,
    pub significance_threshold:  f64,
    pub auto_promote:            bool,
    pub winning_variant:         Option<String>,
    pub concluded_at:            Option<DateTime<Utc>>,
    pub promoted_at:             Option<DateTime<Utc>>,
    pub rolled_back_at:          Option<DateTime<Utc>>,
    pub rollback_reason:         Option<String>,
    pub metrics:                 Value,
    pub created_at:              DateTime<Utc>,
    pub updated_at:              DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ExperimentStatus { Draft, Running, Paused, Concluded, RolledBack }

impl std::fmt::Display for ExperimentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExperimentStatus::Draft       => write!(f, "draft"),
            ExperimentStatus::Running     => write!(f, "running"),
            ExperimentStatus::Paused      => write!(f, "paused"),
            ExperimentStatus::Concluded   => write!(f, "concluded"),
            ExperimentStatus::RolledBack  => write!(f, "rolled_back"),
        }
    }
}

// ── Module: Debug ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Replay {
    pub id:               Uuid,
    pub source_run_id:    Uuid,
    pub agent_id:         Option<Uuid>,
    pub status:           ReplayStatus,
    pub substitutions:    Value,
    pub replay_run_id:    Option<Uuid>,
    pub diverged_at_step: Option<i32>,
    pub diff_summary:     Option<Value>,
    pub created_by:       Option<String>,
    pub created_at:       DateTime<Utc>,
    pub completed_at:     Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ReplayStatus { Pending, Running, Completed, Failed }

impl std::fmt::Display for ReplayStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { ReplayStatus::Pending => write!(f, "pending"), ReplayStatus::Running => write!(f, "running"), ReplayStatus::Completed => write!(f, "completed"), ReplayStatus::Failed => write!(f, "failed") }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diff {
    pub id:         Uuid,
    pub diff_type:  String,
    pub left_id:    String,
    pub right_id:   String,
    pub diff_json:  Value,
    pub summary:    Option<String>,
    pub created_at: DateTime<Utc>,
}

// ── Module: Optimize ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slo {
    pub id:              Uuid,
    pub agent_id:        Uuid,
    pub name:            String,
    pub metric:          String,
    pub threshold:       f64,
    pub window_hours:    i32,
    pub status:          SloStatus,
    pub current_value:   Option<f64>,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub created_at:      DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SloStatus { Healthy, Warning, Breached }

impl std::fmt::Display for SloStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { SloStatus::Healthy => write!(f, "healthy"), SloStatus::Warning => write!(f, "warning"), SloStatus::Breached => write!(f, "breached") }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id:               Uuid,
    pub agent_id:         Option<Uuid>,
    pub rec_type:         String,
    pub title:            String,
    pub description:      String,
    pub impact_tokens:    Option<i32>,
    pub impact_cost_usd:  Option<f64>,
    pub impact_quality:   Option<f64>,
    pub status:           RecStatus,
    pub action_payload:   Value,
    pub applied_by:       Option<String>,
    pub applied_at:       Option<DateTime<Utc>>,
    pub dismissed_at:     Option<DateTime<Utc>>,
    pub created_at:       DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RecStatus { Open, Applied, Dismissed, Snoozed }

impl std::fmt::Display for RecStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { RecStatus::Open => write!(f, "open"), RecStatus::Applied => write!(f, "applied"), RecStatus::Dismissed => write!(f, "dismissed"), RecStatus::Snoozed => write!(f, "snoozed") }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEvent {
    pub id:              Uuid,
    pub agent_id:        Uuid,
    pub drift_type:      String,
    pub severity:        String,
    pub description:     String,
    pub baseline_value:  Option<f64>,
    pub current_value:   Option<f64>,
    pub delta_pct:       Option<f64>,
    pub run_id:          Option<Uuid>,
    pub acknowledged:    bool,
    pub detected_at:     DateTime<Utc>,
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateAgentRequest {
    pub name:         String,
    pub connector_id: Option<String>,
    pub description:  Option<String>,
    pub team:         Option<String>,
    pub tags:         Option<Vec<String>>,
    pub metadata:     Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePromptRequest {
    pub agent_id:      Option<Uuid>,
    pub name:          String,
    pub description:   Option<String>,
    pub tags:          Option<Vec<String>>,
    pub system_prompt: Option<String>,
    pub user_template: Option<String>,
    pub variables:     Option<Value>,
    pub model_config:  Option<Value>,
    pub author:        Option<String>,
    pub commit_message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePromptVersionRequest {
    pub system_prompt:  Option<String>,
    pub user_template:  Option<String>,
    pub variables:      Option<Value>,
    pub model_config:   Option<Value>,
    pub author:         Option<String>,
    pub commit_message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApprovePromptRequest {
    pub approved: bool,
    pub reviewer: String,
    pub reason:   Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateExperimentRequest {
    pub agent_id:                Option<Uuid>,
    pub name:                    String,
    pub description:             Option<String>,
    pub variant_control_id:      Uuid,
    pub variant_treatment_id:    Uuid,
    pub traffic_split_pct:       Option<i32>,
    pub significance_threshold:  Option<f64>,
    pub auto_promote:            Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CreateReplayRequest {
    pub source_run_id:  Uuid,
    pub substitutions:  Option<Value>,
    pub created_by:     Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSloRequest {
    pub agent_id:     Uuid,
    pub name:         String,
    pub metric:       String,
    pub threshold:    f64,
    pub window_hours: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct ApplyRecommendationRequest {
    pub applied_by: String,
}

#[derive(Debug, Deserialize)]
pub struct Pagination {
    pub limit:  Option<i64>,
    pub offset: Option<i64>,
}

impl Pagination {
    pub fn limit(&self)  -> i64 { self.limit.unwrap_or(50).min(200) }
    pub fn offset(&self) -> i64 { self.offset.unwrap_or(0) }
}

// ── Health ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status:    String,
    pub db:        String,
    pub connector: String,
    pub version:   String,
}
