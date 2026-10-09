//! Domain types for Conductor — all DB-mapped and API-serializable.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

// ── Pipeline ──────────────────────────────────────────────────────────────────

/// A versioned pipeline definition stored in the DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pipeline {
    pub id: Uuid,
    pub name: String,
    pub version: i32,
    pub yaml_source: String,
    pub compiled_json: Value,
    pub status: PipelineStatus,
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "text")]
#[serde(rename_all = "lowercase")]
pub enum PipelineStatus {
    Active,
    Archived,
}

impl std::fmt::Display for PipelineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineStatus::Active => write!(f, "active"),
            PipelineStatus::Archived => write!(f, "archived"),
        }
    }
}

// ── Pipeline YAML DSL ─────────────────────────────────────────────────────────

/// The YAML DSL that users write. Parsed from raw YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineDsl {
    pub name: String,
    #[serde(default = "default_version_str")]
    pub version: String,
    pub agents: Vec<AgentDef>,
    #[serde(default)]
    pub edges: Vec<EdgeDef>,
    #[serde(default)]
    pub gates: Vec<GateDef>,
    #[serde(default)]
    pub budget: Option<PipelineBudget>,
    #[serde(default)]
    pub description: Option<String>,
}

fn default_version_str() -> String { "v1".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDef {
    pub id: String,
    pub role: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub budget: Option<AgentBudget>,
    #[serde(default)]
    pub system_prompt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeDef {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub when: Option<String>,
    #[serde(default)]
    pub schema: Option<Value>,
    #[serde(default)]
    pub hitl: Option<HitlConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitlConfig {
    #[serde(default)]
    pub required_if: Option<String>,
    pub reviewers: Vec<String>,
    #[serde(default)]
    pub timeout_minutes: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateDef {
    #[serde(default)]
    pub on_version_promote: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBudget {
    #[serde(default)]
    pub per_run: Option<u64>,      // token limit per run
    #[serde(default)]
    pub per_day: Option<u64>,
    #[serde(default)]
    pub max_cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineBudget {
    #[serde(default)]
    pub total_per_run: Option<u64>,
    #[serde(default)]
    pub total_per_day: Option<u64>,
    #[serde(default)]
    pub on_exceed: Option<String>,  // "pause_and_notify" | "abort" | "alert"
}

// ── Run ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub id: Uuid,
    pub pipeline_id: Uuid,
    pub connector_run_id: Option<String>,
    pub status: RunStatus,
    pub inputs: Value,
    pub outputs: Option<Value>,
    pub budget_used_tokens: i64,
    pub budget_used_usd: f64,
    pub parent_run_id: Option<Uuid>,
    pub replay_from_step: Option<i32>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "text")]
#[serde(rename_all = "lowercase")]
pub enum RunStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Aborted,
}

impl std::fmt::Display for RunStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RunStatus::Pending    => "pending",
            RunStatus::Running    => "running",
            RunStatus::Paused     => "paused",
            RunStatus::Completed  => "completed",
            RunStatus::Failed     => "failed",
            RunStatus::Aborted    => "aborted",
        };
        write!(f, "{}", s)
    }
}

// ── Step ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub id: Uuid,
    pub run_id: Uuid,
    pub step_index: i32,
    pub step_name: String,
    pub agent_id: String,
    pub status: StepStatus,
    pub input_json: Value,
    pub output_json: Option<Value>,
    pub schema_valid: Option<bool>,
    pub cost_tokens: i32,
    pub cost_usd: f64,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "text")]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    Running,
    WaitingApproval,
    Completed,
    Failed,
    Skipped,
}

impl std::fmt::Display for StepStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            StepStatus::Pending          => "pending",
            StepStatus::Running          => "running",
            StepStatus::WaitingApproval  => "waiting_approval",
            StepStatus::Completed        => "completed",
            StepStatus::Failed           => "failed",
            StepStatus::Skipped          => "skipped",
        };
        write!(f, "{}", s)
    }
}

// ── Approval ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: Uuid,
    pub run_id: Uuid,
    pub step_id: Uuid,
    pub step_index: i32,
    pub step_name: String,
    pub required_if: Option<String>,
    pub reviewers: Vec<String>,
    pub status: ApprovalStatus,
    pub reviewer: Option<String>,
    pub reason: Option<String>,
    pub requested_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "text")]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ApprovalStatus::Pending   => "pending",
            ApprovalStatus::Approved  => "approved",
            ApprovalStatus::Rejected  => "rejected",
            ApprovalStatus::Expired   => "expired",
        };
        write!(f, "{}", s)
    }
}

// ── Schedule ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schedule {
    pub id: Uuid,
    pub pipeline_id: Uuid,
    pub name: String,
    pub trigger_type: String,
    pub cron_expr: Option<String>,
    pub webhook_token: Option<String>,
    pub default_inputs: Value,
    pub enabled: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ── Gate ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gate {
    pub id: Uuid,
    pub pipeline_id: Uuid,
    pub gate_type: String,
    pub config_json: Value,
    pub required: bool,
    pub created_at: DateTime<Utc>,
}

// ── API request/response types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreatePipelineRequest {
    pub yaml: String,
}

#[derive(Debug, Deserialize)]
pub struct StartRunRequest {
    #[serde(default)]
    pub inputs: Value,
}

#[derive(Debug, Deserialize)]
pub struct ApprovalDecisionRequest {
    pub approved: bool,
    pub reviewer: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReplayRequest {
    #[serde(default)]
    pub new_inputs: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct CreateScheduleRequest {
    pub pipeline_id: Uuid,
    pub name: String,
    #[serde(default = "default_cron_trigger")]
    pub trigger_type: String,
    #[serde(default)]
    pub cron_expr: Option<String>,
    #[serde(default)]
    pub default_inputs: Option<Value>,
}

fn default_cron_trigger() -> String { "cron".into() }

#[derive(Debug, Serialize)]
pub struct RunDetail {
    pub run: Run,
    pub steps: Vec<Step>,
    pub pending_approvals: Vec<Approval>,
}

#[derive(Debug, Serialize)]
pub struct ReceiptChain {
    pub run_id: Uuid,
    pub pipeline_name: String,
    pub pipeline_version: i32,
    pub connector_run_id: Option<String>,
    pub steps: Vec<StepReceipt>,
    pub chain_valid: bool,
    pub root_cid: String,
}

#[derive(Debug, Serialize)]
pub struct StepReceipt {
    pub step_index: i32,
    pub step_name: String,
    pub agent_id: String,
    pub status: String,
    pub cost_tokens: i32,
    pub output_hash: String,
    pub cid: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub db: String,
    pub connector: String,
    pub version: &'static str,
}
