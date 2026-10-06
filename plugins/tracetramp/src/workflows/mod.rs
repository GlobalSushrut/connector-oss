//! Workflow Engine for agentic pipelines
//!
//! Orchestrates multi-step AI workflows with state management,
//! human-in-the-loop, and tool integration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

pub mod engine;
pub mod state;
pub mod triggers;
pub mod builder;

/// Workflow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub tenant_id: String,
    pub steps: Vec<Step>,
    pub edges: Vec<Edge>,
    pub triggers: Vec<TriggerConfig>,
    pub variables: HashMap<String, VariableDef>,
    pub settings: WorkflowSettings,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub step_type: StepType,
    pub config: StepConfig,
    pub retry_policy: Option<RetryPolicy>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum StepType {
    Llm,
    Tool,
    Condition,
    Loop,
    Parallel,
    Wait,
    Human,
    Webhook,
    Transform,
    Subworkflow,
    Code,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum StepConfig {
    Llm {
        model: String,
        system_prompt: Option<String>,
        temperature: Option<f32>,
        max_tokens: Option<u64>,
        tools: Vec<String>,
        response_schema: Option<serde_json::Value>,
        memory_context: Option<String>,
    },
    Tool {
        tool_name: String,
        parameters: HashMap<String, serde_json::Value>,
    },
    Condition {
        expression: String, // jq expression
        true_branch: String,
        false_branch: String,
    },
    Loop {
        items_expression: String,
        item_var: String,
        subworkflow_id: String,
        max_iterations: u32,
    },
    Parallel {
        branches: Vec<String>,
        aggregation: AggregationType,
    },
    Wait {
        duration_seconds: u64,
        until_timestamp: Option<DateTime<Utc>>,
    },
    Human {
        prompt: String,
        approvers: Vec<String>,
        timeout_seconds: u64,
    },
    Webhook {
        url: String,
        method: String,
        headers: HashMap<String, String>,
        body_template: String,
    },
    Transform {
        mapping: HashMap<String, String>, // output_field -> jq expression
    },
    Subworkflow {
        workflow_id: String,
        input_mapping: HashMap<String, String>,
    },
    Code {
        language: CodeLanguage,
        code: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeLanguage {
    Python,
    JavaScript,
    Rust,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationType {
    Join,
    Merge,
    First,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerConfig {
    #[serde(rename = "type")]
    pub trigger_type: TriggerType,
    pub config: TriggerTypeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerType {
    Http,
    Schedule,
    Webhook,
    Queue,
    Stream,
    Event,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum TriggerTypeConfig {
    Http { path: String, method: String },
    Schedule { cron: String, timezone: String },
    Webhook { provider: String, event_type: String },
    Queue { queue_name: String },
    Stream { stream_name: String },
    Event { event_type: String, filter: serde_json::Value },
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableDef {
    #[serde(rename = "type")]
    pub var_type: String,
    pub default: Option<serde_json::Value>,
    pub required: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkflowSettings {
    pub checkpoint_interval: u64,
    pub max_execution_time: u64,
    pub enable_debug_logging: bool,
    pub failure_handling: FailureHandling,
    pub concurrency_limit: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureHandling {
    #[default]
    Fail,
    Retry,
    Continue,
    Alert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub backoff_multiplier: f64,
    pub retryable_errors: Vec<String>,
}

/// Workflow execution instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRun {
    pub id: String,
    pub workflow_id: String,
    pub tenant_id: String,
    pub status: RunStatus,
    pub input: serde_json::Value,
    pub output: Option<serde_json::Value>,
    pub step_results: HashMap<String, StepResult>,
    pub current_step: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Pending,
    Running,
    WaitingHuman,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: String,
    pub status: StepExecutionStatus,
    pub input: serde_json::Value,
    pub output: Option<serde_json::Value>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub execution_time_ms: u64,
    pub attempts: u32,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
    Waiting,
}
