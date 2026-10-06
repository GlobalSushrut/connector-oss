//! Tool Registry and Execution Engine
//!
//! Supports: OpenAI functions, Anthropic tools, OpenFaaS, REST APIs, 
//! custom plugins, and agentic workflows

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod registry;
pub mod executor;
pub mod formats;
pub mod openfaas;
pub mod pipeline;
pub mod ollama;

/// Universal tool definition that normalizes across providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub tool_type: ToolType,
    pub parameters: ToolParameters,
    pub execution: ExecutionConfig,
    pub auth: Option<ToolAuth>,
    pub rate_limit: Option<RateLimit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolType {
    OpenAiFunction,
    AnthropicTool,
    OpenFaasFunction,
    RestApi,
    GraphQl,
    SqlQuery,
    PythonScript,
    Container,
    AgenticWorkflow,
    MCP, // Model Context Protocol
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolParameters {
    pub required: Vec<String>,
    pub properties: serde_json::Value, // JSON Schema
    pub additional_properties: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    /// For REST/GraphQL: endpoint URL
    pub endpoint: Option<String>,
    /// For OpenFaaS: function name
    pub function_name: Option<String>,
    /// For OpenFaaS: gateway URL
    pub gateway_url: Option<String>,
    /// For scripts: code or path
    pub code: Option<String>,
    /// For containers: image reference
    pub container_image: Option<String>,
    /// For agentic: workflow definition
    pub workflow_id: Option<String>,
    /// For MCP: server URL
    pub mcp_server: Option<String>,
    /// HTTP method for REST
    pub method: Option<String>,
    /// Timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Retry configuration
    pub retry: Option<RetryConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolAuth {
    pub auth_type: AuthType,
    pub credentials_source: String, // env, vault, inline
    pub credential_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    Bearer,
    ApiKey,
    Basic,
    OAuth2,
    Mtls,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub burst_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub backoff_ms: u64,
    pub max_backoff_ms: u64,
}

fn default_timeout() -> u64 { 30 }

/// Tool execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool_name: String,
    pub success: bool,
    pub output: ToolOutput,
    pub execution_time_ms: u64,
    pub tokens_consumed: Option<TokenUsage>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolOutput {
    Text(String),
    Json(serde_json::Value),
    Binary(Vec<u8>),
    Stream(String), // Streaming handle
    Error { code: String, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
}

/// Tool call from LLM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
}

/// Pipeline definition for agentic workflows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pipeline {
    pub id: String,
    pub name: String,
    pub description: String,
    pub steps: Vec<PipelineStep>,
    pub triggers: Vec<PipelineTrigger>,
    pub state_management: StateManagement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStep {
    pub id: String,
    pub name: String,
    pub step_type: StepType,
    pub tool: Option<String>,
    pub llm_config: Option<LlmStepConfig>,
    pub condition: Option<StepCondition>,
    pub on_error: ErrorHandling,
    pub next_steps: Vec<String>, // DAG support
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepType {
    LlmCall,
    ToolCall,
    Condition,
    Loop,
    Parallel,
    Wait,
    HumanApproval,
    StateUpdate,
    Webhook,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmStepConfig {
    pub model: String,
    pub system_prompt: Option<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u64>,
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepCondition {
    pub expression: String, // jq-style expression
    pub true_step: String,
    pub false_step: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorHandling {
    Fail,
    Retry { max_attempts: u32 },
    Fallback { step_id: String },
    Continue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineTrigger {
    pub trigger_type: TriggerType,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerType {
    HttpWebhook,
    Schedule,
    MessageQueue,
    Stream,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateManagement {
    pub persistence: bool,
    pub ttl_seconds: Option<u64>,
    pub checkpoint_interval: Option<u64>,
}
