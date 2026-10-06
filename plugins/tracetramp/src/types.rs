//! Core types for TraceTramp

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;
use crate::providers::TokenUsage;

/// The canonical request schema that all incoming requests normalize to
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RuntimeExecutionRequest {
    /// Unique request identifier (assigned by gateway)
    #[serde(default = "Uuid::new_v4")]
    pub request_id: Uuid,
    
    /// Trace identifier (carries through full request lifecycle)
    #[serde(default = "Uuid::new_v4")]
    pub trace_id: Uuid,
    
    /// Tenant identifier (from API key resolution)
    pub tenant_id: String,
    
    /// Application identifier
    pub app_id: String,
    
    /// Environment (dev, staging, prod)
    #[serde(default)]
    pub environment: String,
    
    /// Workflow identifier (optional)
    pub workflow_id: Option<String>,
    
    /// Session identifier for context
    pub session_id: Option<String>,
    
    /// Actor (user/system) making the request
    pub actor_id: String,
    
    /// Actor role for RBAC
    pub actor_role: String,
    
    /// Request mode: **Control** (default — meter + filter + quarantine + traces) or **View**
    /// (optional passthrough diagnostics; requires `TRACETRAMP_ALLOW_VIEW_PIPELINE` + header).
    #[serde(default)]
    pub request_mode: RequestMode,
    
    /// Model intent (e.g., "summarize", "code", "analyze"). Not the model id.
    pub model_intent: String,

    /// Provider model id from the request (`gpt-4o`, `deepseek-chat`). Empty when unknown.
    #[serde(default)]
    pub model_id: String,
    
    /// Input payload (normalized from various provider formats)
    pub input_payload: serde_json::Value,
    
    /// Tools requested for this execution
    #[serde(default)]
    pub tools_requested: Vec<String>,
    
    /// Memory scope for context access
    pub memory_scope: Option<String>,
    
    /// Action targets (what systems this might affect)
    #[serde(default)]
    pub action_targets: Vec<String>,
    
    /// Output mode: text, stream, or structured
    #[serde(default)]
    pub output_mode: OutputMode,
    
    /// Budget context for this request
    pub budget_context: BudgetContext,
    
    /// Compliance tags (HIPAA, GDPR, SOC2, etc.)
    #[serde(default)]
    pub compliance_tags: Vec<String>,
    
    /// Execution profile (performance vs cost vs quality)
    #[serde(default)]
    pub execution_profile: String,
    
    /// Policy bundle reference for this request
    #[serde(default)]
    pub policy_bundle: String,

    /// Connector `GET /api/v1/kernel/agents/:pid/status` → `data` object; merged into `trace_events.metadata` (control pipeline).
    #[serde(skip)]
    pub kernel_host_snapshot: Option<serde_json::Value>,

    /// When true, default high-risk HITL classification is skipped (used only for admin-resumed runs).
    #[serde(skip)]
    pub hitl_bypass: bool,

    /// Lab / integration: `X-TraceTramp-Test-Hold: 1` — pause before LLM with a pending approval (semi-auto remediation).
    #[serde(skip)]
    pub test_hold_requested: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestMode {
    /// Passthrough lane; not the serde default — **Control** is default for new payloads.
    View,
    #[default]
    Control,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputMode {
    #[default]
    Text,
    Stream,
    Structured,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Validate)]
pub struct BudgetContext {
    pub max_tokens: Option<u64>,
    pub max_cost_usd: Option<f64>,
    pub priority: Option<u8>, // 1-10, higher = more important
}

/// A runtime event in the execution lifecycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: Uuid,
    pub trace_id: Uuid,
    pub request_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub step: ExecutionStep,
    pub result: StepResult,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStep {
    RequestReceived,
    IdentityResolved,
    PolicyChecked,
    RiskScored,
    RouteSelected,
    MemoryRequested,
    MemoryAllowed,
    MemoryBlocked,
    ToolRequested,
    ToolAllowed,
    ToolBlocked,
    ApprovalRequested,
    ApprovalResolved,
    ProviderCalled,
    ResponseReceived,
    OutputChecked,
    OutputRedacted,
    OutputBlocked,
    ActionExecuted,
    ResponseReleased,
    CostRecorded,
    ReceiptIssued,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepResult {
    Success,
    Allow,
    Block { reason: String },
    Redact { fields: Vec<String> },
    Route { target: String },
    RequireApproval { approvers: Vec<String> },
    Error { message: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Checkpoint,
    Decision,
    Enforcement,
    Observation,
    Error,
}

/// Evidence types from the Evidence Plane
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub trace_id: Uuid,
    pub events: Vec<RuntimeEvent>,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub status: ExecutionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Explain {
    pub request_id: Uuid,
    pub decisions: Vec<DecisionExplanation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionExplanation {
    pub step: ExecutionStep,
    pub result: StepResult,
    pub reason: String,
    pub policy_ref: Option<String>,
    pub score: Option<f64>,
}

/// Raw decision tree capturing LLM's actual decision-making process
/// This is the true moat - evidence of what AI decided and why
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionTree {
    pub trace_id: String,
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub root: DecisionNode,
    pub metadata: DecisionMetadata,
}

/// A node in the decision tree representing one step in AI reasoning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionNode {
    /// Unique ID for this decision step
    pub node_id: String,
    /// Type of decision being made
    pub node_type: DecisionNodeType,
    /// The raw prompt/input sent to LLM (the true evidence)
    pub input: String,
    /// The system prompt/context used
    pub context: Option<String>,
    /// The LLM output/response
    pub output: String,
    /// The action/decision derived from output
    pub action: String,
    /// Model used for this decision
    pub model: String,
    /// Provider (openai, anthropic, etc.)
    pub provider: String,
    /// Tokens consumed
    pub tokens: TokenUsage,
    /// Latency in milliseconds
    pub latency_ms: u64,
    /// Child decisions (for multi-step reasoning)
    pub children: Vec<DecisionNode>,
    /// Decision confidence score (0-1)
    pub confidence: Option<f64>,
    /// Policy checks applied to this decision
    pub policy_checks: Vec<PolicyCheck>,
}

/// Types of decision nodes in the tree
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionNodeType {
    /// Initial user request interpretation
    IntentRecognition,
    /// Tool/function selection decision
    ToolSelection,
    /// Parameter extraction for tools
    ParameterExtraction,
    /// Response generation
    ResponseGeneration,
    /// Safety/policy evaluation
    SafetyCheck,
    /// Final output formatting
    OutputFormatting,
    /// Human approval checkpoint
    HumanCheckpoint,
    /// Error recovery decision
    ErrorRecovery,
    /// Custom decision type
    Custom { name: String },
}

/// Policy check result for a decision node
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    Allow,
    Block,
    Redact,
    Alert,
    RequireApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheck {
    pub policy_id: String,
    pub policy_name: String,
    pub check_type: String,
    pub result: PolicyOutcome,
    pub details: serde_json::Value,
}

/// Metadata about the decision tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionMetadata {
    pub tenant_id: String,
    pub actor_id: String,
    pub app_id: String,
    pub session_id: Option<String>,
    pub workflow_id: Option<String>,
    pub total_tokens: u64,
    pub total_cost_usd: f64,
    pub total_latency_ms: u64,
    pub node_count: usize,
    pub final_outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prove {
    pub request_id: Uuid,
    pub request_hash: String,
    pub policy_hash: String,
    pub chain_status: String,
    pub receipt_count: u32,
    pub tamper_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostRecord {
    pub request_id: Uuid,
    pub trace_id: Uuid,
    pub tenant_id: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cost_usd: f64,
    pub timestamp: DateTime<Utc>,
    pub tags: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Blocked,
    Approved,
    Rejected,
}

/// OpenAI-compatible request/response types for proxy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ToolDefinition>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    #[serde(rename = "type")]
    pub tool_type: String,
    pub function: FunctionDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}
