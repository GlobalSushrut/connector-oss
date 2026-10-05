//! User-facing types — the minimal set developers need to know.

use serde::{Deserialize, Serialize};
use connector_engine::action::Action;

/// LLM configuration — which model to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// Provider name (e.g., "openai", "anthropic", "deepseek")
    pub provider: String,
    /// Model name (e.g., "gpt-4o", "claude-3.5-sonnet")
    pub model: String,
    /// API key
    pub api_key: String,
    /// Optional custom endpoint
    pub endpoint: Option<String>,
}

/// Memory store configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Connection string (e.g., "sqlite://./memory.db", "postgres://...")
    pub connection: String,
}

/// Tool definition — a function the agent can call.
#[derive(Debug, Clone)]
pub struct ToolDef {
    /// Tool identifier
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// The actual function (stored as a type-erased callback)
    /// In real implementation, this would be a trait object or function pointer.
    /// For now, we track metadata only — actual execution is external.
    pub requires_approval: bool,
}

/// Actor configuration — defines an agent in a pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorDef {
    /// Actor name
    pub name: String,
    /// Role (determines RBAC policy)
    pub role: Option<String>,
    /// Instructions for the LLM
    pub instructions: Option<String>,
    /// Tools this actor can use
    pub allowed_tools: Vec<String>,
    /// Tools explicitly denied
    pub denied_tools: Vec<String>,
    /// Data classifications this actor can access
    pub allowed_data: Vec<String>,
    /// Data classifications denied
    pub denied_data: Vec<String>,
    /// Tools requiring human approval before execution
    pub require_approval: Vec<String>,
    /// Actors whose memory this actor can read
    pub memory_from: Vec<String>,
    /// Typed Action definitions registered to this actor
    #[serde(skip)]
    pub actions: Vec<Action>,
}

impl ActorDef {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            role: None,
            instructions: None,
            allowed_tools: Vec::new(),
            denied_tools: Vec::new(),
            allowed_data: Vec::new(),
            denied_data: Vec::new(),
            require_approval: Vec::new(),
            memory_from: Vec::new(),
            actions: Vec::new(),
        }
    }
}

/// Flow step — defines routing between actors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStep {
    /// Source actor name
    pub from: String,
    /// Target actor name
    pub to: String,
    /// Optional condition (evaluated at runtime)
    pub condition: Option<String>,
}

/// Flow definition — the routing graph between actors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowDef {
    /// First actor to execute
    pub start: String,
    /// Steps in the flow
    pub steps: Vec<FlowStep>,
}
