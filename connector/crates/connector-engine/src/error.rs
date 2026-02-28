//! Engine error types — unified errors across both kernels.

use thiserror::Error;

/// Errors from the Connector Engine (Ring 3).
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Agent already exists: {0}")]
    AgentAlreadyExists(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Pipeline not found: {0}")]
    PipelineNotFound(String),

    #[error("Memory write failed: {0}")]
    MemoryWriteFailed(String),

    #[error("Memory read failed: {0}")]
    MemoryReadFailed(String),

    #[error("RBAC denied: agent '{agent}' cannot perform '{action}' on '{resource}'")]
    RbacDenied {
        agent: String,
        action: String,
        resource: String,
    },

    #[error("Tool not allowed: agent '{agent}' cannot use tool '{tool}'")]
    ToolDenied {
        agent: String,
        tool: String,
    },

    #[error("Budget exceeded: {resource} used {used}/{limit}")]
    BudgetExceeded {
        resource: String,
        used: u64,
        limit: u64,
    },

    #[error("Approval required: action '{action}' requires human approval")]
    ApprovalRequired {
        action: String,
    },

    #[error("Data access denied: agent '{agent}' cannot access data classified as '{classification}'")]
    DataAccessDenied {
        agent: String,
        classification: String,
    },

    #[error("Kernel error: {0}")]
    KernelError(String),

    #[error("Vakya construction failed: {0}")]
    VakyaError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Engine store error: {0}")]
    StoreError(String),

    #[error("Instruction blocked: {0}")]
    InstructionBlocked(String),
}

impl From<serde_json::Error> for EngineError {
    fn from(e: serde_json::Error) -> Self {
        EngineError::SerializationError(e.to_string())
    }
}

/// Result type for engine operations.
pub type EngineResult<T> = Result<T, EngineError>;
