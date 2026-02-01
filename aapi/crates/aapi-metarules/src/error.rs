//! Error types for MetaRules

use thiserror::Error;

/// MetaRules errors
#[derive(Error, Debug)]
pub enum MetaRulesError {
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),

    #[error("Rule evaluation failed: {0}")]
    EvaluationFailed(String),

    #[error("Invalid rule: {0}")]
    InvalidRule(String),

    #[error("Context error: {0}")]
    ContextError(String),

    #[error("Approval required: {0}")]
    ApprovalRequired(String),

    #[error("Approval denied: {0}")]
    ApprovalDenied(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Budget exceeded: {0}")]
    BudgetExceeded(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type MetaRulesResult<T> = Result<T, MetaRulesError>;
