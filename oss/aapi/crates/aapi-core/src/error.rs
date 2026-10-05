//! Error types for AAPI Core

use thiserror::Error;

/// Core errors that can occur during AAPI operations
#[derive(Error, Debug)]
pub enum AapiError {
    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Canonicalization error: {0}")]
    Canonicalization(String),

    #[error("Schema error: {0}")]
    Schema(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid field value for '{field}': {reason}")]
    InvalidField { field: String, reason: String },

    #[error("Capability error: {0}")]
    Capability(String),

    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("Budget exceeded: {resource} used {used}, limit {limit}")]
    BudgetExceeded {
        resource: String,
        used: u64,
        limit: u64,
    },

    #[error("TTL expired: expired at {expired_at}")]
    TtlExpired { expired_at: String },

    #[error("Scope violation: action '{action}' not in allowed scope")]
    ScopeViolation { action: String },

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias for AAPI operations
pub type AapiResult<T> = Result<T, AapiError>;

/// Reason codes for PRAMĀṆA receipts
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    /// Action completed successfully
    Success,
    /// Action completed with partial success
    PartialSuccess,
    /// Action failed due to validation error
    ValidationFailed,
    /// Action denied due to authorization
    AuthorizationDenied,
    /// Action denied due to capability scope
    ScopeViolation,
    /// Action denied due to budget exhaustion
    BudgetExceeded,
    /// Action denied due to TTL expiration
    TtlExpired,
    /// Action denied by MetaRule policy
    PolicyDenied,
    /// Action requires human approval
    ApprovalRequired,
    /// Action failed due to adapter error
    AdapterError,
    /// Action failed due to target system error
    TargetError,
    /// Action timed out
    Timeout,
    /// Action was cancelled
    Cancelled,
    /// Internal system error
    InternalError,
}

impl ReasonCode {
    /// Returns true if this is a success code
    pub fn is_success(&self) -> bool {
        matches!(self, ReasonCode::Success | ReasonCode::PartialSuccess)
    }

    /// Returns true if this is a denial code
    pub fn is_denial(&self) -> bool {
        matches!(
            self,
            ReasonCode::AuthorizationDenied
                | ReasonCode::ScopeViolation
                | ReasonCode::BudgetExceeded
                | ReasonCode::TtlExpired
                | ReasonCode::PolicyDenied
        )
    }

    /// Returns true if this requires human intervention
    pub fn requires_human(&self) -> bool {
        matches!(self, ReasonCode::ApprovalRequired)
    }
}
