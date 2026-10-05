//! Error types for adapters

use thiserror::Error;

/// Adapter errors
#[derive(Error, Debug)]
pub enum AdapterError {
    #[error("Action not supported: {0}")]
    UnsupportedAction(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Effect capture failed: {0}")]
    EffectCapture(String),

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    #[error("Timeout")]
    Timeout,

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type AdapterResult<T> = Result<T, AdapterError>;
