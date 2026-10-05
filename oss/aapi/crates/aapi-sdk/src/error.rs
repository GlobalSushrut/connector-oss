//! SDK error types

use thiserror::Error;

/// SDK errors
#[derive(Error, Debug)]
pub enum SdkError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Authorization error: {0}")]
    Authorization(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Gateway error: {code} - {message}")]
    Gateway { code: String, message: String },

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Signing error: {0}")]
    Signing(String),

    #[error("Timeout")]
    Timeout,
}

pub type SdkResult<T> = Result<T, SdkError>;
