//! Error types for the Gateway

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// Gateway errors
#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),

    #[error("Capability error: {0}")]
    Capability(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Rate limited")]
    RateLimited,

    #[error("Adapter error: {0}")]
    Adapter(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let (status, error_response) = match &self {
            GatewayError::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse {
                    error: "VALIDATION_ERROR".to_string(),
                    message: msg.clone(),
                    details: None,
                },
            ),
            GatewayError::AuthorizationDenied(msg) => (
                StatusCode::FORBIDDEN,
                ErrorResponse {
                    error: "AUTHORIZATION_DENIED".to_string(),
                    message: msg.clone(),
                    details: None,
                },
            ),
            GatewayError::Capability(msg) => (
                StatusCode::FORBIDDEN,
                ErrorResponse {
                    error: "CAPABILITY_ERROR".to_string(),
                    message: msg.clone(),
                    details: None,
                },
            ),
            GatewayError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                ErrorResponse {
                    error: "NOT_FOUND".to_string(),
                    message: msg.clone(),
                    details: None,
                },
            ),
            GatewayError::Conflict(msg) => (
                StatusCode::CONFLICT,
                ErrorResponse {
                    error: "CONFLICT".to_string(),
                    message: msg.clone(),
                    details: None,
                },
            ),
            GatewayError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorResponse {
                    error: "RATE_LIMITED".to_string(),
                    message: "Too many requests".to_string(),
                    details: None,
                },
            ),
            GatewayError::Adapter(msg) => (
                StatusCode::BAD_GATEWAY,
                ErrorResponse {
                    error: "ADAPTER_ERROR".to_string(),
                    message: msg.clone(),
                    details: None,
                },
            ),
            GatewayError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse {
                    error: "INTERNAL_ERROR".to_string(),
                    message: msg.clone(),
                    details: None,
                },
            ),
            GatewayError::Database(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorResponse {
                    error: "DATABASE_ERROR".to_string(),
                    message: msg.clone(),
                    details: None,
                },
            ),
            GatewayError::Serialization(e) => (
                StatusCode::BAD_REQUEST,
                ErrorResponse {
                    error: "SERIALIZATION_ERROR".to_string(),
                    message: e.to_string(),
                    details: None,
                },
            ),
        };

        (status, Json(error_response)).into_response()
    }
}

/// Error response body
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

pub type GatewayResult<T> = Result<T, GatewayError>;
