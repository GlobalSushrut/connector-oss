//! Error types for TraceTramp

use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde_json::json;
use thiserror::Error;
use tracing::error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Redis error: {0}")]
    Redis(String),
    
    #[error("Connector proxy error: {0}")]
    ConnectorProxy(String),
    
    #[error("Admission denied: {0}")]
    AdmissionDenied(String),
    
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
    
    #[error("Tenant not found: {0}")]
    TenantNotFound(String),
    
    #[error("Budget exceeded: {0}")]
    BudgetExceeded(String),
    
    #[error("Approval required: {0}")]
    ApprovalRequired(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Bad request: {0}")]
    BadRequest(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Redis(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::ConnectorProxy(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::AdmissionDenied(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::PolicyViolation(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Serialization(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::TenantNotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::BudgetExceeded(msg) => (StatusCode::PAYMENT_REQUIRED, msg.clone()),
            AppError::ApprovalRequired(msg) => (StatusCode::ACCEPTED, msg.clone()), // 202 - requires action
            AppError::RateLimitExceeded => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
        };
        
        error!("Error response: {} - {}", status, error_message);
        
        let body = Json(json!({
            "error": {
                "code": status.as_u16(),
                "message": error_message,
                "type": format!("{:?}", self),
            }
        }));
        
        (status, body).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => AppError::NotFound("Record not found".to_string()),
            _ => AppError::Database(e.to_string()),
        }
    }
}

impl From<redis::RedisError> for AppError {
    fn from(e: redis::RedisError) -> Self {
        AppError::Redis(e.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Serialization(e.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}

impl From<reqwest::Error> for AppError {
    fn from(e: reqwest::Error) -> Self {
        AppError::ConnectorProxy(e.to_string())
    }
}
