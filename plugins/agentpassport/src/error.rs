//! Structured error types with CISO-grade error codes.
//! Never leak internal details — all errors serialise to a safe public shape.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("authentication required")]
    Unauthorized,

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("connector error: {0}")]
    Connector(String),

    #[error("internal error")]
    Internal(#[from] anyhow::Error),

    #[error("database error")]
    Database(#[from] sqlx::Error),
}

impl From<validator::ValidationErrors> for AppError {
    fn from(e: validator::ValidationErrors) -> Self {
        AppError::Validation(e.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::NotFound(msg)     => (StatusCode::NOT_FOUND,            "NOT_FOUND",            msg.clone()),
            AppError::Validation(msg)   => (StatusCode::UNPROCESSABLE_ENTITY, "VALIDATION_ERROR",     msg.clone()),
            AppError::Unauthorized      => (StatusCode::UNAUTHORIZED,         "UNAUTHORIZED",         "Authentication required".into()),
            AppError::Forbidden(msg)    => (StatusCode::FORBIDDEN,            "FORBIDDEN",            msg.clone()),
            AppError::Conflict(msg)     => (StatusCode::CONFLICT,             "CONFLICT",             msg.clone()),
            AppError::BadRequest(msg)   => (StatusCode::BAD_REQUEST,          "BAD_REQUEST",          msg.clone()),
            AppError::Crypto(msg)       => (StatusCode::INTERNAL_SERVER_ERROR,"CRYPTO_ERROR",         msg.clone()),
            AppError::Connector(msg)    => (StatusCode::BAD_GATEWAY,          "CONNECTOR_ERROR",      msg.clone()),
            AppError::Internal(_)       => (StatusCode::INTERNAL_SERVER_ERROR,"INTERNAL_ERROR",       "An internal error occurred".into()),
            AppError::Database(e) => {
                // Map common constraint names to safe public messages
                let msg = if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
                    "A record with this identifier already exists"
                } else if e.to_string().contains("foreign key") {
                    "Referenced entity does not exist"
                } else {
                    "A database error occurred"
                };
                (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", msg.to_string())
            }
        };

        tracing::error!(
            code = code,
            status = status.as_u16(),
            error = %self,
            "AgentPassport error"
        );

        metrics::counter!("agentpassport_errors_total",
            "code"   => code,
            "status" => status.as_u16().to_string()
        ).increment(1);

        let body = json!({
            "error": {
                "code":    code,
                "message": message,
                "status":  status.as_u16(),
            }
        });

        (status, Json(body)).into_response()
    }
}
