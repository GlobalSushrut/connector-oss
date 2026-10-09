//! Typed error enum with correct HTTP status code mapping.
//! All routes return AppError — never raw anyhow.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum AppError {
    // 400 Bad Request
    #[error("Bad request: {0}")]
    BadRequest(String),

    // 401 Unauthorized
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    // 403 Forbidden
    #[error("Forbidden: {0}")]
    Forbidden(String),

    // 404 Not Found
    #[error("Not found: {0}")]
    NotFound(String),

    // 409 Conflict
    #[error("Conflict: {0}")]
    Conflict(String),

    // 422 Unprocessable
    #[error("Validation error: {0}")]
    Validation(String),

    // 503 Service Unavailable (circuit breaker open, Connector down)
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    // 500 Internal Server Error
    #[error("Internal error: {0}")]
    Internal(anyhow::Error),
}

impl AppError {
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_)        => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_)      => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_)         => StatusCode::FORBIDDEN,
            AppError::NotFound(_)          => StatusCode::NOT_FOUND,
            AppError::Conflict(_)          => StatusCode::CONFLICT,
            AppError::Validation(_)        => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::Internal(_)          => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            AppError::BadRequest(_)        => "BAD_REQUEST",
            AppError::Unauthorized(_)      => "UNAUTHORIZED",
            AppError::Forbidden(_)         => "FORBIDDEN",
            AppError::NotFound(_)          => "NOT_FOUND",
            AppError::Conflict(_)          => "CONFLICT",
            AppError::Validation(_)        => "VALIDATION_ERROR",
            AppError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            AppError::Internal(_)          => "INTERNAL_ERROR",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code   = self.code();
        let msg    = self.to_string();

        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %msg, code, "Internal server error");
        } else {
            tracing::warn!(error = %msg, code, status = status.as_u16(), "Request error");
        }

        (status, Json(json!({
            "error":   code,
            "message": msg,
        }))).into_response()
    }
}

// ── Conversions ───────────────────────────────────────────────────────────────

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        let msg = e.to_string();
        // Map well-known anyhow messages to correct HTTP codes
        if msg.contains("not found") || msg.contains("Not found") {
            return AppError::NotFound(msg);
        }
        if msg.contains("Circuit breaker OPEN") || msg.contains("Service unavailable") {
            return AppError::ServiceUnavailable(msg);
        }
        if msg.contains("already resolved") || msg.contains("not paused") {
            return AppError::Conflict(msg);
        }
        AppError::Internal(e)
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::RowNotFound => AppError::NotFound("Record not found".into()),
            sqlx::Error::Database(db) if db.is_unique_violation() =>
                AppError::Conflict(format!("Duplicate record: {}", db.message())),
            _ => AppError::Internal(e.into()),
        }
    }
}

pub type ApiResult<T> = Result<axum::Json<T>, AppError>;
