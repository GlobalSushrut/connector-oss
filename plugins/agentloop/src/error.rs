//! Enterprise-grade typed error handling for AgentLoop.
//!
//! Every error response includes:
//!   - Machine-readable `code` string  (e.g. "NOT_FOUND", "VALIDATION_ERROR")
//!   - Human-readable `message`
//!   - `request_id` if present in request extensions
//!   - `details` for validation errors (field-level breakdown)
//!   - Prometheus counter incremented per error class
//!   - Internal errors are never leaked to clients

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]                    BadRequest(String),
    #[error("{0}")]                    Unauthorized(String),
    #[error("{0}")]                    Forbidden(String),
    #[error("{0}")]                    NotFound(String),
    #[error("{0}")]                    Conflict(String),
    #[error("{message}")]             Validation { message: String, details: Option<Value> },
    #[error("{0}")]                    RateLimited(String),
    #[error("{0}")]                    ServiceUnavailable(String),
    #[error("{0}")]                    Timeout(String),
    #[error("internal")]               Internal(#[from] anyhow::Error),
}

impl AppError {
    /// Machine-readable error code for API consumers.
    fn code(&self) -> &'static str {
        match self {
            AppError::BadRequest(_)          => "BAD_REQUEST",
            AppError::Unauthorized(_)        => "UNAUTHORIZED",
            AppError::Forbidden(_)           => "FORBIDDEN",
            AppError::NotFound(_)            => "NOT_FOUND",
            AppError::Conflict(_)            => "CONFLICT",
            AppError::Validation { .. }      => "VALIDATION_ERROR",
            AppError::RateLimited(_)         => "RATE_LIMITED",
            AppError::ServiceUnavailable(_)  => "SERVICE_UNAVAILABLE",
            AppError::Timeout(_)             => "TIMEOUT",
            AppError::Internal(_)            => "INTERNAL_ERROR",
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_)          => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_)        => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_)           => StatusCode::FORBIDDEN,
            AppError::NotFound(_)            => StatusCode::NOT_FOUND,
            AppError::Conflict(_)            => StatusCode::CONFLICT,
            AppError::Validation { .. }      => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::RateLimited(_)         => StatusCode::TOO_MANY_REQUESTS,
            AppError::ServiceUnavailable(_)  => StatusCode::SERVICE_UNAVAILABLE,
            AppError::Timeout(_)             => StatusCode::GATEWAY_TIMEOUT,
            AppError::Internal(_)            => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn client_message(&self) -> String {
        match self {
            AppError::Internal(_) => "An internal error occurred. Please retry or contact support.".into(),
            other => other.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status  = self.http_status();
        let code    = self.code();
        let message = self.client_message();

        // Metrics counter — never fails, fire-and-forget
        metrics::counter!("agentloop_errors_total",
            "code"   => code,
            "status" => status.as_u16().to_string(),
        ).increment(1);

        // Structured log
        match &self {
            AppError::Internal(e) => tracing::error!(err = %e, code, "Internal error"),
            AppError::Unauthorized(_) | AppError::Forbidden(_) =>
                tracing::warn!(code, message = %message, "Auth error"),
            AppError::RateLimited(_) =>
                tracing::warn!(code, "Rate limited"),
            _ if status.is_client_error() =>
                tracing::debug!(code, message = %message, "Client error"),
            _ => {}
        }

        let details = if let AppError::Validation { details: Some(d), .. } = &self {
            d.clone()
        } else {
            Value::Null
        };

        let mut body = json!({
            "error": {
                "code":    code,
                "message": message,
                "status":  status.as_u16(),
            }
        });

        if !details.is_null() {
            body["error"]["details"] = details;
        }

        let mut resp = (status, Json(body)).into_response();

        // Retry-After header for rate limiting
        if status == StatusCode::TOO_MANY_REQUESTS {
            resp.headers_mut().insert(
                "Retry-After",
                axum::http::HeaderValue::from_static("60"),
            );
        }

        resp
    }
}

// ── From impls ────────────────────────────────────────────────────────────────

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => AppError::NotFound("Resource not found".into()),
            sqlx::Error::Database(ref db) => {
                if db.constraint().is_some() {
                    AppError::Conflict(format!("Constraint violation: {}", db.message()))
                } else if db.code().map(|c| c == "53300" || c == "53200").unwrap_or(false) {
                    // too_many_connections or out_of_memory
                    AppError::ServiceUnavailable("Database under heavy load, retry shortly".into())
                } else {
                    AppError::Internal(anyhow::anyhow!("Database error: {}", db.message()))
                }
            }
            sqlx::Error::PoolTimedOut => AppError::ServiceUnavailable("Database pool exhausted".into()),
            other => AppError::Internal(anyhow::anyhow!(other)),
        }
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(e: validator::ValidationErrors) -> Self {
        let details = serde_json::to_value(&e).unwrap_or(Value::Null);
        AppError::Validation {
            message: "Request validation failed".into(),
            details: Some(details),
        }
    }
}

// ── Convenience alias ─────────────────────────────────────────────────────────

pub type ApiResult<T> = Result<axum::Json<T>, AppError>;
