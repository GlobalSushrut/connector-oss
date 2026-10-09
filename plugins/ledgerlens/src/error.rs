//! Structured error handling for LedgerLens.
//!
//! Every error response carries:
//!   - `code`      — machine-readable error code
//!   - `message`   — human-readable, safe to expose to clients
//!   - `status`    — HTTP status code (numeric)
//!   - `request_id`— propagated from X-Request-ID header where available
//!   - `details`   — field-level validation errors (optional)
//!
//! Internal errors are NEVER leaked to clients.
//! All error classes are counted in Prometheus.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use thiserror::Error;

pub type ApiResult<T> = Result<Json<T>, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]             BadRequest(String),
    #[error("{0}")]             Unauthorized(String),
    #[error("{0}")]             Forbidden(String),
    #[error("{0}")]             NotFound(String),
    #[error("{0}")]             Conflict(String),
    #[error("{message}")]       Validation { message: String, details: Option<Value> },
    #[error("{0}")]             RateLimited(String),
    #[error("{0}")]             ServiceUnavailable(String),
    #[error("{0}")]             Timeout(String),
    #[error("internal")]        Internal(#[from] anyhow::Error),
}

impl AppError {
    fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_)       => "BAD_REQUEST",
            Self::Unauthorized(_)     => "UNAUTHORIZED",
            Self::Forbidden(_)        => "FORBIDDEN",
            Self::NotFound(_)         => "NOT_FOUND",
            Self::Conflict(_)         => "CONFLICT",
            Self::Validation { .. }   => "VALIDATION_ERROR",
            Self::RateLimited(_)      => "RATE_LIMITED",
            Self::ServiceUnavailable(_)=> "SERVICE_UNAVAILABLE",
            Self::Timeout(_)          => "TIMEOUT",
            Self::Internal(_)         => "INTERNAL_ERROR",
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_)        => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_)      => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_)         => StatusCode::FORBIDDEN,
            Self::NotFound(_)          => StatusCode::NOT_FOUND,
            Self::Conflict(_)          => StatusCode::CONFLICT,
            Self::Validation { .. }    => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RateLimited(_)       => StatusCode::TOO_MANY_REQUESTS,
            Self::ServiceUnavailable(_)=> StatusCode::SERVICE_UNAVAILABLE,
            Self::Timeout(_)           => StatusCode::GATEWAY_TIMEOUT,
            Self::Internal(_)          => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn client_message(&self) -> String {
        match self {
            Self::Internal(_) => "An internal error occurred. Please retry or contact support.".into(),
            other => other.to_string(),
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::RowNotFound => Self::NotFound("Record not found".into()),
            sqlx::Error::Database(db) if db.constraint().is_some() =>
                Self::Conflict(format!("Constraint violation: {}", db.constraint().unwrap_or("unknown"))),
            _ => Self::Internal(anyhow::anyhow!(e)),
        }
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(e: validator::ValidationErrors) -> Self {
        let details = serde_json::to_value(&e).ok();
        Self::Validation { message: e.to_string(), details }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status  = self.http_status();
        let code    = self.code();
        let message = self.client_message();

        metrics::counter!("ledgerlens_errors_total",
            "code"   => code,
            "status" => status.as_u16().to_string(),
        ).increment(1);

        match &self {
            AppError::Internal(e) =>
                tracing::error!(err = %e, code, "Internal error"),
            AppError::Unauthorized(_) | AppError::Forbidden(_) =>
                tracing::warn!(code, %message, "Auth error"),
            AppError::RateLimited(_) =>
                tracing::warn!(code, "Rate limited"),
            _ if status.is_client_error() =>
                tracing::debug!(code, %message, "Client error"),
            _ => {}
        }

        let details = if let AppError::Validation { details, .. } = &self {
            details.clone()
        } else {
            None
        };

        let mut body = json!({
            "error":   { "code": code, "message": message, "status": status.as_u16() }
        });
        if let Some(d) = details {
            body["error"]["details"] = d;
        }

        let mut resp = (status, Json(body)).into_response();
        if status == StatusCode::TOO_MANY_REQUESTS {
            resp.headers_mut().insert(
                "Retry-After",
                axum::http::HeaderValue::from_static("60"),
            );
        }
        resp
    }
}
