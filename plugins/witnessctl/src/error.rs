use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    #[error("Session sealed — no new captures allowed")]
    SessionSealed,

    #[error("Admission denied: {0}")]
    AdmissionDenied(String),

    #[error("Firewall blocked: {0}")]
    FirewallBlocked(String),

    #[error("Connector error: {0}")]
    ConnectorError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("HTTP client error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, raw_message) = match &self {
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.clone()),
            AppError::TooManyRequests(m) => (StatusCode::TOO_MANY_REQUESTS, m.clone()),
            AppError::SessionSealed => (StatusCode::CONFLICT, self.to_string()),
            AppError::AdmissionDenied(m) => (StatusCode::FORBIDDEN, m.clone()),
            AppError::FirewallBlocked(m) => (StatusCode::FORBIDDEN, m.clone()),
            AppError::ConnectorError(m) => (StatusCode::BAD_GATEWAY, m.clone()),
            AppError::DatabaseError(e) => {
                tracing::error!("DB error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
            }
            AppError::HttpError(e) => {
                tracing::error!("HTTP error: {}", e);
                (StatusCode::BAD_GATEWAY, format!("Upstream error: {}", e))
            }
            AppError::Internal(m) => {
                tracing::error!("Internal error: {}", m);
                (StatusCode::INTERNAL_SERVER_ERROR, m.clone())
            }
        };

        let (error_code, message) = if let AppError::BadRequest(_) = &self {
            raw_message
                .split_once('|')
                .map(|(code, msg)| (Some(code.to_string()), msg.to_string()))
                .unwrap_or((None, raw_message))
        } else {
            (None, raw_message)
        };

        (status, Json(json!({ "error": message, "error_code": error_code }))).into_response()
    }
}
