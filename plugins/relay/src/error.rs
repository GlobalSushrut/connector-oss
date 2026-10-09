use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Validation: {0}")]
    Validation(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Budget exceeded: {0}")]
    BudgetExceeded(String),

    #[error("Admission denied: {0}")]
    AdmissionDenied(String),

    #[error("Function unreachable: {0}")]
    FunctionUnreachable(String),

    #[error("Connector error: {0}")]
    Connector(String),

    #[error("Proxy error: {0}")]
    Proxy(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::NotFound(m)           => (StatusCode::NOT_FOUND,                "RELAY_001_NOT_FOUND",        m.clone()),
            AppError::Validation(m)         => (StatusCode::UNPROCESSABLE_ENTITY,     "RELAY_002_VALIDATION",       m.clone()),
            AppError::Unauthorized          => (StatusCode::UNAUTHORIZED,             "RELAY_003_UNAUTHORIZED",     "Authentication required".into()),
            AppError::Forbidden(m)          => (StatusCode::FORBIDDEN,               "RELAY_004_FORBIDDEN",        m.clone()),
            AppError::Conflict(m)           => (StatusCode::CONFLICT,                "RELAY_005_CONFLICT",         m.clone()),
            AppError::BadRequest(m)         => (StatusCode::BAD_REQUEST,             "RELAY_006_BAD_REQUEST",      m.clone()),
            AppError::BudgetExceeded(m)     => (StatusCode::TOO_MANY_REQUESTS,       "RELAY_007_BUDGET_EXCEEDED",  m.clone()),
            AppError::AdmissionDenied(m)    => (StatusCode::FORBIDDEN,               "RELAY_008_ADMISSION_DENIED", m.clone()),
            AppError::FunctionUnreachable(m)=> (StatusCode::BAD_GATEWAY,            "RELAY_009_UNREACHABLE",      m.clone()),
            AppError::Connector(m)          => (StatusCode::BAD_GATEWAY,            "RELAY_010_CONNECTOR",        m.clone()),
            AppError::Proxy(m)              => (StatusCode::BAD_GATEWAY,            "RELAY_011_PROXY",            m.clone()),
            AppError::Database(e)           => (StatusCode::INTERNAL_SERVER_ERROR,  "RELAY_012_DATABASE",         e.to_string()),
            AppError::Internal(e)           => (StatusCode::INTERNAL_SERVER_ERROR,  "RELAY_013_INTERNAL",         e.to_string()),
        };

        tracing::error!(code = code, error = %message, "AppError");

        metrics::counter!("relay_errors_total",
            "code"   => code,
            "status" => status.as_str().to_owned()
        ).increment(1);

        (status, Json(json!({ "error": code, "message": message }))).into_response()
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(e: validator::ValidationErrors) -> Self {
        AppError::Validation(e.to_string())
    }
}
