//! GlueError - Canonical error envelope

use crate::result::ResultMeta;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Canonical error from any GLUE operation
#[derive(Debug, Clone, Error, Serialize, Deserialize)]
#[error("{message}")]
pub struct GlueError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, alias = "hint", skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default)]
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlueErrorEnvelope {
    pub ok: bool,
    pub error: GlueError,
    #[serde(default)]
    pub meta: ResultMeta,
}

/// Standard error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // Auth/Access
    AuthRequired,
    AccessDenied,
    QuotaReached,
    PolicyViolation,
    // Resource
    NotFound,
    AlreadyExists,
    InvalidState,
    // Contract
    CompileError,
    ValidationError,
    ExecutionError,
    // Input
    InvalidInput,
    MissingRequired,
    TypeMismatch,
    // System
    InternalError,
    Timeout,
    Unavailable,
}

impl GlueError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            detail: None,
            hints: Vec::new(),
            docs: None,
            status: None,
            retryable: false,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hints.push(hint.into());
        self
    }

    pub fn with_docs(mut self, url: impl Into<String>) -> Self {
        self.docs = Some(url.into());
        self
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    pub fn into_envelope(self) -> GlueErrorEnvelope {
        GlueErrorEnvelope {
            ok: false,
            error: self,
            meta: ResultMeta::default(),
        }
    }

    // Convenience constructors
    pub fn not_found(what: &str) -> Self {
        Self::new(ErrorCode::NotFound, format!("{} not found", what))
    }

    pub fn compile_error(msg: &str) -> Self {
        Self::new(ErrorCode::CompileError, msg)
    }

    pub fn invalid_input(msg: &str) -> Self {
        Self::new(ErrorCode::InvalidInput, msg)
    }

    pub fn policy_violation(policy: &str, reason: &str) -> Self {
        Self::new(
            ErrorCode::PolicyViolation,
            format!("Policy '{}' violated: {}", policy, reason),
        )
    }
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuthRequired => "auth_required",
            Self::AccessDenied => "access_denied",
            Self::QuotaReached => "quota_reached",
            Self::PolicyViolation => "policy_violation",
            Self::NotFound => "not_found",
            Self::AlreadyExists => "already_exists",
            Self::InvalidState => "invalid_state",
            Self::CompileError => "compile_error",
            Self::ValidationError => "validation_error",
            Self::ExecutionError => "execution_error",
            Self::InvalidInput => "invalid_input",
            Self::MissingRequired => "missing_required",
            Self::TypeMismatch => "type_mismatch",
            Self::InternalError => "internal_error",
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
        }
    }
}

impl GlueErrorEnvelope {
    pub fn new(error: GlueError) -> Self {
        error.into_envelope()
    }
}
