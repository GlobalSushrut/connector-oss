//! Error Code Registry — Standardized error responses
//!
//! This module implements a comprehensive error registry with:
//! - Machine-readable error codes
//! - Human-readable messages
//! - Actionable hints
//! - Documentation URLs
//! - Copy-paste fix examples
//!
//! All API errors should use `ConnectorError` for consistent responses.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// API Version Constants
// =============================================================================

/// Current API version
pub const CURRENT_API_VERSION: u32 = 1;

/// Minimum supported API version
pub const MIN_SUPPORTED_API_VERSION: u32 = 1;

/// Maximum supported API version
pub const MAX_SUPPORTED_API_VERSION: u32 = 1;

// =============================================================================
// Error Codes
// =============================================================================

/// Error code categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    /// Authentication errors (401)
    Auth,
    /// Authorization errors (403)
    Authz,
    /// Validation errors (400)
    Validation,
    /// Not found errors (404)
    NotFound,
    /// Conflict errors (409)
    Conflict,
    /// Rate limit errors (429)
    RateLimit,
    /// Internal errors (500)
    Internal,
    /// Service unavailable (503)
    Unavailable,
    /// API version errors (400)
    Version,
    /// Resource limit errors (429)
    Limit,
}

impl ErrorCategory {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Auth => 401,
            Self::Authz => 403,
            Self::Validation => 400,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::RateLimit => 429,
            Self::Internal => 500,
            Self::Unavailable => 503,
            Self::Version => 400,
            Self::Limit => 429,
        }
    }
}

/// Standard error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    // Auth errors (1xxx)
    AuthMissing,
    AuthInvalid,
    AuthExpired,
    AuthRevoked,
    TokenMalformed,
    TokenExpired,
    
    // Authz errors (2xxx)
    PermissionDenied,
    CapabilityMissing,
    CapabilityExpired,
    ResourceForbidden,
    ActionForbidden,
    
    // Validation errors (3xxx)
    InvalidRequest,
    InvalidJson,
    InvalidField,
    MissingField,
    FieldTooLong,
    FieldTooShort,
    InvalidFormat,
    InvalidPath,
    InvalidCid,
    
    // Not found errors (4xxx)
    AgentNotFound,
    SessionNotFound,
    MemoryNotFound,
    ToolNotFound,
    ResourceNotFound,
    RouteNotFound,
    
    // Conflict errors (5xxx)
    AgentExists,
    SessionExists,
    MemoryExists,
    ConcurrentModification,
    StateConflict,
    
    // Rate limit errors (6xxx)
    RateLimitExceeded,
    QuotaExceeded,
    BudgetExhausted,
    TokenBudgetExceeded,
    
    // Internal errors (7xxx)
    InternalError,
    DatabaseError,
    StorageError,
    KernelError,
    SerializationError,
    
    // Unavailable errors (8xxx)
    ServiceUnavailable,
    MaintenanceMode,
    DependencyUnavailable,
    CircuitOpen,
    
    // Version errors (9xxx)
    ApiVersionUnsupported,
    ApiVersionTooOld,
    ApiVersionTooNew,
    SchemaVersionMismatch,
    
    // Limit errors (10xxx)
    AgentLimitReached,
    SessionLimitReached,
    MemoryLimitReached,
    FileSizeLimitExceeded,
    RequestSizeLimitExceeded,
}

impl ErrorCode {
    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::AuthMissing | Self::AuthInvalid | Self::AuthExpired |
            Self::AuthRevoked | Self::TokenMalformed | Self::TokenExpired => ErrorCategory::Auth,
            
            Self::PermissionDenied | Self::CapabilityMissing | Self::CapabilityExpired |
            Self::ResourceForbidden | Self::ActionForbidden => ErrorCategory::Authz,
            
            Self::InvalidRequest | Self::InvalidJson | Self::InvalidField |
            Self::MissingField | Self::FieldTooLong | Self::FieldTooShort |
            Self::InvalidFormat | Self::InvalidPath | Self::InvalidCid => ErrorCategory::Validation,
            
            Self::AgentNotFound | Self::SessionNotFound | Self::MemoryNotFound |
            Self::ToolNotFound | Self::ResourceNotFound | Self::RouteNotFound => ErrorCategory::NotFound,
            
            Self::AgentExists | Self::SessionExists | Self::MemoryExists |
            Self::ConcurrentModification | Self::StateConflict => ErrorCategory::Conflict,
            
            Self::RateLimitExceeded | Self::QuotaExceeded | Self::BudgetExhausted |
            Self::TokenBudgetExceeded => ErrorCategory::RateLimit,
            
            Self::InternalError | Self::DatabaseError | Self::StorageError |
            Self::KernelError | Self::SerializationError => ErrorCategory::Internal,
            
            Self::ServiceUnavailable | Self::MaintenanceMode |
            Self::DependencyUnavailable | Self::CircuitOpen => ErrorCategory::Unavailable,
            
            Self::ApiVersionUnsupported | Self::ApiVersionTooOld |
            Self::ApiVersionTooNew | Self::SchemaVersionMismatch => ErrorCategory::Version,
            
            Self::AgentLimitReached | Self::SessionLimitReached |
            Self::MemoryLimitReached | Self::FileSizeLimitExceeded |
            Self::RequestSizeLimitExceeded => ErrorCategory::Limit,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuthMissing => "auth_missing",
            Self::AuthInvalid => "auth_invalid",
            Self::AuthExpired => "auth_expired",
            Self::AuthRevoked => "auth_revoked",
            Self::TokenMalformed => "token_malformed",
            Self::TokenExpired => "token_expired",
            Self::PermissionDenied => "permission_denied",
            Self::CapabilityMissing => "capability_missing",
            Self::CapabilityExpired => "capability_expired",
            Self::ResourceForbidden => "resource_forbidden",
            Self::ActionForbidden => "action_forbidden",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidJson => "invalid_json",
            Self::InvalidField => "invalid_field",
            Self::MissingField => "missing_field",
            Self::FieldTooLong => "field_too_long",
            Self::FieldTooShort => "field_too_short",
            Self::InvalidFormat => "invalid_format",
            Self::InvalidPath => "invalid_path",
            Self::InvalidCid => "invalid_cid",
            Self::AgentNotFound => "agent_not_found",
            Self::SessionNotFound => "session_not_found",
            Self::MemoryNotFound => "memory_not_found",
            Self::ToolNotFound => "tool_not_found",
            Self::ResourceNotFound => "resource_not_found",
            Self::RouteNotFound => "route_not_found",
            Self::AgentExists => "agent_exists",
            Self::SessionExists => "session_exists",
            Self::MemoryExists => "memory_exists",
            Self::ConcurrentModification => "concurrent_modification",
            Self::StateConflict => "state_conflict",
            Self::RateLimitExceeded => "rate_limit_exceeded",
            Self::QuotaExceeded => "quota_exceeded",
            Self::BudgetExhausted => "budget_exhausted",
            Self::TokenBudgetExceeded => "token_budget_exceeded",
            Self::InternalError => "internal_error",
            Self::DatabaseError => "database_error",
            Self::StorageError => "storage_error",
            Self::KernelError => "kernel_error",
            Self::SerializationError => "serialization_error",
            Self::ServiceUnavailable => "service_unavailable",
            Self::MaintenanceMode => "maintenance_mode",
            Self::DependencyUnavailable => "dependency_unavailable",
            Self::CircuitOpen => "circuit_open",
            Self::ApiVersionUnsupported => "api_version_unsupported",
            Self::ApiVersionTooOld => "api_version_too_old",
            Self::ApiVersionTooNew => "api_version_too_new",
            Self::SchemaVersionMismatch => "schema_version_mismatch",
            Self::AgentLimitReached => "agent_limit_reached",
            Self::SessionLimitReached => "session_limit_reached",
            Self::MemoryLimitReached => "memory_limit_reached",
            Self::FileSizeLimitExceeded => "file_size_limit_exceeded",
            Self::RequestSizeLimitExceeded => "request_size_limit_exceeded",
        }
    }
}

// =============================================================================
// ConnectorError
// =============================================================================

/// Standard error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorError {
    /// Machine-readable error code (lowercase_snake_case)
    pub code: String,
    /// Human-readable error message
    pub message: String,
    /// Actionable hint for fixing the error
    pub hint: Option<String>,
    /// URL to documentation for this error
    pub docs: Option<String>,
    /// Copy-paste example to fix the error
    pub example: Option<String>,
    /// Additional details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, serde_json::Value>>,
    /// Request ID for tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl ConnectorError {
    pub fn new(code: ErrorCode, message: &str) -> Self {
        Self {
            code: code.as_str().into(),
            message: message.into(),
            hint: None,
            docs: Some(format!("https://docs.connector.dev/errors/{}", code.as_str())),
            example: None,
            details: None,
            request_id: None,
        }
    }

    pub fn with_hint(mut self, hint: &str) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn with_example(mut self, example: &str) -> Self {
        self.example = Some(example.into());
        self
    }

    pub fn with_details(mut self, details: HashMap<String, serde_json::Value>) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_request_id(mut self, request_id: &str) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    pub fn http_status(&self) -> u16 {
        // Parse code to get category
        if self.code.starts_with("auth_") { return 401; }
        if self.code.starts_with("permission_") || self.code.starts_with("capability_") ||
           self.code.starts_with("resource_forbidden") || self.code.starts_with("action_forbidden") { return 403; }
        if self.code.starts_with("invalid_") || self.code.starts_with("missing_") ||
           self.code.starts_with("field_") { return 400; }
        if self.code.ends_with("_not_found") { return 404; }
        if self.code.ends_with("_exists") || self.code.starts_with("concurrent_") ||
           self.code.starts_with("state_") { return 409; }
        if self.code.starts_with("rate_") || self.code.ends_with("_exceeded") ||
           self.code.ends_with("_exhausted") { return 429; }
        if self.code.starts_with("internal_") || self.code.ends_with("_error") { return 500; }
        if self.code.starts_with("service_") || self.code.starts_with("maintenance_") ||
           self.code.starts_with("dependency_") || self.code.starts_with("circuit_") { return 503; }
        if self.code.starts_with("api_version_") || self.code.starts_with("schema_") { return 400; }
        if self.code.ends_with("_limit_reached") { return 429; }
        500
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "error": {
                "code": self.code,
                "message": self.message,
                "hint": self.hint,
                "docs": self.docs,
                "example": self.example,
                "details": self.details,
                "request_id": self.request_id
            }
        })
    }
}

// =============================================================================
// Pre-built Errors
// =============================================================================

impl ConnectorError {
    // Auth errors
    pub fn auth_missing() -> Self {
        Self::new(ErrorCode::AuthMissing, "Authentication required")
            .with_hint("Include an API key in the Authorization header")
            .with_example("curl -H 'Authorization: Bearer YOUR_API_KEY' ...")
    }

    pub fn auth_invalid() -> Self {
        Self::new(ErrorCode::AuthInvalid, "Invalid authentication credentials")
            .with_hint("Check that your API key is correct and active")
    }

    pub fn token_expired() -> Self {
        Self::new(ErrorCode::TokenExpired, "Authentication token has expired")
            .with_hint("Refresh your token or obtain a new one")
    }

    // Authz errors
    pub fn permission_denied(resource: &str) -> Self {
        Self::new(ErrorCode::PermissionDenied, &format!("Permission denied for {}", resource))
            .with_hint("Check that your API key has the required permissions")
    }

    pub fn capability_missing(capability: &str) -> Self {
        Self::new(ErrorCode::CapabilityMissing, &format!("Missing capability: {}", capability))
            .with_hint("Request the required capability in your UCAN token")
    }

    // Validation errors
    pub fn invalid_request(reason: &str) -> Self {
        Self::new(ErrorCode::InvalidRequest, &format!("Invalid request: {}", reason))
    }

    pub fn invalid_json(error: &str) -> Self {
        Self::new(ErrorCode::InvalidJson, &format!("Invalid JSON: {}", error))
            .with_hint("Check that your request body is valid JSON")
    }

    pub fn missing_field(field: &str) -> Self {
        Self::new(ErrorCode::MissingField, &format!("Missing required field: {}", field))
            .with_hint(&format!("Include '{}' in your request", field))
    }

    pub fn invalid_field(field: &str, reason: &str) -> Self {
        Self::new(ErrorCode::InvalidField, &format!("Invalid field '{}': {}", field, reason))
    }

    // Not found errors
    pub fn agent_not_found(agent_id: &str) -> Self {
        Self::new(ErrorCode::AgentNotFound, &format!("Agent not found: {}", agent_id))
            .with_hint("Check that the agent ID is correct and the agent exists")
    }

    pub fn session_not_found(session_id: &str) -> Self {
        Self::new(ErrorCode::SessionNotFound, &format!("Session not found: {}", session_id))
            .with_hint("The session may have expired or been closed")
    }

    pub fn memory_not_found(path: &str) -> Self {
        Self::new(ErrorCode::MemoryNotFound, &format!("Memory not found: {}", path))
            .with_hint("Check that the memory path is correct")
    }

    // Conflict errors
    pub fn agent_exists(agent_id: &str) -> Self {
        Self::new(ErrorCode::AgentExists, &format!("Agent already exists: {}", agent_id))
            .with_hint("Use a different agent ID or update the existing agent")
    }

    pub fn concurrent_modification(resource: &str) -> Self {
        Self::new(ErrorCode::ConcurrentModification, &format!("Concurrent modification of {}", resource))
            .with_hint("Retry the operation with the latest version")
    }

    // Rate limit errors
    pub fn rate_limit_exceeded(limit: u32, window: &str) -> Self {
        Self::new(ErrorCode::RateLimitExceeded, &format!("Rate limit exceeded: {} requests per {}", limit, window))
            .with_hint("Wait before retrying or upgrade your plan for higher limits")
    }

    pub fn token_budget_exceeded(used: u64, limit: u64) -> Self {
        Self::new(ErrorCode::TokenBudgetExceeded, &format!("Token budget exceeded: {} / {}", used, limit))
            .with_hint("Increase your token budget or wait for the next billing period")
    }

    // Internal errors
    pub fn internal(message: &str) -> Self {
        Self::new(ErrorCode::InternalError, message)
            .with_hint("This is a server error. Please try again or contact support.")
    }

    pub fn database_error(message: &str) -> Self {
        Self::new(ErrorCode::DatabaseError, &format!("Database error: {}", message))
    }

    // Version errors
    pub fn api_version_unsupported(version: u32) -> Self {
        Self::new(ErrorCode::ApiVersionUnsupported, &format!("API version {} is not supported", version))
            .with_hint(&format!("Use API version {} to {}", MIN_SUPPORTED_API_VERSION, MAX_SUPPORTED_API_VERSION))
            .with_example(&format!("{{ \"api_version\": {} }}", CURRENT_API_VERSION))
    }

    pub fn api_version_too_old(version: u32) -> Self {
        Self::new(ErrorCode::ApiVersionTooOld, &format!("API version {} is too old", version))
            .with_hint(&format!("Minimum supported version is {}", MIN_SUPPORTED_API_VERSION))
    }

    pub fn api_version_too_new(version: u32) -> Self {
        Self::new(ErrorCode::ApiVersionTooNew, &format!("API version {} is not yet supported", version))
            .with_hint(&format!("Maximum supported version is {}", MAX_SUPPORTED_API_VERSION))
    }

    // Limit errors
    pub fn agent_limit_reached(current: u32, limit: u32) -> Self {
        Self::new(ErrorCode::AgentLimitReached, &format!("Agent limit reached: {} / {}", current, limit))
            .with_hint("Delete unused agents or upgrade your plan")
    }
}

// =============================================================================
// Versioned Syscall Request
// =============================================================================

/// Versioned syscall request wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedSyscallRequest<T> {
    /// API version
    pub api_version: u32,
    /// Request payload
    pub payload: T,
}

impl<T> VersionedSyscallRequest<T> {
    pub fn new(payload: T) -> Self {
        Self {
            api_version: CURRENT_API_VERSION,
            payload,
        }
    }

    pub fn with_version(mut self, version: u32) -> Self {
        self.api_version = version;
        self
    }

    /// Check if version is supported
    pub fn check_version(&self) -> Result<(), ConnectorError> {
        if self.api_version < MIN_SUPPORTED_API_VERSION {
            return Err(ConnectorError::api_version_too_old(self.api_version));
        }
        if self.api_version > MAX_SUPPORTED_API_VERSION {
            return Err(ConnectorError::api_version_too_new(self.api_version));
        }
        Ok(())
    }
}

// =============================================================================
// Grouped Syscall Payloads
// =============================================================================

/// Agent lifecycle operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AgentLifecycleOp {
    Register { name: String, config: Option<serde_json::Value> },
    Boot { agent_id: String },
    Start { agent_id: String },
    Suspend { agent_id: String },
    Resume { agent_id: String },
    Terminate { agent_id: String },
}

/// Memory operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum MemoryOp {
    Write { path: String, content: serde_json::Value },
    Read { path: String },
    Evict { path: String },
    Seal { path: String },
    Clear { path: String },
    Alloc { size: u64 },
}

/// Session operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SessionOp {
    Create { agent_id: String, config: Option<serde_json::Value> },
    Close { session_id: String },
    Compress { session_id: String },
}

/// Access control operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AccessControlOp {
    Grant { subject: String, capability: String, expires_at: Option<i64> },
    Revoke { subject: String, capability: String },
    Check { subject: String, capability: String },
}

/// Grouped syscall payload
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "category", rename_all = "snake_case")]
pub enum GroupedSyscallPayload {
    AgentLifecycle(AgentLifecycleOp),
    Memory(MemoryOp),
    Session(SessionOp),
    AccessControl(AccessControlOp),
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_category() {
        assert_eq!(ErrorCode::AuthMissing.category(), ErrorCategory::Auth);
        assert_eq!(ErrorCode::PermissionDenied.category(), ErrorCategory::Authz);
        assert_eq!(ErrorCode::InvalidRequest.category(), ErrorCategory::Validation);
        assert_eq!(ErrorCode::AgentNotFound.category(), ErrorCategory::NotFound);
        assert_eq!(ErrorCode::AgentExists.category(), ErrorCategory::Conflict);
        assert_eq!(ErrorCode::RateLimitExceeded.category(), ErrorCategory::RateLimit);
        assert_eq!(ErrorCode::InternalError.category(), ErrorCategory::Internal);
        assert_eq!(ErrorCode::ServiceUnavailable.category(), ErrorCategory::Unavailable);
        assert_eq!(ErrorCode::ApiVersionUnsupported.category(), ErrorCategory::Version);
        assert_eq!(ErrorCode::AgentLimitReached.category(), ErrorCategory::Limit);
    }

    #[test]
    fn test_connector_error() {
        let err = ConnectorError::auth_missing();
        assert_eq!(err.code, "auth_missing");
        assert_eq!(err.http_status(), 401);
        assert!(err.hint.is_some());
        assert!(err.example.is_some());
    }

    #[test]
    fn test_connector_error_json() {
        let err = ConnectorError::agent_not_found("agent-123");
        let json = err.to_json();
        
        assert_eq!(json["error"]["code"], "agent_not_found");
        assert!(json["error"]["message"].as_str().unwrap().contains("agent-123"));
    }

    #[test]
    fn test_versioned_request() {
        let req = VersionedSyscallRequest::new("test payload");
        assert_eq!(req.api_version, CURRENT_API_VERSION);
        assert!(req.check_version().is_ok());

        let old_req = VersionedSyscallRequest::new("test").with_version(0);
        assert!(old_req.check_version().is_err());
    }

    #[test]
    fn test_grouped_syscall_payload() {
        let payload = GroupedSyscallPayload::AgentLifecycle(
            AgentLifecycleOp::Register {
                name: "test-agent".into(),
                config: None,
            }
        );

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("agent_lifecycle"));
        assert!(json.contains("register"));
    }

    #[test]
    fn test_api_version_constants() {
        assert!(CURRENT_API_VERSION >= MIN_SUPPORTED_API_VERSION);
        assert!(CURRENT_API_VERSION <= MAX_SUPPORTED_API_VERSION);
    }
}
