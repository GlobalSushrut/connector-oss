//! V2 API Error System
//!
//! Comprehensive error handling designed for beginners.
//! Every error tells you:
//! 1. What went wrong
//! 2. Why it went wrong
//! 3. How to fix it (with copy-paste examples)
//! 4. Where to learn more

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::fmt;

use super::{V2Error, V2ErrorExample, V2Meta, V2Response};

/// All V2 API error codes with full context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2ErrorCode {
    // =========================================================================
    // Authentication Errors (auth_*)
    // =========================================================================
    AuthMissing,
    AuthInvalid,
    AuthExpired,
    AuthInsufficientScope,
    
    // =========================================================================
    // Agent Errors (agent_*)
    // =========================================================================
    AgentNotFound,
    AgentAlreadyExists,
    AgentNotRunning,
    AgentAlreadyRunning,
    AgentSuspended,
    AgentTerminated,
    AgentNameInvalid,
    AgentNameTooLong,
    AgentLimitReached,
    
    // =========================================================================
    // Memory Errors (memory_*)
    // =========================================================================
    MemoryNotFound,
    MemoryAlreadyExists,
    MemoryTooLarge,
    MemoryInvalidContent,
    MemoryQuotaExceeded,
    MemoryCidInvalid,
    
    // =========================================================================
    // Session Errors (session_*)
    // =========================================================================
    SessionNotFound,
    SessionExpired,
    SessionClosed,
    SessionLimitReached,
    
    // =========================================================================
    // Tool Errors (tool_*)
    // =========================================================================
    ToolNotFound,
    ToolInvocationFailed,
    ToolTimeout,
    ToolParameterMissing,
    ToolParameterInvalid,
    
    // =========================================================================
    // Validation Errors (validation_*)
    // =========================================================================
    ValidationFailed,
    ValidationFieldMissing,
    ValidationFieldInvalid,
    ValidationBodyMissing,
    ValidationBodyInvalid,
    
    // =========================================================================
    // Rate Limiting (rate_*)
    // =========================================================================
    RateLimitExceeded,
    QuotaExceeded,
    
    // =========================================================================
    // Server Errors (server_*)
    // =========================================================================
    ServerError,
    ServerOverloaded,
    ServerMaintenance,
}

impl V2ErrorCode {
    /// Get the string code
    pub fn code(&self) -> &'static str {
        match self {
            // Auth
            Self::AuthMissing => "auth_missing",
            Self::AuthInvalid => "auth_invalid",
            Self::AuthExpired => "auth_expired",
            Self::AuthInsufficientScope => "auth_insufficient_scope",
            
            // Agent
            Self::AgentNotFound => "agent_not_found",
            Self::AgentAlreadyExists => "agent_already_exists",
            Self::AgentNotRunning => "agent_not_running",
            Self::AgentAlreadyRunning => "agent_already_running",
            Self::AgentSuspended => "agent_suspended",
            Self::AgentTerminated => "agent_terminated",
            Self::AgentNameInvalid => "agent_name_invalid",
            Self::AgentNameTooLong => "agent_name_too_long",
            Self::AgentLimitReached => "agent_limit_reached",
            
            // Memory
            Self::MemoryNotFound => "memory_not_found",
            Self::MemoryAlreadyExists => "memory_already_exists",
            Self::MemoryTooLarge => "memory_too_large",
            Self::MemoryInvalidContent => "memory_invalid_content",
            Self::MemoryQuotaExceeded => "memory_quota_exceeded",
            Self::MemoryCidInvalid => "memory_cid_invalid",
            
            // Session
            Self::SessionNotFound => "session_not_found",
            Self::SessionExpired => "session_expired",
            Self::SessionClosed => "session_closed",
            Self::SessionLimitReached => "session_limit_reached",
            
            // Tool
            Self::ToolNotFound => "tool_not_found",
            Self::ToolInvocationFailed => "tool_invocation_failed",
            Self::ToolTimeout => "tool_timeout",
            Self::ToolParameterMissing => "tool_parameter_missing",
            Self::ToolParameterInvalid => "tool_parameter_invalid",
            
            // Validation
            Self::ValidationFailed => "validation_failed",
            Self::ValidationFieldMissing => "validation_field_missing",
            Self::ValidationFieldInvalid => "validation_field_invalid",
            Self::ValidationBodyMissing => "validation_body_missing",
            Self::ValidationBodyInvalid => "validation_body_invalid",
            
            // Rate
            Self::RateLimitExceeded => "rate_limit_exceeded",
            Self::QuotaExceeded => "quota_exceeded",
            
            // Server
            Self::ServerError => "server_error",
            Self::ServerOverloaded => "server_overloaded",
            Self::ServerMaintenance => "server_maintenance",
        }
    }
    
    /// Get HTTP status code
    pub fn status(&self) -> StatusCode {
        match self {
            // Auth - 401/403
            Self::AuthMissing | Self::AuthInvalid | Self::AuthExpired => StatusCode::UNAUTHORIZED,
            Self::AuthInsufficientScope => StatusCode::FORBIDDEN,
            
            // Not Found - 404
            Self::AgentNotFound | Self::MemoryNotFound | Self::SessionNotFound | Self::ToolNotFound => StatusCode::NOT_FOUND,
            
            // Conflict - 409
            Self::AgentAlreadyExists | Self::MemoryAlreadyExists | Self::AgentAlreadyRunning => StatusCode::CONFLICT,
            
            // Precondition - 412
            Self::AgentNotRunning | Self::AgentSuspended | Self::AgentTerminated | 
            Self::SessionExpired | Self::SessionClosed => StatusCode::PRECONDITION_FAILED,
            
            // Validation - 400
            Self::ValidationFailed | Self::ValidationFieldMissing | Self::ValidationFieldInvalid |
            Self::ValidationBodyMissing | Self::ValidationBodyInvalid |
            Self::AgentNameInvalid | Self::AgentNameTooLong |
            Self::MemoryInvalidContent | Self::MemoryCidInvalid |
            Self::ToolParameterMissing | Self::ToolParameterInvalid => StatusCode::BAD_REQUEST,
            
            // Payload too large - 413
            Self::MemoryTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            
            // Rate limit - 429
            Self::RateLimitExceeded | Self::QuotaExceeded |
            Self::AgentLimitReached | Self::SessionLimitReached | Self::MemoryQuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
            
            // Timeout - 504
            Self::ToolTimeout => StatusCode::GATEWAY_TIMEOUT,
            
            // Server - 500/503
            Self::ServerError | Self::ToolInvocationFailed => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ServerOverloaded | Self::ServerMaintenance => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
    
    /// Get default message
    pub fn message(&self) -> &'static str {
        match self {
            Self::AuthMissing => "Authentication required. Please provide an API key or JWT token.",
            Self::AuthInvalid => "Invalid authentication credentials.",
            Self::AuthExpired => "Your authentication token has expired.",
            Self::AuthInsufficientScope => "Your API key doesn't have permission for this action.",
            
            Self::AgentNotFound => "Agent not found. It may have been deleted or never existed.",
            Self::AgentAlreadyExists => "An agent with this name already exists.",
            Self::AgentNotRunning => "This agent is not running. Start it first.",
            Self::AgentAlreadyRunning => "This agent is already running.",
            Self::AgentSuspended => "This agent is suspended. Resume it first.",
            Self::AgentTerminated => "This agent has been terminated and cannot be used.",
            Self::AgentNameInvalid => "Agent name contains invalid characters.",
            Self::AgentNameTooLong => "Agent name is too long (max 64 characters).",
            Self::AgentLimitReached => "You've reached the maximum number of agents for your plan.",
            
            Self::MemoryNotFound => "Memory not found. The CID may be incorrect or the memory was deleted.",
            Self::MemoryAlreadyExists => "A memory with this CID already exists.",
            Self::MemoryTooLarge => "Memory content is too large (max 10MB).",
            Self::MemoryInvalidContent => "Memory content is invalid or malformed.",
            Self::MemoryQuotaExceeded => "Memory quota exceeded. Delete old memories or upgrade your plan.",
            Self::MemoryCidInvalid => "Invalid CID format. CIDs should be content-addressed identifiers.",
            
            Self::SessionNotFound => "Session not found.",
            Self::SessionExpired => "This session has expired. Create a new one.",
            Self::SessionClosed => "This session is closed. Create a new one.",
            Self::SessionLimitReached => "Maximum concurrent sessions reached.",
            
            Self::ToolNotFound => "Tool not found. Check available tools with GET /api/v2/tools.",
            Self::ToolInvocationFailed => "Tool invocation failed.",
            Self::ToolTimeout => "Tool invocation timed out.",
            Self::ToolParameterMissing => "Required tool parameter is missing.",
            Self::ToolParameterInvalid => "Tool parameter has invalid value.",
            
            Self::ValidationFailed => "Request validation failed.",
            Self::ValidationFieldMissing => "Required field is missing.",
            Self::ValidationFieldInvalid => "Field has invalid value.",
            Self::ValidationBodyMissing => "Request body is required.",
            Self::ValidationBodyInvalid => "Request body is invalid JSON.",
            
            Self::RateLimitExceeded => "Rate limit exceeded. Please slow down.",
            Self::QuotaExceeded => "Usage quota exceeded for this billing period.",
            
            Self::ServerError => "An unexpected error occurred. Please try again.",
            Self::ServerOverloaded => "Server is temporarily overloaded. Please retry in a moment.",
            Self::ServerMaintenance => "Server is under maintenance. Please try again later.",
        }
    }
}

/// Rich API error with full context for beginners
#[derive(Debug, Clone)]
pub struct V2ApiError {
    pub code: V2ErrorCode,
    pub message: Option<String>,
    pub reason: Option<String>,
    pub hint: Option<String>,
    pub field: Option<String>,
    pub expected: Option<String>,
    pub received: Option<String>,
    pub example: Option<V2ErrorExample>,
    pub see_also: Vec<String>,
}

impl V2ApiError {
    /// Create a new error from code
    pub fn new(code: V2ErrorCode) -> Self {
        Self {
            code,
            message: None,
            reason: None,
            hint: None,
            field: None,
            expected: None,
            received: None,
            example: None,
            see_also: Vec::new(),
        }
    }
    
    /// Custom message
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }
    
    /// Why this happened
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
    
    /// How to fix it
    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
    
    /// Which field caused the error
    pub fn field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }
    
    /// What was expected
    pub fn expected(mut self, expected: impl Into<String>) -> Self {
        self.expected = Some(expected.into());
        self
    }
    
    /// What was received
    pub fn received(mut self, received: impl Into<String>) -> Self {
        self.received = Some(received.into());
        self
    }
    
    /// Copy-paste example
    pub fn example(mut self, example: V2ErrorExample) -> Self {
        self.example = Some(example);
        self
    }
    
    /// Related resources
    pub fn see_also(mut self, links: Vec<String>) -> Self {
        self.see_also = links;
        self
    }
    
    /// Convert to V2Error
    pub fn to_v2_error(&self) -> V2Error {
        V2Error {
            code: self.code.code().to_string(),
            message: self.message.clone().unwrap_or_else(|| self.code.message().to_string()),
            reason: self.reason.clone(),
            hint: self.hint.clone().or_else(|| self.default_hint()),
            example: self.example.clone().or_else(|| self.default_example()),
            field: self.field.clone(),
            expected: self.expected.clone(),
            received: self.received.clone(),
            docs: format!("https://connector.ai/docs/errors/{}", self.code.code()),
            see_also: self.see_also.clone(),
        }
    }
    
    /// Get default hint for this error code
    fn default_hint(&self) -> Option<String> {
        let hint = match self.code {
            V2ErrorCode::AuthMissing => "Add 'Authorization: Bearer YOUR_API_KEY' header to your request.",
            V2ErrorCode::AuthInvalid => "Check that your API key is correct and hasn't been revoked.",
            V2ErrorCode::AuthExpired => "Get a new token using POST /api/v1/auth/token.",
            V2ErrorCode::AuthInsufficientScope => "Request a new API key with the required scopes.",
            
            V2ErrorCode::AgentNotFound => "List available agents with GET /api/v2/agents to find the correct ID.",
            V2ErrorCode::AgentAlreadyExists => "Use a different name or delete the existing agent first.",
            V2ErrorCode::AgentNotRunning => "Start the agent with POST /api/v2/agents/{id}/start.",
            V2ErrorCode::AgentAlreadyRunning => "The agent is already running. No action needed.",
            V2ErrorCode::AgentSuspended => "Resume the agent with POST /api/v2/agents/{id}/resume.",
            V2ErrorCode::AgentNameInvalid => "Use only letters, numbers, hyphens, and underscores.",
            V2ErrorCode::AgentNameTooLong => "Shorten the name to 64 characters or less.",
            V2ErrorCode::AgentLimitReached => "Delete unused agents or upgrade your plan.",
            
            V2ErrorCode::MemoryNotFound => "Check the CID is correct. List memories with GET /api/v2/memory.",
            V2ErrorCode::MemoryTooLarge => "Split the content into smaller chunks or compress it.",
            V2ErrorCode::MemoryInvalidContent => "Ensure content is valid JSON.",
            V2ErrorCode::MemoryQuotaExceeded => "Delete old memories or upgrade your plan.",
            V2ErrorCode::MemoryCidInvalid => "CIDs are returned when you write memory. Use that exact value.",
            
            V2ErrorCode::SessionNotFound => "Create a new session with POST /api/v2/sessions.",
            V2ErrorCode::SessionExpired => "Create a new session. Sessions expire after 24 hours of inactivity.",
            
            V2ErrorCode::ToolNotFound => "List available tools with GET /api/v2/tools.",
            V2ErrorCode::ToolParameterMissing => "Check the tool's required parameters with GET /api/v2/tools/{id}.",
            V2ErrorCode::ToolTimeout => "Try again. If it keeps timing out, the tool may be overloaded.",
            
            V2ErrorCode::ValidationFieldMissing => "Add the missing field to your request body.",
            V2ErrorCode::ValidationBodyMissing => "Send a JSON body with your request.",
            V2ErrorCode::ValidationBodyInvalid => "Check your JSON syntax. Use a JSON validator if needed.",
            
            V2ErrorCode::RateLimitExceeded => "Wait a few seconds and retry. Check the Retry-After header.",
            V2ErrorCode::QuotaExceeded => "Wait until your quota resets or upgrade your plan.",
            
            V2ErrorCode::ServerError => "This is our fault. Please try again or contact support.",
            V2ErrorCode::ServerOverloaded => "Wait a moment and retry. The server is handling high load.",
            V2ErrorCode::ServerMaintenance => "Check https://status.connector.ai for maintenance updates.",
            
            _ => return None,
        };
        Some(hint.to_string())
    }
    
    /// Get default example for this error code
    fn default_example(&self) -> Option<V2ErrorExample> {
        match self.code {
            V2ErrorCode::AuthMissing => Some(V2ErrorExample {
                description: "Add authentication header".to_string(),
                curl: Some(r#"curl -X GET "https://api.connector.ai/api/v2/agents" \
  -H "Authorization: Bearer YOUR_API_KEY""#.to_string()),
                body: None,
                python: Some(r#"import httpx
client = httpx.Client(headers={"Authorization": "Bearer YOUR_API_KEY"})
response = client.get("https://api.connector.ai/api/v2/agents")"#.to_string()),
            }),
            
            V2ErrorCode::AgentNotFound => Some(V2ErrorExample {
                description: "List agents to find the correct ID".to_string(),
                curl: Some(r#"curl -X GET "https://api.connector.ai/api/v2/agents" \
  -H "Authorization: Bearer YOUR_API_KEY""#.to_string()),
                body: None,
                python: None,
            }),
            
            V2ErrorCode::AgentNotRunning => Some(V2ErrorExample {
                description: "Start the agent first".to_string(),
                curl: Some(r#"curl -X POST "https://api.connector.ai/api/v2/agents/{id}/start" \
  -H "Authorization: Bearer YOUR_API_KEY""#.to_string()),
                body: None,
                python: None,
            }),
            
            V2ErrorCode::ValidationFieldMissing => Some(V2ErrorExample {
                description: "Include all required fields".to_string(),
                curl: None,
                body: Some(serde_json::json!({
                    "name": "my-agent",
                    "description": "Optional description"
                })),
                python: None,
            }),
            
            V2ErrorCode::ValidationBodyMissing => Some(V2ErrorExample {
                description: "Send a JSON body".to_string(),
                curl: Some(r#"curl -X POST "https://api.connector.ai/api/v2/agents" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-agent"}'"#.to_string()),
                body: Some(serde_json::json!({"name": "my-agent"})),
                python: None,
            }),
            
            V2ErrorCode::MemoryNotFound => Some(V2ErrorExample {
                description: "List memories to find the correct CID".to_string(),
                curl: Some(r#"curl -X GET "https://api.connector.ai/api/v2/memory?agent_id=YOUR_AGENT_ID" \
  -H "Authorization: Bearer YOUR_API_KEY""#.to_string()),
                body: None,
                python: None,
            }),
            
            V2ErrorCode::ToolNotFound => Some(V2ErrorExample {
                description: "List available tools".to_string(),
                curl: Some(r#"curl -X GET "https://api.connector.ai/api/v2/tools" \
  -H "Authorization: Bearer YOUR_API_KEY""#.to_string()),
                body: None,
                python: None,
            }),
            
            V2ErrorCode::RateLimitExceeded => Some(V2ErrorExample {
                description: "Implement exponential backoff".to_string(),
                curl: None,
                body: None,
                python: Some(r#"import time
import httpx

def request_with_retry(url, max_retries=3):
    for i in range(max_retries):
        response = httpx.get(url, headers={"Authorization": "Bearer KEY"})
        if response.status_code != 429:
            return response
        wait = int(response.headers.get("Retry-After", 2 ** i))
        time.sleep(wait)
    raise Exception("Max retries exceeded")"#.to_string()),
            }),
            
            _ => None,
        }
    }
}

impl IntoResponse for V2ApiError {
    fn into_response(self) -> Response {
        let status = self.code.status();
        let response: V2Response<()> = V2Response {
            ok: false,
            data: None,
            error: Some(self.to_v2_error()),
            meta: V2Meta::now(),
        };
        (status, Json(response)).into_response()
    }
}

impl fmt::Display for V2ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.code(), self.message.as_ref().unwrap_or(&self.code.message().to_string()))
    }
}

impl std::error::Error for V2ApiError {}

// ============================================================================
// Convenience constructors for common errors
// ============================================================================

impl V2ApiError {
    /// Agent not found
    pub fn agent_not_found(agent_id: &str) -> Self {
        Self::new(V2ErrorCode::AgentNotFound)
            .reason(format!("No agent exists with ID '{}'", agent_id))
            .hint("List available agents with GET /api/v2/agents")
    }
    
    /// Memory not found
    pub fn memory_not_found(cid: &str) -> Self {
        Self::new(V2ErrorCode::MemoryNotFound)
            .reason(format!("No memory exists with CID '{}'", cid))
            .hint("List memories with GET /api/v2/memory?agent_id=YOUR_AGENT")
    }
    
    /// Session not found
    pub fn session_not_found(session_id: &str) -> Self {
        Self::new(V2ErrorCode::SessionNotFound)
            .reason(format!("No session exists with ID '{}'", session_id))
            .hint("Create a new session with POST /api/v2/sessions")
    }
    
    /// Tool not found
    pub fn tool_not_found(tool_id: &str) -> Self {
        Self::new(V2ErrorCode::ToolNotFound)
            .reason(format!("No tool exists with ID '{}'", tool_id))
            .hint("List available tools with GET /api/v2/tools")
    }
    
    /// Missing required field
    pub fn field_missing(field: &str) -> Self {
        Self::new(V2ErrorCode::ValidationFieldMissing)
            .field(field)
            .message(format!("Required field '{}' is missing", field))
            .hint(format!("Add '{}' to your request body", field))
    }
    
    /// Invalid field value
    pub fn field_invalid(field: &str, expected: &str, received: &str) -> Self {
        Self::new(V2ErrorCode::ValidationFieldInvalid)
            .field(field)
            .expected(expected)
            .received(received)
            .message(format!("Field '{}' has invalid value", field))
            .hint(format!("Expected {}, but got '{}'", expected, received))
    }
    
    /// Agent not running
    pub fn agent_not_running(agent_id: &str) -> Self {
        Self::new(V2ErrorCode::AgentNotRunning)
            .reason(format!("Agent '{}' is not currently running", agent_id))
            .hint(format!("Start it with: POST /api/v2/agents/{}/start", agent_id))
    }
    
    /// Rate limited
    pub fn rate_limited(retry_after: u64) -> Self {
        Self::new(V2ErrorCode::RateLimitExceeded)
            .reason("Too many requests in a short period")
            .hint(format!("Wait {} seconds before retrying", retry_after))
    }
    
    /// Server error with context
    pub fn server_error(context: &str) -> Self {
        Self::new(V2ErrorCode::ServerError)
            .reason(context.to_string())
            .hint("Please try again. If the problem persists, contact support with the request_id.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_codes() {
        assert_eq!(V2ErrorCode::AgentNotFound.code(), "agent_not_found");
        assert_eq!(V2ErrorCode::AgentNotFound.status(), StatusCode::NOT_FOUND);
    }
    
    #[test]
    fn test_error_builder() {
        let err = V2ApiError::agent_not_found("test-123");
        let v2_err = err.to_v2_error();
        
        assert_eq!(v2_err.code, "agent_not_found");
        assert!(v2_err.reason.is_some());
        assert!(v2_err.hint.is_some());
    }
    
    #[test]
    fn test_field_missing_error() {
        let err = V2ApiError::field_missing("name");
        let v2_err = err.to_v2_error();
        
        assert_eq!(v2_err.code, "validation_field_missing");
        assert_eq!(v2_err.field, Some("name".to_string()));
        assert!(v2_err.message.contains("name"));
    }
}
