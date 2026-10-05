//! # V2 Simplified API Layer
//!
//! This module provides a simplified, developer-friendly API surface that hides
//! internal complexity while exposing the full power of the Connector platform.
//!
//! ## Design Principles
//! 1. **Kafka/S3-level simplicity** — Every operation should feel as simple as `s3.put_object()`
//! 2. **Smart defaults** — Works out of the box, customizable when needed
//! 3. **Consistent patterns** — Same structure across all resources
//! 4. **Self-documenting** — Responses include hints and next actions
//! 5. **Noob-friendly errors** — Every error tells you exactly what to do
//!
//! ## Route Structure
//! ```text
//! /api/v2/agents          — Agent lifecycle (CRUD + actions)
//! /api/v2/memory          — Memory operations (read/write/search)
//! /api/v2/tools           — Tool registry and invocation
//! /api/v2/sessions        — Session management
//! /api/v2/audit           — Audit log access (OCSF format)
//! /api/v2/health          — Health and maturity scores
//! ```

pub mod agents;
pub mod memory;
pub mod tools;
pub mod sessions;
pub mod audit;
pub mod health;
pub mod exec;
pub mod deploy;
pub mod system;
pub mod registry;
pub mod storage;
pub mod network;
pub mod dns;
pub mod tls;
pub mod router;
pub mod errors;

pub use router::v2_router;
pub use errors::{V2ErrorCode, V2ApiError};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Standard V2 API response envelope
/// 
/// Every response follows this structure for consistency:
/// ```json
/// {
///   "ok": true,
///   "data": { ... },
///   "meta": { "request_id": "...", "next_actions": [...] }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V2Response<T: Serialize> {
    /// Whether the request succeeded
    pub ok: bool,
    /// Response data (present on success)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// Error details (present on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<V2Error>,
    /// Metadata about the response
    pub meta: V2Meta,
}

/// Comprehensive error structure designed for beginners
/// 
/// Every error includes:
/// - What went wrong (message)
/// - Why it went wrong (reason)  
/// - How to fix it (hint + example)
/// - Where to learn more (docs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V2Error {
    /// Machine-readable error code (e.g., "agent_not_found")
    pub code: String,
    
    /// Human-readable message explaining what went wrong
    pub message: String,
    
    /// Why this error occurred (context)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    
    /// Actionable hint on how to fix it
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    
    /// Copy-paste example to fix the issue
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<V2ErrorExample>,
    
    /// Related fields that caused the error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    
    /// Expected value or format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    
    /// Actual value received
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received: Option<String>,
    
    /// Documentation URL
    pub docs: String,
    
    /// Similar successful requests for reference
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub see_also: Vec<String>,
}

/// Copy-paste example to fix an error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V2ErrorExample {
    /// Description of what this example does
    pub description: String,
    
    /// The curl command or code snippet
    pub curl: Option<String>,
    
    /// JSON body example
    pub body: Option<serde_json::Value>,
    
    /// Python SDK example
    #[serde(skip_serializing_if = "Option::is_none")]
    pub python: Option<String>,
}

/// Response metadata with helpful context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V2Meta {
    /// Request ID for tracing (share this when reporting issues)
    pub request_id: String,
    
    /// API version
    pub version: String,
    
    /// Response timestamp (ISO 8601)
    pub timestamp: String,
    
    /// How long the request took (milliseconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    
    /// Suggested next actions - what you can do next
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub next_actions: Vec<NextAction>,
    
    /// Warnings (non-fatal issues)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    
    /// Tips for better usage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip: Option<String>,
}

/// Suggested next action with full context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextAction {
    /// Action name (e.g., "start_agent")
    pub action: String,
    
    /// HTTP method
    pub method: String,
    
    /// Endpoint path (with placeholders filled in)
    pub path: String,
    
    /// What this action does
    pub description: String,
    
    /// Why you might want to do this
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    
    /// Example request body
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example_body: Option<serde_json::Value>,
}

impl<T: Serialize> V2Response<T> {
    pub fn success(data: T) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
            meta: V2Meta::now(),
        }
    }

    pub fn success_with_actions(data: T, actions: Vec<NextAction>) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
            meta: V2Meta::now().with_actions(actions),
        }
    }
}

impl V2Response<()> {
    pub fn error(code: &str, message: &str) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(V2Error {
                code: code.to_string(),
                message: message.to_string(),
                reason: None,
                hint: None,
                example: None,
                field: None,
                expected: None,
                received: None,
                docs: format!("https://connector.ai/docs/errors/{}", code),
                see_also: Vec::new(),
            }),
            meta: V2Meta::now(),
        }
    }

    pub fn error_with_hint(code: &str, message: &str, hint: &str) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(V2Error {
                code: code.to_string(),
                message: message.to_string(),
                reason: None,
                hint: Some(hint.to_string()),
                example: None,
                field: None,
                expected: None,
                received: None,
                docs: format!("https://connector.ai/docs/errors/{}", code),
                see_also: Vec::new(),
            }),
            meta: V2Meta::now(),
        }
    }
}

impl V2Meta {
    pub fn now() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            request_id: format!("req_{:x}", now.as_nanos()),
            version: "2.0".to_string(),
            timestamp: format_iso8601(now.as_millis() as i64),
            duration_ms: None,
            next_actions: Vec::new(),
            warnings: Vec::new(),
            tip: None,
        }
    }

    pub fn with_actions(mut self, actions: Vec<NextAction>) -> Self {
        self.next_actions = actions;
        self
    }
    
    pub fn with_tip(mut self, tip: impl Into<String>) -> Self {
        self.tip = Some(tip.into());
        self
    }
    
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }
    
    pub fn with_duration(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }
}

fn format_iso8601(ms: i64) -> String {
    let secs = ms / 1000;
    let millis = (ms % 1000) as u32;
    let days = secs / 86400;
    let time = secs % 86400;
    let h = time / 3600;
    let m = (time % 3600) / 60;
    let s = time % 60;
    
    let mut year = 1970i64;
    let mut rem = days;
    loop {
        let dy = if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 { 366 } else { 365 };
        if rem < dy { break; }
        rem -= dy;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let dm: [i64; 12] = if leap { [31,29,31,30,31,30,31,31,30,31,30,31] } else { [31,28,31,30,31,30,31,31,30,31,30,31] };
    let mut mon = 1;
    for d in dm { if rem < d { break; } rem -= d; mon += 1; }
    let day = rem + 1;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", year, mon, day, h, m, s, millis)
}

impl<T: Serialize> IntoResponse for V2Response<T> {
    fn into_response(self) -> Response {
        let status = if self.ok { StatusCode::OK } else { StatusCode::BAD_REQUEST };
        (status, Json(self)).into_response()
    }
}
