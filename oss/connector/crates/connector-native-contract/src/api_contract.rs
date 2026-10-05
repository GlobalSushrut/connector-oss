//! Canonical control API contract types (Phase 3 foundation).
//!
//! Hand-maintained until OpenAPI is generated from route schemas.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const API_ERROR_SCHEMA: &str = "connector.api.error.v1";
pub const API_OPERATION_SCHEMA: &str = "connector.api.operation.v1";

/// Standard structured error envelope for native/control API responses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiErrorEnvelope {
    pub schema: String,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_safe: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

impl ApiErrorEnvelope {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            schema: API_ERROR_SCHEMA.into(),
            code: code.into(),
            message: message.into(),
            phase: None,
            retry_safe: None,
            operation_id: None,
            trace_id: None,
            detail: None,
        }
    }

    pub fn package_gate(honesty: impl Into<String>) -> Self {
        Self::new("package_gate", honesty).with_phase("admission")
    }

    pub fn with_phase(mut self, phase: impl Into<String>) -> Self {
        self.phase = Some(phase.into());
        self
    }

    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn with_retry_safe(mut self, retry_safe: bool) -> Self {
        self.retry_safe = Some(retry_safe);
        self
    }

    /// HTTP body: `{ "ok": false, "error": <envelope> }`.
    pub fn to_response_json(&self) -> Value {
        json!({ "ok": false, "error": self })
    }

    /// Parse from a full response body or a bare envelope object.
    pub fn from_response_value(v: &Value) -> Option<Self> {
        if let Ok(e) = serde_json::from_value::<Self>(v.clone()) {
            if e.schema == API_ERROR_SCHEMA {
                return Some(e);
            }
        }
        v.get("error")
            .and_then(|e| serde_json::from_value::<Self>(e.clone()).ok())
            .filter(|e| e.schema == API_ERROR_SCHEMA)
    }

    /// Compatibility shim: strings shaped `package_gate:<honesty>`.
    pub fn from_legacy_string(s: &str) -> Option<Self> {
        s.strip_prefix("package_gate:")
            .map(|honesty| Self::package_gate(honesty).with_retry_safe(false))
    }
}

/// Minimal operation handle returned by durable runs / invocations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiOperationRef {
    pub schema: String,
    pub operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_uri: Option<String>,
}

impl ApiOperationRef {
    pub fn new(operation_id: impl Into<String>) -> Self {
        Self {
            schema: API_OPERATION_SCHEMA.into(),
            operation_id: operation_id.into(),
            status: None,
            receipt_uri: None,
        }
    }
}

/// OpenAPI 3.1 fragment for `ApiErrorEnvelope` (merge into components.schemas).
pub fn openapi_error_schema() -> Value {
    json!({
        "type": "object",
        "required": ["schema", "code", "message"],
        "properties": {
            "schema": { "type": "string", "const": API_ERROR_SCHEMA },
            "code": { "type": "string", "example": "package_gate" },
            "message": { "type": "string" },
            "phase": { "type": "string" },
            "retry_safe": { "type": "boolean" },
            "operation_id": { "type": "string" },
            "trace_id": { "type": "string" },
            "detail": { "type": "object" }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_envelope_schema() {
        let e = ApiErrorEnvelope::package_gate("test");
        assert_eq!(e.schema, API_ERROR_SCHEMA);
        assert_eq!(e.code, "package_gate");
        assert_eq!(e.phase.as_deref(), Some("admission"));
    }

    #[test]
    fn round_trip_response_json() {
        let e = ApiErrorEnvelope::package_gate("denied").with_detail(json!({"v": 1}));
        let body = e.to_response_json();
        let parsed = ApiErrorEnvelope::from_response_value(&body).unwrap();
        assert_eq!(parsed.code, "package_gate");
        assert_eq!(parsed.message, "denied");
    }

    #[test]
    fn legacy_string_parse() {
        let e = ApiErrorEnvelope::from_legacy_string("package_gate:need pin").unwrap();
        assert_eq!(e.message, "need pin");
    }
}
