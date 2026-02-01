//! Adapter traits and types

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use aapi_core::types::EffectBucket;
use aapi_core::Vakya;
use crate::effect::CapturedEffect;
use crate::error::AdapterResult;

/// Core trait for all adapters
#[async_trait]
pub trait Adapter: Send + Sync {
    /// Get the adapter domain (e.g., "file", "http", "database")
    fn domain(&self) -> &str;

    /// Get the adapter version
    fn version(&self) -> &str;

    /// Get supported actions
    fn supported_actions(&self) -> Vec<&str>;

    /// Check if an action is supported
    fn supports_action(&self, action: &str) -> bool {
        self.supported_actions().iter().any(|a| {
            *a == action || action.starts_with(&format!("{}.", self.domain()))
        })
    }

    /// Execute an action and return the result with captured effects
    async fn execute(&self, vakya: &Vakya, context: &ExecutionContext) -> AdapterResult<ExecutionResult>;

    /// Check if an action can be rolled back
    fn can_rollback(&self, action: &str) -> bool;

    /// Rollback a previously executed action
    async fn rollback(&self, effect: &CapturedEffect) -> AdapterResult<()>;

    /// Health check
    async fn health_check(&self) -> AdapterResult<HealthStatus>;
}

/// Execution context passed to adapters
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Request ID
    pub request_id: String,
    /// Trace ID for distributed tracing
    pub trace_id: Option<String>,
    /// Span ID
    pub span_id: Option<String>,
    /// Timeout in milliseconds
    pub timeout_ms: Option<u64>,
    /// Whether to capture before/after state
    pub capture_state: bool,
    /// Whether this is a dry run
    pub dry_run: bool,
    /// Additional context values
    pub values: HashMap<String, serde_json::Value>,
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            trace_id: None,
            span_id: None,
            timeout_ms: Some(30000),
            capture_state: true,
            dry_run: false,
            values: HashMap::new(),
        }
    }
}

impl ExecutionContext {
    pub fn new(request_id: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            ..Default::default()
        }
    }

    pub fn with_trace(mut self, trace_id: impl Into<String>, span_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self.span_id = Some(span_id.into());
        self
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }

    pub fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }

    pub fn set_value(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.values.insert(key.into(), value);
    }

    pub fn get_value(&self, key: &str) -> Option<&serde_json::Value> {
        self.values.get(key)
    }
}

/// Result of action execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Whether the execution succeeded
    pub success: bool,
    /// Result data
    pub data: Option<serde_json::Value>,
    /// Error message if failed
    pub error: Option<String>,
    /// Captured effects
    pub effects: Vec<CapturedEffect>,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ExecutionResult {
    pub fn success(data: serde_json::Value, effects: Vec<CapturedEffect>, duration_ms: u64) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            effects,
            duration_ms,
            metadata: HashMap::new(),
        }
    }

    pub fn failure(error: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error.into()),
            effects: vec![],
            duration_ms,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Health status of an adapter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub message: Option<String>,
    pub latency_ms: Option<u64>,
    pub details: HashMap<String, serde_json::Value>,
}

impl HealthStatus {
    pub fn healthy() -> Self {
        Self {
            healthy: true,
            message: None,
            latency_ms: None,
            details: HashMap::new(),
        }
    }

    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            healthy: false,
            message: Some(message.into()),
            latency_ms: None,
            details: HashMap::new(),
        }
    }

    pub fn with_latency(mut self, latency_ms: u64) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }
}

/// Action descriptor for adapter registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDescriptor {
    /// Full action name (domain.verb)
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// Expected effect bucket
    pub effect_bucket: EffectBucket,
    /// Whether the action is idempotent
    pub idempotent: bool,
    /// Whether the action can be rolled back
    pub reversible: bool,
    /// Input schema (JSON Schema)
    pub input_schema: Option<serde_json::Value>,
    /// Output schema (JSON Schema)
    pub output_schema: Option<serde_json::Value>,
}

impl ActionDescriptor {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            effect_bucket: EffectBucket::None,
            idempotent: false,
            reversible: false,
            input_schema: None,
            output_schema: None,
        }
    }

    pub fn with_effect(mut self, bucket: EffectBucket) -> Self {
        self.effect_bucket = bucket;
        self
    }

    pub fn idempotent(mut self) -> Self {
        self.idempotent = true;
        self
    }

    pub fn reversible(mut self) -> Self {
        self.reversible = true;
        self
    }
}
