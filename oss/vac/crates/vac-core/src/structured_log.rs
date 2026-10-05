//! Structured Logging Standard — Enforced schema for all log entries
//!
//! This module implements a structured logging standard:
//! - Enforced JSON schema for all log entries
//! - Severity levels (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
//! - Correlation with traces (trace_id, span_id)
//! - Standard fields (timestamp, service, component, message, etc.)
//! - Log categories for filtering
//!
//! Design sources: OpenTelemetry Logs, ECS (Elastic Common Schema), OCSF

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Log Severity
// =============================================================================

/// Log severity levels (OpenTelemetry compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogSeverity {
    /// Finest-grained debugging information
    Trace = 1,
    /// Debugging information
    Debug = 5,
    /// Informational messages
    Info = 9,
    /// Warning conditions
    Warn = 13,
    /// Error conditions
    Error = 17,
    /// Fatal/critical conditions
    Fatal = 21,
}

impl LogSeverity {
    pub fn from_level(level: tracing::Level) -> Self {
        match level {
            tracing::Level::TRACE => Self::Trace,
            tracing::Level::DEBUG => Self::Debug,
            tracing::Level::INFO => Self::Info,
            tracing::Level::WARN => Self::Warn,
            tracing::Level::ERROR => Self::Fatal,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Fatal => "FATAL",
        }
    }

    pub fn severity_number(&self) -> u8 {
        *self as u8
    }
}

impl Default for LogSeverity {
    fn default() -> Self {
        Self::Info
    }
}

// =============================================================================
// Log Category
// =============================================================================

/// Log category for filtering and routing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogCategory {
    /// Kernel operations (syscalls, dispatch)
    Kernel,
    /// Agent lifecycle (register, start, stop, terminate)
    Agent,
    /// Memory operations (read, write, evict)
    Memory,
    /// Session management
    Session,
    /// Tool invocations
    Tool,
    /// Security events (auth, access control)
    Security,
    /// Audit trail
    Audit,
    /// Performance metrics
    Performance,
    /// Network/communication
    Network,
    /// Storage operations
    Storage,
    /// Scheduler operations
    Scheduler,
    /// Configuration changes
    Config,
    /// Health checks
    Health,
    /// Custom category
    Custom(String),
}

impl LogCategory {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Kernel => "kernel",
            Self::Agent => "agent",
            Self::Memory => "memory",
            Self::Session => "session",
            Self::Tool => "tool",
            Self::Security => "security",
            Self::Audit => "audit",
            Self::Performance => "performance",
            Self::Network => "network",
            Self::Storage => "storage",
            Self::Scheduler => "scheduler",
            Self::Config => "config",
            Self::Health => "health",
            Self::Custom(s) => s,
        }
    }
}

impl Default for LogCategory {
    fn default() -> Self {
        Self::Kernel
    }
}

// =============================================================================
// Structured Log Entry
// =============================================================================

/// Structured log entry — enforced schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredLogEntry {
    // --- Required fields ---
    /// Timestamp in RFC 3339 format
    pub timestamp: String,
    /// Timestamp in epoch nanoseconds (for precise ordering)
    pub timestamp_nanos: u64,
    /// Severity level
    pub severity: LogSeverity,
    /// Severity number (OpenTelemetry compatible)
    pub severity_number: u8,
    /// Human-readable message
    pub message: String,

    // --- Service identification ---
    /// Service name
    pub service: String,
    /// Service version
    pub version: String,
    /// Component within service
    pub component: String,
    /// Environment (production, staging, development)
    pub environment: String,

    // --- Trace context ---
    /// Trace ID (W3C format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Span ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    /// Parent span ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    /// Trace flags
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_flags: Option<u8>,

    // --- Categorization ---
    /// Log category
    pub category: LogCategory,
    /// Event type (more specific than category)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    /// Tags for filtering
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    // --- Agent context ---
    /// Agent PID (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<String>,
    /// Session ID (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Tenant ID (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    // --- Error context ---
    /// Error code (if error)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Error type (if error)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
    /// Stack trace (if error)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<String>,

    // --- Performance ---
    /// Duration in microseconds (if timed operation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_us: Option<u64>,

    // --- Structured data ---
    /// Additional structured attributes
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, serde_json::Value>,

    // --- Resource attributes (OpenTelemetry) ---
    /// Host name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    /// Process ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    /// Thread ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<u64>,
}

impl StructuredLogEntry {
    /// Create a new log entry with required fields
    pub fn new(severity: LogSeverity, message: impl Into<String>) -> Self {
        let now = std::time::SystemTime::now();
        let timestamp_nanos = now
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Format as RFC 3339
        let secs = timestamp_nanos / 1_000_000_000;
        let nanos = timestamp_nanos % 1_000_000_000;
        let timestamp = format!(
            "{}.{:09}Z",
            chrono_lite_format(secs),
            nanos
        );

        Self {
            timestamp,
            timestamp_nanos,
            severity,
            severity_number: severity.severity_number(),
            message: message.into(),
            service: "connector".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            component: "kernel".to_string(),
            environment: std::env::var("CONNECTOR_ENV").unwrap_or_else(|_| "development".to_string()),
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            trace_flags: None,
            category: LogCategory::default(),
            event_type: None,
            tags: vec![],
            agent_pid: None,
            session_id: None,
            tenant_id: None,
            error_code: None,
            error_type: None,
            stack_trace: None,
            duration_us: None,
            attributes: HashMap::new(),
            host_name: None,
            process_id: None,
            thread_id: None,
        }
    }

    // Builder methods
    pub fn with_category(mut self, category: LogCategory) -> Self {
        self.category = category;
        self
    }

    pub fn with_component(mut self, component: impl Into<String>) -> Self {
        self.component = component.into();
        self
    }

    pub fn with_trace_context(mut self, trace_id: String, span_id: String) -> Self {
        self.trace_id = Some(trace_id);
        self.span_id = Some(span_id);
        self
    }

    pub fn with_agent(mut self, agent_pid: impl Into<String>) -> Self {
        self.agent_pid = Some(agent_pid.into());
        self
    }

    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    pub fn with_error(mut self, code: impl Into<String>, error_type: impl Into<String>) -> Self {
        self.error_code = Some(code.into());
        self.error_type = Some(error_type.into());
        self
    }

    pub fn with_stack_trace(mut self, trace: impl Into<String>) -> Self {
        self.stack_trace = Some(trace.into());
        self
    }

    pub fn with_duration(mut self, duration_us: u64) -> Self {
        self.duration_us = Some(duration_us);
        self
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.attributes.insert(key.into(), v);
        }
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn with_event_type(mut self, event_type: impl Into<String>) -> Self {
        self.event_type = Some(event_type.into());
        self
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Convert to pretty JSON string
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

/// Simple timestamp formatter (avoids chrono dependency)
fn chrono_lite_format(secs: u64) -> String {
    // Convert seconds since epoch to ISO 8601 date-time
    const SECS_PER_DAY: u64 = 86400;
    const SECS_PER_HOUR: u64 = 3600;
    const SECS_PER_MIN: u64 = 60;

    let days = secs / SECS_PER_DAY;
    let remaining = secs % SECS_PER_DAY;
    let hours = remaining / SECS_PER_HOUR;
    let remaining = remaining % SECS_PER_HOUR;
    let minutes = remaining / SECS_PER_MIN;
    let seconds = remaining % SECS_PER_MIN;

    // Calculate year, month, day from days since epoch (1970-01-01)
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    // Simplified calculation - good enough for logging
    let mut remaining_days = days as i64;
    let mut year = 1970u32;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u32;
    for &days_in_month in &days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days as u32 + 1;
    (year, month, day)
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

// =============================================================================
// Log Macros (convenience)
// =============================================================================

/// Create a trace log entry
#[macro_export]
macro_rules! log_trace {
    ($msg:expr) => {
        $crate::structured_log::StructuredLogEntry::new(
            $crate::structured_log::LogSeverity::Trace,
            $msg,
        )
    };
    ($msg:expr, $($key:ident = $value:expr),* $(,)?) => {
        $crate::structured_log::StructuredLogEntry::new(
            $crate::structured_log::LogSeverity::Trace,
            $msg,
        )$(.with_attribute(stringify!($key), $value))*
    };
}

/// Create a debug log entry
#[macro_export]
macro_rules! log_debug {
    ($msg:expr) => {
        $crate::structured_log::StructuredLogEntry::new(
            $crate::structured_log::LogSeverity::Debug,
            $msg,
        )
    };
    ($msg:expr, $($key:ident = $value:expr),* $(,)?) => {
        $crate::structured_log::StructuredLogEntry::new(
            $crate::structured_log::LogSeverity::Debug,
            $msg,
        )$(.with_attribute(stringify!($key), $value))*
    };
}

/// Create an info log entry
#[macro_export]
macro_rules! log_info {
    ($msg:expr) => {
        $crate::structured_log::StructuredLogEntry::new(
            $crate::structured_log::LogSeverity::Info,
            $msg,
        )
    };
    ($msg:expr, $($key:ident = $value:expr),* $(,)?) => {
        $crate::structured_log::StructuredLogEntry::new(
            $crate::structured_log::LogSeverity::Info,
            $msg,
        )$(.with_attribute(stringify!($key), $value))*
    };
}

/// Create a warn log entry
#[macro_export]
macro_rules! log_warn {
    ($msg:expr) => {
        $crate::structured_log::StructuredLogEntry::new(
            $crate::structured_log::LogSeverity::Warn,
            $msg,
        )
    };
    ($msg:expr, $($key:ident = $value:expr),* $(,)?) => {
        $crate::structured_log::StructuredLogEntry::new(
            $crate::structured_log::LogSeverity::Warn,
            $msg,
        )$(.with_attribute(stringify!($key), $value))*
    };
}

/// Create an error log entry
#[macro_export]
macro_rules! log_error {
    ($msg:expr) => {
        $crate::structured_log::StructuredLogEntry::new(
            $crate::structured_log::LogSeverity::Error,
            $msg,
        )
    };
    ($msg:expr, $($key:ident = $value:expr),* $(,)?) => {
        $crate::structured_log::StructuredLogEntry::new(
            $crate::structured_log::LogSeverity::Error,
            $msg,
        )$(.with_attribute(stringify!($key), $value))*
    };
}

// =============================================================================
// Tracing Integration — Bridge tracing::event! to structured logs
// =============================================================================

#[cfg(feature = "structured-logging")]
use tracing::{Event, Subscriber};
#[cfg(feature = "structured-logging")]
use tracing_subscriber::layer::Context;
#[cfg(feature = "structured-logging")]
use tracing_subscriber::Layer;
#[cfg(feature = "structured-logging")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "structured-logging")]
use std::io::Write;

/// A tracing layer that emits structured JSON logs with trace correlation.
///
/// This layer captures all `tracing::event!` calls and converts them to
/// `StructuredLogEntry` format with automatic trace/span ID correlation.
///
/// # Example
///
/// ```rust,ignore
/// use tracing_subscriber::prelude::*;
/// use vac_core::structured_log::StructuredLogLayer;
///
/// // Set up structured logging with trace correlation
/// let structured_layer = StructuredLogLayer::new()
///     .with_service("connector")
///     .with_component("kernel");
///
/// tracing_subscriber::registry()
///     .with(structured_layer)
///     .init();
///
/// // Now all tracing events are emitted as structured JSON
/// tracing::info!(agent_pid = "pid:001", operation = "mem_write", "Memory write completed");
/// ```
#[cfg(feature = "structured-logging")]
pub struct StructuredLogLayer {
    service: String,
    component: String,
    environment: String,
    /// Optional writer for log output (defaults to stdout)
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    /// Whether to include resource attributes (host, process, thread)
    include_resource_attrs: bool,
}

#[cfg(feature = "structured-logging")]
impl StructuredLogLayer {
    /// Create a new structured log layer with defaults
    pub fn new() -> Self {
        Self {
            service: "connector".to_string(),
            component: "kernel".to_string(),
            environment: std::env::var("CONNECTOR_ENV").unwrap_or_else(|_| "development".to_string()),
            writer: Arc::new(Mutex::new(Box::new(std::io::stdout()))),
            include_resource_attrs: true,
        }
    }

    /// Set the service name
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = service.into();
        self
    }

    /// Set the component name
    pub fn with_component(mut self, component: impl Into<String>) -> Self {
        self.component = component.into();
        self
    }

    /// Set the environment
    pub fn with_environment(mut self, env: impl Into<String>) -> Self {
        self.environment = env.into();
        self
    }

    /// Set a custom writer (for file output, network, etc.)
    pub fn with_writer<W: Write + Send + 'static>(mut self, writer: W) -> Self {
        self.writer = Arc::new(Mutex::new(Box::new(writer)));
        self
    }

    /// Disable resource attributes (host, process, thread)
    pub fn without_resource_attrs(mut self) -> Self {
        self.include_resource_attrs = false;
        self
    }
}

#[cfg(feature = "structured-logging")]
impl Default for StructuredLogLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// Visitor to extract fields from tracing events
#[cfg(feature = "structured-logging")]
struct FieldVisitor {
    message: Option<String>,
    attributes: HashMap<String, serde_json::Value>,
    agent_pid: Option<String>,
    session_id: Option<String>,
    tenant_id: Option<String>,
    error_code: Option<String>,
    error_type: Option<String>,
    duration_us: Option<u64>,
    category: Option<LogCategory>,
}

#[cfg(feature = "structured-logging")]
impl FieldVisitor {
    fn new() -> Self {
        Self {
            message: None,
            attributes: HashMap::new(),
            agent_pid: None,
            session_id: None,
            tenant_id: None,
            error_code: None,
            error_type: None,
            duration_us: None,
            category: None,
        }
    }
}

#[cfg(feature = "structured-logging")]
impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let value_str = format!("{:?}", value);
        match field.name() {
            "message" => self.message = Some(value_str.trim_matches('"').to_string()),
            "agent_pid" | "pid" => self.agent_pid = Some(value_str.trim_matches('"').to_string()),
            "session_id" | "session" => self.session_id = Some(value_str.trim_matches('"').to_string()),
            "tenant_id" | "tenant" => self.tenant_id = Some(value_str.trim_matches('"').to_string()),
            "error_code" | "code" => self.error_code = Some(value_str.trim_matches('"').to_string()),
            "error_type" | "error" => self.error_type = Some(value_str.trim_matches('"').to_string()),
            "category" => {
                self.category = Some(match value_str.trim_matches('"').to_lowercase().as_str() {
                    "kernel" => LogCategory::Kernel,
                    "agent" => LogCategory::Agent,
                    "memory" => LogCategory::Memory,
                    "session" => LogCategory::Session,
                    "tool" => LogCategory::Tool,
                    "security" => LogCategory::Security,
                    "audit" => LogCategory::Audit,
                    "performance" => LogCategory::Performance,
                    "network" => LogCategory::Network,
                    "storage" => LogCategory::Storage,
                    "scheduler" => LogCategory::Scheduler,
                    "config" => LogCategory::Config,
                    "health" => LogCategory::Health,
                    other => LogCategory::Custom(other.to_string()),
                });
            }
            _ => {
                self.attributes.insert(
                    field.name().to_string(),
                    serde_json::Value::String(value_str.trim_matches('"').to_string()),
                );
            }
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "message" => self.message = Some(value.to_string()),
            "agent_pid" | "pid" => self.agent_pid = Some(value.to_string()),
            "session_id" | "session" => self.session_id = Some(value.to_string()),
            "tenant_id" | "tenant" => self.tenant_id = Some(value.to_string()),
            "error_code" | "code" => self.error_code = Some(value.to_string()),
            "error_type" | "error" => self.error_type = Some(value.to_string()),
            _ => {
                self.attributes.insert(
                    field.name().to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            }
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        match field.name() {
            "duration_us" | "duration" => self.duration_us = Some(value as u64),
            _ => {
                self.attributes.insert(
                    field.name().to_string(),
                    serde_json::Value::Number(value.into()),
                );
            }
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        match field.name() {
            "duration_us" | "duration" => self.duration_us = Some(value),
            _ => {
                self.attributes.insert(
                    field.name().to_string(),
                    serde_json::json!(value),
                );
            }
        }
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.attributes.insert(
            field.name().to_string(),
            serde_json::Value::Bool(value),
        );
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.attributes.insert(
            field.name().to_string(),
            serde_json::json!(value),
        );
    }
}

#[cfg(feature = "structured-logging")]
impl<S> Layer<S> for StructuredLogLayer
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        // Extract fields from the event
        let mut visitor = FieldVisitor::new();
        event.record(&mut visitor);

        // Get message from visitor or metadata target
        let message = visitor.message.unwrap_or_else(|| {
            event.metadata().target().to_string()
        });

        // Map tracing level to LogSeverity
        let severity = LogSeverity::from_level(*event.metadata().level());

        // Create structured log entry
        let mut entry = StructuredLogEntry::new(severity, message);
        entry.service = self.service.clone();
        entry.component = self.component.clone();
        entry.environment = self.environment.clone();

        // Set category from visitor or derive from metadata target
        entry.category = visitor.category.unwrap_or_else(|| {
            let target = event.metadata().target();
            if target.contains("kernel") {
                LogCategory::Kernel
            } else if target.contains("agent") {
                LogCategory::Agent
            } else if target.contains("memory") || target.contains("mem") {
                LogCategory::Memory
            } else if target.contains("session") {
                LogCategory::Session
            } else if target.contains("tool") {
                LogCategory::Tool
            } else if target.contains("security") || target.contains("auth") {
                LogCategory::Security
            } else if target.contains("audit") {
                LogCategory::Audit
            } else {
                LogCategory::Kernel
            }
        });

        // Extract trace context from current span
        if let Some(span) = ctx.lookup_current() {
            let extensions = span.extensions();
            
            // Try to get OpenTelemetry trace context
            #[cfg(feature = "opentelemetry")]
            if let Some(otel_data) = extensions.get::<tracing_opentelemetry::OtelData>() {
                if let Some(parent) = &otel_data.parent_cx {
                    use opentelemetry::trace::TraceContextExt;
                    let span_ctx = parent.span().span_context();
                    entry.trace_id = Some(format!("{:032x}", span_ctx.trace_id()));
                    entry.span_id = Some(format!("{:016x}", span_ctx.span_id()));
                }
            }

            // Fallback: use span ID as correlation
            entry.span_id = entry.span_id.or_else(|| Some(format!("{:x}", span.id().into_u64())));
            
            // Add span name as event type
            entry.event_type = Some(span.name().to_string());
        }

        // Set agent context
        entry.agent_pid = visitor.agent_pid;
        entry.session_id = visitor.session_id;
        entry.tenant_id = visitor.tenant_id;

        // Set error context
        entry.error_code = visitor.error_code;
        entry.error_type = visitor.error_type;

        // Set duration
        entry.duration_us = visitor.duration_us;

        // Set attributes
        entry.attributes = visitor.attributes;

        // Add resource attributes if enabled
        if self.include_resource_attrs {
            entry.host_name = std::env::var("HOSTNAME").ok();
            entry.process_id = Some(std::process::id());
            // Thread ID from std (available since Rust 1.67)
            entry.thread_id = None; // Thread ID requires nightly or external crate
        }

        // Write the log entry as JSON
        let json = entry.to_json();
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writeln!(writer, "{}", json);
        }
    }
}

// =============================================================================
// Log Export — Loki / Elasticsearch compatible output
// =============================================================================

/// Log export format for different backends
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogExportFormat {
    /// JSON lines (one JSON object per line) — Loki, Elasticsearch, Datadog
    JsonLines,
    /// Loki push API format (streams with labels)
    LokiPush,
    /// Elasticsearch bulk API format
    ElasticsearchBulk,
}

/// Log exporter for sending logs to external systems
pub struct LogExporter {
    format: LogExportFormat,
    buffer: Vec<StructuredLogEntry>,
    max_buffer_size: usize,
    /// Labels for Loki (job, instance, etc.)
    labels: HashMap<String, String>,
    /// Index name for Elasticsearch
    index_name: String,
}

impl LogExporter {
    /// Create a new log exporter
    pub fn new(format: LogExportFormat) -> Self {
        let mut labels = HashMap::new();
        labels.insert("job".to_string(), "connector".to_string());
        labels.insert("service".to_string(), "connector".to_string());

        Self {
            format,
            buffer: Vec::new(),
            max_buffer_size: 1000,
            labels,
            index_name: "connector-logs".to_string(),
        }
    }

    /// Set Loki labels
    pub fn with_labels(mut self, labels: HashMap<String, String>) -> Self {
        self.labels = labels;
        self
    }

    /// Set Elasticsearch index name
    pub fn with_index(mut self, index: impl Into<String>) -> Self {
        self.index_name = index.into();
        self
    }

    /// Add a log entry to the buffer
    pub fn push(&mut self, entry: StructuredLogEntry) {
        self.buffer.push(entry);
        if self.buffer.len() >= self.max_buffer_size {
            // In production, this would flush to the backend
            self.buffer.clear();
        }
    }

    /// Export buffered logs in the configured format
    pub fn export(&mut self) -> String {
        let result = match self.format {
            LogExportFormat::JsonLines => self.export_json_lines(),
            LogExportFormat::LokiPush => self.export_loki_push(),
            LogExportFormat::ElasticsearchBulk => self.export_elasticsearch_bulk(),
        };
        self.buffer.clear();
        result
    }

    fn export_json_lines(&self) -> String {
        self.buffer
            .iter()
            .map(|e| e.to_json())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn export_loki_push(&self) -> String {
        // Loki push API format: {"streams": [{"stream": {...labels...}, "values": [[timestamp_ns, line], ...]}]}
        let values: Vec<serde_json::Value> = self.buffer
            .iter()
            .map(|e| {
                serde_json::json!([
                    e.timestamp_nanos.to_string(),
                    e.to_json()
                ])
            })
            .collect();

        serde_json::json!({
            "streams": [{
                "stream": self.labels,
                "values": values
            }]
        }).to_string()
    }

    fn export_elasticsearch_bulk(&self) -> String {
        // Elasticsearch bulk API format: action + document pairs
        self.buffer
            .iter()
            .flat_map(|e| {
                let action = serde_json::json!({
                    "index": {
                        "_index": self.index_name
                    }
                });
                vec![action.to_string(), e.to_json()]
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// =============================================================================
// Convenience macros for structured tracing events
// =============================================================================

/// Emit a structured debug event with automatic trace correlation
///
/// # Example
/// ```rust,ignore
/// use vac_core::structured_debug;
///
/// structured_debug!(
///     category = "memory",
///     agent_pid = "pid:001",
///     operation = "mem_write",
///     bytes = 1024,
///     "Memory write completed"
/// );
/// ```
#[macro_export]
macro_rules! structured_debug {
    ($($key:ident = $value:expr),* $(,)? , $msg:expr) => {
        tracing::debug!($($key = $value,)* message = $msg)
    };
    ($msg:expr) => {
        tracing::debug!(message = $msg)
    };
}

/// Emit a structured info event with automatic trace correlation
#[macro_export]
macro_rules! structured_info {
    ($($key:ident = $value:expr),* $(,)? , $msg:expr) => {
        tracing::info!($($key = $value,)* message = $msg)
    };
    ($msg:expr) => {
        tracing::info!(message = $msg)
    };
}

/// Emit a structured warning event with automatic trace correlation
#[macro_export]
macro_rules! structured_warn {
    ($($key:ident = $value:expr),* $(,)? , $msg:expr) => {
        tracing::warn!($($key = $value,)* message = $msg)
    };
    ($msg:expr) => {
        tracing::warn!(message = $msg)
    };
}

/// Emit a structured error event with automatic trace correlation
#[macro_export]
macro_rules! structured_error {
    ($($key:ident = $value:expr),* $(,)? , $msg:expr) => {
        tracing::error!($($key = $value,)* message = $msg)
    };
    ($msg:expr) => {
        tracing::error!(message = $msg)
    };
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let entry = StructuredLogEntry::new(LogSeverity::Info, "Test message");
        assert_eq!(entry.severity, LogSeverity::Info);
        assert_eq!(entry.message, "Test message");
        assert!(!entry.timestamp.is_empty());
    }

    #[test]
    fn test_log_entry_builder() {
        let entry = StructuredLogEntry::new(LogSeverity::Error, "Error occurred")
            .with_category(LogCategory::Security)
            .with_agent("pid:001")
            .with_error("AUTH_FAILED", "AuthenticationError")
            .with_attribute("ip_address", "192.168.1.1");

        assert_eq!(entry.category, LogCategory::Security);
        assert_eq!(entry.agent_pid, Some("pid:001".to_string()));
        assert_eq!(entry.error_code, Some("AUTH_FAILED".to_string()));
        assert!(entry.attributes.contains_key("ip_address"));
    }

    #[test]
    fn test_log_to_json() {
        let entry = StructuredLogEntry::new(LogSeverity::Info, "Test")
            .with_category(LogCategory::Kernel);
        
        let json = entry.to_json();
        assert!(json.contains("\"severity\":\"INFO\""));
        assert!(json.contains("\"message\":\"Test\""));
        assert!(json.contains("\"category\":\"kernel\""));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(LogSeverity::Trace < LogSeverity::Debug);
        assert!(LogSeverity::Debug < LogSeverity::Info);
        assert!(LogSeverity::Info < LogSeverity::Warn);
        assert!(LogSeverity::Warn < LogSeverity::Error);
        assert!(LogSeverity::Error < LogSeverity::Fatal);
    }

    #[test]
    fn test_timestamp_format() {
        let ts = chrono_lite_format(0);
        assert_eq!(ts, "1970-01-01T00:00:00");

        let ts = chrono_lite_format(1609459200); // 2021-01-01 00:00:00
        assert_eq!(ts, "2021-01-01T00:00:00");
    }
}
