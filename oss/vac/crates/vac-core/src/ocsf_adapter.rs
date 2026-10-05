//! OCSF Adapter — transforms KernelAuditEntry to OCSF 1.3.0 format.
//!
//! OCSF (Open Cybersecurity Schema Framework) is the industry standard for
//! security event logging, enabling native ingestion by SIEMs like Splunk,
//! Datadog, Elastic, and others.
//!
//! Reference: https://schema.ocsf.io/1.3.0/
//!
//! This adapter maps Connector kernel audit entries to OCSF System Activity
//! events (class_uid 6001), enabling enterprise security teams to monitor
//! AI agent operations using their existing security tooling.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::{KernelAuditEntry, MemoryKernelOp, OpOutcome, TelemetrySeverity};

// =============================================================================
// OCSF 1.3.0 Schema Types
// =============================================================================

/// OCSF Event — the top-level structure for all OCSF events.
/// This implements the System Activity class (class_uid: 6001).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfEvent {
    /// OCSF metadata
    pub metadata: OcsfMetadata,

    /// Event class UID (6001 = System Activity)
    pub class_uid: u32,

    /// Event class name
    pub class_name: String,

    /// Category UID (6 = System Activity)
    pub category_uid: u32,

    /// Category name
    pub category_name: String,

    /// Activity ID (1=Create, 2=Read, 3=Update, 4=Delete, 5=Other)
    pub activity_id: u32,

    /// Activity name
    pub activity_name: String,

    /// Type UID (class_uid * 100 + activity_id)
    pub type_uid: u32,

    /// Type name
    pub type_name: String,

    /// Event time (Unix timestamp in milliseconds)
    pub time: i64,

    /// Severity ID (0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical, 6=Fatal)
    pub severity_id: u8,

    /// Severity name
    pub severity: String,

    /// Status (Success, Failure, Unknown)
    pub status: String,

    /// Status ID (0=Unknown, 1=Success, 2=Failure)
    pub status_id: u8,

    /// Status detail (error message if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_detail: Option<String>,

    /// Actor — who performed the action
    pub actor: OcsfActor,

    /// Device — the system where the event occurred
    pub device: OcsfDevice,

    /// Observables — key data points extracted from the event
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub observables: Vec<OcsfObservable>,

    /// Enrichments — additional context
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub enrichments: Vec<OcsfEnrichment>,

    /// Raw data — original event data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<String>,

    /// Message — human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Duration in microseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,

    /// Unmapped fields — Connector-specific extensions
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub unmapped: HashMap<String, serde_json::Value>,
}

/// OCSF Metadata — product and log provider information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfMetadata {
    /// OCSF schema version
    pub version: String,

    /// Product information
    pub product: OcsfProduct,

    /// Log provider
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_provider: Option<String>,

    /// Original event UID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// Correlation UID (for linking related events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_uid: Option<String>,

    /// Log name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_name: Option<String>,

    /// Logged time (when the event was logged, may differ from event time)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logged_time: Option<i64>,
}

/// OCSF Product — identifies the product generating events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfProduct {
    /// Product name
    pub name: String,

    /// Product version
    pub version: String,

    /// Vendor name
    pub vendor_name: String,

    /// Product UID (optional unique identifier)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// Product feature (component within the product)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature: Option<OcsfFeature>,
}

/// OCSF Feature — a component within a product
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfFeature {
    /// Feature name
    pub name: String,

    /// Feature UID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// Feature version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// OCSF Actor — the entity that performed the action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfActor {
    /// Actor type (Process, User, Service, etc.)
    #[serde(rename = "type")]
    pub type_: String,

    /// Actor type ID
    pub type_id: u8,

    /// Actor UID (unique identifier)
    pub uid: String,

    /// Actor name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Process information (if actor is a process)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<OcsfProcess>,

    /// Session information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<OcsfSession>,
}

/// OCSF Process — process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfProcess {
    /// Process ID
    pub pid: i64,

    /// Process name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Command line
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd_line: Option<String>,
}

/// OCSF Session — session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfSession {
    /// Session UID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// Session type
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub type_: Option<String>,
}

/// OCSF Device — the system where the event occurred
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfDevice {
    /// Device type (Server, Workstation, etc.)
    #[serde(rename = "type")]
    pub type_: String,

    /// Device type ID
    pub type_id: u8,

    /// Hostname
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,

    /// Operating system
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<OcsfOs>,
}

/// OCSF OS — operating system information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfOs {
    /// OS name
    pub name: String,

    /// OS type (Linux, Windows, macOS, etc.)
    #[serde(rename = "type")]
    pub type_: String,

    /// OS type ID
    pub type_id: u8,
}

/// OCSF Observable — a key data point extracted from the event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfObservable {
    /// Observable name
    pub name: String,

    /// Observable type (Resource UID, Hash, etc.)
    #[serde(rename = "type")]
    pub type_: String,

    /// Observable type ID
    pub type_id: u8,

    /// Observable value
    pub value: String,
}

/// OCSF Enrichment — additional context added to the event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfEnrichment {
    /// Enrichment name
    pub name: String,

    /// Enrichment value
    pub value: String,

    /// Enrichment type
    #[serde(rename = "type")]
    pub type_: String,
}

// =============================================================================
// OCSF Adapter Configuration
// =============================================================================

/// Configuration for the OCSF adapter
#[derive(Debug, Clone)]
pub struct OcsfAdapterConfig {
    /// Product name
    pub product_name: String,
    /// Product version
    pub product_version: String,
    /// Vendor name
    pub vendor_name: String,
    /// Hostname (optional, auto-detected if None)
    pub hostname: Option<String>,
    /// Include raw data in output
    pub include_raw_data: bool,
}

impl Default for OcsfAdapterConfig {
    fn default() -> Self {
        Self {
            product_name: "Connector".to_string(),
            product_version: env!("CARGO_PKG_VERSION").to_string(),
            vendor_name: "Connector Platform".to_string(),
            hostname: None,
            include_raw_data: false,
        }
    }
}

// =============================================================================
// Conversion Functions
// =============================================================================

/// Convert a KernelAuditEntry to an OCSF event
pub fn to_ocsf(entry: &KernelAuditEntry, config: &OcsfAdapterConfig) -> OcsfEvent {
    let (activity_id, activity_name) = map_operation_to_activity(&entry.operation);
    let (severity_id, severity_name) = map_severity(&entry.severity, &entry.outcome);
    let (status_id, status_name) = map_outcome(&entry.outcome);

    let class_uid = 6001; // System Activity
    let type_uid = class_uid * 100 + activity_id;

    let mut observables = Vec::new();
    let mut enrichments = Vec::new();
    let mut unmapped = HashMap::new();

    // Add target as observable
    if let Some(ref target) = entry.target {
        observables.push(OcsfObservable {
            name: "target".to_string(),
            type_: "Resource UID".to_string(),
            type_id: 10,
            value: target.clone(),
        });
    }

    // Add HMAC chain hashes as enrichments
    if let Some(ref before) = entry.before_hash {
        enrichments.push(OcsfEnrichment {
            name: "before_hash".to_string(),
            value: before.clone(),
            type_: "Hash".to_string(),
        });
    }
    if let Some(ref after) = entry.after_hash {
        enrichments.push(OcsfEnrichment {
            name: "after_hash".to_string(),
            value: after.clone(),
            type_: "Hash".to_string(),
        });
    }
    if let Some(ref merkle) = entry.merkle_root {
        enrichments.push(OcsfEnrichment {
            name: "merkle_root".to_string(),
            value: merkle.clone(),
            type_: "Hash".to_string(),
        });
    }

    // Add VAKYA ID if present
    if let Some(ref vakya) = entry.vakya_id {
        enrichments.push(OcsfEnrichment {
            name: "vakya_id".to_string(),
            value: vakya.clone(),
            type_: "Authorization".to_string(),
        });
    }

    // Add SCITT receipt if present
    if let Some(ref scitt) = entry.scitt_receipt_cid {
        enrichments.push(OcsfEnrichment {
            name: "scitt_receipt_cid".to_string(),
            value: scitt.clone(),
            type_: "Attestation".to_string(),
        });
    }

    // Add causal chain as unmapped
    if !entry.causal_chain.is_empty() {
        unmapped.insert(
            "causal_chain".to_string(),
            serde_json::json!(entry.causal_chain),
        );
    }

    // Add GenAI attributes if present
    if let Some(ref gen_ai) = entry.gen_ai_attrs {
        unmapped.insert("gen_ai".to_string(), serde_json::to_value(gen_ai).unwrap_or_default());
    }

    // Extract PID number from agent_pid (e.g., "pid:000003" -> 3)
    let pid_num = entry
        .agent_pid
        .strip_prefix("pid:")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);

    let raw_data = if config.include_raw_data {
        serde_json::to_string(entry).ok()
    } else {
        None
    };

    OcsfEvent {
        metadata: OcsfMetadata {
            version: "1.3.0".to_string(),
            product: OcsfProduct {
                name: config.product_name.clone(),
                version: config.product_version.clone(),
                vendor_name: config.vendor_name.clone(),
                uid: Some("connector-platform".to_string()),
                feature: Some(OcsfFeature {
                    name: "VAC Memory Kernel".to_string(),
                    uid: Some("vac-core".to_string()),
                    version: None,
                }),
            },
            log_provider: Some("VAC Memory Kernel".to_string()),
            uid: Some(entry.audit_id.clone()),
            correlation_uid: entry.vakya_id.clone(),
            log_name: Some("kernel_audit".to_string()),
            logged_time: Some(entry.timestamp),
        },
        class_uid,
        class_name: "System Activity".to_string(),
        category_uid: 6,
        category_name: "System Activity".to_string(),
        activity_id,
        activity_name: activity_name.clone(),
        type_uid,
        type_name: format!("System Activity: {}", activity_name),
        time: entry.timestamp,
        severity_id,
        severity: severity_name,
        status: status_name.clone(),
        status_id,
        status_detail: entry.error.clone(),
        actor: OcsfActor {
            type_: "Process".to_string(),
            type_id: 6,
            uid: entry.agent_pid.clone(),
            name: entry.reason.clone(),
            process: Some(OcsfProcess {
                pid: pid_num,
                name: Some(entry.agent_pid.clone()),
                cmd_line: None,
            }),
            session: None,
        },
        device: OcsfDevice {
            type_: "Server".to_string(),
            type_id: 1,
            hostname: config.hostname.clone(),
            ip: None,
            os: Some(OcsfOs {
                name: "Linux".to_string(),
                type_: "Linux".to_string(),
                type_id: 200,
            }),
        },
        observables,
        enrichments,
        raw_data,
        message: entry.natural_language.clone(),
        duration: entry.duration_us,
        unmapped,
    }
}

/// Convert multiple KernelAuditEntry to OCSF events
pub fn to_ocsf_batch(entries: &[KernelAuditEntry], config: &OcsfAdapterConfig) -> Vec<OcsfEvent> {
    entries.iter().map(|e| to_ocsf(e, config)).collect()
}

/// Convert to OCSF JSON string (for SIEM ingestion)
pub fn to_ocsf_json(entry: &KernelAuditEntry, config: &OcsfAdapterConfig) -> Result<String, serde_json::Error> {
    let event = to_ocsf(entry, config);
    serde_json::to_string(&event)
}

/// Convert to OCSF JSON Lines (JSONL) format for batch ingestion
pub fn to_ocsf_jsonl(entries: &[KernelAuditEntry], config: &OcsfAdapterConfig) -> Result<String, serde_json::Error> {
    let mut lines = Vec::with_capacity(entries.len());
    for entry in entries {
        let event = to_ocsf(entry, config);
        lines.push(serde_json::to_string(&event)?);
    }
    Ok(lines.join("\n"))
}

// =============================================================================
// Mapping Functions
// =============================================================================

/// Map MemoryKernelOp to OCSF activity
fn map_operation_to_activity(op: &MemoryKernelOp) -> (u32, String) {
    match op {
        // Create operations (activity_id = 1)
        MemoryKernelOp::AgentRegister => (1, "Agent Register".to_string()),
        MemoryKernelOp::AgentBoot => (1, "Agent Boot".to_string()),
        MemoryKernelOp::SessionCreate => (1, "Session Create".to_string()),
        MemoryKernelOp::MemWrite => (1, "Memory Write".to_string()),
        MemoryKernelOp::MemAlloc => (1, "Memory Allocate".to_string()),
        MemoryKernelOp::AccessGrant => (1, "Access Grant".to_string()),
        MemoryKernelOp::PortCreate => (1, "Port Create".to_string()),
        MemoryKernelOp::PortBind => (1, "Port Bind".to_string()),
        MemoryKernelOp::McpRegisterBridge => (1, "MCP Bridge Register".to_string()),
        MemoryKernelOp::A2AOpenChannel => (1, "A2A Channel Open".to_string()),
        MemoryKernelOp::RegisterCgroup => (1, "Cgroup Register".to_string()),
        MemoryKernelOp::RegisterAgentDid => (1, "Agent DID Register".to_string()),
        MemoryKernelOp::PublishAgentCard => (1, "Agent Card Publish".to_string()),
        MemoryKernelOp::RegisterSignalHandler => (1, "Signal Handler Register".to_string()),

        // Read operations (activity_id = 2)
        MemoryKernelOp::MemRead => (2, "Memory Read".to_string()),
        MemoryKernelOp::AccessCheck => (2, "Access Check".to_string()),
        MemoryKernelOp::IntegrityCheck => (2, "Integrity Check".to_string()),
        MemoryKernelOp::LlmDequeue => (2, "LLM Dequeue".to_string()),
        MemoryKernelOp::PortReceive => (2, "Port Receive".to_string()),
        MemoryKernelOp::ResolveAgentCard => (2, "Agent Card Resolve".to_string()),
        MemoryKernelOp::GetContextPressure => (2, "Context Pressure Get".to_string()),
        MemoryKernelOp::PolicyCheck => (2, "Policy Check".to_string()),

        // Update operations (activity_id = 3)
        MemoryKernelOp::AgentStart => (3, "Agent Start".to_string()),
        MemoryKernelOp::AgentResume => (3, "Agent Resume".to_string()),
        MemoryKernelOp::AgentSuspend => (3, "Agent Suspend".to_string()),
        MemoryKernelOp::MemSeal => (3, "Memory Seal".to_string()),
        MemoryKernelOp::MemPromote => (3, "Memory Promote".to_string()),
        MemoryKernelOp::MemDemote => (3, "Memory Demote".to_string()),
        MemoryKernelOp::SessionCompress => (3, "Session Compress".to_string()),
        MemoryKernelOp::ToolDispatch => (3, "Tool Dispatch".to_string()),
        MemoryKernelOp::McpInvokeTool => (3, "MCP Tool Invoke".to_string()),
        MemoryKernelOp::A2ASendMessage => (3, "A2A Send Message".to_string()),
        MemoryKernelOp::A2AUpdateTaskState => (3, "A2A Task State Update".to_string()),
        MemoryKernelOp::LlmSchedule => (3, "LLM Schedule".to_string()),
        MemoryKernelOp::LlmSchedulerConfig => (3, "LLM Scheduler Config".to_string()),
        MemoryKernelOp::RecordComputeUsage => (3, "Record Compute Usage".to_string()),
        MemoryKernelOp::RecordTokenUsage => (3, "Record Token Usage".to_string()),
        MemoryKernelOp::SetTokenBudget => (3, "Set Token Budget".to_string()),
        MemoryKernelOp::ContextSnapshot => (3, "Context Snapshot".to_string()),
        MemoryKernelOp::ContextRestore => (3, "Context Restore".to_string()),
        MemoryKernelOp::UpdateContext => (3, "Update Context".to_string()),
        MemoryKernelOp::TrimContextWindow => (3, "Trim Context Window".to_string()),
        MemoryKernelOp::PortSend => (3, "Port Send".to_string()),
        MemoryKernelOp::PortDelegate => (3, "Port Delegate".to_string()),
        MemoryKernelOp::SendSignal => (3, "Send Signal".to_string()),
        MemoryKernelOp::IndexRebuild => (3, "Index Rebuild".to_string()),

        // Delete operations (activity_id = 4)
        MemoryKernelOp::AgentTerminate => (4, "Agent Terminate".to_string()),
        MemoryKernelOp::MemEvict => (4, "Memory Evict".to_string()),
        MemoryKernelOp::MemClear => (4, "Memory Clear".to_string()),
        MemoryKernelOp::SessionClose => (4, "Session Close".to_string()),
        MemoryKernelOp::AccessRevoke => (4, "Access Revoke".to_string()),
        MemoryKernelOp::PortClose => (4, "Port Close".to_string()),
        MemoryKernelOp::A2ACloseChannel => (4, "A2A Channel Close".to_string()),
        MemoryKernelOp::McpDeregisterBridge => (4, "MCP Bridge Deregister".to_string()),
        MemoryKernelOp::RevokeAgentDid => (4, "Agent DID Revoke".to_string()),
        MemoryKernelOp::GarbageCollect => (4, "Garbage Collect".to_string()),
    }
}

/// Map severity to OCSF severity
fn map_severity(severity: &TelemetrySeverity, outcome: &OpOutcome) -> (u8, String) {
    // If outcome is Denied or Failed, bump severity
    let base_severity = match severity {
        TelemetrySeverity::Debug => (1, "Informational"),
        TelemetrySeverity::Info => (1, "Informational"),
        TelemetrySeverity::Warn => (3, "Medium"),
        TelemetrySeverity::Error => (4, "High"),
        TelemetrySeverity::Critical => (5, "Critical"),
        TelemetrySeverity::Fatal => (6, "Fatal"),
    };

    match outcome {
        OpOutcome::Denied => (4, "High".to_string()),
        OpOutcome::Failed => (3, "Medium".to_string()),
        _ => (base_severity.0, base_severity.1.to_string()),
    }
}

/// Map OpOutcome to OCSF status
fn map_outcome(outcome: &OpOutcome) -> (u8, String) {
    match outcome {
        OpOutcome::Success => (1, "Success".to_string()),
        OpOutcome::Denied => (2, "Failure".to_string()),
        OpOutcome::Failed => (2, "Failure".to_string()),
        OpOutcome::Skipped => (1, "Success".to_string()), // Skipped is not a failure
        OpOutcome::Pending => (0, "Unknown".to_string()),
    }
}

// =============================================================================
// CloudEvents Wrapper (for webhook delivery)
// =============================================================================

/// CloudEvents 1.0 wrapper for OCSF events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudEvent {
    /// CloudEvents spec version
    pub specversion: String,

    /// Event type
    #[serde(rename = "type")]
    pub type_: String,

    /// Event source
    pub source: String,

    /// Event ID
    pub id: String,

    /// Event time (ISO 8601)
    pub time: String,

    /// Data content type
    pub datacontenttype: String,

    /// Event data (the OCSF event)
    pub data: OcsfEvent,
}

/// Wrap an OCSF event in a CloudEvents envelope
pub fn to_cloudevent(ocsf: OcsfEvent, source: &str) -> CloudEvent {
    let time_ms = ocsf.time;
    let time_iso = timestamp_to_iso8601(time_ms);

    CloudEvent {
        specversion: "1.0".to_string(),
        type_: format!("com.connector.kernel.{}", ocsf.activity_name.to_lowercase().replace(' ', "_")),
        source: source.to_string(),
        id: ocsf.metadata.uid.clone().unwrap_or_else(|| uuid_v4()),
        time: time_iso,
        datacontenttype: "application/json".to_string(),
        data: ocsf,
    }
}

/// Simple UUID v4 generator (no external dependency)
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:032x}", now)
}

/// Convert millisecond timestamp to ISO 8601 format (no chrono dependency)
fn timestamp_to_iso8601(ms: i64) -> String {
    let secs = ms / 1000;
    let millis = (ms % 1000) as u32;
    
    // Calculate date components from Unix timestamp
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    
    // Simple date calculation (not accounting for leap seconds, good enough for logging)
    let mut year = 1970i64;
    let mut remaining_days = days_since_epoch;
    
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
    
    let mut month = 1;
    for days in days_in_months.iter() {
        if remaining_days < *days {
            break;
        }
        remaining_days -= *days;
        month += 1;
    }
    let day = remaining_days + 1;
    
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hours, minutes, seconds, millis
    )
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::GenAiAttributes;

    fn make_test_entry() -> KernelAuditEntry {
        KernelAuditEntry {
            audit_id: "audit:001".to_string(),
            timestamp: 1773845532013,
            operation: MemoryKernelOp::MemWrite,
            agent_pid: "pid:000003".to_string(),
            target: Some("bafyrei...".to_string()),
            outcome: OpOutcome::Success,
            reason: Some("Store user preference".to_string()),
            error: None,
            duration_us: Some(2091),
            vakya_id: Some("vakya:abc123".to_string()),
            before_hash: Some("b2ab0412...".to_string()),
            after_hash: Some("8b90fbd2...".to_string()),
            merkle_root: Some("merkle:root123".to_string()),
            scitt_receipt_cid: None,
            natural_language: Some("Agent pid:000003 wrote 512 bytes to namespace org:acme".to_string()),
            business_impact: None,
            remediation_hint: None,
            causal_chain: vec!["audit:000".to_string()],
            severity: TelemetrySeverity::Info,
            gen_ai_attrs: Some(GenAiAttributes {
                gen_ai_system: "connector-os".to_string(),
                gen_ai_operation: "memory_write".to_string(),
                gen_ai_agent_id: "pid:000003".to_string(),
                token_input: 150,
                token_output: 50,
                model: Some("gpt-4o".to_string()),
                threat_score: 0.0,
                namespace: Some("org:acme".to_string()),
            }),
        }
    }

    #[test]
    fn test_to_ocsf_basic() {
        let entry = make_test_entry();
        let config = OcsfAdapterConfig::default();
        let ocsf = to_ocsf(&entry, &config);

        assert_eq!(ocsf.class_uid, 6001);
        assert_eq!(ocsf.class_name, "System Activity");
        assert_eq!(ocsf.activity_id, 1); // MemWrite is Create
        assert_eq!(ocsf.activity_name, "Memory Write");
        assert_eq!(ocsf.status, "Success");
        assert_eq!(ocsf.status_id, 1);
        assert_eq!(ocsf.severity_id, 1); // Info
        assert_eq!(ocsf.time, 1773845532013);
        assert_eq!(ocsf.actor.uid, "pid:000003");
        assert_eq!(ocsf.metadata.version, "1.3.0");
    }

    #[test]
    fn test_to_ocsf_failed() {
        let mut entry = make_test_entry();
        entry.outcome = OpOutcome::Denied;
        entry.error = Some("Access denied: insufficient permissions".to_string());

        let config = OcsfAdapterConfig::default();
        let ocsf = to_ocsf(&entry, &config);

        assert_eq!(ocsf.status, "Failure");
        assert_eq!(ocsf.status_id, 2);
        assert_eq!(ocsf.severity_id, 4); // High (bumped due to Denied)
        assert_eq!(ocsf.status_detail, Some("Access denied: insufficient permissions".to_string()));
    }

    #[test]
    fn test_to_ocsf_observables() {
        let entry = make_test_entry();
        let config = OcsfAdapterConfig::default();
        let ocsf = to_ocsf(&entry, &config);

        assert!(!ocsf.observables.is_empty());
        let target_obs = ocsf.observables.iter().find(|o| o.name == "target");
        assert!(target_obs.is_some());
        assert_eq!(target_obs.unwrap().value, "bafyrei...");
    }

    #[test]
    fn test_to_ocsf_enrichments() {
        let entry = make_test_entry();
        let config = OcsfAdapterConfig::default();
        let ocsf = to_ocsf(&entry, &config);

        assert!(!ocsf.enrichments.is_empty());
        let vakya_enrich = ocsf.enrichments.iter().find(|e| e.name == "vakya_id");
        assert!(vakya_enrich.is_some());
        assert_eq!(vakya_enrich.unwrap().value, "vakya:abc123");
    }

    #[test]
    fn test_to_ocsf_json() {
        let entry = make_test_entry();
        let config = OcsfAdapterConfig::default();
        let json = to_ocsf_json(&entry, &config).unwrap();

        assert!(json.contains("\"class_uid\":6001"));
        assert!(json.contains("\"version\":\"1.3.0\""));
        assert!(json.contains("\"activity_name\":\"Memory Write\""));
    }

    #[test]
    fn test_to_ocsf_jsonl() {
        let entries = vec![make_test_entry(), make_test_entry()];
        let config = OcsfAdapterConfig::default();
        let jsonl = to_ocsf_jsonl(&entries, &config).unwrap();

        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_to_cloudevent() {
        let entry = make_test_entry();
        let config = OcsfAdapterConfig::default();
        let ocsf = to_ocsf(&entry, &config);
        let ce = to_cloudevent(ocsf, "connector://node-001");

        assert_eq!(ce.specversion, "1.0");
        assert!(ce.type_.starts_with("com.connector.kernel."));
        assert_eq!(ce.source, "connector://node-001");
        assert_eq!(ce.datacontenttype, "application/json");
    }

    #[test]
    fn test_operation_mapping() {
        // Test various operation mappings
        assert_eq!(map_operation_to_activity(&MemoryKernelOp::AgentRegister).0, 1);
        assert_eq!(map_operation_to_activity(&MemoryKernelOp::MemRead).0, 2);
        assert_eq!(map_operation_to_activity(&MemoryKernelOp::AgentSuspend).0, 3);
        assert_eq!(map_operation_to_activity(&MemoryKernelOp::AgentTerminate).0, 4);
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(map_severity(&TelemetrySeverity::Info, &OpOutcome::Success).0, 1);
        assert_eq!(map_severity(&TelemetrySeverity::Error, &OpOutcome::Success).0, 4);
        assert_eq!(map_severity(&TelemetrySeverity::Info, &OpOutcome::Denied).0, 4); // Bumped
    }
}
