//! Knowledge Container & Asset Pipeline — Kafka-style data cleaning and structuring.
//!
//! This module implements the data flow from raw assets to validated knowledge:
//!
//! ```text
//! /v/assets/{container}/ → Validation → Cleaning → Structuring → /k/knowledge/{domain}/
//! ```
//!
//! ## Key Concepts
//!
//! - **AssetContainer**: Folder-like structure in `/v/` namespace for raw input files
//! - **KnowledgeContainer**: Validated, structured data in `/k/` namespace
//! - **IngestionPipeline**: Kafka-style stream processing for data cleaning
//! - **FileType**: Supported input formats with validation rules
//! - **DataStandard**: Schema requirements for knowledge packets
//!
//! ## Design Principles
//!
//! 1. **No garbage in**: All data must pass validation before becoming knowledge
//! 2. **Defined file types**: Only supported formats can be ingested
//! 3. **Kafka-style cleaning**: Stream processing with transforms and filters
//! 4. **Provenance tracking**: Every knowledge packet traces back to source asset
//! 5. **Schema enforcement**: Knowledge must conform to defined standards

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Get current timestamp in milliseconds.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════
// Supported File Types
// ═══════════════════════════════════════════════════════════════

/// Supported file types for asset ingestion.
/// Each type has specific validation rules and extraction logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetFileType {
    /// Plain text files (.txt)
    PlainText,
    /// Markdown documents (.md)
    Markdown,
    /// JSON data files (.json)
    Json,
    /// CSV tabular data (.csv)
    Csv,
    /// PDF documents (.pdf) — requires extraction
    Pdf,
    /// HTML web pages (.html, .htm)
    Html,
    /// YAML configuration (.yaml, .yml)
    Yaml,
    /// XML documents (.xml)
    Xml,
    /// Source code files (various extensions)
    SourceCode,
    /// Binary data (images, audio, etc.) — metadata only
    Binary,
}

impl AssetFileType {
    /// Detect file type from extension.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "txt" => Some(Self::PlainText),
            "md" | "markdown" => Some(Self::Markdown),
            "json" => Some(Self::Json),
            "csv" | "tsv" => Some(Self::Csv),
            "pdf" => Some(Self::Pdf),
            "html" | "htm" => Some(Self::Html),
            "yaml" | "yml" => Some(Self::Yaml),
            "xml" => Some(Self::Xml),
            "rs" | "py" | "js" | "ts" | "go" | "java" | "c" | "cpp" | "h" => Some(Self::SourceCode),
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "mp3" | "wav" | "mp4" => Some(Self::Binary),
            _ => None,
        }
    }

    /// Check if this file type is extractable (can produce text content).
    pub fn is_extractable(&self) -> bool {
        !matches!(self, Self::Binary)
    }

    /// Maximum file size in bytes for this type.
    pub fn max_size_bytes(&self) -> u64 {
        match self {
            Self::PlainText | Self::Markdown => 10 * 1024 * 1024,  // 10 MB
            Self::Json | Self::Yaml | Self::Xml => 50 * 1024 * 1024, // 50 MB
            Self::Csv => 100 * 1024 * 1024, // 100 MB
            Self::Pdf => 50 * 1024 * 1024, // 50 MB
            Self::Html => 10 * 1024 * 1024, // 10 MB
            Self::SourceCode => 5 * 1024 * 1024, // 5 MB
            Self::Binary => 500 * 1024 * 1024, // 500 MB (metadata only)
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Asset Container
// ═══════════════════════════════════════════════════════════════

/// An asset container — folder-like structure in `/v/` namespace.
/// Holds raw input files before they're processed into knowledge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetContainer {
    /// Container ID (unique within namespace)
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Full namespace path (e.g., "v/medical/patient_records")
    pub namespace: String,
    /// Allowed file types for this container
    pub allowed_types: Vec<AssetFileType>,
    /// Maximum total size in bytes
    pub quota_bytes: u64,
    /// Current usage in bytes
    pub used_bytes: u64,
    /// Number of assets in container
    pub asset_count: u64,
    /// Data standard this container feeds into
    pub target_standard: Option<String>,
    /// Target knowledge namespace (e.g., "k/medical/facts")
    pub target_knowledge_ns: Option<String>,
    /// Created timestamp (ms)
    pub created_at: i64,
    /// Last modified timestamp (ms)
    pub modified_at: i64,
    /// Owner agent PID
    pub owner_pid: String,
    /// Container metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AssetContainer {
    /// Create a new asset container.
    pub fn new(id: String, name: String, owner_pid: String) -> Self {
        let now = now_ms();
        Self {
            id: id.clone(),
            name,
            namespace: format!("v/{}", id),
            allowed_types: vec![
                AssetFileType::PlainText,
                AssetFileType::Markdown,
                AssetFileType::Json,
                AssetFileType::Csv,
            ],
            quota_bytes: 1024 * 1024 * 1024, // 1 GB default
            used_bytes: 0,
            asset_count: 0,
            target_standard: None,
            target_knowledge_ns: None,
            created_at: now,
            modified_at: now,
            owner_pid,
            metadata: HashMap::new(),
        }
    }

    /// Check if a file type is allowed in this container.
    pub fn allows_type(&self, file_type: AssetFileType) -> bool {
        self.allowed_types.contains(&file_type)
    }

    /// Check if container has capacity for more data.
    pub fn has_capacity(&self, additional_bytes: u64) -> bool {
        self.used_bytes + additional_bytes <= self.quota_bytes
    }
}

// ═══════════════════════════════════════════════════════════════
// Asset Record
// ═══════════════════════════════════════════════════════════════

/// A single asset record — metadata for a raw file in a container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRecord {
    /// Asset CID (content-addressed ID)
    pub cid: String,
    /// Original filename
    pub filename: String,
    /// Detected file type
    pub file_type: AssetFileType,
    /// File size in bytes
    pub size_bytes: u64,
    /// MIME type
    pub mime_type: String,
    /// Container this asset belongs to
    pub container_id: String,
    /// Ingestion status
    pub status: AssetStatus,
    /// Upload timestamp
    pub uploaded_at: i64,
    /// Processing timestamp (when ingestion started)
    pub processed_at: Option<i64>,
    /// Resulting knowledge packet CIDs (after successful ingestion)
    pub knowledge_cids: Vec<String>,
    /// Validation errors (if any)
    pub validation_errors: Vec<String>,
    /// Extracted metadata
    pub extracted_metadata: HashMap<String, serde_json::Value>,
    /// Checksum (SHA-256)
    pub checksum: String,
}

/// Status of an asset in the ingestion pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetStatus {
    /// Uploaded, awaiting validation
    Pending,
    /// Passed validation, awaiting processing
    Validated,
    /// Currently being processed
    Processing,
    /// Successfully converted to knowledge
    Ingested,
    /// Failed validation
    ValidationFailed,
    /// Failed during processing
    ProcessingFailed,
    /// Quarantined (suspicious content)
    Quarantined,
}

// ═══════════════════════════════════════════════════════════════
// Data Standard
// ═══════════════════════════════════════════════════════════════

/// A data standard — schema requirements for knowledge packets.
/// Ensures knowledge conforms to defined structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataStandard {
    /// Standard ID
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Version (semver)
    pub version: String,
    /// Required fields in knowledge packets
    pub required_fields: Vec<FieldSpec>,
    /// Optional fields
    pub optional_fields: Vec<FieldSpec>,
    /// Validation rules
    pub validation_rules: Vec<ValidationRule>,
    /// Domain this standard applies to
    pub domain: Option<String>,
    /// Description
    pub description: String,
}

/// Field specification in a data standard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSpec {
    /// Field name
    pub name: String,
    /// Field type
    pub field_type: FieldType,
    /// Description
    pub description: String,
    /// Default value (if optional)
    pub default: Option<serde_json::Value>,
}

/// Field types for data standards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Cid,
    Json,
    Array,
    Map,
}

/// Validation rule for data standards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    /// Rule ID
    pub id: String,
    /// Field this rule applies to (or "*" for all)
    pub field: String,
    /// Rule type
    pub rule_type: ValidationRuleType,
    /// Error message if validation fails
    pub error_message: String,
}

/// Types of validation rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ValidationRuleType {
    /// Field must not be empty
    NotEmpty,
    /// String must match regex
    Regex { pattern: String },
    /// Numeric value must be in range
    Range { min: Option<f64>, max: Option<f64> },
    /// String length constraints
    Length { min: Option<usize>, max: Option<usize> },
    /// Value must be one of allowed values
    OneOf { values: Vec<serde_json::Value> },
    /// Custom validation function name
    Custom { function: String },
}

// ═══════════════════════════════════════════════════════════════
// Ingestion Pipeline (Kafka-style)
// ═══════════════════════════════════════════════════════════════

/// Ingestion pipeline configuration — Kafka-style stream processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionPipeline {
    /// Pipeline ID
    pub id: String,
    /// Pipeline name
    pub name: String,
    /// Source asset container
    pub source_container: String,
    /// Target knowledge namespace
    pub target_namespace: String,
    /// Data standard to apply
    pub data_standard: Option<String>,
    /// Processing stages (in order)
    pub stages: Vec<PipelineStage>,
    /// Whether pipeline is active
    pub active: bool,
    /// Batch size for processing
    pub batch_size: usize,
    /// Retry policy
    pub retry_policy: RetryPolicy,
}

/// A stage in the ingestion pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStage {
    /// Stage ID
    pub id: String,
    /// Stage name
    pub name: String,
    /// Stage type
    pub stage_type: PipelineStageType,
    /// Stage configuration
    pub config: HashMap<String, serde_json::Value>,
}

/// Types of pipeline stages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PipelineStageType {
    /// Validate file type and size
    FileValidation,
    /// Extract text content from file
    ContentExtraction,
    /// Clean and normalize text
    TextCleaning {
        /// Remove HTML tags
        strip_html: bool,
        /// Normalize whitespace
        normalize_whitespace: bool,
        /// Convert to lowercase
        lowercase: bool,
        /// Remove special characters
        remove_special: bool,
    },
    /// Chunk large documents
    Chunking {
        /// Maximum chunk size in tokens
        max_tokens: usize,
        /// Overlap between chunks
        overlap_tokens: usize,
    },
    /// Extract entities
    EntityExtraction,
    /// Apply data standard validation
    SchemaValidation {
        /// Standard ID to validate against
        standard_id: String,
    },
    /// Generate embeddings
    Embedding {
        /// Model to use
        model: String,
    },
    /// Custom transform function
    CustomTransform {
        /// Function name
        function: String,
    },
    /// Filter records
    Filter {
        /// Filter predicate
        predicate: String,
    },
    /// Deduplicate records
    Deduplication {
        /// Fields to use for dedup key
        key_fields: Vec<String>,
    },
}

/// Retry policy for failed processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Initial backoff in milliseconds
    pub initial_backoff_ms: u64,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
    /// Maximum backoff in milliseconds
    pub max_backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff_ms: 1000,
            backoff_multiplier: 2.0,
            max_backoff_ms: 60_000,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Knowledge Container
// ═══════════════════════════════════════════════════════════════

/// A knowledge container — validated, structured data in `/k/` namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeContainer {
    /// Container ID
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Full namespace path (e.g., "k/medical/facts")
    pub namespace: String,
    /// Domain this knowledge belongs to
    pub domain: String,
    /// Data standard applied
    pub data_standard: Option<String>,
    /// Number of knowledge packets
    pub packet_count: u64,
    /// Total tokens (estimated)
    pub total_tokens: u64,
    /// Entity count (from knowledge graph)
    pub entity_count: u64,
    /// Source asset containers
    pub source_containers: Vec<String>,
    /// Created timestamp
    pub created_at: i64,
    /// Last updated timestamp
    pub updated_at: i64,
    /// Owner agent PID
    pub owner_pid: String,
    /// Whether this container is sealed (no more writes)
    pub sealed: bool,
    /// Container metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl KnowledgeContainer {
    /// Create a new knowledge container.
    pub fn new(id: String, name: String, domain: String, owner_pid: String) -> Self {
        let now = now_ms();
        Self {
            id: id.clone(),
            name,
            namespace: format!("k/{}/{}", domain, id),
            domain,
            data_standard: None,
            packet_count: 0,
            total_tokens: 0,
            entity_count: 0,
            source_containers: Vec::new(),
            created_at: now,
            updated_at: now,
            owner_pid,
            sealed: false,
            metadata: HashMap::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// App Container (/x/) — Executable Apps (like APK/EXE)
// ═══════════════════════════════════════════════════════════════

/// Protocol type for app communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppProtocol {
    /// Model Context Protocol — standard for external tool integration
    Mcp,
    /// HTTP/REST API
    Http,
    /// WebSocket for real-time communication
    WebSocket,
    /// gRPC for high-performance RPC
    Grpc,
    /// Custom protocol handler
    Custom,
}

/// App container — executable apps in `/x/` namespace (like APK/EXE).
/// User-installable from marketplace, sandboxed execution.
/// Controls external tools using MCP, HTTP, or other protocols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppContainer {
    /// App ID (unique identifier)
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Full namespace path (e.g., "x/apps/slack_bot")
    pub namespace: String,
    /// App version (semver)
    pub version: String,
    /// Protocol used for tool communication
    pub protocol: AppProtocol,
    /// Tools provided by this app
    pub tools: Vec<AppTool>,
    /// Required permissions/capabilities
    pub permissions: Vec<String>,
    /// App status
    pub status: AppStatus,
    /// Publisher/author
    pub publisher: String,
    /// Signature (for verification)
    pub signature: Option<String>,
    /// Created timestamp
    pub created_at: i64,
    /// Last updated timestamp
    pub updated_at: i64,
    /// Owner agent PID
    pub owner_pid: String,
    /// App metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Status of an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppStatus {
    /// Installed but not running
    Installed,
    /// Currently running
    Running,
    /// Paused/suspended
    Paused,
    /// Stopped
    Stopped,
    /// Failed to start
    Failed,
    /// Pending installation
    Pending,
}

/// A tool provided by an app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppTool {
    /// Tool name
    pub name: String,
    /// Tool description
    pub description: String,
    /// Input schema (JSON Schema)
    pub input_schema: serde_json::Value,
    /// Output schema (JSON Schema)
    pub output_schema: Option<serde_json::Value>,
    /// Whether tool requires confirmation
    pub requires_confirmation: bool,
}

impl AppContainer {
    /// Create a new app container.
    pub fn new(id: String, name: String, version: String, protocol: AppProtocol, owner_pid: String) -> Self {
        let now = now_ms();
        Self {
            id: id.clone(),
            name,
            namespace: format!("x/apps/{}", id),
            version,
            protocol,
            tools: Vec::new(),
            permissions: Vec::new(),
            status: AppStatus::Installed,
            publisher: owner_pid.clone(),
            signature: None,
            created_at: now,
            updated_at: now,
            owner_pid,
            metadata: HashMap::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Core Container (/c/) — Native Core Logic (like /bin)
// ═══════════════════════════════════════════════════════════════

/// Core module — native platform logic in `/c/` namespace.
/// Platform-signed critical infrastructure using CNP protocol.
/// Direct kernel syscalls, no protocol overhead, trusted code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreModule {
    /// Module ID (unique identifier)
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Full namespace path (e.g., "c/core/auth")
    pub namespace: String,
    /// Module version (semver)
    pub version: String,
    /// Module category
    pub category: CoreCategory,
    /// Syscalls this module can invoke
    pub allowed_syscalls: Vec<String>,
    /// Dependencies on other core modules
    pub dependencies: Vec<String>,
    /// Platform signature (Ed25519)
    pub signature: String,
    /// Signer identity
    pub signer: String,
    /// Module status
    pub status: CoreStatus,
    /// Created timestamp
    pub created_at: i64,
    /// Last updated timestamp
    pub updated_at: i64,
    /// Module metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Category of core module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreCategory {
    /// Authentication and authorization
    Auth,
    /// Billing and metering
    Billing,
    /// Compliance and audit
    Compliance,
    /// Security and firewall
    Security,
    /// Scheduling and orchestration
    Scheduler,
    /// Storage and persistence
    Storage,
    /// Networking and protocols
    Network,
    /// Monitoring and observability
    Monitor,
    /// Custom/other
    Custom,
}

/// Status of a core module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreStatus {
    /// Loaded and ready
    Ready,
    /// Currently executing
    Active,
    /// Temporarily disabled
    Disabled,
    /// Failed verification
    Invalid,
    /// Pending load
    Pending,
}

impl CoreModule {
    /// Create a new core module.
    pub fn new(id: String, name: String, version: String, category: CoreCategory, signature: String, signer: String) -> Self {
        let now = now_ms();
        Self {
            id: id.clone(),
            name,
            namespace: format!("c/core/{}", id),
            version,
            category,
            allowed_syscalls: Vec::new(),
            dependencies: Vec::new(),
            signature,
            signer,
            status: CoreStatus::Pending,
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        }
    }

    /// Verify module signature.
    pub fn verify_signature(&self) -> bool {
        // In production, this would verify Ed25519 signature
        // For now, just check signature is non-empty
        !self.signature.is_empty()
    }
}

// ═══════════════════════════════════════════════════════════════
// Ingestion Result
// ═══════════════════════════════════════════════════════════════

/// Result of processing an asset through the ingestion pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionResult {
    /// Source asset CID
    pub asset_cid: String,
    /// Whether ingestion succeeded
    pub success: bool,
    /// Resulting knowledge packet CIDs
    pub knowledge_cids: Vec<String>,
    /// Number of entities extracted
    pub entities_extracted: usize,
    /// Processing duration in milliseconds
    pub duration_ms: u64,
    /// Stages completed
    pub stages_completed: Vec<String>,
    /// Stage that failed (if any)
    pub failed_stage: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Warnings generated during processing
    pub warnings: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_type_detection() {
        assert_eq!(AssetFileType::from_extension("txt"), Some(AssetFileType::PlainText));
        assert_eq!(AssetFileType::from_extension("md"), Some(AssetFileType::Markdown));
        assert_eq!(AssetFileType::from_extension("json"), Some(AssetFileType::Json));
        assert_eq!(AssetFileType::from_extension("csv"), Some(AssetFileType::Csv));
        assert_eq!(AssetFileType::from_extension("pdf"), Some(AssetFileType::Pdf));
        assert_eq!(AssetFileType::from_extension("rs"), Some(AssetFileType::SourceCode));
        assert_eq!(AssetFileType::from_extension("png"), Some(AssetFileType::Binary));
        assert_eq!(AssetFileType::from_extension("unknown"), None);
    }

    #[test]
    fn test_asset_container_capacity() {
        let mut container = AssetContainer::new("test".into(), "Test".into(), "agent1".into());
        container.quota_bytes = 1000;
        container.used_bytes = 500;
        
        assert!(container.has_capacity(400));
        assert!(container.has_capacity(500));
        assert!(!container.has_capacity(501));
    }

    #[test]
    fn test_asset_container_allowed_types() {
        let container = AssetContainer::new("test".into(), "Test".into(), "agent1".into());
        
        assert!(container.allows_type(AssetFileType::PlainText));
        assert!(container.allows_type(AssetFileType::Json));
        assert!(!container.allows_type(AssetFileType::Pdf)); // Not in default allowed types
    }

    #[test]
    fn test_knowledge_container_namespace() {
        let kc = KnowledgeContainer::new(
            "facts".into(),
            "Medical Facts".into(),
            "medical".into(),
            "agent1".into(),
        );
        
        assert_eq!(kc.namespace, "k/medical/facts");
        assert_eq!(kc.domain, "medical");
    }

    #[test]
    fn test_app_container_namespace() {
        let app = AppContainer::new(
            "slack_bot".into(),
            "Slack Bot".into(),
            "1.0.0".into(),
            AppProtocol::Mcp,
            "agent1".into(),
        );
        
        assert_eq!(app.namespace, "x/apps/slack_bot");
        assert_eq!(app.protocol, AppProtocol::Mcp);
        assert_eq!(app.status, AppStatus::Installed);
    }

    #[test]
    fn test_core_module_namespace() {
        let core = CoreModule::new(
            "auth".into(),
            "Authentication".into(),
            "1.0.0".into(),
            CoreCategory::Auth,
            "sig_abc123".into(),
            "platform".into(),
        );
        
        assert_eq!(core.namespace, "c/core/auth");
        assert_eq!(core.category, CoreCategory::Auth);
        assert!(core.verify_signature());
    }

    #[test]
    fn test_core_module_invalid_signature() {
        let core = CoreModule::new(
            "test".into(),
            "Test".into(),
            "1.0.0".into(),
            CoreCategory::Custom,
            "".into(), // Empty signature
            "".into(),
        );
        
        assert!(!core.verify_signature());
    }
}
