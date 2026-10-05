//! Shared types for the Memory Transport and Object Fabric.
//!
//! Defines canonical event, record, and lifecycle types used across all fabric layers.
//!
//! **Agent-agnostic:** These types serve any autonomous agent — LLMs, neural networks,
//! ML pipelines, robotics controllers, sensor fusion systems, classical AI, rule engines.
//!
//! **Modality-agnostic:** Memory can be text, images, video, audio, sensor readings,
//! point clouds, model weights, embeddings, binary blobs, or any structured/unstructured data.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// =============================================================================
// Event Types — what happened
// =============================================================================

/// Classification of memory-bearing actions that enter the commit log.
///
/// Covers the full spectrum of autonomous agent activity — not just LLM text
/// interactions but also sensor ingestion, perception outputs, actuation commands,
/// model training checkpoints, inference results, and multimodal data flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // ── Agent Interactions ──
    InteractionCreated,
    ToolOutputProduced,
    FileUploaded,
    TraceSegmentRecorded,
    ChunkExtractionDone,
    EmbeddingCreated,
    ProjectionCreated,
    SummaryEmitted,

    // ── Multimodal Ingestion ──
    ImageCaptured,
    VideoFrameIngested,
    AudioSegmentIngested,
    SensorReadingRecorded,
    PointCloudCaptured,
    BinaryBlobStored,

    // ── ML / Neural Network Pipeline ──
    ModelCheckpointSaved,
    TrainingMetricLogged,
    InferenceResultProduced,
    DatasetVersionCreated,
    FeatureVectorComputed,
    GradientSnapshotSaved,
    ModelDeployed,
    ModelRetired,

    // ── Perception / Actuation (Robotics, Embodied Agents) ──
    PerceptionOutputProduced,
    ActuationCommandIssued,
    EnvironmentStateObserved,
    RewardSignalReceived,
    PlanStepExecuted,

    // ── Lifecycle ──
    ObjectArchived,
    RetentionMoved,
    IndexRebuilt,
    ReplaySnapshotFrozen,
    AgentRegistered,
    AgentTerminated,
    SessionOpened,
    SessionClosed,
    PolicyChanged,
    ContainerCreated,
    ContainerDeleted,
}

// =============================================================================
// Memory Class — what kind of memory
// =============================================================================

/// Semantic classification of a memory unit.
///
/// Covers classical cognitive memory categories plus ML/robotics-specific
/// categories for model weights, sensor streams, perception, and actuation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryClass {
    // ── Cognitive ──
    Episodic,
    Semantic,
    Procedural,
    Working,
    Reasoning,

    // ── Multimodal / Sensory ──
    Sensory,
    Visual,
    Auditory,
    Spatial,

    // ── ML / Neural Network ──
    ModelWeights,
    TrainingData,
    InferenceResult,
    FeatureMap,
    Gradient,

    // ── Robotics / Embodied ──
    Perception,
    Actuation,
    EnvironmentState,
    Reward,

    // ── Structural ──
    Evidence,
    Projection,
    Summary,
    Artifact,
    Dataset,
    System,
}

// =============================================================================
// Visibility — who can see it
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Private,
    Shared,
    Organizational,
    Public,
    System,
}

// =============================================================================
// Retention — how long to keep it
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    Ephemeral,
    Session,
    ShortTerm,
    LongTerm,
    Permanent,
    Evidence,
}

// =============================================================================
// Storage Tier — where it lives physically
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageTier {
    Hot,
    Warm,
    Cold,
    Archive,
}

// =============================================================================
// Memory Lifecycle State
// =============================================================================

/// Lifecycle state of a memory unit.
///
/// ```text
/// ingested → committed → materializing → materialized → queryable
///   → summarized / projected / archived → deleted
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryState {
    Ingested,
    Committed,
    Materializing,
    Materialized,
    Queryable,
    Summarized,
    Projected,
    Archived,
    Deleted,
}

// =============================================================================
// Payload Descriptor
// =============================================================================

/// Describes the payload of a memory event.
///
/// Small payloads (<64KB) are inlined as JSON. Large payloads (images, video,
/// model weights, sensor dumps, point clouds) are stored in the Object Fabric
/// and referenced by `object_ref`. Multipart payloads reference multiple
/// object parts for very large data (video streams, datasets, checkpoints).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadDescriptor {
    pub content_type: String,
    pub size_bytes: u64,
    pub content_hash: String,
    pub modality: Modality,
    pub format: ContentFormat,
    pub inline_payload: Option<serde_json::Value>,
    pub object_ref: Option<String>,
    /// For multipart/chunked uploads: references to individual parts.
    pub part_refs: Vec<String>,
    /// Dimensions for structured data (e.g., image WxH, tensor shape, sample rate).
    pub dimensions: Vec<u64>,
    /// Number of channels (e.g., RGB=3, stereo audio=2, LiDAR rings=64).
    pub channels: u32,
    /// Frame rate for temporal data (video fps, sensor Hz). 0 = not applicable.
    pub sample_rate_hz: f64,
    /// Duration in milliseconds for temporal data. 0 = not applicable.
    pub duration_ms: u64,
}

impl PayloadDescriptor {
    /// Maximum inline payload size (64 KB).
    pub const MAX_INLINE_BYTES: u64 = 65_536;

    pub fn inline(content_type: &str, payload: serde_json::Value) -> Self {
        let bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let hash = sha2_hex(&bytes);
        Self {
            content_type: content_type.to_string(),
            size_bytes: bytes.len() as u64,
            content_hash: hash,
            modality: Modality::from_content_type(content_type),
            format: ContentFormat::Json,
            inline_payload: Some(payload),
            object_ref: None,
            part_refs: Vec::new(),
            dimensions: Vec::new(),
            channels: 0,
            sample_rate_hz: 0.0,
            duration_ms: 0,
        }
    }

    pub fn object_ref(content_type: &str, size_bytes: u64, content_hash: String, uri: String) -> Self {
        Self {
            content_type: content_type.to_string(),
            size_bytes,
            content_hash,
            modality: Modality::from_content_type(content_type),
            format: ContentFormat::from_content_type(content_type),
            inline_payload: None,
            object_ref: Some(uri),
            part_refs: Vec::new(),
            dimensions: Vec::new(),
            channels: 0,
            sample_rate_hz: 0.0,
            duration_ms: 0,
        }
    }

    /// Create a descriptor for an image payload stored in the Object Fabric.
    pub fn image(content_type: &str, size_bytes: u64, hash: String, uri: String, width: u64, height: u64, channels: u32) -> Self {
        Self {
            content_type: content_type.to_string(),
            size_bytes,
            content_hash: hash,
            modality: Modality::Image,
            format: ContentFormat::from_content_type(content_type),
            inline_payload: None,
            object_ref: Some(uri),
            part_refs: Vec::new(),
            dimensions: vec![width, height],
            channels,
            sample_rate_hz: 0.0,
            duration_ms: 0,
        }
    }

    /// Create a descriptor for video stored in the Object Fabric.
    pub fn video(content_type: &str, size_bytes: u64, hash: String, uri: String, width: u64, height: u64, fps: f64, duration_ms: u64) -> Self {
        Self {
            content_type: content_type.to_string(),
            size_bytes,
            content_hash: hash,
            modality: Modality::Video,
            format: ContentFormat::from_content_type(content_type),
            inline_payload: None,
            object_ref: Some(uri),
            part_refs: Vec::new(),
            dimensions: vec![width, height],
            channels: 3,
            sample_rate_hz: fps,
            duration_ms,
        }
    }

    /// Create a descriptor for audio stored in the Object Fabric.
    pub fn audio(content_type: &str, size_bytes: u64, hash: String, uri: String, sample_rate: f64, channels: u32, duration_ms: u64) -> Self {
        Self {
            content_type: content_type.to_string(),
            size_bytes,
            content_hash: hash,
            modality: Modality::Audio,
            format: ContentFormat::from_content_type(content_type),
            inline_payload: None,
            object_ref: Some(uri),
            part_refs: Vec::new(),
            dimensions: Vec::new(),
            channels,
            sample_rate_hz: sample_rate,
            duration_ms,
        }
    }

    /// Create a descriptor for sensor data (accelerometer, gyro, LiDAR, etc.).
    pub fn sensor(content_type: &str, size_bytes: u64, hash: String, uri: String, sensor_channels: u32, sample_rate: f64) -> Self {
        Self {
            content_type: content_type.to_string(),
            size_bytes,
            content_hash: hash,
            modality: Modality::Sensor,
            format: ContentFormat::from_content_type(content_type),
            inline_payload: None,
            object_ref: Some(uri),
            part_refs: Vec::new(),
            dimensions: Vec::new(),
            channels: sensor_channels,
            sample_rate_hz: sample_rate,
            duration_ms: 0,
        }
    }

    /// Create a descriptor for a tensor (model weights, feature maps, gradients).
    pub fn tensor(content_type: &str, size_bytes: u64, hash: String, uri: String, shape: Vec<u64>) -> Self {
        Self {
            content_type: content_type.to_string(),
            size_bytes,
            content_hash: hash,
            modality: Modality::Tensor,
            format: ContentFormat::from_content_type(content_type),
            inline_payload: None,
            object_ref: Some(uri),
            part_refs: Vec::new(),
            dimensions: shape,
            channels: 0,
            sample_rate_hz: 0.0,
            duration_ms: 0,
        }
    }

    /// Create a descriptor for a point cloud (LiDAR, depth sensor, 3D scan).
    pub fn point_cloud(content_type: &str, size_bytes: u64, hash: String, uri: String, point_count: u64, dims_per_point: u32) -> Self {
        Self {
            content_type: content_type.to_string(),
            size_bytes,
            content_hash: hash,
            modality: Modality::PointCloud,
            format: ContentFormat::from_content_type(content_type),
            inline_payload: None,
            object_ref: Some(uri),
            part_refs: Vec::new(),
            dimensions: vec![point_count],
            channels: dims_per_point,
            sample_rate_hz: 0.0,
            duration_ms: 0,
        }
    }

    /// Create a multipart descriptor for very large data (datasets, video archives).
    pub fn multipart(content_type: &str, total_bytes: u64, hash: String, parts: Vec<String>) -> Self {
        Self {
            content_type: content_type.to_string(),
            size_bytes: total_bytes,
            content_hash: hash,
            modality: Modality::from_content_type(content_type),
            format: ContentFormat::from_content_type(content_type),
            inline_payload: None,
            object_ref: None,
            part_refs: parts,
            dimensions: Vec::new(),
            channels: 0,
            sample_rate_hz: 0.0,
            duration_ms: 0,
        }
    }

    /// Whether this payload is stored externally (not inlined).
    pub fn is_external(&self) -> bool {
        self.object_ref.is_some() || !self.part_refs.is_empty()
    }

    /// Whether this is a multipart payload.
    pub fn is_multipart(&self) -> bool {
        !self.part_refs.is_empty()
    }
}

// =============================================================================
// Policy Snapshot
// =============================================================================

/// Captures the policy state at the moment of event creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub visibility: Visibility,
    pub retention_class: RetentionClass,
    pub encryption_required: bool,
    pub evidence_required: bool,
    pub allowed_readers: Vec<String>,
}

impl Default for PolicySnapshot {
    fn default() -> Self {
        Self {
            visibility: Visibility::Private,
            retention_class: RetentionClass::LongTerm,
            encryption_required: false,
            evidence_required: false,
            allowed_readers: Vec::new(),
        }
    }
}

// =============================================================================
// MemoryEvent — canonical commit log entry
// =============================================================================

/// A single event in the commit log.
///
/// Every memory-bearing action first becomes a committed event before any
/// downstream processing. This is the Kafka-like side of the architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEvent {
    pub event_id: String,
    pub tenant_id: String,
    pub container_id: String,
    pub trace_id: Option<String>,
    pub partition_key: String,
    pub event_type: EventType,
    pub memory_class: MemoryClass,
    pub producer_id: String,
    pub idempotency_key: String,
    pub payload: PayloadDescriptor,
    pub policy: PolicySnapshot,
    pub timestamp: i64,
    pub lsn: u64,
}

// =============================================================================
// MemoryRecord — fully materialized memory unit
// =============================================================================

/// A fully materialized memory record.
///
/// Created after all materializers have processed the source MemoryEvent.
/// This is the S3 + kernel + index side of the architecture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRecord {
    pub mid: String,
    pub tenant_id: String,
    pub container_id: String,
    pub cid: String,
    pub object_uri: Option<String>,
    pub metadata_ref: Option<String>,
    pub vector_ref: Option<String>,
    pub continuity_ref: Option<String>,
    pub receipt_ref: Option<String>,
    pub visibility: Visibility,
    pub retention_class: RetentionClass,
    pub memory_class: MemoryClass,
    pub lineage_ref: Option<String>,
    pub state: MemoryState,
    pub materialization_version: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

// =============================================================================
// Materializer Types
// =============================================================================

/// Types of materializers that consume from the commit log.
///
/// Includes classical index materializers plus multimodal-specific processors
/// for images, audio, video, sensor data, and ML model artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializerType {
    Object,
    Metadata,
    Vector,
    Continuity,
    KernelFinalizer,
    // ── Multimodal Materializers ──
    ImageProcessor,
    AudioProcessor,
    VideoProcessor,
    SensorProcessor,
    PointCloudProcessor,
    TensorProcessor,
    ModelRegistry,
    // ── Knowledge Graph Materializer ──
    Knowledge,
}

/// Status of a materializer processing a specific event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Skipped,
}

/// Tracks which materializers have processed an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializationState {
    pub event_id: String,
    pub statuses: HashMap<MaterializerType, MaterializationStatus>,
}

impl MaterializationState {
    pub fn new(event_id: String, required: &[MaterializerType]) -> Self {
        let mut statuses = HashMap::new();
        for mt in required {
            statuses.insert(*mt, MaterializationStatus::Pending);
        }
        Self { event_id, statuses }
    }

    pub fn is_complete(&self) -> bool {
        self.statuses.values().all(|s| matches!(s, MaterializationStatus::Completed | MaterializationStatus::Skipped))
    }

    pub fn mark(&mut self, mt: MaterializerType, status: MaterializationStatus) {
        self.statuses.insert(mt, status);
    }
}

// =============================================================================
// Container Types
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerType {
    Agent,
    Shared,
    Organizational,
    Evidence,
    Projection,
    // ── ML / Data Science ──
    ModelRegistry,
    Dataset,
    Experiment,
    // ── Sensor / Robotics ──
    SensorStream,
    PerceptionPipeline,
    ActuationLog,
}

// =============================================================================
// Edge Types (for Continuity Fabric)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeType {
    Next,
    Prev,
    DerivedFrom,
    Supports,
    Rejects,
    ForksTo,
    MergesInto,
    Compresses,
    ProjectsTo,
    SharedWith,
    // ── ML / Pipeline ──
    TrainedOn,
    ProducedBy,
    InputTo,
    OutputOf,
    // ── Sensor / Perception ──
    PerceivedFrom,
    ActuatedBy,
    CalibratedWith,
    FusedFrom,
}

// =============================================================================
// Node Types (for Continuity Fabric)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    TraceRoot,
    ThoughtSpan,
    MemoryNode,
    PageNode,
    SummaryNode,
    DecisionNode,
    MergeNode,
    ProjectionNode,
    // ── ML / Pipeline ──
    ModelNode,
    DatasetNode,
    TrainingRunNode,
    InferenceNode,
    // ── Perception / Sensor ──
    SensorNode,
    PerceptionNode,
    ActuationNode,
    EnvironmentNode,
}

// =============================================================================
// Span Types (for reasoning reconstruction)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanType {
    Observation,
    Retrieval,
    Hypothesis,
    Comparison,
    Rejection,
    Decision,
    ExecutionIntent,
    Validation,
    MergeSummary,
    ProjectionSummary,
    // ── ML / Pipeline ──
    Training,
    Inference,
    Evaluation,
    FeatureExtraction,
    // ── Perception / Sensor ──
    SensorFusion,
    ObjectDetection,
    PathPlanning,
    MotorControl,
}

// =============================================================================
// Helpers
// =============================================================================

// =============================================================================
// Modality — what kind of data
// =============================================================================

/// The sensory/data modality of a memory payload.
///
/// This system stores *any* kind of data an autonomous agent can produce or
/// consume — not just text. A robotics controller stores point clouds and
/// motor commands. A vision model stores images and bounding boxes. An audio
/// pipeline stores waveforms. An RL agent stores environment states and rewards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    Text,
    Image,
    Video,
    Audio,
    Sensor,
    PointCloud,
    Tensor,
    Embedding,
    StructuredData,
    Binary,
    TimeSeries,
    Graph,
    Document,
    Code,
    Mixed,
}

impl Modality {
    /// Infer modality from MIME content type.
    pub fn from_content_type(ct: &str) -> Self {
        let ct_lower = ct.to_lowercase();
        if ct_lower.starts_with("image/") { return Self::Image; }
        if ct_lower.starts_with("video/") { return Self::Video; }
        if ct_lower.starts_with("audio/") { return Self::Audio; }
        if ct_lower.contains("json") { return Self::StructuredData; }
        if ct_lower.starts_with("text/") { return Self::Text; }
        if ct_lower.contains("tensor") || ct_lower.contains("numpy") || ct_lower.contains("npy") {
            return Self::Tensor;
        }
        if ct_lower.contains("point-cloud") || ct_lower.contains("pcd") || ct_lower.contains("ply") {
            return Self::PointCloud;
        }
        if ct_lower.contains("time-series") || ct_lower.contains("csv") {
            return Self::TimeSeries;
        }
        Self::Binary
    }
}

// =============================================================================
// Content Format — encoding/serialization format
// =============================================================================

/// Low-level encoding format of the payload data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentFormat {
    Json,
    Cbor,
    MessagePack,
    Protobuf,
    Arrow,
    Parquet,
    Numpy,
    Safetensors,
    Onnx,
    Png,
    Jpeg,
    WebP,
    Mp4,
    WebM,
    Wav,
    Flac,
    Ogg,
    Pcd,
    Ply,
    Csv,
    Raw,
    Custom(u32),
}

impl ContentFormat {
    pub fn from_content_type(ct: &str) -> Self {
        let ct_lower = ct.to_lowercase();
        if ct_lower.contains("json") { return Self::Json; }
        if ct_lower.contains("cbor") { return Self::Cbor; }
        if ct_lower.contains("msgpack") || ct_lower.contains("messagepack") { return Self::MessagePack; }
        if ct_lower.contains("protobuf") || ct_lower.contains("proto") { return Self::Protobuf; }
        if ct_lower.contains("arrow") { return Self::Arrow; }
        if ct_lower.contains("parquet") { return Self::Parquet; }
        if ct_lower.contains("numpy") || ct_lower.contains("npy") { return Self::Numpy; }
        if ct_lower.contains("safetensors") { return Self::Safetensors; }
        if ct_lower.contains("onnx") { return Self::Onnx; }
        if ct_lower.contains("png") { return Self::Png; }
        if ct_lower.contains("jpeg") || ct_lower.contains("jpg") { return Self::Jpeg; }
        if ct_lower.contains("webp") { return Self::WebP; }
        if ct_lower.contains("mp4") { return Self::Mp4; }
        if ct_lower.contains("webm") { return Self::WebM; }
        if ct_lower.contains("wav") { return Self::Wav; }
        if ct_lower.contains("flac") { return Self::Flac; }
        if ct_lower.contains("ogg") { return Self::Ogg; }
        if ct_lower.contains("pcd") { return Self::Pcd; }
        if ct_lower.contains("ply") { return Self::Ply; }
        if ct_lower.contains("csv") { return Self::Csv; }
        Self::Raw
    }
}

// =============================================================================
// Agent Kind — what type of autonomous agent produced this
// =============================================================================

/// Classification of the agent that produced or owns memory.
///
/// The fabric is not just for LLMs — it serves any autonomous agent:
/// neural networks, ML pipelines, robotics controllers, sensor fusion
/// systems, rule engines, classical planners, hybrid systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    Llm,
    NeuralNetwork,
    ReinforcementLearning,
    SupervisedModel,
    UnsupervisedModel,
    GenerativeModel,
    Diffusion,
    Gan,
    Vae,
    Transformer,
    Cnn,
    Rnn,
    GraphNeuralNetwork,
    ClassicalPlanner,
    RuleEngine,
    ExpertSystem,
    BayesianAgent,
    EvolutionaryAgent,
    MultiAgentSystem,
    RoboticsController,
    SensorFusion,
    EmbodiedAgent,
    HybridAgent,
    Human,
    Pipeline,
    Custom,
}

// =============================================================================
// Helpers
// =============================================================================

/// SHA-256 hash as hex string.
pub fn sha2_hex(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let hash: [u8; 32] = Sha256::new().chain_update(data).finalize().into();
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Generate a time-ordered unique ID (UUID v7-like).
pub fn generate_id(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros();
    let rand_part: u32 = rand::random();
    format!("{}:{:016x}:{:08x}", prefix, ts, rand_part)
}

/// Current timestamp in milliseconds.
pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_descriptor_inline() {
        let pd = PayloadDescriptor::inline("application/json", serde_json::json!({"test": true}));
        assert_eq!(pd.content_type, "application/json");
        assert!(pd.inline_payload.is_some());
        assert!(pd.object_ref.is_none());
        assert!(!pd.content_hash.is_empty());
        assert!(pd.size_bytes > 0);
    }

    #[test]
    fn test_payload_descriptor_object() {
        let pd = PayloadDescriptor::object_ref(
            "application/octet-stream", 1_000_000,
            "abc123".to_string(), "s3://bucket/key".to_string(),
        );
        assert!(pd.inline_payload.is_none());
        assert_eq!(pd.object_ref.as_deref(), Some("s3://bucket/key"));
    }

    #[test]
    fn test_materialization_state() {
        let required = vec![MaterializerType::Object, MaterializerType::Vector, MaterializerType::KernelFinalizer];
        let mut ms = MaterializationState::new("evt:001".to_string(), &required);
        assert!(!ms.is_complete());

        ms.mark(MaterializerType::Object, MaterializationStatus::Completed);
        assert!(!ms.is_complete());

        ms.mark(MaterializerType::Vector, MaterializationStatus::Completed);
        ms.mark(MaterializerType::KernelFinalizer, MaterializationStatus::Completed);
        assert!(ms.is_complete());
    }

    #[test]
    fn test_materialization_state_skipped() {
        let required = vec![MaterializerType::Object, MaterializerType::Vector];
        let mut ms = MaterializationState::new("evt:002".to_string(), &required);
        ms.mark(MaterializerType::Object, MaterializationStatus::Completed);
        ms.mark(MaterializerType::Vector, MaterializationStatus::Skipped);
        assert!(ms.is_complete());
    }

    #[test]
    fn test_generate_id() {
        let id1 = generate_id("evt");
        let id2 = generate_id("evt");
        assert!(id1.starts_with("evt:"));
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_sha2_hex() {
        let hash = sha2_hex(b"hello");
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_memory_state_lifecycle() {
        let states = vec![
            MemoryState::Ingested,
            MemoryState::Committed,
            MemoryState::Materializing,
            MemoryState::Materialized,
            MemoryState::Queryable,
        ];
        for (i, s) in states.iter().enumerate() {
            let json = serde_json::to_string(s).unwrap();
            let back: MemoryState = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back, "Roundtrip failed at index {}", i);
        }
    }

    #[test]
    fn test_event_type_serde() {
        let et = EventType::InteractionCreated;
        let json = serde_json::to_string(&et).unwrap();
        assert_eq!(json, "\"interaction_created\"");
        let back: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(et, back);
    }

    #[test]
    fn test_modality_from_content_type() {
        assert_eq!(Modality::from_content_type("image/png"), Modality::Image);
        assert_eq!(Modality::from_content_type("image/jpeg"), Modality::Image);
        assert_eq!(Modality::from_content_type("video/mp4"), Modality::Video);
        assert_eq!(Modality::from_content_type("audio/wav"), Modality::Audio);
        assert_eq!(Modality::from_content_type("application/json"), Modality::StructuredData);
        assert_eq!(Modality::from_content_type("text/plain"), Modality::Text);
        assert_eq!(Modality::from_content_type("application/x-numpy"), Modality::Tensor);
        assert_eq!(Modality::from_content_type("application/x-pcd"), Modality::PointCloud);
        assert_eq!(Modality::from_content_type("application/octet-stream"), Modality::Binary);
    }

    #[test]
    fn test_content_format_from_content_type() {
        assert_eq!(ContentFormat::from_content_type("application/json"), ContentFormat::Json);
        assert_eq!(ContentFormat::from_content_type("image/png"), ContentFormat::Png);
        assert_eq!(ContentFormat::from_content_type("video/mp4"), ContentFormat::Mp4);
        assert_eq!(ContentFormat::from_content_type("audio/wav"), ContentFormat::Wav);
        assert_eq!(ContentFormat::from_content_type("application/x-safetensors"), ContentFormat::Safetensors);
        assert_eq!(ContentFormat::from_content_type("application/x-onnx"), ContentFormat::Onnx);
        assert_eq!(ContentFormat::from_content_type("application/x-parquet"), ContentFormat::Parquet);
    }

    #[test]
    fn test_payload_descriptor_image() {
        let pd = PayloadDescriptor::image("image/png", 1_000_000, "hash".into(), "s3://b/k".into(), 1920, 1080, 3);
        assert_eq!(pd.modality, Modality::Image);
        assert_eq!(pd.dimensions, vec![1920, 1080]);
        assert_eq!(pd.channels, 3);
        assert!(pd.is_external());
        assert!(!pd.is_multipart());
    }

    #[test]
    fn test_payload_descriptor_video() {
        let pd = PayloadDescriptor::video("video/mp4", 50_000_000, "h".into(), "s3://b/k".into(), 1920, 1080, 30.0, 60000);
        assert_eq!(pd.modality, Modality::Video);
        assert_eq!(pd.sample_rate_hz, 30.0);
        assert_eq!(pd.duration_ms, 60000);
    }

    #[test]
    fn test_payload_descriptor_audio() {
        let pd = PayloadDescriptor::audio("audio/wav", 5_000_000, "h".into(), "s3://b/k".into(), 44100.0, 2, 30000);
        assert_eq!(pd.modality, Modality::Audio);
        assert_eq!(pd.sample_rate_hz, 44100.0);
        assert_eq!(pd.channels, 2);
    }

    #[test]
    fn test_payload_descriptor_sensor() {
        let pd = PayloadDescriptor::sensor("application/x-sensor", 1024, "h".into(), "s3://b/k".into(), 6, 100.0);
        assert_eq!(pd.modality, Modality::Sensor);
        assert_eq!(pd.channels, 6); // e.g., 3-axis accel + 3-axis gyro
    }

    #[test]
    fn test_payload_descriptor_tensor() {
        let pd = PayloadDescriptor::tensor("application/x-safetensors", 500_000_000, "h".into(), "s3://b/k".into(), vec![768, 3072]);
        assert_eq!(pd.modality, Modality::Tensor);
        assert_eq!(pd.dimensions, vec![768, 3072]);
    }

    #[test]
    fn test_payload_descriptor_point_cloud() {
        let pd = PayloadDescriptor::point_cloud("application/x-pcd", 10_000_000, "h".into(), "s3://b/k".into(), 100_000, 4);
        assert_eq!(pd.modality, Modality::PointCloud);
        assert_eq!(pd.dimensions, vec![100_000]); // 100K points
        assert_eq!(pd.channels, 4); // x, y, z, intensity
    }

    #[test]
    fn test_payload_descriptor_multipart() {
        let parts = vec!["s3://b/part0".into(), "s3://b/part1".into(), "s3://b/part2".into()];
        let pd = PayloadDescriptor::multipart("application/octet-stream", 3_000_000_000, "h".into(), parts);
        assert!(pd.is_multipart());
        assert!(pd.is_external());
        assert_eq!(pd.part_refs.len(), 3);
    }

    #[test]
    fn test_agent_kind_serde() {
        let ak = AgentKind::RoboticsController;
        let json = serde_json::to_string(&ak).unwrap();
        assert_eq!(json, "\"robotics_controller\"");
        let back: AgentKind = serde_json::from_str(&json).unwrap();
        assert_eq!(ak, back);
    }

    #[test]
    fn test_ml_event_types_serde() {
        let cases = vec![
            EventType::ModelCheckpointSaved,
            EventType::InferenceResultProduced,
            EventType::SensorReadingRecorded,
            EventType::PerceptionOutputProduced,
            EventType::ActuationCommandIssued,
            EventType::ImageCaptured,
            EventType::PointCloudCaptured,
        ];
        for et in cases {
            let json = serde_json::to_string(&et).unwrap();
            let back: EventType = serde_json::from_str(&json).unwrap();
            assert_eq!(et, back);
        }
    }

    #[test]
    fn test_ml_memory_classes_serde() {
        let cases = vec![
            MemoryClass::ModelWeights,
            MemoryClass::TrainingData,
            MemoryClass::Perception,
            MemoryClass::Actuation,
            MemoryClass::Sensory,
            MemoryClass::Visual,
            MemoryClass::FeatureMap,
        ];
        for mc in cases {
            let json = serde_json::to_string(&mc).unwrap();
            let back: MemoryClass = serde_json::from_str(&json).unwrap();
            assert_eq!(mc, back);
        }
    }
}
