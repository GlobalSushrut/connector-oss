//! CNP Types — unified type system for the Connector Native Protocol.
//!
//! Defines the protocol message envelope that flows through all 7 layers,
//! session state, error types, and protocol-level metadata.
//!
//! Layer mapping:
//!   L1 (Codec)     → CnpFrame, CnpWireFormat
//!   L2 (Transport) → CnpEncryptedFrame
//!   L3 (Security)  → CnpSecuredFrame
//!   L4 (Channel)   → CnpChannelMessage
//!   L5 (Routing)   → CnpRoutedMessage
//!   L6 (Contract)  → CnpSessionMessage
//!   L7 (Cognitive) → CnpPayload (top-level user-facing)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// CNP Protocol Version
// ═══════════════════════════════════════════════════════════════

/// Protocol version — major.minor for wire compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnpVersion {
    pub major: u16,
    pub minor: u16,
}

impl CnpVersion {
    pub const CURRENT: Self = Self { major: 1, minor: 0 };

    pub fn is_compatible(&self, other: &CnpVersion) -> bool {
        self.major == other.major
    }
}

impl std::fmt::Display for CnpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CNP/{}.{}", self.major, self.minor)
    }
}

// ═══════════════════════════════════════════════════════════════
// CNP Message Envelope — the unified message that flows through all layers
// ═══════════════════════════════════════════════════════════════

/// The top-level CNP message — what applications construct and receive.
/// Each layer wraps/unwraps metadata as the message descends/ascends the stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnpMessage {
    /// Unique message identifier (UUID v7 for time-ordering)
    pub message_id: String,
    /// Protocol version
    pub version: CnpVersion,
    /// Sender agent PID
    pub from_agent: String,
    /// Target agent PID
    pub to_agent: String,
    /// The payload — spans all abstraction levels
    pub payload: CnpPayload,
    /// Session this message belongs to (None = sessionless)
    pub session_id: Option<String>,
    /// Port to send through (None = auto-resolve)
    pub port_id: Option<String>,
    /// Message timestamp (ms epoch)
    pub timestamp_ms: i64,
    /// TTL in milliseconds (0 = no expiry)
    pub ttl_ms: i64,
    /// Priority (0 = normal, higher = more urgent)
    pub priority: u8,
    /// Reply-to message ID (for request-response correlation)
    pub reply_to: Option<String>,
    /// CID of evidence supporting this message
    pub evidence_cid: Option<String>,
    /// Trace context for distributed observability
    pub trace_id: Option<String>,
    /// Application-level metadata
    pub metadata: HashMap<String, String>,
}

impl CnpMessage {
    /// Create a new message with required fields.
    pub fn new(
        from_agent: impl Into<String>,
        to_agent: impl Into<String>,
        payload: CnpPayload,
    ) -> Self {
        Self {
            message_id: generate_message_id(),
            version: CnpVersion::CURRENT,
            from_agent: from_agent.into(),
            to_agent: to_agent.into(),
            payload,
            session_id: None,
            port_id: None,
            timestamp_ms: now_ms(),
            ttl_ms: CNP_DEFAULT_TTL_MS,
            priority: 0,
            reply_to: None,
            evidence_cid: None,
            trace_id: None,
            metadata: HashMap::new(),
        }
    }

    /// Builder: set session ID.
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Builder: set port ID.
    pub fn with_port(mut self, port_id: impl Into<String>) -> Self {
        self.port_id = Some(port_id.into());
        self
    }

    /// Builder: set TTL.
    pub fn with_ttl(mut self, ttl_ms: i64) -> Self {
        self.ttl_ms = ttl_ms;
        self
    }

    /// Builder: set priority.
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Builder: set reply-to.
    pub fn with_reply_to(mut self, reply_to: impl Into<String>) -> Self {
        self.reply_to = Some(reply_to.into());
        self
    }

    /// Builder: set evidence CID.
    pub fn with_evidence(mut self, cid: impl Into<String>) -> Self {
        self.evidence_cid = Some(cid.into());
        self
    }

    /// Builder: add metadata.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Check if this message has expired.
    pub fn is_expired(&self) -> bool {
        if self.ttl_ms == 0 { return false; }
        now_ms() > self.timestamp_ms + self.ttl_ms
    }

    /// Check if this is a cognitive-level message.
    pub fn is_cognitive(&self) -> bool {
        matches!(self.payload, CnpPayload::Cognitive { .. })
    }

    /// Check if this is a request expecting a response.
    pub fn expects_response(&self) -> bool {
        matches!(self.payload, CnpPayload::Request { .. } | CnpPayload::KnowledgeRequest { .. })
    }
}

// ═══════════════════════════════════════════════════════════════
// CNP Payload — spans all abstraction levels
// ═══════════════════════════════════════════════════════════════

/// Payload variants — from raw bytes to cognitive thought-objects.
/// This is the key type that bridges the abjective–subjective divide.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CnpPayload {
    // ── L1: Abjective (raw data) ─────────────────────────────
    /// Raw binary payload with content-type metadata.
    #[serde(rename = "raw")]
    Raw {
        content_type: String,
        data: Vec<u8>,
        content_hash: Option<String>,
    },

    /// Sensor reading — edge/IoT native.
    #[serde(rename = "sensor")]
    Sensor {
        sensor_id: String,
        modality: SensorModality,
        reading: SensorReading,
        timestamp_us: u64,
    },

    /// Actuation command — robotics native.
    #[serde(rename = "actuation")]
    Actuation {
        target_id: String,
        command: ActuationCommand,
        deadline_us: Option<u64>,
    },

    /// Tensor/model data — ML pipeline native.
    #[serde(rename = "tensor")]
    Tensor {
        name: String,
        shape: Vec<u64>,
        dtype: TensorDtype,
        data_ref: String,
        format: TensorFormat,
    },

    // ── L4: Structural (typed protocol messages) ─────────────
    /// CID-referenced packet share (memory sharing between agents).
    #[serde(rename = "packet_share")]
    PacketShare {
        cids: Vec<String>,
        namespace: String,
    },

    /// Tool grant (delegate tool access to another agent).
    #[serde(rename = "tool_grant")]
    ToolGrant {
        tool_id: String,
        allowed_actions: Vec<String>,
        ttl_ms: Option<i64>,
    },

    /// Event notification.
    #[serde(rename = "event")]
    Event {
        event_type: String,
        data: serde_json::Value,
    },

    /// Request (expects a Response).
    #[serde(rename = "request")]
    Request {
        request_id: String,
        action: String,
        body: serde_json::Value,
    },

    /// Response (to a Request).
    #[serde(rename = "response")]
    Response {
        request_id: String,
        success: bool,
        body: serde_json::Value,
    },

    /// Pipeline handoff (pass context to next agent in chain).
    #[serde(rename = "pipeline_handoff")]
    PipelineHandoff {
        pipeline_id: String,
        step: u32,
        context_cids: Vec<String>,
        next_action: String,
    },

    // ── L7: Subjective (cognitive thought-objects) ────────────
    /// Full cognitive message — typed thought exchange.
    #[serde(rename = "cognitive")]
    Cognitive {
        cognitive_type: CognitiveMsgType,
    },

    // ── L6: Contract-level ───────────────────────────────────
    /// Knowledge request.
    #[serde(rename = "knowledge_request")]
    KnowledgeRequest {
        topic: String,
        knowledge_forms: Vec<String>,
    },

    /// Knowledge response.
    #[serde(rename = "knowledge_response")]
    KnowledgeResponse {
        knowledge: Vec<KnowledgeItem>,
        source_cids: Vec<String>,
    },

    /// Negotiation message (propose/counter/accept/reject).
    #[serde(rename = "negotiation")]
    Negotiation {
        negotiation_id: String,
        action: NegotiationAction,
    },

    /// Text (backward-compatible simple message).
    #[serde(rename = "text")]
    Text {
        content: String,
    },
}

// ═══════════════════════════════════════════════════════════════
// Sensor / Robotics / ML subtypes (L1 abjective)
// ═══════════════════════════════════════════════════════════════

/// Sensor modality for edge/IoT payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorModality {
    Imu,
    Gps,
    Temperature,
    Pressure,
    Humidity,
    Lidar,
    Camera,
    DepthCamera,
    Ultrasonic,
    Infrared,
    Microphone,
    Accelerometer,
    Gyroscope,
    Magnetometer,
    Custom(String),
}

/// A sensor reading with typed value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorReading {
    /// Scalar values (temperature, pressure, etc.)
    pub values: Vec<f64>,
    /// Optional raw bytes (image frame, audio chunk, point cloud)
    pub raw_data_ref: Option<String>,
    /// Dimensions (e.g., image WxH, point cloud NxD)
    pub dimensions: Vec<u64>,
    /// Number of channels (RGB=3, stereo=2, LiDAR rings=64)
    pub channels: u32,
    /// Sample rate in Hz (0 = not applicable)
    pub sample_rate_hz: f64,
    /// Unit of measurement
    pub unit: String,
    /// Confidence/quality score (0.0–1.0)
    pub quality: f64,
}

impl SensorReading {
    /// Create a simple scalar reading.
    pub fn scalar(value: f64, unit: impl Into<String>) -> Self {
        Self {
            values: vec![value],
            raw_data_ref: None,
            dimensions: vec![],
            channels: 1,
            sample_rate_hz: 0.0,
            unit: unit.into(),
            quality: 1.0,
        }
    }

    /// Create a multi-value reading (e.g., IMU: ax,ay,az,gx,gy,gz).
    pub fn multi(values: Vec<f64>, unit: impl Into<String>) -> Self {
        Self {
            values,
            raw_data_ref: None,
            dimensions: vec![],
            channels: 1,
            sample_rate_hz: 0.0,
            unit: unit.into(),
            quality: 1.0,
        }
    }
}

/// Actuation command for robotics payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActuationCommand {
    /// Motor velocity command (rad/s per joint).
    SetVelocity { joint_velocities: Vec<f64> },
    /// Motor position command (rad per joint).
    SetPosition { joint_positions: Vec<f64> },
    /// Gripper command.
    Gripper { open: bool, force_n: f64 },
    /// Navigation waypoint.
    NavigateTo { x: f64, y: f64, z: f64, heading_rad: f64 },
    /// Emergency stop.
    EmergencyStop,
    /// Generic command with JSON body.
    Custom { command_type: String, params: serde_json::Value },
}

/// Tensor data type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TensorDtype {
    Float16,
    Float32,
    Float64,
    Int8,
    Int16,
    Int32,
    Int64,
    Uint8,
    Bool,
    BFloat16,
}

/// Tensor serialization format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TensorFormat {
    Safetensors,
    Numpy,
    Onnx,
    Raw,
}

// ═══════════════════════════════════════════════════════════════
// Cognitive subtypes (L7 subjective)
// ═══════════════════════════════════════════════════════════════

/// Cognitive message type — structured thought exchange.
/// Maps to CognitiveMessageType in cognitive/types.rs but designed
/// for wire-level serialization through the CNP stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveMsgType {
    /// Share a tension that needs collaborative resolution.
    ShareTension {
        tension_id: String,
        tension_type: String,
        magnitude: f64,
        context_cids: Vec<String>,
        description: String,
    },
    /// Share a commitment for coordination.
    ShareCommitment {
        commitment_id: String,
        action: String,
        plan_fragment_cid: Option<String>,
    },
    /// Share evaluation of a possibility.
    ShareEvaluation {
        possibility_id: String,
        feasibility: f64,
        desirability: f64,
        risk: f64,
        evidence_cids: Vec<String>,
    },
    /// Request plan coordination.
    PlanCoordination {
        plan_id: String,
        requested_action: String,
        context_cids: Vec<String>,
    },
    /// Report reflection results.
    ReflectionReport {
        commitment_id: String,
        outcome_match: f64,
        learnings: Vec<String>,
        evidence_cids: Vec<String>,
    },
    /// Thought checkpoint transfer (full cognitive state).
    ThoughtCheckpoint {
        checkpoint_cid: String,
        layer: u8,
        cycle_number: u32,
    },
}

// ═══════════════════════════════════════════════════════════════
// Contract-level subtypes (L6)
// ═══════════════════════════════════════════════════════════════

/// A knowledge item in a KnowledgeResponse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeItem {
    pub form: String,
    pub content: serde_json::Value,
    pub confidence: f64,
    pub source_cid: Option<String>,
}

/// Negotiation action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NegotiationAction {
    Propose {
        capability_key: String,
        terms: NegotiationTermsWire,
    },
    CounterPropose {
        terms: NegotiationTermsWire,
        message: Option<String>,
    },
    Accept,
    Reject {
        reason: Option<String>,
    },
    Withdraw,
}

/// Wire-format negotiation terms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationTermsWire {
    pub max_latency_ms: u64,
    pub availability_pct: f64,
    pub cost_per_call: u64,
    pub stake_amount: u64,
    pub ttl_ms: i64,
}

// ═══════════════════════════════════════════════════════════════
// CNP Wire Frames — layer-specific wrappers
// ═══════════════════════════════════════════════════════════════

/// L1: Content-addressed wire frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnpFrame {
    /// Content identifier (SHA-256 of serialized payload)
    pub cid: String,
    /// DAG-CBOR serialized bytes
    pub data: Vec<u8>,
    /// Size of the serialized message
    pub size_bytes: u64,
}

/// L2: Encrypted frame (output of Noise_IK encryption).
#[derive(Debug, Clone)]
pub struct CnpEncryptedFrame {
    /// Channel ID used for encryption
    pub channel_id: String,
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// Send counter (nonce)
    pub counter: u64,
}

/// L3: Secured frame (with authentication and anti-replay).
#[derive(Debug, Clone)]
pub struct CnpSecuredFrame {
    /// The encrypted frame
    pub encrypted: CnpEncryptedFrame,
    /// Port ID
    pub port_id: String,
    /// HMAC-SHA256 signature
    pub signature: String,
    /// Anti-replay nonce
    pub nonce: u64,
    /// Message TTL
    pub ttl_ms: i64,
    /// Timestamp
    pub timestamp_ms: i64,
}

/// L4+L5: Routed message ready for delivery.
#[derive(Debug, Clone)]
pub struct CnpRoutedMessage {
    /// The secured frame
    pub secured: CnpSecuredFrame,
    /// Source cell ID
    pub source_cell: String,
    /// Target cell ID (empty = local)
    pub target_cell: String,
    /// Source agent PID
    pub source_agent: String,
    /// Target agent PID
    pub target_agent: String,
    /// Delivery attempt count
    pub attempt: u32,
}

// ═══════════════════════════════════════════════════════════════
// CNP Session
// ═══════════════════════════════════════════════════════════════

/// Session state for a CNP connection between two agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CnpSessionState {
    /// Session negotiation in progress.
    Negotiating,
    /// Noise handshake in progress.
    Handshaking,
    /// Session established — messages can flow.
    Active,
    /// Session is draining (graceful close).
    Draining,
    /// Session closed.
    Closed,
    /// Session failed.
    Failed { reason: String },
}

/// A CNP session — manages the lifecycle of a connection between two agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnpSession {
    /// Unique session identifier
    pub session_id: String,
    /// Local agent PID
    pub local_agent: String,
    /// Remote agent PID
    pub remote_agent: String,
    /// Session state
    pub state: CnpSessionState,
    /// Noise channel ID (established during handshake)
    pub noise_channel_id: Option<String>,
    /// Port ID bound to this session
    pub port_id: Option<String>,
    /// Service contract ID (if negotiated)
    pub contract_id: Option<String>,
    /// Messages sent in this session
    pub messages_sent: u64,
    /// Messages received in this session
    pub messages_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Session creation time
    pub created_at: i64,
    /// Last activity time
    pub last_activity: i64,
    /// Session TTL (0 = no expiry)
    pub ttl_ms: i64,
}

impl CnpSession {
    /// Create a new session in Negotiating state.
    pub fn new(
        local_agent: impl Into<String>,
        remote_agent: impl Into<String>,
    ) -> Self {
        let now = now_ms();
        Self {
            session_id: generate_session_id(),
            local_agent: local_agent.into(),
            remote_agent: remote_agent.into(),
            state: CnpSessionState::Negotiating,
            noise_channel_id: None,
            port_id: None,
            contract_id: None,
            messages_sent: 0,
            messages_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            created_at: now,
            last_activity: now,
            ttl_ms: 0,
        }
    }

    /// Check if session is in a state that allows message sending.
    pub fn can_send(&self) -> bool {
        self.state == CnpSessionState::Active
    }

    /// Check if session has expired.
    pub fn is_expired(&self) -> bool {
        if self.ttl_ms == 0 { return false; }
        now_ms() > self.created_at + self.ttl_ms
    }

    /// Record a sent message.
    pub fn record_sent(&mut self, bytes: u64) {
        self.messages_sent += 1;
        self.bytes_sent += bytes;
        self.last_activity = now_ms();
    }

    /// Record a received message.
    pub fn record_received(&mut self, bytes: u64) {
        self.messages_received += 1;
        self.bytes_received += bytes;
        self.last_activity = now_ms();
    }

    /// Transition to a new state.
    pub fn transition(&mut self, new_state: CnpSessionState) -> Result<(), CnpError> {
        let valid = match (&self.state, &new_state) {
            (CnpSessionState::Negotiating, CnpSessionState::Handshaking) => true,
            (CnpSessionState::Negotiating, CnpSessionState::Active) => true, // Skip handshake (local)
            (CnpSessionState::Negotiating, CnpSessionState::Failed { .. }) => true,
            (CnpSessionState::Handshaking, CnpSessionState::Active) => true,
            (CnpSessionState::Handshaking, CnpSessionState::Failed { .. }) => true,
            (CnpSessionState::Active, CnpSessionState::Draining) => true,
            (CnpSessionState::Active, CnpSessionState::Failed { .. }) => true,
            (CnpSessionState::Draining, CnpSessionState::Closed) => true,
            _ => false,
        };
        if !valid {
            return Err(CnpError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: format!("{:?}", new_state),
            });
        }
        self.state = new_state;
        self.last_activity = now_ms();
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
// CNP Error
// ═══════════════════════════════════════════════════════════════

/// Errors from the CNP protocol stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CnpError {
    /// Message encoding/decoding failed.
    CodecError { detail: String },
    /// Noise channel handshake or encryption failed.
    TransportError { detail: String },
    /// Port security validation failed.
    SecurityError { verdict: String },
    /// Port not found or not bound.
    ChannelError { detail: String },
    /// Cross-cell routing failed.
    RoutingError { detail: String },
    /// Session not found or invalid state.
    SessionError { detail: String },
    /// Negotiation failed.
    NegotiationError { detail: String },
    /// Message expired (TTL exceeded).
    MessageExpired { message_id: String, ttl_ms: i64 },
    /// Invalid state transition.
    InvalidStateTransition { from: String, to: String },
    /// Rate limit exceeded.
    RateLimitExceeded { agent: String, limit: u32 },
    /// Agent not found.
    AgentNotFound { agent_pid: String },
    /// Version mismatch.
    VersionMismatch { local: String, remote: String },
    /// Payload too large.
    PayloadTooLarge { size: u64, max: u64 },
}

impl std::fmt::Display for CnpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CnpError::CodecError { detail } => write!(f, "CNP codec error: {}", detail),
            CnpError::TransportError { detail } => write!(f, "CNP transport error: {}", detail),
            CnpError::SecurityError { verdict } => write!(f, "CNP security error: {}", verdict),
            CnpError::ChannelError { detail } => write!(f, "CNP channel error: {}", detail),
            CnpError::RoutingError { detail } => write!(f, "CNP routing error: {}", detail),
            CnpError::SessionError { detail } => write!(f, "CNP session error: {}", detail),
            CnpError::NegotiationError { detail } => write!(f, "CNP negotiation error: {}", detail),
            CnpError::MessageExpired { message_id, ttl_ms } =>
                write!(f, "CNP message {} expired (TTL {}ms)", message_id, ttl_ms),
            CnpError::InvalidStateTransition { from, to } =>
                write!(f, "CNP invalid transition: {} → {}", from, to),
            CnpError::RateLimitExceeded { agent, limit } =>
                write!(f, "CNP rate limit exceeded for {}: {}/s", agent, limit),
            CnpError::AgentNotFound { agent_pid } =>
                write!(f, "CNP agent not found: {}", agent_pid),
            CnpError::VersionMismatch { local, remote } =>
                write!(f, "CNP version mismatch: local={}, remote={}", local, remote),
            CnpError::PayloadTooLarge { size, max } =>
                write!(f, "CNP payload too large: {} > {} bytes", size, max),
        }
    }
}

impl std::error::Error for CnpError {}

/// Result type for CNP operations.
pub type CnpResult<T> = Result<T, CnpError>;

// ═══════════════════════════════════════════════════════════════
// Protocol Constants
// ═══════════════════════════════════════════════════════════════

/// L1: Maximum inline payload size (64KB).
pub const CNP_MAX_INLINE_BYTES: u64 = 65_536;
/// L2: Default cipher suite.
pub const CNP_DEFAULT_CIPHER: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
/// L3: Anti-replay nonce window (60 seconds).
pub const CNP_NONCE_WINDOW_MS: i64 = 60_000;
/// L3: Default message TTL (30 seconds).
pub const CNP_DEFAULT_TTL_MS: i64 = 30_000;
/// L4: Default port buffer size.
pub const CNP_DEFAULT_PORT_BUFFER: u32 = 256;
/// L4: Max delegation depth.
pub const CNP_MAX_DELEGATION_DEPTH: u8 = 3;
/// L5: Max cross-cell retry count.
pub const CNP_MAX_RETRIES: u32 = 3;
/// L5: Ack timeout.
pub const CNP_ACK_TIMEOUT_MS: i64 = 30_000;
/// L6: Max negotiation rounds.
pub const CNP_MAX_NEGOTIATION_ROUNDS: u32 = 5;
/// L6: Negotiation TTL.
pub const CNP_NEGOTIATION_TTL_MS: i64 = 300_000;
/// L7: Max tensions per message batch.
pub const CNP_MAX_TENSION_BATCH: usize = 10;
/// L7: Max knowledge items per response.
pub const CNP_MAX_KNOWLEDGE_ITEMS: usize = 50;
/// Max message size (10MB).
pub const CNP_MAX_MESSAGE_BYTES: u64 = 10 * 1024 * 1024;

// ═══════════════════════════════════════════════════════════════
// Delivery Receipt
// ═══════════════════════════════════════════════════════════════

/// Delivery receipt — returned to sender after message is processed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnpReceipt {
    /// Original message ID
    pub message_id: String,
    /// Delivery outcome
    pub outcome: DeliveryOutcome,
    /// Time taken to deliver (ms)
    pub delivery_ms: u64,
    /// Layer at which delivery completed/failed
    pub layer: CnpLayer,
    /// CID of the delivered message
    pub message_cid: Option<String>,
    /// Timestamp
    pub timestamp_ms: i64,
}

/// Which layer processed or failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CnpLayer {
    L1Codec,
    L2Transport,
    L3Security,
    L4Channel,
    L5Routing,
    L6Contract,
    L7Cognitive,
}

/// Delivery outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryOutcome {
    Delivered,
    Queued,
    Rejected { reason: String },
    Failed { error: String },
    Expired,
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn generate_message_id() -> String {
    format!("cnp-msg-{:016x}-{:04x}",
        now_ms() as u64,
        rand_u16())
}

fn generate_session_id() -> String {
    format!("cnp-sess-{:016x}-{:04x}",
        now_ms() as u64,
        rand_u16())
}

/// Simple pseudo-random u16 for ID uniqueness (not crypto-grade).
fn rand_u16() -> u16 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    hasher.finish() as u16
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_compatibility() {
        let v1 = CnpVersion { major: 1, minor: 0 };
        let v1_1 = CnpVersion { major: 1, minor: 1 };
        let v2 = CnpVersion { major: 2, minor: 0 };
        assert!(v1.is_compatible(&v1_1));
        assert!(!v1.is_compatible(&v2));
    }

    #[test]
    fn test_message_creation() {
        let msg = CnpMessage::new(
            "agent-a",
            "agent-b",
            CnpPayload::Text { content: "hello".into() },
        );
        assert_eq!(msg.from_agent, "agent-a");
        assert_eq!(msg.to_agent, "agent-b");
        assert_eq!(msg.version, CnpVersion::CURRENT);
        assert!(!msg.is_cognitive());
        assert!(!msg.expects_response());
    }

    #[test]
    fn test_cognitive_message() {
        let msg = CnpMessage::new(
            "agent-a",
            "agent-b",
            CnpPayload::Cognitive {
                cognitive_type: CognitiveMsgType::ShareTension {
                    tension_id: "t-1".into(),
                    tension_type: "goal_conflict".into(),
                    magnitude: 0.8,
                    context_cids: vec![],
                    description: "Conflicting goals".into(),
                },
            },
        );
        assert!(msg.is_cognitive());
    }

    #[test]
    fn test_sensor_payload() {
        let msg = CnpMessage::new(
            "sensor-hub",
            "fusion-agent",
            CnpPayload::Sensor {
                sensor_id: "imu-001".into(),
                modality: SensorModality::Imu,
                reading: SensorReading::multi(
                    vec![0.01, -9.81, 0.03, 0.001, 0.002, -0.001],
                    "m/s²,rad/s",
                ),
                timestamp_us: 1700000000_000000,
            },
        );
        assert!(!msg.is_cognitive());
        if let CnpPayload::Sensor { reading, .. } = &msg.payload {
            assert_eq!(reading.values.len(), 6);
        }
    }

    #[test]
    fn test_actuation_payload() {
        let msg = CnpMessage::new(
            "planner-agent",
            "robot-arm",
            CnpPayload::Actuation {
                target_id: "arm-001".into(),
                command: ActuationCommand::SetPosition {
                    joint_positions: vec![0.0, 1.57, 0.0, -1.57, 0.0, 0.0],
                },
                deadline_us: Some(50_000),
            },
        );
        if let CnpPayload::Actuation { command, .. } = &msg.payload {
            match command {
                ActuationCommand::SetPosition { joint_positions } => {
                    assert_eq!(joint_positions.len(), 6);
                }
                _ => panic!("Expected SetPosition"),
            }
        }
    }

    #[test]
    fn test_session_lifecycle() {
        let mut session = CnpSession::new("agent-a", "agent-b");
        assert_eq!(session.state, CnpSessionState::Negotiating);
        assert!(!session.can_send());

        // Negotiating → Handshaking → Active
        session.transition(CnpSessionState::Handshaking).unwrap();
        session.transition(CnpSessionState::Active).unwrap();
        assert!(session.can_send());

        // Record activity
        session.record_sent(1024);
        assert_eq!(session.messages_sent, 1);
        assert_eq!(session.bytes_sent, 1024);

        // Active → Draining → Closed
        session.transition(CnpSessionState::Draining).unwrap();
        assert!(!session.can_send());
        session.transition(CnpSessionState::Closed).unwrap();
    }

    #[test]
    fn test_invalid_state_transition() {
        let mut session = CnpSession::new("a", "b");
        // Cannot go directly from Negotiating to Draining
        let result = session.transition(CnpSessionState::Draining);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_builder() {
        let msg = CnpMessage::new("a", "b", CnpPayload::Text { content: "hi".into() })
            .with_session("sess-1")
            .with_port("port-1")
            .with_ttl(5000)
            .with_priority(3)
            .with_evidence("cid-abc")
            .with_metadata("key", "value");

        assert_eq!(msg.session_id.as_deref(), Some("sess-1"));
        assert_eq!(msg.port_id.as_deref(), Some("port-1"));
        assert_eq!(msg.ttl_ms, 5000);
        assert_eq!(msg.priority, 3);
        assert_eq!(msg.evidence_cid.as_deref(), Some("cid-abc"));
        assert_eq!(msg.metadata.get("key").map(String::as_str), Some("value"));
    }

    #[test]
    fn test_negotiation_payload() {
        let msg = CnpMessage::new(
            "requester",
            "provider",
            CnpPayload::Negotiation {
                negotiation_id: "neg-001".into(),
                action: NegotiationAction::Propose {
                    capability_key: "translation:translate".into(),
                    terms: NegotiationTermsWire {
                        max_latency_ms: 500,
                        availability_pct: 99.0,
                        cost_per_call: 100,
                        stake_amount: 1000,
                        ttl_ms: 86_400_000,
                    },
                },
            },
        );
        assert!(!msg.is_cognitive());
    }

    #[test]
    fn test_receipt() {
        let receipt = CnpReceipt {
            message_id: "msg-1".into(),
            outcome: DeliveryOutcome::Delivered,
            delivery_ms: 12,
            layer: CnpLayer::L7Cognitive,
            message_cid: Some("cid-xyz".into()),
            timestamp_ms: now_ms(),
        };
        assert!(matches!(receipt.outcome, DeliveryOutcome::Delivered));
        assert_eq!(receipt.layer, CnpLayer::L7Cognitive);
    }
}
