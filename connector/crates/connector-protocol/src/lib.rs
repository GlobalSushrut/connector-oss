//! # Connector Protocol (CP/1.0)
//!
//! A universal control protocol for robots, machines, tools, and software.
//! Military-grade security, formally verifiable, post-quantum ready.
//!
//! ## 7-Layer Architecture
//!
//! - **Layer 1: Identity** — DICE, SPIFFE, DID-based entity identity
//! - **Layer 2: Channel** — Noise_IK handshake, encrypted channels
//! - **Layer 3: Consensus** — HotStuff BFT, Raft, TSN scheduling
//! - **Layer 4: Routing** — Content-addressed routing via CID
//! - **Layer 5: Capability** — UCAN-style tokens, 120 capabilities
//! - **Layer 6: Contract** — 3-phase execution contracts (from connector-caps)
//! - **Layer 7: Intent** — AI agent goal decomposition
//!
//! ## Safety First
//!
//! Safety is not an afterthought. Emergency stop is an ambient capability
//! that requires no token and cannot be denied by policy.

pub mod error;
pub mod safety;
pub mod identity;
pub mod channel;
pub mod envelope;
pub mod capability;
pub mod consensus;
pub mod routing;
pub mod telemetry;
pub mod intent;
pub mod attestation;

// Re-export key types
pub use error::{ProtocolError, ProtoResult};

pub use identity::{
    EntityClass, EntityId, IdentityProof, DIDDocument,
    ConnectorExtensions, AuthenticationMethod, ServiceEndpoint,
    EntityRegistry,
};

pub use safety::{
    SafetyIntegrityLevel, EmergencyStop, ClearStop, EStopScope,
    Geofence, Interlock, LockoutTagout, WatchdogState, SafetyManager,
};

pub use channel::{
    TransportBinding, ChannelConfig, ChannelState, Channel,
};

pub use envelope::{
    Envelope, EnvelopeFlags, MessageType, Priority, OrderingMode,
    Recipient, MAGIC, VERSION,
};

pub use capability::{
    RiskLevel, CapabilityCategory, ProtocolCapability,
    ProtocolCapabilityRegistry,
};

pub use consensus::{
    ConsensusManager, ConsensusPhase, ConsensusDecision,
    Proposal, Vote, TimeSlot,
};

pub use routing::{
    Router, RouteEntry, RoutingStrategy,
};

pub use telemetry::{
    TelemetryManager, TelemetrySample, StreamConfig, QoSProfile,
};

pub use intent::{
    Intent, CapabilityRequest, CoordinationPattern,
};

pub use attestation::{
    AttestationVerifier, AttestationEvidence, AttestationResult,
    FirmwareMeasurement,
};
