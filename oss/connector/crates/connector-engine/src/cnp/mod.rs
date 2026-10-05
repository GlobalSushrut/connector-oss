//! # Connector Native Protocol (CNP)
//!
//! The 7-layer native communication stack for the Connector platform.
//! Bridges **abjective** (wire-level, machine-verifiable) primitives with
//! **subjective** (cognitive, agent-meaningful) communication.
//!
//! ## Layer Architecture
//!
//! ```text
//! L7: Cognitive Exchange    — typed thought-objects (tensions, commitments, plans)
//! L6: Intent & Contract     — service contracts, negotiation, gateway
//! L5: Cross-Cell Routing    — transparent delivery with retry + dead-letter
//! L4: Port System           — typed channels with capability attenuation
//! L3: Port Security         — HMAC, anti-replay, TTL, rate limiting
//! L2: Noise_IK Transport    — encrypted agent-to-agent channels
//! L1: Content-Addressed     — DAG-CBOR serialization, SHA-256 CID
//! ```
//!
//! ## Usage
//!
//! ```rust,no_run
//! use connector_engine::cnp::{CnpStack, CnpStackConfig, CnpMessage, CnpPayload};
//!
//! let config = CnpStackConfig::new("my-agent", "cell-1");
//! let mut stack = CnpStack::new(config);
//!
//! // Establish session with peer
//! let session_id = stack.establish_session("peer-agent", [0xAA; 32], [0xBB; 32]).unwrap();
//!
//! // Send a message (flows through all 7 layers)
//! let msg = CnpMessage::new("my-agent", "peer-agent", CnpPayload::Text { content: "hello".into() });
//! let receipt = stack.send(msg).unwrap();
//!
//! // Receive messages
//! let messages = stack.receive_all("peer-agent").unwrap();
//! ```
//!
//! ## Capability Spectrum
//!
//! CNP is a **superset** of MCP (tool invocation) and A2A (task delegation):
//! - Everything MCP does → CNP L4 `ToolDelegate` ports + `ToolGrant` payloads
//! - Everything A2A does → CNP L4–L7 typed channels + cognitive exchange
//! - **Plus:** robotics (`Actuation`), edge/IoT (`Sensor`), ML (`Tensor`),
//!   cognitive (`ShareTension`, `PlanCoordination`, `KnowledgeRequest`)

pub mod types;
pub mod codec;
pub mod transport;
pub mod channel;
pub mod stack;

// Re-export primary API types
pub use types::{
    CnpMessage, CnpPayload, CnpVersion, CnpSession, CnpSessionState,
    CnpError, CnpResult, CnpReceipt, CnpLayer, DeliveryOutcome,
    CnpFrame, CnpEncryptedFrame, CnpSecuredFrame, CnpRoutedMessage,
    // Sensor/Robotics/ML subtypes
    SensorModality, SensorReading, ActuationCommand, TensorDtype, TensorFormat,
    // Cognitive subtypes
    CognitiveMsgType,
    // Contract subtypes
    KnowledgeItem, NegotiationAction, NegotiationTermsWire,
    // Constants
    CNP_DEFAULT_TTL_MS, CNP_MAX_MESSAGE_BYTES, CNP_MAX_RETRIES,
    CNP_MAX_DELEGATION_DEPTH, CNP_MAX_NEGOTIATION_ROUNDS,
};
pub use codec::CnpCodec;
pub use transport::{CnpEncryptor, CnpSecurityLayer};
pub use channel::{
    CnpPort, CnpPortType, CnpPortDirection, CnpPortPermission, CnpPortCapability,
    CnpRouter, CellStatus,
};
pub use stack::{CnpStack, CnpStackConfig, CnpStackStats};
