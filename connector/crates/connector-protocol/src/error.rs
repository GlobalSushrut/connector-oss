//! Error types for the Connector Protocol (CP/1.0).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("identity error: {0}")]
    Identity(String),

    #[error("channel error: {0}")]
    Channel(String),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("envelope error: {0}")]
    Envelope(String),

    #[error("capability error: {0}")]
    Capability(String),

    #[error("safety violation: {0}")]
    SafetyViolation(String),

    #[error("emergency stop: {0}")]
    EmergencyStop(String),

    #[error("attestation failed: {0}")]
    AttestationFailed(String),

    #[error("consensus error: {0}")]
    Consensus(String),

    #[error("routing error: {0}")]
    Routing(String),

    #[error("discovery error: {0}")]
    Discovery(String),

    #[error("signature error: {0}")]
    Signature(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("timeout")]
    Timeout,

    #[error("not found: {0}")]
    NotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("interlock not satisfied: {0}")]
    InterlockViolation(String),

    #[error("lockout active: {0}")]
    LockoutActive(String),

    #[error("geofence violation: {0}")]
    GeofenceViolation(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type ProtoResult<T> = Result<T, ProtocolError>;
