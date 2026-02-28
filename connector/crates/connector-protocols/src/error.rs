//! Error types for connector-protocols.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("transport error: {0}")]
    Transport(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("authorization denied: {0}")]
    AuthzDenied(String),

    #[error("firewall blocked: {0}")]
    FirewallBlocked(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("kernel error: {0}")]
    Kernel(String),

    #[error("DID resolution failed: {0}")]
    DidResolution(String),

    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;
