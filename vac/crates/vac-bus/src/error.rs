//! Error types for the event bus.

use thiserror::Error;

/// Errors that can occur during bus operations.
#[derive(Debug, Error)]
pub enum BusError {
    /// Failed to publish an event
    #[error("publish failed: {0}")]
    PublishFailed(String),

    /// Failed to subscribe to a topic
    #[error("subscribe failed: {0}")]
    SubscribeFailed(String),

    /// Bus is closed / shutting down
    #[error("bus closed")]
    Closed,

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("deserialization error: {0}")]
    Deserialization(String),

    /// Connection error (for network-based buses)
    #[error("connection error: {0}")]
    Connection(String),

    /// Timeout
    #[error("timeout after {0}ms")]
    Timeout(u64),

    /// Internal error
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result type for bus operations.
pub type BusResult<T> = Result<T, BusError>;
