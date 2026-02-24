//! Error types for vac-cluster.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClusterError {
    #[error("store error: {0}")]
    Store(String),

    #[error("bus error: {0}")]
    Bus(#[from] vac_bus::BusError),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("cell not ready: {0}")]
    NotReady(String),

    #[error("replication error: {0}")]
    Replication(String),

    #[error("CID mismatch: expected {expected}, got {actual}")]
    CidMismatch { expected: String, actual: String },
}

pub type ClusterResult<T> = Result<T, ClusterError>;
