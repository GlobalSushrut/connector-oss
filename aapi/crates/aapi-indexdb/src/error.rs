//! Error types for IndexDB

use thiserror::Error;

/// Errors that can occur during IndexDB operations
#[derive(Error, Debug)]
pub enum IndexDbError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Record not found: {0}")]
    NotFound(String),

    #[error("Duplicate record: {0}")]
    Duplicate(String),

    #[error("Invalid record: {0}")]
    InvalidRecord(String),

    #[error("Merkle tree error: {0}")]
    MerkleError(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Migration error: {0}")]
    Migration(String),

    #[error("Query error: {0}")]
    Query(String),

    #[error("Integrity violation: {0}")]
    IntegrityViolation(String),

    #[error("Connection error: {0}")]
    Connection(String),
}

pub type IndexDbResult<T> = Result<T, IndexDbError>;
