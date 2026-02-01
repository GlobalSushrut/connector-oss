//! Error types for VAC

use thiserror::Error;

#[derive(Error, Debug)]
pub enum VacError {
    #[error("CID computation failed: {0}")]
    CidError(String),
    
    #[error("Codec error: {0}")]
    CodecError(String),
    
    #[error("Invalid hash: expected {expected} bytes, got {actual}")]
    InvalidHash { expected: usize, actual: usize },
    
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    
    #[error("Block chain broken at block {block_no}: {reason}")]
    BrokenChain { block_no: u64, reason: String },
    
    #[error("Merkle proof verification failed")]
    MerkleProofFailed,
    
    #[error("Store error: {0}")]
    StoreError(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

pub type VacResult<T> = Result<T, VacError>;
