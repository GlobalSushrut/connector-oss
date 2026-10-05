//! Contract validation and invariant errors.

use thiserror::Error;

/// Errors produced by native contract helpers (URI parse, confidence, invariants).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum NativeContractError {
    #[error("invalid connector URI: {0}")]
    InvalidUri(String),
    #[error("invalid confidence transition: {0}")]
    InvalidConfidence(String),
    #[error("invariant violated: {0}")]
    Invariant(String),
}
