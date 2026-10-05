//! AAPI IndexDB - Append-only Evidence Log
//!
//! IndexDB provides:
//! - Append-only storage for VĀKYA, effects, and receipts
//! - Merkle tree indexing for transparency proofs
//! - Query capabilities for audit and replay
//! - Support for SQLite (embedded) and PostgreSQL (enterprise)

pub mod store;
pub mod models;
pub mod merkle;
pub mod query;
pub mod error;

pub use store::*;
pub use models::*;
pub use merkle::*;
pub use query::*;
pub use error::*;
