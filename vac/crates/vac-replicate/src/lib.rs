//! VAC Replicate — CID-based replication engine extending vac-sync
//!
//! Provides Merkle sync scheduling, peer management, and real-time
//! streaming replication. Builds on `vac-sync`'s block-verified protocol.

pub mod error;
pub mod peer;
pub mod merkle_sync;

#[cfg(test)]
mod tests;

pub use error::*;
pub use peer::*;
pub use merkle_sync::*;
