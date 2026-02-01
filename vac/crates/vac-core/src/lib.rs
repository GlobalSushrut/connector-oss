//! VAC Core - Core types and traits for Vault Attestation Chain
//!
//! This crate provides the foundational types for VAC:
//! - Event, ClaimBundle, Bracket, Node, Frame
//! - BlockHeader, ManifestRoot, VaultPatch
//! - CID computation and DAG-CBOR encoding

pub mod types;
pub mod cid;
pub mod codec;
pub mod error;

pub use types::*;
pub use cid::*;
pub use codec::*;
pub use error::*;
