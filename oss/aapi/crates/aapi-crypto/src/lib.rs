//! AAPI Crypto - Cryptographic primitives for AAPI
//!
//! This crate provides:
//! - Ed25519 key generation and signing
//! - Capability token creation and verification
//! - DSSE (Dead Simple Signing Envelope) support
//! - Merkle proof generation and verification

pub mod keys;
pub mod signing;
pub mod capability;
pub mod dsse;
pub mod error;

pub use keys::*;
pub use signing::*;
pub use capability::*;
pub use dsse::*;
pub use error::*;
