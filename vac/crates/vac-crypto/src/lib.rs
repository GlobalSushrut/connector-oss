//! VAC Crypto - Cryptographic primitives for VAC
//!
//! - Ed25519 signatures for block signing
//! - Key generation and management
//! - DID key format support

pub mod keys;
pub mod signing;

pub use keys::*;
pub use signing::*;
