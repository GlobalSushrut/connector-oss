//! Connector Native Protocol (CNP) stack layers.
//!
//! L3 security refuses empty-key mTLS success (U5.4).

pub mod stack;
pub mod wire;
pub mod peer_overlay;

pub use stack::security::{CnpSecurity, SecurityContext, SecurityError};
