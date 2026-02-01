//! AAPI SDK - Client Library for AAPI Gateway
//!
//! This SDK provides:
//! - Easy-to-use client for submitting VĀKYA requests
//! - Automatic signing and capability management
//! - Response handling and effect tracking

pub mod client;
pub mod builder;
pub mod error;

pub use client::*;
pub use builder::*;
pub use error::*;

// Re-export core types for convenience
pub use aapi_core::{Vakya, VakyaId, Karta, Karma, Kriya, Adhikarana};
pub use aapi_core::types::{PrincipalId, ResourceId, Namespace, Timestamp};
