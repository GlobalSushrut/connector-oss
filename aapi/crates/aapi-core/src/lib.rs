//! AAPI Core - VĀKYA Schema, Sandhi Canonicalization, and Validation
//!
//! This crate provides the foundational types and algorithms for the
//! Agentic Action Protocol Interface (AAPI).

pub mod vakya;
pub mod sandhi;
pub mod validation;
pub mod error;
pub mod types;

pub use vakya::*;
pub use sandhi::*;
pub use validation::*;
pub use error::*;
pub use types::*;
