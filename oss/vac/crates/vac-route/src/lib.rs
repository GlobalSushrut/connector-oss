//! VAC Route — Consistent hash router for cell-based agent distribution.
//!
//! Routes agents to cells using a consistent hash ring with virtual nodes.
//! Supports dynamic cell add/remove with minimal agent re-routing (~1/N).

pub mod error;
pub mod ring;
pub mod router;

#[cfg(test)]
mod tests;

pub use error::*;
pub use ring::*;
pub use router::*;
