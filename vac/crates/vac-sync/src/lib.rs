//! VAC Sync - Sync protocol for VAC vaults
//!
//! Implements block-verified sync as specified in arch.md §19.1

pub mod protocol;
pub mod diff;

pub use protocol::*;
pub use diff::*;
