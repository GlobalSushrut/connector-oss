//! VAC Prolly Tree - Probabilistic B-tree with content-defined chunking
//!
//! Implements the narrow tree structure from arch.md §16:
//! - History-independent structure
//! - O(log n) lookup, insert, delete
//! - Efficient diff/sync via Merkle proofs
//! - Branching factor Q = 32

pub mod tree;
pub mod node;
pub mod proof;
pub mod boundary;

pub use tree::*;
pub use node::*;
pub use proof::*;
pub use boundary::*;

/// Default branching factor
pub const DEFAULT_Q: usize = 32;

/// Boundary threshold for content-defined chunking
pub const BOUNDARY_THRESHOLD: u32 = u32::MAX / DEFAULT_Q as u32;
