//! VAC Store - Content-addressable storage
//!
//! Provides the VaultBody CAS (Content Addressable Store) for VAC objects.

pub mod cas;
pub mod memory;

pub use cas::*;
pub use memory::*;
