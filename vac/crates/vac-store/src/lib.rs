//! VAC Store - Content-addressable storage
//!
//! Provides the VaultBody CAS (Content Addressable Store) for VAC objects.

pub mod cas;
pub mod memory;
pub mod prolly_bridge;
pub mod indexdb_bridge;
mod wiring_tests;

pub use cas::*;
pub use memory::*;
