//! AAPI Adapters - Karaṇa Adapters for Action Execution
//!
//! Adapters translate VĀKYA requests into concrete actions and capture effects.
//! Each adapter handles a specific domain (file, http, database, etc.).

pub mod traits;
pub mod file;
pub mod http;
pub mod effect;
pub mod registry;
pub mod error;

pub use traits::*;
pub use file::*;
pub use http::*;
pub use effect::*;
pub use registry::*;
pub use error::*;
