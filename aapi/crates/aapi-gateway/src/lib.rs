//! AAPI Gateway - HTTP Server for AAPI Protocol
//!
//! The Gateway provides:
//! - REST API for VĀKYA submission and execution
//! - Capability token validation
//! - Effect capture and logging
//! - Receipt generation
//! - Transparency log integration

pub mod server;
pub mod handlers;
pub mod middleware;
pub mod state;
pub mod error;
pub mod routes;

pub use server::*;
pub use handlers::*;
pub use state::*;
pub use error::*;
