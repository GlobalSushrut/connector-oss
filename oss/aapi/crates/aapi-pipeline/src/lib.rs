//! AAPI Pipeline — Distributed VAKYA pipeline engine.
//!
//! Provides:
//! - `VakyaPipeline`: Chain of steps across cells with dependency tracking
//! - `VakyaRouter`: Routes VAKYAs to local or remote cells
//! - `SagaCoordinator`: Reverse-order rollback for distributed transactions (D8)

pub mod error;
pub mod pipeline;
pub mod router;
pub mod saga;

pub use error::*;
pub use pipeline::*;
pub use router::*;
pub use saga::*;

#[cfg(test)]
mod tests;
