//! Event bus abstraction for distributed VAC replication.
//!
//! Provides the `EventBus` trait and implementations for different scale tiers:
//! - `InProcessBus`: tokio::sync::broadcast for Nano/Micro (1-100 agents)
//! - NatsBus: async-nats + JetStream for Small-Large (future, behind feature flag)

pub mod types;
pub mod error;
pub mod traits;
pub mod in_process;
#[cfg(feature = "nats")]
pub mod nats_bus;

pub use types::*;
pub use error::*;
pub use traits::*;
pub use in_process::*;
#[cfg(feature = "nats")]
pub use nats_bus::{NatsBus, NatsConfig};

#[cfg(test)]
mod tests;
