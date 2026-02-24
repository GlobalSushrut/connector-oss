//! Cell-based clustering for distributed VAC kernels.
//!
//! Provides:
//! - `Cell`: The distribution unit — wraps a kernel + identity + sequence counter
//! - `ClusterKernelStore`: Implements `KernelStore` over local store + event bus
//! - `replication_loop`: Background task that receives events from other cells

pub mod cell;
pub mod cluster_store;
pub mod receiver;
pub mod error;
pub mod membership;

pub use cell::*;
pub use cluster_store::*;
pub use receiver::*;
pub use error::*;
pub use membership::*;

#[cfg(test)]
mod tests;
