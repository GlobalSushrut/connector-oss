//! Cell-based clustering for distributed VAC kernels.
//!
//! Provides:
//! - `Cell`: The distribution unit — wraps a kernel + identity + sequence counter
//! - `ClusterKernelStore`: Implements `KernelStore` over local store + event bus
//! - `replication_loop`: Background task that receives events from other cells

pub mod cell;
pub mod cell_drain;
pub mod cluster_store;
pub mod receiver;
pub mod error;
pub mod membership;
pub mod ring;
pub mod s3_bridge;
pub mod tier_manager;
pub mod wal;
pub mod migration;

pub use cell::*;
pub use cluster_store::*;
pub use receiver::*;
pub use error::*;
pub use membership::*;
pub use cell_drain::{CellDrain, DrainError, DrainResult, DrainStats, AgentMigration, AgentRegistry};
pub use ring::ConsistentHashRing;
pub use s3_bridge::{S3Bridge, S3BridgeError, ArcCache, ColdPacket, ObjectStore, InMemoryObjectStore, TieringStats};
pub use wal::{InMemoryWal, DiskWal, ReplicationWalEntry, Lsn};
pub use migration::{migrate_agent, AgentMigrationReport};

#[cfg(test)]
mod tests;
