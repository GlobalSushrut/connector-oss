//! Managers — Grouped subsystem managers for DualDispatcher.
//!
//! This module extracts related engines from DualDispatcher into cohesive managers,
//! reducing the dispatcher's field count from ~80 to ~15 and improving maintainability.
//!
//! ## Manager Groups
//!
//! | Manager | Responsibility | Engines |
//! |---------|---------------|---------|
//! | `SecurityManager` | Runtime security enforcement | guard_pipeline, policy_engine, firewall, injection_detector |
//! | `ObservabilityManager` | Monitoring and analysis | watchdog, reputation, behavior |
//! | `DistributedManager` | Cross-cell routing | cross_cell, adaptive_router, session_router |
//! | `EconomyManager` | Payments and pricing | escrow, pricer, global_quota |
//! | `ProtocolManager` | External communication | gateway, noise_channels, negotiation |
//!
//! ## Usage
//!
//! ```rust,ignore
//! use connector_engine::managers::*;
//!
//! // DualDispatcher now uses managers instead of individual engines
//! let security = SecurityManager::new();
//! let observability = ObservabilityManager::new();
//! let distributed = DistributedManager::new("cell-1");
//! let economy = EconomyManager::new();
//! let protocol = ProtocolManager::new();
//! ```

mod security;
mod observability;
mod distributed;
mod economy;
mod protocol;

pub use security::SecurityManager;
pub use observability::ObservabilityManager;
pub use distributed::DistributedManager;
pub use economy::EconomyManager;
pub use protocol::ProtocolManager;
