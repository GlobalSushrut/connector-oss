//! Agents Module — Resource Management, Allocation, Scaling
//!
//! **Not the HTTP source of truth (U1.5).** Live agent registration caps and
//! lifecycle enforcement go through `services::agents` → VAC kernel ACB /
//! `substrate::agent_progeny`. These modules are library/experimental planners
//! and must not be double-wired onto register routes.

#![deprecated(
    note = "quota SoT is services::agents + VAC kernel caps; do not wire this module to HTTP"
)]

pub mod resource_manager;
pub mod index_integration;
pub mod allocator;
pub mod autoscaler;
pub mod reclaimer;
pub mod capacity;

pub use resource_manager::{ResourceManager, ResourceType, ResourceAllocation, ReservationPriority};
pub use index_integration::{AgentIndexIntegration, AgentIndexEntry, AgentQuery, SelectionStrategy};
pub use allocator::{AutoAllocator, AllocationRequest, AllocationPriority};
pub use autoscaler::{AutoScaler, ScalingPolicy};
pub use reclaimer::{Reclaimer, IdleConfig, ReclaimAction};
pub use capacity::{CapacityPlanner, CapacityReport, CapacityPrediction};
