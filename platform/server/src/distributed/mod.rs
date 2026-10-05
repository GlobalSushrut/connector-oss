//! Distributed orchestration and cross-cell communication
//!
//! This module provides distributed system capabilities including
//! cell discovery, routing, and consensus.

// Core Distributed Infrastructure (6 Layers)
pub mod transport;        // Real cross-cell transport (QUIC/WebSocket)
pub mod failure_detector; // SWIM gossip + Phi accrual detection
pub mod leader_election;  // Knot-based leader election
pub mod service_registry; // Cell & service discovery (DNS-like)
pub mod scheduler;        // Distributed task placement
pub mod topology;         // Network topology discovery

// Production Infrastructure
pub mod traffic_manager;  // High-volume traffic management & caching
pub mod cloud_manager;    // Multi-cloud, CDN, DNS, Proxy management

// Protocol Stack
pub mod cnp {
    pub use super::cnp_stack::*;
}
pub mod cnp_stack;

// Re-exports for convenience
pub use transport::{
    peer_tls_honesty, CellTransport, CellAddress, CellMessage, TransportProtocol,
};
pub use failure_detector::{SwimFailureDetector, CellLiveness, CellStatus};
pub use leader_election::{KnotLeaderElection, LeaderState, LeaderTerm};
pub use service_registry::{ServiceRegistry, ServiceEntry, AgentRegistration};
pub use scheduler::{MiniScheduler as CellScheduler, Cell, Task, SchedulingStrategy};
pub use topology::{TopologyDiscovery, TopologyLink, NetworkPath};
pub use traffic_manager::{TrafficManager, TrafficCache, CongestionController};
pub use cloud_manager::{CloudManager, DnsManager, CdnManager, ProxyManager, CloudProvider};
pub use cnp_stack::{CnpStack, CnpMessage, CnpSession, Intent};
