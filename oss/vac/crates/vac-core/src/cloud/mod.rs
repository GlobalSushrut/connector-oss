//! Cloud-Native Agent Infrastructure
//!
//! Kubernetes-aligned primitives for deploying, scaling, and managing agents
//! in production cloud environments.
//!
//! # Design Principles
//!
//! 1. **Declarative** — Define desired state, let controllers reconcile
//! 2. **Kubernetes-compatible** — Familiar patterns for K8s operators
//! 3. **Horizontally scalable** — 1k agents/cell, 100 cells = 100k agents
//! 4. **Observable** — Prometheus metrics, OpenTelemetry traces
//! 5. **Self-healing** — Automatic recovery from failures
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    CONTROL PLANE                             │
//! │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐│
//! │  │ API Server  │ │ Scheduler   │ │ Controller Manager      ││
//! │  │ (REST/gRPC) │ │ (Adaptive)  │ │ (AgentSet, Deployment)  ││
//! │  └─────────────┘ └─────────────┘ └─────────────────────────┘│
//! │  ┌─────────────────────────────────────────────────────────┐│
//! │  │                    Knot Consensus                        ││
//! │  │              (State replication, leader election)        ││
//! │  └─────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────┘
//!                               │
//!               ┌───────────────┼───────────────┐
//!               ▼               ▼               ▼
//! ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
//! │     CELL-01     │ │     CELL-02     │ │     CELL-N      │
//! │  ┌───────────┐  │ │  ┌───────────┐  │ │  ┌───────────┐  │
//! │  │ AgentEVM  │  │ │  │ AgentEVM  │  │ │  │ AgentEVM  │  │
//! │  │ (1k agents)│  │ │  │ (1k agents)│  │ │  │ (1k agents)│  │
//! │  └───────────┘  │ │  └───────────┘  │ │  └───────────┘  │
//! │  ┌───────────┐  │ │  ┌───────────┐  │ │  ┌───────────┐  │
//! │  │ CellAgent │  │ │  │ CellAgent │  │ │  │ CellAgent │  │
//! │  │ (kubelet) │  │ │  │ (kubelet) │  │ │  │ (kubelet) │  │
//! │  └───────────┘  │ │  └───────────┘  │ │  └───────────┘  │
//! └─────────────────┘ └─────────────────┘ └─────────────────┘
//! ```
//!
//! # Industry Scaling Limits
//!
//! | Metric | Target | K8s Reference |
//! |--------|--------|---------------|
//! | Agents per Cell | 1,000 | 110 pods/node |
//! | Cells per Cluster | 100 | 5,000 nodes |
//! | Total Agents | 100,000 | 150,000 pods |
//! | Agent startup | <5s | <10s |
//! | Heartbeat interval | 5s | 10s |
//! | Failover time | <30s | 40s |
//! | API latency p99 | <100ms | <1s |
//!
//! # Modules
//!
//! - `spec` — Declarative agent specifications (AgentSpec, ResourceRequirements)
//! - `labels` — Label selectors for grouping and filtering
//! - `agent_set` — Replica management (like ReplicaSet)
//! - `deployment` — Rolling updates, rollback (like Deployment)
//! - `hpa` — Horizontal autoscaling
//! - `service` — Service discovery
//! - `metrics` — Prometheus-compatible metrics export

pub mod spec;
pub mod labels;
pub mod agent_set;
pub mod deployment;
pub mod hpa;
pub mod service;
pub mod metrics;

pub use spec::*;
pub use labels::*;
pub use agent_set::*;
pub use deployment::*;
pub use hpa::*;
pub use service::*;
pub use metrics::*;
