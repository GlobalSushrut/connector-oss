//! # Memory Transport and Object Fabric
//!
//! Kernel-Governed Memory Transport and Container Fabric for the Connector platform.
//!
//! ## Architecture
//!
//! ```text
//! Agents / Tools / APIs / Runtime / Uploads
//!                   │
//!                   ▼
//!           Memory Ingress Gateway
//!    (normalize, classify, scope, dedupe, stamp)
//!                   │
//!                   ▼
//!           Memory Commit Log Fabric
//!  (append, partition, checkpoint, replay, materialize)
//!                   │
//!       ┌───────────┼────────────┬─────────────┐
//!       ▼           ▼            ▼             ▼
//!  Kernel Ledger  Object Fabric  Index Fabric  Continuity Fabric
//!  (authority)    (S3 layer)     (vector/meta) (graph/pagechain)
//!       │           │            │             │
//!       └───────────┴────────────┴─────────────┘
//!                   │
//!                   ▼
//!            Retrieval Execution Plane
//!    (scope → search → expand → stabilize → prove)
//! ```
//!
//! ## Design Principles
//!
//! 1. **Kernel is the authority** — identity, policy, ownership, proofs, lineage
//! 2. **Commit log is ingestion truth** — event ordering, replay, visibility transitions
//! 3. **Object fabric is durability truth** — S3-compatible large payload storage
//! 4. **Indexes are retrieval accelerators** — vector, metadata, timeline, relation
//! 5. **Continuity fabric is cognition truth** — reasoning graphs, page chains, spans
//!
//! ## Scaling Model
//!
//! | Mode | Agents | Nodes | Backend |
//! |------|--------|-------|---------|
//! | Developer | 1 | 1 | In-memory / local files |
//! | Single-server | 10–100 | 1 | Local commit log + MinIO + Qdrant |
//! | Production | 1,000+ | 100+ | Kafka/Redpanda + S3 + clustered Qdrant |
//! | Sovereign | 1,000+ | 100+ | Self-hosted object store + portable log |

pub mod types;
pub mod commit_log;
pub mod object;
pub mod index;
pub mod continuity;
pub mod container;
pub mod ingress;
