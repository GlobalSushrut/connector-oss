//! VAC Core - Core types and traits for Vault Attestation Chain
//!
//! This crate provides the foundational types for VAC:
//! - Event, ClaimBundle, Bracket, Node, Frame
//! - BlockHeader, ManifestRoot, VaultPatch
//! - CID computation and DAG-CBOR encoding
//! - MemPacket: Universal 3D memory envelope (Content/Provenance/Authority)
//! - SessionEnvelope: Conversation/interaction grouping
//! - MemoryTier (Hot/Warm/Cold/Archive), MemoryScope (Working/Episodic/Semantic/Procedural)
//! - MemoryQuery, ToolInteraction, StateSnapshot, AgentNamespace
//! - Prolly key builder/parser for structured indexing

pub mod types;
pub mod cid;
pub mod codec;
pub mod error;
pub mod kernel;
pub mod range_window;
pub mod interference;
pub mod knot;
pub mod audit_export;
pub mod store;
pub mod integration;
pub mod extensions;
pub mod adaptive_scheduler;
pub mod self_healing;
pub mod namespace_types;
pub mod guard;
pub mod cgroup_controllers;
pub mod port_security;

pub use types::*;
pub use cid::*;
pub use codec::*;
pub use error::*;
