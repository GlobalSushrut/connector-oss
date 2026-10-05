//! VAC Core - Core types and traits for Vault Attestation Chain
//!
//! This crate provides the foundational types for VAC:
//! - `MemoryKernel`: The memory kernel with syscall dispatch
//! - `MemPacket`: Universal 3D memory envelope (Content/Provenance/Authority)
//! - `MemoryKernelOp`: All kernel operations
//! - `SyscallRequest`, `SyscallResult`: Kernel syscall interface
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use vac_core::{MemoryKernel, SyscallRequest, MemoryKernelOp};
//!
//! let mut kernel = MemoryKernel::new();
//! let req = SyscallRequest {
//!     agent_pid: "agent-1".to_string(),
//!     operation: MemoryKernelOp::AgentRegister,
//!     ..Default::default()
//! };
//! let result = kernel.dispatch(req);
//! ```

// ═══════════════════════════════════════════════════════════════════════════
// Public Modules — Ring 0 Foundation
// ═══════════════════════════════════════════════════════════════════════════

pub mod types;
pub mod cid;
pub mod codec;
pub mod error;
pub mod kernel;
pub mod knot;
pub mod store;
pub mod namespace_types;
pub mod structured_log;

// ═══════════════════════════════════════════════════════════════════════════
// Internal Modules — pub(crate) visibility recommended for most
// ═══════════════════════════════════════════════════════════════════════════

pub mod range_window;
pub mod interference;
pub mod audit_export;
pub mod integration;
pub mod extensions;
pub mod adaptive_scheduler;
pub mod self_healing;
pub mod guard;
pub mod cgroup_controllers;
pub mod port_security;
pub mod identity;
pub mod disruptor;
pub mod vector;
pub mod agent_boot;
pub mod agent_evm;
pub mod cloud;
pub mod fabric;
pub mod knowledge;
pub mod ocsf_adapter;
pub mod process;
pub mod vfs;
pub mod commands;
pub mod hardware_contract;
pub mod resource_enforcer;
pub mod thread;
pub mod replay;
pub mod memory_map;
pub mod security;
pub mod kernel_arch;
pub mod pid_namespace;
pub mod isolation;
pub mod cost_tracking;
pub mod debug;
pub mod advanced;
pub mod secrets;
pub mod migrations;
pub mod migration;
pub mod error_registry;
pub mod data_governance;
pub mod abuse_detection;

// ═══════════════════════════════════════════════════════════════════════════
// Public API — Explicit Re-exports (<20 items)
// ═══════════════════════════════════════════════════════════════════════════

// --- Kernel API (primary interface) ---
pub use kernel::{MemoryKernel, SharedKernel, SyscallRequest, SyscallResult, SyscallValue, SyscallPayload};

// --- Core Types ---
pub use types::{
    // Memory packet (the universal envelope)
    MemPacket, PacketType, MemoryTier, MemoryScope,
    // Memory operations
    MemoryKernelOp, OpOutcome,
    // Session management
    SessionEnvelope,
    // Agent control
    AgentControlBlock, AgentStatus, AgentPhase, AgentRole,
    // Namespace
    AgentNamespace,
};

// --- CID and Encoding ---
pub use cid::{compute_cid, build_prolly_key, parse_prolly_key};
pub use codec::ContentAddressable;

// --- Errors ---
pub use error::VacError;

// --- Knot Engine ---
pub use knot::{KnotEngine, ConsolidationEngine, ConsolidationTickResult};
