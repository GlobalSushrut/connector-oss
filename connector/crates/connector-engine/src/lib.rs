//! # Connector Engine (Ring 3)
//!
//! The bridge between VAC Memory Kernel (Ring 1) and AAPI Action Kernel (Ring 2).
//! Absorbs all complexity from both kernels and presents a unified orchestration layer.
//!
//! ## Sub-systems
//!
//! - **auto_derive**: Auto-derives PacketType, MemoryScope, MemoryTier, CID from content
//! - **auto_vakya**: Auto-constructs AAPI Vakya from simple method calls
//! - **dispatcher**: Dual-kernel dispatcher (routes to VAC + AAPI)
//! - **trust**: Trust score computation from real kernel data
//! - **output**: PipelineOutput assembly from both kernels
//! - **memory_format**: ConnectorMemory ↔ MemPacket conversion
//! - **trace**: Structured observability — span tree, multi-audience views
//! - **tool_def**: Tool definition (legacy, kept for compatibility)
//! - **action**: Universal action interface — controls anything via typed parameters
//! - **error**: Engine error types

pub mod auto_derive;
pub mod auto_vakya;
pub mod dispatcher;
pub mod claims;
pub mod grounding;
pub mod judgment;
pub mod memory;
pub mod rag;
pub mod trust;
pub mod output;
pub mod memory_format;
pub mod trace;
pub mod tool_def;
pub mod action;
#[cfg(test)]
mod action_tests;
pub mod error;
pub mod llm;
pub mod perception;
pub mod knowledge;
pub mod logic;
pub mod binding;
pub mod aapi;
pub mod firewall;
pub mod behavior;
pub mod compliance;
pub mod kernel_ops;
pub mod checkpoint;
pub mod llm_router;
pub mod redb_store;
pub mod instruction;
pub mod semantic_injection;
pub mod firewall_events;
pub mod adaptive_threshold;
pub mod session_stickiness;
pub mod cross_cell_port;
pub mod global_quota;
pub mod circuit_breaker;
pub mod policy_engine;
pub mod content_guard;
pub mod guard_pipeline;
pub mod secret_store;
pub mod service_contract;
pub mod agent_index;
pub mod discovery;
pub mod reputation;
pub mod escrow;
pub mod pricing;
pub mod negotiation;
pub mod orchestrator;
pub mod watchdog;
pub mod adaptive_router;
pub mod context_manager;
pub mod post_quantum;
pub mod noise_channel;
pub mod fips_crypto;
pub mod bft_consensus;
pub mod formal_verify;
pub mod gateway_bridge;
pub mod saga_bridge;
pub mod engine_store;
pub mod sqlite_store;
pub mod storage_zone;
mod l6_integration;
mod stability_test;

pub use auto_derive::AutoDerive;
pub use auto_vakya::AutoVakya;
pub use dispatcher::DualDispatcher;
pub use claims::{Claim, ClaimSet, ClaimVerifier, Evidence, SupportLevel, VerificationOutcome, VerificationResult};
pub use grounding::{GroundingTable, CodeEntry};
pub use memory::{MemoryCoordinator, KnowledgeCoordinator, PacketSummary};
pub use judgment::{JudgmentEngine, JudgmentResult, JudgmentConfig, JudgmentDimensions};
pub use rag::{RagEngine, RetrievalContext, RetrievedFact};
pub use trust::TrustComputer;
pub use output::*;
pub use memory_format::ConnectorMemory;
pub use trace::{Trace, TraceBuilder, Span, SpanType, SpanLevel, SpanStatus, TraceSummary, StepSummary};
pub use tool_def::{Tool, ToolBuilder, ToolParam, ParamType, ToolRules, ToolResult, ToolParams, ToolHandler, ExecutableTool, ToolRegistry};
pub use action::{Action, ActionBuilder, ActionParam, Param, ParamConstraints, ActionRules, ActionResult, ActionContext, EffectType, RollbackStrategy, Postcondition};
pub use error::EngineError;
pub use perception::{PerceptionEngine, Observation, PerceivedContext, ObservationConfig};
pub use knowledge::{KnowledgeEngine, IngestResult, CompiledKnowledge, ContradictionReport};
pub use logic::{LogicEngine, Plan, PlanStep, StepStatus, ReasoningChain, ReasoningStep, Reflection, ReconsiderationResult};
pub use binding::{BindingEngine, CognitivePhase, CycleSummary, CognitiveReport};
pub use aapi::{ActionEngine, PolicyEffect, PolicyRule, PolicyDecision, ActionPolicy, BudgetTracker, IssuedCapability, ActionEntry, InteractionEntry, ComplianceConfig};
pub use kernel_ops::{KernelOps, KernelStats, NamespaceInfo, SessionInfo, AgentInfo, AuditEntry, HealthReport, ExportData};
