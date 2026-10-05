//! # Surface Output Engine (SOE)
//!
//! Enterprise-grade output layer that transforms raw Connector outputs into
//! structured, human-readable operational surfaces.
//!
//! ## Architecture
//!
//! ```text
//! Request → Governance → Time Resolution → Kernel Query → Surface Build → CID → Receipt → Render
//!     ↓          ↓              ↓               ↓              ↓          ↓        ↓         ↓
//!   Actor    Policy        TimeSelector    T0/T1 Data    SurfaceDoc   Cache   Chain    Output
//! ```
//!
//! ## Infrastructure Patterns (matching CNP/CLS/Cognitive/Books)
//!
//! | Pattern | Implementation |
//! |---------|----------------|
//! | CID-based content addressing | `cid.rs` — Every surface gets `soe1-sha256-*` CID |
//! | Receipt/proof chains | `receipt.rs` — Every render produces signed receipt |
//! | Trust tiers (T0-T3) | `tiers.rs` — Kernel→Engine→Derived→Rendered |
//! | Time-travel queries | `time.rs` — `--at`, `--since`, `--last` selectors |
//! | Governance/policy | `governance.rs` — Role-based access control |
//! | Streaming/live | `stream.rs` — Real-time event bus |
//! | Telemetry/metrics | `metrics.rs` — Render stats, cache hits, errors |
//! | Kernel integration | `kernel.rs` — Bridge to memory kernel and books |
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use connector_engine::surface::*;
//!
//! // Full engine with all infrastructure
//! let mut engine = SurfaceEngine::default();
//! let request = RenderRequest::new(SurfaceType::Agent, "claims-001", "user-1", Role::Developer)
//!     .view(SurfaceView::Ops)
//!     .time(SurfaceTimeSelector::Last(SurfaceDuration::hours(1)));
//!
//! let result = engine.render(request)?;
//! println!("{}", result.to_terminal());
//! println!("CID: {}", result.cid());
//! println!("Tier: {:?}", result.tier());
//! println!("Receipt: {:?}", result.receipt);
//!
//! // Or use fluent builder for simple cases
//! let surface = SurfaceBuilder::agent("claims-001")
//!     .judgment_ok("Agent running normally")
//!     .signal_check("Health OK")
//!     .build();
//! ```
//!
//! ## Features
//!
//! - **CID Content Addressing** — Surfaces are content-addressed for caching/dedup
//! - **Receipt Chains** — Every render produces verifiable proof
//! - **Trust Tiers** — T0 (kernel) → T1 (engine) → T2 (derived) → T3 (rendered)
//! - **Time Travel** — Query historical state with `--at`, `--since`, `--last`
//! - **Governance** — Policy-based access control per role
//! - **Streaming** — Real-time event bus for Monitor surface
//! - **Metrics** — Full telemetry for observability
//! - **Kernel Bridge** — Direct connection to memory kernel and books

pub mod document;
pub mod adapter;
pub mod renderer;
pub mod domains;
pub mod contract;
pub mod builder;
pub mod roles;
pub mod errors;
pub mod pagination;
pub mod compound;
pub mod export;
pub mod routing;
pub mod cid;
pub mod receipt;
pub mod stream;
pub mod tiers;
pub mod time;
pub mod governance;
pub mod metrics;
pub mod kernel;
pub mod engine;
pub mod sandbox;
pub mod distributed;
pub mod lifecycle;
pub mod pipeline;
pub mod multiagent;
pub mod glue_printer;
pub mod signal;
pub mod intelligence;
pub mod operator;
pub mod package;
pub mod translator;
#[cfg(test)]
mod tests;

pub use document::{
    SurfaceDocument, SurfaceMeta, SurfaceType, SurfaceView,
    SurfaceHeader, SubjectIdentity, ResourceKind,
    StateVector, ExecutionState, TrustState, HealthState, ComplianceState,
    EvidencePosture, EvidenceStatus, TrustScore, TrustGrade, TrustComponents,
    SurfaceBadge, Severity,
    SurfaceSection, SectionKind, SectionContent,
    StatItem, KeyValueItem, TimelineEvent, Finding, ListItem, EvidenceItem, TraceSpan,
    ResourceLink, LinkAction, BlobContainer, ContentType,
    SurfaceAction, SurfaceFooter,
};
pub use adapter::{SurfaceRenderable, SurfaceContext};
pub use renderer::{Renderer, TerminalRenderer, JsonRenderer};
pub use domains::{build_agent_surface, build_audit_surface, build_compliance_surface, build_debug_surface, build_books_surface};
pub use contract::{SurfaceContract, Judgment, Signal, SignalIcon, ContractValidation};
pub use builder::SurfaceBuilder;
pub use roles::{Role, RedactionLevel, Redactor, ValueType};
pub use errors::{SurfaceError, ErrorCategory, ErrorSurfaceBuilder};
pub use pagination::{PageRequest, PageInfo, Filter, FilterOp, FilterValue, SearchQuery, Sort, SortDirection, Query};
pub use compound::{CompoundSurface, CompositionStrategy, CompoundBuilder};
pub use export::{ExportFormat, MarkdownRenderer, HtmlRenderer, Exporter};
pub use routing::{SurfaceRoute, SurfaceRouter, RoutingContext};
pub use cid::{SurfaceCid, AddressedSurface, SurfaceCache};
pub use receipt::{SurfaceReceipt, ReceiptChain, TimeContext};
pub use stream::{SurfaceEvent, SurfaceEventType, SurfaceEventPayload, SurfaceBus, SurfaceSubscriber, LiveSurface};
pub use tiers::{TrustTier, TierVerification, VerificationMethod, TieredSurface};
pub use time::{SurfaceTimeSelector, SurfaceDuration, DurationUnit, ResolvedTimeRange, TimedSurfaceQuery};
pub use governance::{SurfaceGovernance, SurfaceAccessRequest, GovernanceResult, PolicyDecision, SurfacePolicy, PolicyRule, PolicyCondition, PolicyAction};
pub use metrics::{SurfaceMetrics, MetricsSnapshot, RenderTimer, metrics};
pub use kernel::{KernelBridge, KernelQuery, KernelQueryType, KernelResult, KernelData, DataSource};
pub use engine::{SurfaceEngine, EngineConfig, RenderRequest, RenderResult, RenderError};
pub use sandbox::{IsolationLevel, ResourceLimits, ResourceUsage, SandboxCapability, CapabilityType, SandboxState, SandboxStatus, SandboxViolation, ViolationType, ViolationAction, build_sandbox_surface};
pub use distributed::{CellInfo, CellStatus, AgentLocation, AgentNetworkStatus, NetworkTopology, DiscoveryQuery, DiscoveryResult, AgentMatch, build_network_surface, build_agent_location_surface};
pub use lifecycle::{LifecycleState, LifecycleEvent, LifecycleTrigger, LifecycleTrace, build_lifecycle_surface};
pub use pipeline::{PipelineStage, PipelineDefinition, StageDefinition, PipelineExecution, PipelineExecutionStatus, StageExecution, StageExecutionStatus, DataFlowMetrics, build_pipeline_surface, build_dataflow_surface};
pub use multiagent::{CoordinationPattern, AgentInteraction, InteractionType, InteractionStatus, CoordinationSession, CoordinationStatus, ConsensusState, ConsensusVote, VoteType, ConsensusStatus, ConsensusResult, build_coordination_surface, build_consensus_surface};
pub use glue_printer::{GluePrinter, PrinterConfig, OutputFormat, PrintedSurface, PrintError, PrintOptions, StabilityReport, printer};
pub use signal::{Signal as SoeSignal, StatusLine, StatusLevel, ProblemBlock, ActionBlock, ActionPriority, ImpactBlock, DeltaBlock, DeltaChange, DeltaDirection, PatternBlock, PatternType, TrustLine};
pub use intelligence::{SignalExtractor, GlobalHealth, SystemHealth, TopIssue, Narrator};
pub use operator::{OperatorOutput, OutputMode, DrillDown, OperatorEngine, QuickStatus, ViewCompressor};
