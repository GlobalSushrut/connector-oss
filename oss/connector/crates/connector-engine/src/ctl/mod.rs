//! ConnectorCTL — Time-Native Operational Language
//!
//! ConnectorCTL is the operational language of Connector. It allows humans to:
//! - operate agents
//! - inspect memory and execution
//! - trace decisions
//! - enforce governance
//! - **navigate time across system state**
//!
//! ## Core Philosophy
//!
//! ConnectorCTL is based on 3 fundamental axes:
//! 1. **Action (Verb)** — What you want to do
//! 2. **Entity (Noun)** — What you are acting on
//! 3. **Time (Temporal Selector)** — When in system reality you are inspecting
//!
//! ## The Key Differentiator
//!
//! Every command in Connector can operate:
//! - **now**
//! - **in the past**
//! - **across a time range**
//! - **at a specific event point**

pub mod grammar;
pub mod time;
pub mod identity;
pub mod output;
pub mod executor;
pub mod surfaces;
pub mod render;

pub use grammar::{Verb, Noun, Command, CommandBuilder};
pub use time::{TimeSelector, TimePoint, TimeRange, Duration};
pub use identity::{ResourceIdentity, ResourceKind};
pub use output::{OutputMode, OutputFormat};
pub use executor::{CommandExecutor, ExecutionResult, SurfaceDocument, TimeContext};
pub use surfaces::{build_debug_surface, build_audit_surface, build_compliance_surface, build_explain_surface, build_trace_surface, build_inspect_surface, build_review_surface};
pub use render::TerminalRenderer;
