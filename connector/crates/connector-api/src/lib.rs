//! # Connector API — Trusted Infrastructure for AI Agents
//!
//! The simplest way to build agents with trust, compliance, and provenance.
//! So simple a noob can use it. So secure banks and military use it without hesitation.
//!
//! ## The Love Ladder — Progressive Simplicity
//!
//! ```rust,no_run
//! use connector_api::Connector;
//!
//! // Level 0: ONE LINE — zero config
//! let r = Connector::quick("What is 2+2?").unwrap();
//!
//! // Level 1: TWO LINES — auto-session
//! let c = Connector::new().build();
//! let r = c.agent("bot").run_quick("Hello!").unwrap();
//!
//! // Level 2: THREE LINES — explicit control
//! let c = Connector::new().llm("openai", "gpt-4o", "sk-...").build();
//! let r = c.agent("bot").instructions("You are helpful").run("Hi!", "user:alice").unwrap();
//!
//! // Level 3: ENTERPRISE — compliance + security + audit
//! let c = Connector::new()
//!     .llm("openai", "gpt-4o", "sk-...")
//!     .compliance(&["hipaa", "soc2"])
//!     .build();
//! let r = c.agent("doctor").instructions("Medical AI").run("Patient has fever", "user:p1").unwrap();
//! println!("{}", r);  // trust score + compliance + provenance
//! ```
//!
//! ## What You Get That Competitors Don't
//!
//! - **Trust Score**: cryptographically verified score (0-100) for every agent run
//! - **Compliance**: HIPAA, SOC2, GDPR — one-line config
//! - **Provenance**: zero-fake guarantee — every event traced to kernel
//! - **Audit Trail**: HMAC-chained, tamper-evident, exportable
//! - **Memory Passport**: portable, signed memory bundles
//!
//! ## First-Time? Start Here
//!
//! ```rust,ignore
//! // See everything Connector can do:
//! println!("{}", Connector::help());
//!
//! // Run a full demo with compliance and trust:
//! println!("{}", Connector::demo());
//!
//! // Already using LangChain/CrewAI? 1-line upgrade:
//! let verified = Connector::verify(your_llm_output, &["hipaa"])?;
//! ```

pub mod types;
pub mod connector;
pub mod agent;
pub mod pipeline;
pub mod security;
pub mod data;
pub mod observe;
pub mod connect;
pub mod display;
pub mod error;
pub mod config;
pub mod auto_detect;
pub mod shorthand;
pub mod db;
pub mod trace;

#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod config_tests_ext;

pub use connector::Connector;
pub use agent::{AgentBuilder, OutputGuard, PipelineOutputExt};
pub use pipeline::PipelineBuilder;
pub use security::SecurityConfig;
pub use data::{DataConfig, DataBuilder, RagConfig, VectorStoreConfig, EmbeddingConfig};
pub use observe::*;
pub use connect::{ConnectConfig, ConnectBuilder};
pub use display::TraceExt;
pub use error::{ConnectorError, print_result};
pub use types::*;
pub use shorthand::parse_shorthand;
pub use auto_detect::{auto_detect_llm, detect_help, detect_all_providers};

// Re-export engine types that developers need
pub use connector_engine::ConnectorMemory;
pub use connector_engine::output::{PipelineOutput, PipelineStatus, AapiSummary, MemorySummary, ConnectorSummary};
pub use connector_engine::trust::TrustScore;
pub use connector_engine::trace::{Trace, Span, SpanType, SpanStatus, TraceSummary};
pub use connector_engine::tool_def::{Tool, ToolBuilder, ToolParam, ParamType, ToolRules, ToolResult, ToolParams};
pub use connector_engine::action::{Action, ActionBuilder, ActionParam, Param, ParamConstraints, ActionRules, ActionResult, ActionContext, EffectType, RollbackStrategy, Postcondition};
