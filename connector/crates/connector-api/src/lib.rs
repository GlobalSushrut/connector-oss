//! # Connector API (Ring 4)
//!
//! The developer-facing API for building agents. So simple anyone can use it.
//! So secure military and banks use it without hesitation.
//!
//! ## 4 Progressive Layers
//!
//! - **Layer 0**: 3-line agent (anyone)
//! - **Layer 1**: Builder pattern (intermediate)
//! - **Layer 2**: Expert configuration (security engineers)
//! - **Layer 3**: Raw kernel access (kernel developers)
//!
//! ## Example
//!
//! ```rust,no_run
//! use connector_api::Connector;
//!
//! let c = Connector::new()
//!     .llm("openai", "gpt-4o", "sk-...")
//!     .build();
//!
//! let output = c.agent("bot")
//!     .instructions("You are helpful")
//!     .run("Hello!", "user:alice");
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
pub use error::ConnectorError;
pub use types::*;

// Re-export engine types that developers need
pub use connector_engine::ConnectorMemory;
pub use connector_engine::output::{PipelineOutput, PipelineStatus, AapiSummary, MemorySummary, ConnectorSummary};
pub use connector_engine::trust::TrustScore;
pub use connector_engine::trace::{Trace, Span, SpanType, SpanStatus, TraceSummary};
pub use connector_engine::tool_def::{Tool, ToolBuilder, ToolParam, ParamType, ToolRules, ToolResult, ToolParams};
pub use connector_engine::action::{Action, ActionBuilder, ActionParam, Param, ParamConstraints, ActionRules, ActionResult, ActionContext, EffectType, RollbackStrategy, Postcondition};
