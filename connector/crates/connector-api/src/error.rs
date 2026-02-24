//! User-facing errors — simple, actionable messages.

use thiserror::Error;

/// Errors from the Connector API (Ring 4).
#[derive(Debug, Error)]
pub enum ConnectorError {
    #[error("Not configured: {0}. Call .{1}() on the builder first.")]
    NotConfigured(String, String),

    #[error("Agent '{0}' not found")]
    AgentNotFound(String),

    #[error("Build error: {0}")]
    BuildError(String),

    #[error("Engine error: {0}")]
    EngineError(#[from] connector_engine::error::EngineError),
}

pub type ConnectorResult<T> = Result<T, ConnectorError>;
