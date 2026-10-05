//! User-facing errors — simple, actionable messages.
//!
//! Every error includes:
//! 1. What went wrong (in plain English)
//! 2. How to fix it (actionable suggestion)
//!
//! No internal jargon, no raw Rust errors, no "lock poisoned".

use thiserror::Error;

/// Errors from the Connector API (Ring 4).
///
/// All messages are designed for end users — no internal jargon.
#[derive(Debug, Error)]
pub enum ConnectorError {
    #[error("Not configured: {0}.\n  Fix: call .{1}() on the builder before .build()")]
    NotConfigured(String, String),

    #[error("Agent '{0}' not found.\n  Fix: check the agent name in your config")]
    AgentNotFound(String),

    #[error("Build error: {0}")]
    BuildError(String),

    #[error("{}", friendly_engine_error(.0))]
    EngineError(#[from] connector_engine::error::EngineError),

    #[error("Internal error: the system encountered an unexpected state.\n  This is a bug — please report it at https://github.com/connector-oss/connector/issues\n  Detail: {0}")]
    InternalError(String),
}

/// Convert engine errors into friendly, actionable messages.
fn friendly_engine_error(e: &connector_engine::error::EngineError) -> String {
    let raw = e.to_string();

    // Lock poisoned → internal error
    if raw.contains("lock poisoned") || raw.contains("poisoned") {
        return "Internal error: concurrent access failed. This is a bug — please report it.".to_string();
    }

    // Agent already registered
    if raw.contains("already registered") || raw.contains("already exists") {
        return format!("{}.\n  Fix: use a different agent name, or reuse the existing one", raw);
    }

    // Memory/namespace errors
    if raw.contains("namespace") && raw.contains("not found") {
        return format!("{}.\n  Fix: check that the agent has been registered first", raw);
    }

    // Firewall/instruction blocked
    if raw.contains("blocked") || raw.contains("InstructionBlocked") {
        return format!("Operation blocked by security policy.\n  Detail: {}\n  Fix: check your firewall/policy config, or add the operation to the allow list", raw);
    }

    // Budget exceeded
    if raw.contains("budget") || raw.contains("exceeded") {
        return format!("{}.\n  Fix: increase the budget with .budget(tokens, cost) or budget: \"$10.00\" in YAML", raw);
    }

    // Default: pass through with context
    format!("Engine error: {}", raw)
}

pub type ConnectorResult<T> = Result<T, ConnectorError>;

/// Pretty-print a ConnectorResult for users who just want to see what happened.
///
/// ```rust,ignore
/// let r = c.agent("bot").run_quick("Hello!");
/// Connector::print(r);  // prints beautiful output OR beautiful error
/// ```
pub fn print_result(result: &ConnectorResult<connector_engine::output::PipelineOutput>) {
    match result {
        Ok(output) => println!("{}", output),
        Err(e) => {
            eprintln!();
            eprintln!("  ❌ {}", e);
            eprintln!();
            eprintln!("  ↳ Connector::help() for usage guide");
            eprintln!();
        }
    }
}
