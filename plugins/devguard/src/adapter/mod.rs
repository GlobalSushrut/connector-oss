//! Tool adapters — translate tool-specific actions into CanonicalActions.
//!
//! Each coding tool has a different protocol (Anthropic API, OpenAI API, MCP).
//! The adapter's job is:
//!   1. Detect if the tool is available
//!   2. Connect the tool to Connector (set env vars, write hooks, register MCP, etc.)
//!   3. Translate tool-specific events into CanonicalAction
//!   4. Disconnect cleanly
//!
//! Enforcement level per tool:
//!   Total   — pre-action blocking via native hook system + LLM proxy
//!   Strong  — LLM proxied + VSCode/IDE hooks (pre-action blocking)
//!   Partial — LLM proxied only; cage watchdog provides post-write revert
//!
//! All 11 supported tools:
//!   Claude Code, Kiro, Cursor, Windsurf, Aider,
//!   Copilot, Continue, Cline, Roo Code, Zed, Generic

use crate::action::{CanonicalAction, SupportLevel, ToolId};
use crate::connector_client::ConnectorClient;
use crate::session::SessionInfo;
use anyhow::Result;

pub mod aider;
pub mod claude;
pub mod cline;
pub mod continue_adapter;
pub mod copilot;
pub mod cursor;
pub mod generic;
pub mod kiro;
pub mod roocode;
pub mod windsurf;
pub mod zed;

/// Every adapter implements this trait.
pub trait Adapter: Send + Sync {
    /// Human-readable adapter name.
    fn name(&self) -> &str;

    /// Which tool ID this adapter handles.
    fn tool_id(&self) -> ToolId;

    /// What level of enforcement this adapter provides.
    fn support_level(&self) -> SupportLevel;

    /// Detect if this tool is available on the system.
    fn detect(&self) -> bool;

    /// Connect the tool under DevGuard governance.
    /// Returns connection instructions for the user.
    fn connect(&self, client: &ConnectorClient, session: &SessionInfo) -> Result<ConnectionInfo>;

    /// Disconnect the tool from DevGuard governance.
    fn disconnect(&self, client: &ConnectorClient, session: &SessionInfo) -> Result<()>;

    /// Translate a raw tool event (JSON from gateway/MCP) into a CanonicalAction.
    fn translate_action(&self, raw: &serde_json::Value) -> Option<CanonicalAction>;
}

/// Information returned after connecting a tool.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Environment variables the user must set to route the tool through Connector.
    pub env_vars: Vec<(String, String)>,
    /// Human-readable connection instructions.
    pub instructions: String,
    /// The command to launch the tool (if applicable).
    pub launch_command: Option<String>,
}

/// Get the adapter for a tool name string.
pub fn get_adapter(tool: &str) -> Box<dyn Adapter> {
    match ToolId::from_str(tool) {
        ToolId::ClaudeCode  => Box::new(claude::ClaudeAdapter),
        ToolId::Kiro        => Box::new(kiro::KiroAdapter),
        ToolId::Cursor      => Box::new(cursor::CursorAdapter),
        ToolId::Windsurf    => Box::new(windsurf::WindsurfAdapter),
        ToolId::Aider       => Box::new(aider::AiderAdapter),
        ToolId::Copilot     => Box::new(copilot::CopilotAdapter),
        ToolId::Continue    => Box::new(continue_adapter::ContinueAdapter),
        ToolId::Cline       => Box::new(cline::ClineAdapter),
        ToolId::RooCode     => Box::new(roocode::RooCodeAdapter),
        ToolId::Zed         => Box::new(zed::ZedAdapter),
        ToolId::Generic     => Box::new(generic::GenericAdapter),
    }
}
