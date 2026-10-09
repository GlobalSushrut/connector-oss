//! Generic adapter — any OpenAI-compatible tool.
//!
//! Fallback for tools without a dedicated adapter.
//! Integration: Set OPENAI_API_BASE → Connector proxy.
//! Level: 1 Strong — LLM calls proxied, sandbox provides FS/Net/Cmd enforcement.

use super::{Adapter, ConnectionInfo};
use crate::action::{CanonicalAction, SupportLevel, ToolId};
use crate::connector_client::ConnectorClient;
use crate::session::SessionInfo;
use anyhow::Result;

pub struct GenericAdapter;

impl Adapter for GenericAdapter {
    fn name(&self) -> &str { "Generic (OpenAI-compat)" }
    fn tool_id(&self) -> ToolId { ToolId::Generic }
    fn support_level(&self) -> SupportLevel { SupportLevel::Strong }

    fn detect(&self) -> bool { true }

    fn connect(&self, _client: &ConnectorClient, session: &SessionInfo) -> Result<ConnectionInfo> {
        Ok(ConnectionInfo {
            env_vars: vec![
                ("OPENAI_API_BASE".into(), session.connector_url.clone()),
            ],
            instructions: format!(
                "Generic tool connected under DevGuard governance.\n\
                 Session: {}  |  Role: {}  |  Identity: {}\n\n\
                 Set OPENAI_API_BASE={} in your tool configuration.\n\
                 Sandbox cage provides FS/Net/Cmd enforcement regardless of tool integration.",
                session.session_id, session.role, session.identity,
                session.connector_url,
            ),
            launch_command: None,
        })
    }

    fn disconnect(&self, _client: &ConnectorClient, _session: &SessionInfo) -> Result<()> {
        Ok(())
    }

    fn translate_action(&self, raw: &serde_json::Value) -> Option<CanonicalAction> {
        let input_str = serde_json::to_string(raw).unwrap_or_default();
        use sha2::{Sha256, Digest};
        let hash = format!("{:x}", Sha256::digest(input_str.as_bytes()));
        Some(CanonicalAction::ToolInvoke {
            tool_name: "generic".into(),
            input_hash: hash,
        })
    }
}
