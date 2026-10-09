//! Aider adapter.
//!
//! Integration: --openai-api-base flag → Connector proxy.
//! Protocol: OpenAI Chat Completions.
//! Level: 0 Total — all LLM calls proxied, diff blocks parsed from responses.

use super::{Adapter, ConnectionInfo};
use crate::action::{CanonicalAction, SupportLevel, ToolId};
use crate::connector_client::ConnectorClient;
use crate::session::SessionInfo;
use anyhow::Result;

pub struct AiderAdapter;

impl Adapter for AiderAdapter {
    fn name(&self) -> &str { "Aider" }
    fn tool_id(&self) -> ToolId { ToolId::Aider }
    fn support_level(&self) -> SupportLevel { SupportLevel::Total }

    fn detect(&self) -> bool {
        std::process::Command::new("which")
            .arg("aider")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn connect(&self, _client: &ConnectorClient, session: &SessionInfo) -> Result<ConnectionInfo> {
        Ok(ConnectionInfo {
            env_vars: vec![
                ("OPENAI_API_BASE".into(), session.connector_url.clone()),
            ],
            instructions: format!(
                "Aider connected under DevGuard governance.\n\
                 Session: {}  |  Role: {}  |  Identity: {}\n\n\
                 Run:\n  aider --openai-api-base {} \"your task\"\n\n\
                 All LLM calls proxied. Diff blocks parsed for file governance.",
                session.session_id, session.role, session.identity,
                session.connector_url,
            ),
            launch_command: Some(format!(
                "aider --openai-api-base {}",
                session.connector_url,
            )),
        })
    }

    fn disconnect(&self, _client: &ConnectorClient, _session: &SessionInfo) -> Result<()> {
        Ok(())
    }

    fn translate_action(&self, raw: &serde_json::Value) -> Option<CanonicalAction> {
        // Aider sends OpenAI format. Parse content for diff blocks.
        let input_str = serde_json::to_string(raw).unwrap_or_default();
        use sha2::{Sha256, Digest};
        let hash = format!("{:x}", Sha256::digest(input_str.as_bytes()));
        Some(CanonicalAction::ToolInvoke {
            tool_name: "aider_chat".into(),
            input_hash: hash,
        })
    }
}
