//! Continue adapter.
//!
//! Integration: ~/.continue/config.json — customCommands + OpenAI proxy.
//! Continue doesn't have a native hook system, so enforcement is via:
//!   1. OpenAI proxy intercepts all LLM calls
//!   2. Cage watchdog reverts unauthorized writes
//!   3. Git pre-commit hook blocks forbidden file commits
//! Level: 2 Partial — LLM intercepted; file/exec enforcement via cage layers.

use super::{Adapter, ConnectionInfo};
use crate::action::{CanonicalAction, SupportLevel, ToolId};
use crate::connector_client::ConnectorClient;
use crate::session::SessionInfo;
use anyhow::Result;
use std::path::PathBuf;

pub struct ContinueAdapter;

impl ContinueAdapter {
    /// Patch ~/.continue/config.json to route through Connector proxy.
    fn patch_continue_config(&self, connector_url: &str) -> bool {
        let home = std::env::var("HOME").unwrap_or_default();
        let config_path = PathBuf::from(&home).join(".continue/config.json");

        if !config_path.exists() {
            let _ = std::fs::create_dir_all(config_path.parent().unwrap());
            let config = serde_json::json!({
                "models": [{
                    "title": "DevGuard Governed",
                    "provider": "openai",
                    "model": "gpt-4",
                    "apiBase": format!("{}/v1", connector_url),
                    "apiKey": "devguard"
                }],
                "allowAnonymousTelemetry": false
            });
            return std::fs::write(&config_path, serde_json::to_string_pretty(&config).unwrap_or_default()).is_ok();
        }

        // Merge: insert/replace devguard model entry
        if let Ok(text) = std::fs::read_to_string(&config_path) {
            if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&text) {
                let devguard_model = serde_json::json!({
                    "title": "DevGuard Governed",
                    "provider": "openai",
                    "model": "gpt-4",
                    "apiBase": format!("{}/v1", connector_url),
                    "apiKey": "devguard"
                });

                if let Some(models) = json.get_mut("models").and_then(|v| v.as_array_mut()) {
                    models.retain(|m| m.get("title").and_then(|t| t.as_str()) != Some("DevGuard Governed"));
                    models.insert(0, devguard_model);
                } else {
                    json["models"] = serde_json::json!([devguard_model]);
                }

                return std::fs::write(&config_path, serde_json::to_string_pretty(&json).unwrap_or_default()).is_ok();
            }
        }

        false
    }
}

impl Adapter for ContinueAdapter {
    fn name(&self) -> &str { "Continue" }
    fn tool_id(&self) -> ToolId { ToolId::Continue }
    fn support_level(&self) -> SupportLevel { SupportLevel::Protocol }

    fn detect(&self) -> bool {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(&home).join(".continue").exists()
    }

    fn connect(&self, _client: &ConnectorClient, session: &SessionInfo) -> Result<ConnectionInfo> {
        let config_ok = self.patch_continue_config(&session.connector_url);

        let config_status = if config_ok {
            "✓ ~/.continue/config.json patched — LLM calls routed through DevGuard"
        } else {
            "⚠ Could not patch ~/.continue/config.json — configure manually"
        };

        Ok(ConnectionInfo {
            env_vars: vec![],
            instructions: format!(
                "Continue connected under DevGuard governance.\n\
                 Session: {}  |  Role: {}  |  Identity: {}\n\
                 {}\n\n\
                 Note: Continue lacks native pre-write hooks. Run `devguard cage start`\n\
                 for FS watchdog + git hooks to enforce file policy.\n\
                 Select 'DevGuard Governed' model in Continue's model picker.",
                session.session_id, session.role, session.identity,
                config_status,
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
        Some(CanonicalAction::ToolInvoke { tool_name: "continue_chat".into(), input_hash: hash })
    }
}
