//! Zed adapter.
//!
//! Integration: ~/.config/zed/settings.json — language_models.openai.api_url
//! Zed doesn't have a native hook system. Enforcement via:
//!   1. OpenAI proxy for LLM call interception
//!   2. Cage watchdog + git hooks for file/exec enforcement
//! Level: 2 Partial — LLM intercepted; file/exec enforcement via cage layers.

use super::{Adapter, ConnectionInfo};
use crate::action::{CanonicalAction, SupportLevel, ToolId};
use crate::connector_client::ConnectorClient;
use crate::session::SessionInfo;
use anyhow::Result;
use std::path::PathBuf;

pub struct ZedAdapter;

impl ZedAdapter {
    /// Patch ~/.config/zed/settings.json to route LLM calls through Connector.
    fn patch_zed_settings(&self, connector_url: &str) -> bool {
        let home = std::env::var("HOME").unwrap_or_default();
        let config_dir = PathBuf::from(&home).join(".config/zed");
        let _ = std::fs::create_dir_all(&config_dir);
        let settings_path = config_dir.join("settings.json");

        let zed_settings = serde_json::json!({
            "language_models": {
                "openai": {
                    "api_url": format!("{}/v1", connector_url),
                    "available_models": [{
                        "name": "gpt-4",
                        "display_name": "DevGuard Governed (GPT-4)",
                        "max_tokens": 128000
                    }]
                }
            },
            "assistant": {
                "default_model": {
                    "provider": "openai",
                    "model": "gpt-4"
                },
                "version": "2"
            }
        });

        if settings_path.exists() {
            if let Ok(text) = std::fs::read_to_string(&settings_path) {
                if let Ok(mut existing) = serde_json::from_str::<serde_json::Value>(&text) {
                    existing["language_models"] = zed_settings["language_models"].clone();
                    existing["assistant"] = zed_settings["assistant"].clone();
                    return std::fs::write(&settings_path, serde_json::to_string_pretty(&existing).unwrap_or_default()).is_ok();
                }
            }
        }

        std::fs::write(&settings_path, serde_json::to_string_pretty(&zed_settings).unwrap_or_default()).is_ok()
    }
}

impl Adapter for ZedAdapter {
    fn name(&self) -> &str { "Zed" }
    fn tool_id(&self) -> ToolId { ToolId::Zed }
    fn support_level(&self) -> SupportLevel { SupportLevel::Protocol }

    fn detect(&self) -> bool {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(&home).join(".config/zed").exists()
            || std::process::Command::new("which").arg("zed")
                .output().map(|o| o.status.success()).unwrap_or(false)
    }

    fn connect(&self, _client: &ConnectorClient, session: &SessionInfo) -> Result<ConnectionInfo> {
        let settings_ok = self.patch_zed_settings(&session.connector_url);

        let settings_status = if settings_ok {
            "✓ ~/.config/zed/settings.json patched — LLM calls routed through DevGuard"
        } else {
            "⚠ Could not patch ~/.config/zed/settings.json — configure manually"
        };

        Ok(ConnectionInfo {
            env_vars: vec![],
            instructions: format!(
                "Zed connected under DevGuard governance.\n\
                 Session: {}  |  Role: {}  |  Identity: {}\n\
                 {}\n\n\
                 Note: Zed lacks native pre-write hooks. Run `devguard cage start`\n\
                 for FS watchdog + git hook enforcement of file policy.\n\
                 Select 'DevGuard Governed (GPT-4)' in Zed's assistant model picker.",
                session.session_id, session.role, session.identity,
                settings_status,
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
        Some(CanonicalAction::ToolInvoke { tool_name: "zed_assistant".into(), input_hash: hash })
    }
}
