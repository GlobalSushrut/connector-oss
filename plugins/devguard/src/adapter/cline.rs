//! Cline adapter.
//!
//! Integration: .vscode/settings.json — cline.apiProvider + cline.openAiBaseUrl.
//! Cline uses the same VSCode hooks.json as Copilot for PreToolUse blocking.
//! Level: 1 Strong — LLM proxied via OpenAI API; file/exec via VSCode hooks.

use super::{Adapter, ConnectionInfo};
use crate::action::{CanonicalAction, SupportLevel, ToolId};
use crate::connector_client::ConnectorClient;
use crate::session::SessionInfo;
use anyhow::Result;
use std::path::PathBuf;

pub struct ClineAdapter;

impl ClineAdapter {
    /// Patch .vscode/settings.json to route Cline LLM calls through Connector.
    fn patch_vscode_settings(&self, connector_url: &str) -> bool {
        let vscode_dir = std::path::Path::new(".vscode");
        let _ = std::fs::create_dir_all(vscode_dir);
        let settings_path = vscode_dir.join("settings.json");

        let cline_settings = serde_json::json!({
            "cline.apiProvider": "openai",
            "cline.openAiBaseUrl": format!("{}/v1", connector_url),
            "cline.openAiApiKey": "devguard",
            "roo-cline.apiProvider": "openai",
            "roo-cline.openAiBaseUrl": format!("{}/v1", connector_url),
            "roo-cline.openAiApiKey": "devguard"
        });

        if settings_path.exists() {
            if let Ok(text) = std::fs::read_to_string(&settings_path) {
                if let Ok(mut existing) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let (Some(obj), Some(new_obj)) = (existing.as_object_mut(), cline_settings.as_object()) {
                        for (k, v) in new_obj {
                            obj.insert(k.clone(), v.clone());
                        }
                        return std::fs::write(&settings_path, serde_json::to_string_pretty(&existing).unwrap_or_default()).is_ok();
                    }
                }
            }
        }

        std::fs::write(&settings_path, serde_json::to_string_pretty(&cline_settings).unwrap_or_default()).is_ok()
    }

    /// Write the hook script for VSCode PreToolUse blocking.
    fn write_hook_script(&self, config_path: &str) -> PathBuf {
        let cage_dir = std::path::Path::new(".devguard");
        let _ = std::fs::create_dir_all(cage_dir);

        let devguard_bin = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("devguard"));

        let script = format!(
            r#"#!/bin/bash
# DevGuard Cline/RooCline hook — PreToolUse blocking.
# VSCode/Cline protocol: exit 2 to BLOCK, exit 0 to allow.
# DO NOT REMOVE — installed by `devguard connect cline`.

DG="{devguard}"
CONFIG="{config}"

if [ ! -f "$CONFIG" ]; then exit 0; fi

TOOL="${{hookEventName:-${{CLINE_TOOL_NAME:-}}}}"
INPUT="${{CLINE_TOOL_INPUT:-}}"

case "$TOOL" in
    Write|file_write|editFiles|createFile)
        PATH_VAL=$(echo "$INPUT" | grep -oP '"path"\s*:\s*"\K[^"]+' 2>/dev/null)
        if [ -n "$PATH_VAL" ]; then
            result=$("$DG" check file write "$PATH_VAL" --config "$CONFIG" 2>&1)
            if echo "$result" | grep -qiE "DENY|BLOCK|denied|forbidden"; then
                echo "[DevGuard] CLINE WRITE BLOCKED: $PATH_VAL"
                echo "  $result"
                exit 2
            fi
        fi
        ;;
    Read|file_read|readFiles)
        PATH_VAL=$(echo "$INPUT" | grep -oP '"path"\s*:\s*"\K[^"]+' 2>/dev/null)
        if [ -n "$PATH_VAL" ]; then
            result=$("$DG" check file read "$PATH_VAL" --config "$CONFIG" 2>&1)
            if echo "$result" | grep -qiE "DENY|BLOCK|denied|forbidden|hidden"; then
                echo "[DevGuard] CLINE READ BLOCKED: $PATH_VAL"
                echo "  $result"
                exit 2
            fi
        fi
        ;;
    Bash|execute_bash|runInTerminal)
        CMD=$(echo "$INPUT" | grep -oP '"command"\s*:\s*"\K[^"]+' 2>/dev/null)
        if [ -n "$CMD" ]; then
            result=$("$DG" check exec "$CMD" --config "$CONFIG" 2>&1)
            if echo "$result" | grep -qiE "DENY|BLOCK|denied|forbidden"; then
                echo "[DevGuard] CLINE EXEC BLOCKED: $CMD"
                echo "  $result"
                exit 2
            fi
        fi
        ;;
esac

exit 0
"#,
            devguard = devguard_bin.display(),
            config = config_path,
        );

        let script_path = cage_dir.join("devguard_cline_hook.sh");
        let _ = std::fs::write(&script_path, &script);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&script_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o755);
                let _ = std::fs::set_permissions(&script_path, perms);
            }
        }

        script_path
    }

    /// Install .vscode/hooks.json for Cline/VSCode PreToolUse blocking.
    fn install_vscode_hooks(&self, hook_script: &std::path::Path) -> bool {
        let vscode_dir = std::path::Path::new(".vscode");
        let _ = std::fs::create_dir_all(vscode_dir);
        let hooks_path = vscode_dir.join("hooks.json");
        let hook_str = hook_script.to_string_lossy();

        let hooks = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Write",          "script": hook_str },
                    { "matcher": "Read",           "script": hook_str },
                    { "matcher": "Bash",           "script": hook_str },
                    { "matcher": "editFiles",      "script": hook_str },
                    { "matcher": "readFiles",      "script": hook_str },
                    { "matcher": "runInTerminal",  "script": hook_str }
                ]
            }
        });

        let final_config = if hooks_path.exists() {
            if let Ok(text) = std::fs::read_to_string(&hooks_path) {
                if let Ok(mut existing) = serde_json::from_str::<serde_json::Value>(&text) {
                    existing["hooks"]["PreToolUse"] = hooks["hooks"]["PreToolUse"].clone();
                    existing
                } else { hooks }
            } else { hooks }
        } else { hooks };

        std::fs::write(&hooks_path, serde_json::to_string_pretty(&final_config).unwrap_or_default()).is_ok()
    }
}

impl Adapter for ClineAdapter {
    fn name(&self) -> &str { "Cline" }
    fn tool_id(&self) -> ToolId { ToolId::Cline }
    fn support_level(&self) -> SupportLevel { SupportLevel::Strong }

    fn detect(&self) -> bool {
        std::path::Path::new(".vscode").exists()
    }

    fn connect(&self, _client: &ConnectorClient, session: &SessionInfo) -> Result<ConnectionInfo> {
        let hook_script = self.write_hook_script("devguard.yaml");
        let hooks_ok = self.install_vscode_hooks(&hook_script);
        let settings_ok = self.patch_vscode_settings(&session.connector_url);

        let status = match (hooks_ok, settings_ok) {
            (true, true) => "✓ .vscode/hooks.json + settings.json written — full enforcement active",
            (true, false) => "✓ hooks.json active | ⚠ settings.json failed — configure cline.openAiBaseUrl manually",
            (false, true) => "⚠ hooks.json failed — file blocking NOT active | ✓ LLM proxy active",
            (false, false) => "⚠ Both hooks and settings failed — check .vscode/ permissions",
        };

        Ok(ConnectionInfo {
            env_vars: vec![],
            instructions: format!(
                "Cline connected under DevGuard governance.\n\
                 Session: {}  |  Role: {}  |  Identity: {}\n\
                 {}\n\n\
                 IMPORTANT: Reload VSCode window for hooks to take effect.\n\
                 All file reads, writes, and commands blocked BEFORE execution.",
                session.session_id, session.role, session.identity, status,
            ),
            launch_command: None,
        })
    }

    fn disconnect(&self, _client: &ConnectorClient, _session: &SessionInfo) -> Result<()> {
        let _ = std::fs::remove_file(".devguard/devguard_cline_hook.sh");
        Ok(())
    }

    fn translate_action(&self, raw: &serde_json::Value) -> Option<CanonicalAction> {
        let tool = raw.get("tool_name").or_else(|| raw.get("name")).and_then(|v| v.as_str())?;
        let input = raw.get("tool_input").or_else(|| raw.get("input")).unwrap_or(raw);

        match tool {
            "Write" | "editFiles" | "createFile" => {
                let path = input.get("path").and_then(|v| v.as_str())?;
                let content = input.get("content").and_then(|v| v.as_str()).unwrap_or("");
                use sha2::{Sha256, Digest};
                let hash = format!("{:x}", Sha256::digest(content.as_bytes()));
                Some(CanonicalAction::FileWrite { path: PathBuf::from(path), content_hash: hash, lines_changed: content.lines().count() as u32 })
            }
            "Read" | "readFiles" => {
                let path = input.get("path").and_then(|v| v.as_str())?;
                Some(CanonicalAction::FileRead { path: PathBuf::from(path) })
            }
            "Bash" | "runInTerminal" => {
                let cmd = input.get("command").and_then(|v| v.as_str())?;
                Some(CanonicalAction::CommandExec { command: cmd.into(), cwd: PathBuf::from("."), background: false })
            }
            _ => {
                use sha2::{Sha256, Digest};
                let hash = format!("{:x}", Sha256::digest(serde_json::to_string(raw).unwrap_or_default().as_bytes()));
                Some(CanonicalAction::ToolInvoke { tool_name: tool.into(), input_hash: hash })
            }
        }
    }
}
