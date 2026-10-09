//! GitHub Copilot adapter.
//!
//! Integration: .vscode/hooks.json — PreToolUse hooks for readFiles, editFiles,
//!              runInTerminal. Exit code 2 blocks BEFORE execution.
//! Protocol: Copilot uses VSCode extension hook system.
//! Level: 1 Strong — pre-action blocking via hooks.json; LLM calls via proxy.

use super::{Adapter, ConnectionInfo};
use crate::action::{CanonicalAction, SupportLevel, ToolId};
use crate::connector_client::ConnectorClient;
use crate::session::SessionInfo;
use anyhow::Result;
use std::path::PathBuf;

pub struct CopilotAdapter;

impl CopilotAdapter {
    /// Write the Copilot hook script (VSCode/Copilot hook format).
    /// Env vars: COPILOT_TOOL_NAME, COPILOT_FILE_PATH, COPILOT_COMMAND
    fn write_hook_script(&self, config_path: &str) -> PathBuf {
        let cage_dir = std::path::Path::new(".devguard");
        let _ = std::fs::create_dir_all(cage_dir);

        let devguard_bin = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("devguard"));

        let script = format!(
            r#"#!/bin/bash
# DevGuard Copilot hook — PreToolUse hook called BEFORE every tool invocation.
# Copilot/VSCode protocol: exit 2 to BLOCK (deny), exit 0 to allow.
# DO NOT REMOVE — installed by `devguard connect copilot`.

DG="{devguard}"
CONFIG="{config}"

if [ ! -f "$CONFIG" ]; then exit 0; fi

TOOL="${{COPILOT_TOOL_NAME:-${{hookEventName:-}}}}"
FILE="${{COPILOT_FILE_PATH:-}}"
CMD="${{COPILOT_COMMAND:-}}"

case "$TOOL" in
    editFiles|writeFiles|createFile|file_write)
        if [ -n "$FILE" ]; then
            result=$("$DG" check file write "$FILE" --config "$CONFIG" 2>&1)
            if echo "$result" | grep -qiE "DENY|BLOCK|denied|forbidden"; then
                echo "[DevGuard] COPILOT WRITE BLOCKED: $FILE"
                echo "  $result"
                exit 2
            fi
        fi
        ;;
    readFiles|file_read)
        if [ -n "$FILE" ]; then
            result=$("$DG" check file read "$FILE" --config "$CONFIG" 2>&1)
            if echo "$result" | grep -qiE "DENY|BLOCK|denied|forbidden|hidden"; then
                echo "[DevGuard] COPILOT READ BLOCKED: $FILE"
                echo "  $result"
                exit 2
            fi
        fi
        ;;
    runInTerminal|execute_bash|runCommand)
        if [ -n "$CMD" ]; then
            result=$("$DG" check exec "$CMD" --config "$CONFIG" 2>&1)
            if echo "$result" | grep -qiE "DENY|BLOCK|denied|forbidden"; then
                echo "[DevGuard] COPILOT EXEC BLOCKED: $CMD"
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

        let script_path = cage_dir.join("devguard_copilot_hook.sh");
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

    /// Write .vscode/hooks.json with PreToolUse matchers.
    fn install_vscode_hooks(&self, hook_script: &std::path::Path) -> bool {
        let vscode_dir = std::path::Path::new(".vscode");
        let _ = std::fs::create_dir_all(vscode_dir);
        let hooks_path = vscode_dir.join("hooks.json");
        let hook_str = hook_script.to_string_lossy();

        let hooks = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "readFiles",      "script": hook_str },
                    { "matcher": "editFiles",       "script": hook_str },
                    { "matcher": "runInTerminal",   "script": hook_str },
                    { "matcher": "createFile",      "script": hook_str }
                ]
            }
        });

        // Merge with existing
        let final_config = if hooks_path.exists() {
            if let Ok(text) = std::fs::read_to_string(&hooks_path) {
                if let Ok(mut existing) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(h) = existing.get_mut("hooks").and_then(|v| v.as_object_mut()) {
                        h.insert("PreToolUse".into(), hooks["hooks"]["PreToolUse"].clone());
                    } else {
                        existing["hooks"] = hooks["hooks"].clone();
                    }
                    existing
                } else { hooks }
            } else { hooks }
        } else { hooks };

        std::fs::write(&hooks_path, serde_json::to_string_pretty(&final_config).unwrap_or_default()).is_ok()
    }
}

impl Adapter for CopilotAdapter {
    fn name(&self) -> &str { "GitHub Copilot" }
    fn tool_id(&self) -> ToolId { ToolId::Copilot }
    fn support_level(&self) -> SupportLevel { SupportLevel::Strong }

    fn detect(&self) -> bool {
        std::path::Path::new(".vscode").exists()
            || std::process::Command::new("code").arg("--version")
                .output().map(|o| o.status.success()).unwrap_or(false)
    }

    fn connect(&self, _client: &ConnectorClient, session: &SessionInfo) -> Result<ConnectionInfo> {
        let hook_script = self.write_hook_script("devguard.yaml");
        let hooks_ok = self.install_vscode_hooks(&hook_script);

        let hook_status = if hooks_ok {
            "✓ .vscode/hooks.json written — readFiles/editFiles/runInTerminal hooks active"
        } else {
            "⚠ Could not write .vscode/hooks.json — write blocking NOT active"
        };

        Ok(ConnectionInfo {
            env_vars: vec![],
            instructions: format!(
                "GitHub Copilot connected under DevGuard governance.\n\
                 Session: {}  |  Role: {}  |  Identity: {}\n\
                 {}\n\n\
                 IMPORTANT: Reload VSCode for hooks to take effect.\n\
                 All file reads, writes, and terminal commands blocked BEFORE execution.",
                session.session_id, session.role, session.identity,
                hook_status,
            ),
            launch_command: None,
        })
    }

    fn disconnect(&self, _client: &ConnectorClient, _session: &SessionInfo) -> Result<()> {
        let _ = std::fs::remove_file(".devguard/devguard_copilot_hook.sh");
        Ok(())
    }

    fn translate_action(&self, raw: &serde_json::Value) -> Option<CanonicalAction> {
        let tool_name = raw.get("tool_name").or_else(|| raw.get("hookEventName"))
            .and_then(|v| v.as_str())?;
        let input = raw.get("tool_input").or_else(|| raw.get("input")).unwrap_or(raw);

        match tool_name {
            "editFiles" | "createFile" => {
                let path = input.get("file_path").or_else(|| input.get("path")).and_then(|v| v.as_str())?;
                let content = input.get("new_content").or_else(|| input.get("content")).and_then(|v| v.as_str()).unwrap_or("");
                use sha2::{Sha256, Digest};
                let hash = format!("{:x}", Sha256::digest(content.as_bytes()));
                Some(CanonicalAction::FileWrite { path: PathBuf::from(path), content_hash: hash, lines_changed: content.lines().count() as u32 })
            }
            "readFiles" => {
                let path = input.get("file_path").or_else(|| input.get("path")).and_then(|v| v.as_str())?;
                Some(CanonicalAction::FileRead { path: PathBuf::from(path) })
            }
            "runInTerminal" => {
                let cmd = input.get("command").and_then(|v| v.as_str())?;
                Some(CanonicalAction::CommandExec { command: cmd.into(), cwd: PathBuf::from("."), background: false })
            }
            _ => {
                use sha2::{Sha256, Digest};
                let hash = format!("{:x}", Sha256::digest(serde_json::to_string(raw).unwrap_or_default().as_bytes()));
                Some(CanonicalAction::ToolInvoke { tool_name: tool_name.into(), input_hash: hash })
            }
        }
    }
}
