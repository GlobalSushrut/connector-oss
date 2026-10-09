//! Kiro adapter.
//!
//! Integration: ~/.kiro/settings/agent.json — preToolUse hooks for fs_read, fs_write,
//!              execute_bash. Exit code 2 blocks the action BEFORE it executes.
//! Protocol: Kiro calls devguard_hook.sh before every tool use.
//! Level: 0 Total — pre-action blocking on read, write, exec.

use super::{Adapter, ConnectionInfo};
use crate::action::{CanonicalAction, SupportLevel, ToolId};
use crate::connector_client::ConnectorClient;
use crate::session::SessionInfo;
use anyhow::Result;
use std::path::PathBuf;

pub struct KiroAdapter;

impl KiroAdapter {
    /// Write the Kiro preToolUse hook script.
    /// Kiro sets: KIRO_TOOL_NAME, KIRO_TOOL_INPUT (JSON), KIRO_FILE_PATH, KIRO_COMMAND
    fn write_hook_script(&self, config_path: &str) -> PathBuf {
        let cage_dir = std::path::Path::new(".devguard");
        let _ = std::fs::create_dir_all(cage_dir);

        let devguard_bin = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("devguard"));

        let script = format!(
            r#"#!/bin/bash
# DevGuard Kiro hook — preToolUse hook called BEFORE every tool invocation.
# Kiro protocol: exit 2 to BLOCK, exit 0 to allow.
# DO NOT REMOVE — installed by `devguard connect kiro`.

DG="{devguard}"
CONFIG="{config}"

if [ ! -f "$CONFIG" ]; then exit 0; fi

TOOL="${{KIRO_TOOL_NAME:-}}"
FILE="${{KIRO_FILE_PATH:-}}"
CMD="${{KIRO_COMMAND:-}}"

case "$TOOL" in
    fs_write|write_file|file_write|edit_file)
        TARGET="${{FILE:-$(echo "$KIRO_TOOL_INPUT" | grep -oP '"path"\s*:\s*"\K[^"]+' 2>/dev/null)}}"
        if [ -n "$TARGET" ]; then
            result=$("$DG" check file write "$TARGET" --config "$CONFIG" 2>&1)
            if echo "$result" | grep -qiE "DENY|BLOCK|denied|forbidden"; then
                echo "[DevGuard] KIRO WRITE BLOCKED: $TARGET"
                echo "  $result"
                exit 2
            fi
        fi
        ;;
    fs_read|read_file|file_read)
        TARGET="${{FILE:-$(echo "$KIRO_TOOL_INPUT" | grep -oP '"path"\s*:\s*"\K[^"]+' 2>/dev/null)}}"
        if [ -n "$TARGET" ]; then
            result=$("$DG" check file read "$TARGET" --config "$CONFIG" 2>&1)
            if echo "$result" | grep -qiE "DENY|BLOCK|denied|forbidden|hidden"; then
                echo "[DevGuard] KIRO READ BLOCKED: $TARGET"
                echo "  $result"
                exit 2
            fi
        fi
        ;;
    execute_bash|bash|shell|run_command)
        COMMAND="${{CMD:-$(echo "$KIRO_TOOL_INPUT" | grep -oP '"command"\s*:\s*"\K[^"]+' 2>/dev/null)}}"
        if [ -n "$COMMAND" ]; then
            result=$("$DG" check exec "$COMMAND" --config "$CONFIG" 2>&1)
            if echo "$result" | grep -qiE "DENY|BLOCK|denied|forbidden"; then
                echo "[DevGuard] KIRO EXEC BLOCKED: $COMMAND"
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

        let script_path = cage_dir.join("devguard_kiro_hook.sh");
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

    /// Write ~/.kiro/settings/agent.json with preToolUse hook matchers.
    fn install_kiro_hooks(&self, hook_script: &std::path::Path) -> bool {
        let home = std::env::var("HOME").unwrap_or_default();
        let kiro_dir = std::path::PathBuf::from(&home).join(".kiro/settings");
        let _ = std::fs::create_dir_all(&kiro_dir);

        let agent_json_path = kiro_dir.join("agent.json");
        let hook_str = hook_script.to_string_lossy();

        let hook_entry = serde_json::json!({
            "preToolUse": [
                { "matcher": "fs_read",       "hooks": [{ "type": "command", "command": hook_str }] },
                { "matcher": "fs_write",      "hooks": [{ "type": "command", "command": hook_str }] },
                { "matcher": "execute_bash",  "hooks": [{ "type": "command", "command": hook_str }] },
                { "matcher": "edit_file",     "hooks": [{ "type": "command", "command": hook_str }] },
                { "matcher": "write_file",    "hooks": [{ "type": "command", "command": hook_str }] }
            ]
        });

        // Merge with existing if present
        let final_config = if agent_json_path.exists() {
            if let Ok(text) = std::fs::read_to_string(&agent_json_path) {
                if let Ok(mut existing) = serde_json::from_str::<serde_json::Value>(&text) {
                    existing["preToolUse"] = hook_entry["preToolUse"].clone();
                    existing
                } else {
                    hook_entry
                }
            } else {
                hook_entry
            }
        } else {
            hook_entry
        };

        std::fs::write(&agent_json_path, serde_json::to_string_pretty(&final_config).unwrap_or_default()).is_ok()
    }
}

impl Adapter for KiroAdapter {
    fn name(&self) -> &str { "Kiro" }
    fn tool_id(&self) -> ToolId { ToolId::Kiro }
    fn support_level(&self) -> SupportLevel { SupportLevel::Total }

    fn detect(&self) -> bool {
        let home = std::env::var("HOME").unwrap_or_default();
        std::path::Path::new(&format!("{}/.kiro", home)).exists()
    }

    fn connect(&self, _client: &ConnectorClient, session: &SessionInfo) -> Result<ConnectionInfo> {
        let hook_script = self.write_hook_script("devguard.yaml");
        let hooks_ok = self.install_kiro_hooks(&hook_script);

        let hook_status = if hooks_ok {
            "✓ ~/.kiro/settings/agent.json written — fs_read/fs_write/execute_bash hooks active"
        } else {
            "⚠ Could not write ~/.kiro/settings/agent.json — write blocking NOT active"
        };

        Ok(ConnectionInfo {
            env_vars: vec![
                ("ANTHROPIC_BASE_URL".into(), session.connector_url.clone()),
            ],
            instructions: format!(
                "Kiro connected under DevGuard governance.\n\
                 Session: {}  |  Role: {}  |  Identity: {}\n\
                 {}\n\n\
                 IMPORTANT: Restart Kiro for agent.json hooks to take effect.\n\
                 All file reads, writes, and commands are blocked BEFORE execution.",
                session.session_id, session.role, session.identity,
                hook_status,
            ),
            launch_command: None,
        })
    }

    fn disconnect(&self, _client: &ConnectorClient, _session: &SessionInfo) -> Result<()> {
        let _ = std::fs::remove_file(".devguard/devguard_kiro_hook.sh");
        Ok(())
    }

    fn translate_action(&self, raw: &serde_json::Value) -> Option<CanonicalAction> {
        let tool_name = raw.get("name").or_else(|| raw.get("tool")).and_then(|v| v.as_str())?;
        let input = raw.get("input").or_else(|| raw.get("arguments")).unwrap_or(raw);

        match tool_name {
            "fs_write" | "write_file" | "edit_file" => {
                let path = input.get("path").and_then(|v| v.as_str())?;
                let content = input.get("content").and_then(|v| v.as_str()).unwrap_or("");
                use sha2::{Sha256, Digest};
                let hash = format!("{:x}", Sha256::digest(content.as_bytes()));
                Some(CanonicalAction::FileWrite {
                    path: PathBuf::from(path),
                    content_hash: hash,
                    lines_changed: content.lines().count() as u32,
                })
            }
            "fs_read" | "read_file" => {
                let path = input.get("path").and_then(|v| v.as_str())?;
                Some(CanonicalAction::FileRead { path: PathBuf::from(path) })
            }
            "execute_bash" | "bash" | "shell" => {
                let command = input.get("command").and_then(|v| v.as_str())?;
                Some(CanonicalAction::CommandExec {
                    command: command.into(),
                    cwd: PathBuf::from("."),
                    background: false,
                })
            }
            _ => {
                use sha2::{Sha256, Digest};
                let hash = format!("{:x}", Sha256::digest(serde_json::to_string(raw).unwrap_or_default().as_bytes()));
                Some(CanonicalAction::ToolInvoke { tool_name: tool_name.into(), input_hash: hash })
            }
        }
    }
}
