//! Cursor adapter.
//!
//! Integration:
//!   1. ~/.cursor/hooks.json — preToolUse hooks for file writes and commands.
//!      Exit code 2 blocks BEFORE execution.
//!   2. ~/.cursor/settings.json — openAIBaseUrl for LLM proxy.
//! Protocol: OpenAI Chat Completions + tool hooks.
//! Level: 0 Total — LLM intercepted + pre-write/pre-exec blocking.

use super::{Adapter, ConnectionInfo};
use crate::action::{CanonicalAction, SupportLevel, ToolId};
use crate::connector_client::ConnectorClient;
use crate::session::SessionInfo;
use anyhow::Result;
use std::path::PathBuf;

pub struct CursorAdapter;

impl CursorAdapter {
    /// Write the hook script Cursor calls before every file write / command.
    /// Cursor sets: CURSOR_TOOL_NAME, CURSOR_FILE_PATH, CURSOR_COMMAND
    fn write_hook_script(&self, config_path: &str) -> PathBuf {
        let cage_dir = std::path::Path::new(".devguard");
        let _ = std::fs::create_dir_all(cage_dir);

        let devguard_bin = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("devguard"));

        let script = format!(
            r#"#!/bin/bash
# DevGuard Cursor hook — preToolUse hook called BEFORE every tool invocation.
# Cursor protocol: stdin JSON; exit 2 blocks the tool call.
# DO NOT REMOVE — installed by `devguard connect cursor`.

DG="{devguard}"
CONFIG="{config}"

if [ ! -x "$DG" ] || [ ! -f "$CONFIG" ]; then
    echo "[DevGuard] DENY: handler or policy is unavailable" >&2
    exit 2
fi

PAYLOAD="$(cat)"
export DEVGUARD_HOOK_PAYLOAD="$PAYLOAD"
if ! command -v python3 >/dev/null 2>&1; then
    echo "[DevGuard] DENY: python3 is required to parse Cursor hook input" >&2
    exit 2
fi
TOOL="${{CURSOR_TOOL_NAME:-${{hookEventName:-}}}}"
FILE="${{CURSOR_FILE_PATH:-}}"
CMD="${{CURSOR_COMMAND:-}}"
if [ -z "$TOOL" ]; then
    TOOL="$(python3 -c 'import json,os; d=json.loads(os.environ["DEVGUARD_HOOK_PAYLOAD"] or "{{}}"); print(d.get("tool_name") or d.get("tool") or d.get("hook_event_name") or "")' 2>/dev/null)" || exit 2
fi
if [ -z "$FILE" ]; then
    FILE="$(python3 -c 'import json,os; d=json.loads(os.environ["DEVGUARD_HOOK_PAYLOAD"] or "{{}}"); i=d.get("tool_input") or d.get("input") or {{}}; print(i.get("file_path") or i.get("path") or "")' 2>/dev/null)" || exit 2
fi
if [ -z "$CMD" ]; then
    CMD="$(python3 -c 'import json,os; d=json.loads(os.environ["DEVGUARD_HOOK_PAYLOAD"] or "{{}}"); i=d.get("tool_input") or d.get("input") or {{}}; print(i.get("command") or "")' 2>/dev/null)" || exit 2
fi

case "$TOOL" in
    editFile|writeFile|createFile|file_write|edit_file|Write|Edit)
        TARGET="$FILE"
        if [ -n "$TARGET" ]; then
            if ! result=$("$DG" check file write "$TARGET" --config "$CONFIG" 2>&1); then
                echo "[DevGuard] CURSOR WRITE BLOCKED: $TARGET"
                echo "  $result"
                exit 2
            fi
        fi
        ;;
    readFile|file_read|Read)
        TARGET="$FILE"
        if [ -n "$TARGET" ]; then
            if ! result=$("$DG" check file read "$TARGET" --config "$CONFIG" 2>&1); then
                echo "[DevGuard] CURSOR READ BLOCKED: $TARGET"
                echo "  $result"
                exit 2
            fi
        fi
        ;;
    runTerminalCommand|executeCommand|bash|Shell|Bash)
        COMMAND="$CMD"
        if [ -n "$COMMAND" ]; then
            if ! result=$("$DG" check exec "$COMMAND" --config "$CONFIG" 2>&1); then
                echo "[DevGuard] CURSOR EXEC BLOCKED: $COMMAND"
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

        let script_path = cage_dir.join("devguard_cursor_hook.sh");
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

    /// Write ~/.cursor/hooks.json with preToolUse matchers.
    fn install_cursor_hooks(&self, hook_script: &std::path::Path) -> bool {
        let home = std::env::var("HOME").unwrap_or_default();
        let cursor_dir = PathBuf::from(&home).join(".cursor");
        let _ = std::fs::create_dir_all(&cursor_dir);
        let hooks_path = cursor_dir.join("hooks.json");
        let hook_str = hook_script.to_string_lossy();

        let hooks = serde_json::json!({
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {
                        "command": hook_str,
                        "failClosed": true,
                        "timeout": 10
                    }
                ]
            }
        });

        let final_config = if hooks_path.exists() {
            if let Ok(text) = std::fs::read_to_string(&hooks_path) {
                if let Ok(mut existing) = serde_json::from_str::<serde_json::Value>(&text) {
                    existing["version"] = serde_json::json!(1);
                    let list = existing["hooks"]["preToolUse"]
                        .as_array_mut()
                        .map(|items| {
                            items.retain(|item| {
                                !item
                                    .get("command")
                                    .or_else(|| item.get("script"))
                                    .and_then(|v| v.as_str())
                                    .is_some_and(|v| v.contains("devguard_cursor_hook"))
                            });
                            items
                        });
                    if let Some(items) = list {
                        items.extend(
                            hooks["hooks"]["preToolUse"]
                                .as_array()
                                .cloned()
                                .unwrap_or_default(),
                        );
                    } else {
                        existing["hooks"]["preToolUse"] =
                            hooks["hooks"]["preToolUse"].clone();
                    }
                    existing
                } else { hooks }
            } else { hooks }
        } else { hooks };

        std::fs::write(&hooks_path, serde_json::to_string_pretty(&final_config).unwrap_or_default()).is_ok()
    }

    /// Patch ~/.cursor/settings.json with openAIBaseUrl for LLM proxy.
    fn patch_cursor_settings(&self, connector_url: &str) -> bool {
        let home = std::env::var("HOME").unwrap_or_default();
        let cursor_dir = PathBuf::from(&home).join(".cursor");
        let _ = std::fs::create_dir_all(&cursor_dir);
        let settings_path = cursor_dir.join("settings.json");

        let cursor_settings = serde_json::json!({
            "openAIBaseUrl": format!("{}/v1", connector_url),
            "cursor.general.enableShadowWorkspace": false
        });

        if settings_path.exists() {
            if let Ok(text) = std::fs::read_to_string(&settings_path) {
                if let Ok(mut existing) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let (Some(obj), Some(new_obj)) = (existing.as_object_mut(), cursor_settings.as_object()) {
                        for (k, v) in new_obj {
                            obj.insert(k.clone(), v.clone());
                        }
                        return std::fs::write(&settings_path, serde_json::to_string_pretty(&existing).unwrap_or_default()).is_ok();
                    }
                }
            }
        }

        std::fs::write(&settings_path, serde_json::to_string_pretty(&cursor_settings).unwrap_or_default()).is_ok()
    }

    /// Write workspace-level Cursor rules for defense-in-depth prompt constraints.
    /// This is advisory (not a hard block), but helps keep the model aligned.
    fn install_cursor_rules(&self) -> bool {
        let rules_dir = std::path::Path::new(".cursor/rules");
        if std::fs::create_dir_all(rules_dir).is_err() {
            return false;
        }
        let rule_path = rules_dir.join("devguard.mdc");
        let content = r#"---
description: DevGuard policy alignment
alwaysApply: true
---

When editing files or running commands:
1. Run DevGuard checks before risky operations.
2. Refuse writes that violate policy feedback.
3. If blocked, explain why and suggest compliant alternatives.
4. Never bypass security controls or hidden path restrictions.
"#;
        std::fs::write(rule_path, content).is_ok()
    }
}

impl Adapter for CursorAdapter {
    fn name(&self) -> &str { "Cursor" }
    fn tool_id(&self) -> ToolId { ToolId::Cursor }
    fn support_level(&self) -> SupportLevel { SupportLevel::Strong }

    fn detect(&self) -> bool {
        let home = std::env::var("HOME").unwrap_or_default();
        std::path::Path::new(&format!("{}/.cursor", home)).exists()
    }

    fn connect(&self, _client: &ConnectorClient, session: &SessionInfo) -> Result<ConnectionInfo> {
        let hook_script = self.write_hook_script("devguard.yaml");
        let hooks_ok = self.install_cursor_hooks(&hook_script);
        let settings_ok = self.patch_cursor_settings(&session.connector_url);
        let rules_ok = self.install_cursor_rules();

        let status = match (hooks_ok, settings_ok, rules_ok) {
            (true, true, true) => "✓ hooks.json + settings.json + .cursor/rules/devguard.mdc active",
            (true, true, false) => "✓ hooks.json + settings.json active | ⚠ rules file failed",
            (true, false, _) => "✓ hooks.json active | ⚠ settings.json failed",
            (false, true, _) => "⚠ hooks.json failed — hard blocking NOT active | ✓ LLM proxy active",
            (false, false, _) => "⚠ hooks/settings failed — check ~/.cursor and workspace permissions",
        };

        Ok(ConnectionInfo {
            env_vars: vec![
                ("OPENAI_BASE_URL".into(), format!("{}/v1", session.connector_url)),
                (
                    "OPENAI_API_KEY".into(),
                    session
                        .session_token
                        .clone()
                        .filter(|t| t.starts_with("cg_"))
                        .unwrap_or_else(|| {
                            // Never invent a phantom key — gateway must reject missing identity.
                            String::new()
                        }),
                ),
            ],
            instructions: format!(
                "Cursor connected under DevGuard governance.\n\
                 Session: {}  |  Role: {}  |  Identity: {}\n\
                 {}\n\n\
                 IMPORTANT: Restart Cursor for hooks.json to take effect.\n\
                 Cursor-mediated reads, writes, and shell commands are checked before execution. \
                 Processes outside Cursor require an OS sandbox or separate control.",
                session.session_id, session.role, session.identity, status,
            ),
            launch_command: None,
        })
    }

    fn disconnect(&self, _client: &ConnectorClient, _session: &SessionInfo) -> Result<()> {
        let _ = std::fs::remove_file(".devguard/devguard_cursor_hook.sh");
        Ok(())
    }

    fn translate_action(&self, raw: &serde_json::Value) -> Option<CanonicalAction> {
        let tool = raw.get("tool_name").or_else(|| raw.get("name")).and_then(|v| v.as_str())?;
        let input = raw.get("tool_input").or_else(|| raw.get("input")).unwrap_or(raw);

        match tool {
            "editFile" | "writeFile" | "createFile" => {
                let path = input.get("path").and_then(|v| v.as_str())?;
                let content = input.get("content").and_then(|v| v.as_str()).unwrap_or("");
                use sha2::{Sha256, Digest};
                let hash = format!("{:x}", Sha256::digest(content.as_bytes()));
                Some(CanonicalAction::FileWrite { path: PathBuf::from(path), content_hash: hash, lines_changed: content.lines().count() as u32 })
            }
            "readFile" => {
                let path = input.get("path").and_then(|v| v.as_str())?;
                Some(CanonicalAction::FileRead { path: PathBuf::from(path) })
            }
            "runTerminalCommand" | "executeCommand" => {
                let cmd = input.get("command").and_then(|v| v.as_str())?;
                Some(CanonicalAction::CommandExec { command: cmd.into(), cwd: PathBuf::from("."), background: false })
            }
            _ => {
                let input_str = serde_json::to_string(raw).unwrap_or_default();
                use sha2::{Sha256, Digest};
                let hash = format!("{:x}", Sha256::digest(input_str.as_bytes()));
                Some(CanonicalAction::ToolInvoke { tool_name: tool.into(), input_hash: hash })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_hook_script_checks_exec_channel() {
        let adapter = CursorAdapter;
        let script = adapter.write_hook_script("devguard.yaml");
        let content = std::fs::read_to_string(script).expect("hook script readable");
        assert!(content.contains("runTerminalCommand|executeCommand|bash"));
        assert!(content.contains("check exec"));
        assert!(content.contains("PAYLOAD=\"$(cat)\""));
        assert!(content.contains("handler or policy is unavailable"));
        assert!(!content.contains("if [ ! -f \"$CONFIG\" ]; then exit 0"));
    }
}
