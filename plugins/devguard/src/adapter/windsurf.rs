//! Windsurf adapter.
//!
//! Integration:
//!   1. `.windsurf/hooks.json` — pre_write_code / pre_run_command hooks that call
//!      `devguard_hook.sh`, which exits 2 to BLOCK Windsurf before the action happens.
//!   2. `.windsurf/mcp_config.json` — Connector MCP server for tool-call governance.
//!
//! The hooks.json approach is the only mechanism that gives a TRUE pre-write block.
//! MCP config governs LLM calls. File permissions + watchdog are the OS-level backup layer.
//! All three layers are installed together for defense-in-depth.

use super::{Adapter, ConnectionInfo};
use crate::action::{CanonicalAction, SupportLevel, ToolId};
use crate::connector_client::ConnectorClient;
use crate::session::SessionInfo;
use anyhow::Result;
use std::path::PathBuf;

pub struct WindsurfAdapter;

impl WindsurfAdapter {
    /// Write `.windsurf/hooks.json` with pre_write_code and pre_run_command hooks.
    /// Windsurf calls these hooks synchronously BEFORE executing the action.
    /// Exit code 2 = BLOCK. Exit code 0 = allow.
    pub fn install_hooks_public(&self, hook_script: &std::path::Path) -> bool {
        self.install_hooks(hook_script)
    }

    pub fn write_hook_script_public(&self, config_path: &str) -> std::path::PathBuf {
        self.write_hook_script(config_path)
    }

    fn install_hooks(&self, hook_script: &std::path::Path) -> bool {
        let config_dir = std::path::Path::new(".windsurf");
        let hooks_path = config_dir.join("hooks.json");
        let _ = std::fs::create_dir_all(config_dir);

        let hook_script_str = hook_script.to_string_lossy();

        let hooks = serde_json::json!({
            "hooks": {
                "pre_read_code": [{
                    "command": hook_script_str,
                    "show_output": true
                }],
                "pre_write_code": [{
                    "command": hook_script_str,
                    "show_output": true
                }],
                "pre_run_command": [{
                    "command": hook_script_str,
                    "show_output": true
                }]
            }
        });

        let mut merged = if hooks_path.exists() {
            std::fs::read_to_string(&hooks_path)
                .ok()
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
                .unwrap_or_else(|| serde_json::json!({}))
        } else {
            serde_json::json!({})
        };
        for event in [
            "pre_read_code",
            "pre_write_code",
            "pre_run_command",
        ] {
            let replacement = hooks["hooks"][event].clone();
            let items = merged["hooks"][event].as_array_mut();
            if let Some(items) = items {
                items.retain(|item| {
                    !item
                        .get("command")
                        .and_then(|v| v.as_str())
                        .is_some_and(|v| v.contains("devguard_hook"))
                });
                items.extend(replacement.as_array().cloned().unwrap_or_default());
            } else {
                merged["hooks"][event] = replacement;
            }
        }
        std::fs::write(
            &hooks_path,
            serde_json::to_string_pretty(&merged).unwrap_or_default(),
        )
        .is_ok()
    }

    fn verify_hooks_installation(&self, hook_script: &std::path::Path) -> bool {
        let hooks_path = std::path::Path::new(".windsurf/hooks.json");
        let hook_text_ok = std::fs::read_to_string(hooks_path)
            .map(|t| t.contains("pre_write_code") && t.contains("pre_run_command"))
            .unwrap_or(false);
        let script_ok = hook_script.exists();
        #[cfg(unix)]
        let script_exec_ok = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(hook_script)
                .map(|m| (m.permissions().mode() & 0o111) != 0)
                .unwrap_or(false)
        };
        #[cfg(not(unix))]
        let script_exec_ok = true;
        hook_text_ok && script_ok && script_exec_ok
    }

    /// Write the hook script that Windsurf executes before every file write / command.
    /// The script receives context via environment variables set by Windsurf:
    ///   WINDSURF_HOOK_EVENT    = "pre_write_code" | "pre_run_command"
    ///   WINDSURF_FILE_PATH     = absolute path being written
    ///   WINDSURF_COMMAND       = command string being run
    ///
    /// Exit 2  → Windsurf BLOCKS the action and shows the reason
    /// Exit 0  → Windsurf allows the action
    fn write_hook_script(&self, config_path: &str) -> std::path::PathBuf {
        let cage_dir = std::path::Path::new(".devguard");
        let _ = std::fs::create_dir_all(cage_dir);

        let devguard_bin = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("devguard"));

        let script = format!(
            r#"#!/bin/bash
# DevGuard Windsurf hook — called BEFORE every file write and command.
# Windsurf protocol: exit 2 to BLOCK, exit 0 to allow.
# DO NOT REMOVE — installed by `devguard connect windsurf`.

DG="{devguard}"
CONFIG="{config}"

# Managed repositories fail closed if the handler or policy is unavailable.
if [ ! -x "$DG" ] || [ ! -f "$CONFIG" ]; then
    echo "[DevGuard] DENY: handler or policy is unavailable" >&2
    exit 2
fi

PAYLOAD="$(cat)"
export DEVGUARD_HOOK_PAYLOAD="$PAYLOAD"
if ! command -v python3 >/dev/null 2>&1; then
    echo "[DevGuard] DENY: python3 is required to parse Windsurf hook input" >&2
    exit 2
fi
EVENT="${{WINDSURF_HOOK_EVENT:-}}"
FILE="${{WINDSURF_FILE_PATH:-}}"
COMMAND="${{WINDSURF_COMMAND:-}}"
if [ -z "$EVENT" ]; then
    EVENT="$(python3 -c 'import json,os; d=json.loads(os.environ["DEVGUARD_HOOK_PAYLOAD"] or "{{}}"); print(d.get("agent_action_name") or "")' 2>/dev/null)" || exit 2
fi
if [ -z "$FILE" ]; then
    FILE="$(python3 -c 'import json,os; d=json.loads(os.environ["DEVGUARD_HOOK_PAYLOAD"] or "{{}}"); i=d.get("tool_info") or {{}}; print(i.get("file_path") or i.get("path") or "")' 2>/dev/null)" || exit 2
fi
if [ -z "$COMMAND" ]; then
    COMMAND="$(python3 -c 'import json,os; d=json.loads(os.environ["DEVGUARD_HOOK_PAYLOAD"] or "{{}}"); i=d.get("tool_info") or {{}}; print(i.get("command_line") or i.get("command") or "")' 2>/dev/null)" || exit 2
fi

case "$EVENT" in
    pre_read_code)
        if [ -n "$FILE" ] && ! result=$("$DG" check file read "$FILE" --config "$CONFIG" 2>&1); then
            echo "[DevGuard] READ BLOCKED: $FILE"
            echo "  $result"
            exit 2
        fi
        ;;

    pre_write_code)
        if [ -n "$FILE" ]; then
            if ! result=$("$DG" check file write "$FILE" --config "$CONFIG" 2>&1); then
                echo "[DevGuard] WRITE BLOCKED: $FILE"
                echo "  Reason: $result"
                echo "  Role does not allow writing to this path."
                exit 2
            fi
        fi
        ;;

    pre_run_command)
        if [ -n "$COMMAND" ]; then
            if ! result=$("$DG" check exec "$COMMAND" --config "$CONFIG" 2>&1); then
                echo "[DevGuard] COMMAND BLOCKED: $COMMAND"
                echo "  Reason: $result"
                echo "  Role does not allow running this command."
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

        let script_path = cage_dir.join("devguard_hook.sh");
        let _ = std::fs::write(&script_path, &script);

        // Must be executable or Windsurf won't run it
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

    /// Write `.windsurf/mcp_config.json` so Connector acts as the MCP server.
    /// This governs LLM calls and tool invocations through the Connector gateway.
    fn ensure_mcp_config(&self, connector_url: &str) -> bool {
        let config_dir = std::path::Path::new(".windsurf");
        let config_path = config_dir.join("mcp_config.json");

        let mcp_entry = serde_json::json!({
            "serverUrl": format!("{}/protocols/mcp/handle", connector_url),
            "description": "Connector DevGuard — governed agent runtime",
            "env": {
                "CONNECTOR_URL": connector_url,
            }
        });

        let final_config = if config_path.exists() {
            if let Ok(existing) = std::fs::read_to_string(&config_path) {
                if let Ok(mut existing_json) = serde_json::from_str::<serde_json::Value>(&existing) {
                    if let Some(servers) = existing_json.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
                        servers.insert("connector".into(), mcp_entry);
                    } else {
                        existing_json["mcpServers"] = serde_json::json!({ "connector": mcp_entry });
                    }
                    existing_json
                } else {
                    serde_json::json!({ "mcpServers": { "connector": mcp_entry } })
                }
            } else {
                serde_json::json!({ "mcpServers": { "connector": mcp_entry } })
            }
        } else {
            let _ = std::fs::create_dir_all(config_dir);
            serde_json::json!({ "mcpServers": { "connector": mcp_entry } })
        };

        std::fs::write(&config_path, serde_json::to_string_pretty(&final_config).unwrap_or_default()).is_ok()
    }

    /// Remove the hooks.json and hook script on disconnect.
    pub fn remove_hooks() {
        let _ = std::fs::remove_file(".windsurf/hooks.json");
        let _ = std::fs::remove_file(".devguard/devguard_hook.sh");
    }
}

impl Adapter for WindsurfAdapter {
    fn name(&self) -> &str { "Windsurf" }
    fn tool_id(&self) -> ToolId { ToolId::Windsurf }
    fn support_level(&self) -> SupportLevel { SupportLevel::Strong }

    fn detect(&self) -> bool {
        std::path::Path::new(".windsurf").exists()
            || std::env::var("HOME")
                .map(|h| std::path::Path::new(&format!("{}/.windsurf", h)).exists())
                .unwrap_or(false)
    }

    fn connect(&self, _client: &ConnectorClient, session: &SessionInfo) -> Result<ConnectionInfo> {
        // Layer 1: Write the hook script that Windsurf will call pre-write/pre-command
        let hook_script = self.write_hook_script("devguard.yaml");

        // Layer 2: Write .windsurf/hooks.json pointing at the hook script
        let hooks_ok = self.install_hooks(&hook_script);
        let hooks_verified = hooks_ok && self.verify_hooks_installation(&hook_script);

        // Layer 3: Write .windsurf/mcp_config.json for LLM/tool-call governance
        let mcp_ok = self.ensure_mcp_config(&session.connector_url);

        let hook_status = if hooks_verified {
            "✓ hooks.json + executable hook script verified (pre-write/pre-command channel ready)"
        } else if hooks_ok {
            "⚠ hooks.json written but hook channel verification incomplete"
        } else {
            "⚠ Could not write .windsurf/hooks.json — write blocking NOT active"
        };

        let mcp_status = if mcp_ok {
            "✓ mcp_config.json written — LLM + tool calls governed"
        } else {
            "⚠ Could not write .windsurf/mcp_config.json"
        };

        Ok(ConnectionInfo {
            env_vars: vec![
                ("OPENAI_API_BASE".into(), format!("{}/v1", session.connector_url)),
            ],
            instructions: format!(
                "Windsurf connected under DevGuard governance.\n\
                 Session: {}  |  Role: {}  |  Identity: {}\n\
                 {}\n\
                 {}\n\n\
                 IMPORTANT: Restart Windsurf for hooks.json to take effect.\n\
                 Windsurf-mediated reads, writes, and shell commands use project hooks. \
                 Processes outside Windsurf require an OS sandbox or separate control.",
                session.session_id, session.role, session.identity,
                hook_status, mcp_status,
            ),
            launch_command: None,
        })
    }

    fn disconnect(&self, _client: &ConnectorClient, _session: &SessionInfo) -> Result<()> {
        Self::remove_hooks();
        Ok(())
    }

    fn translate_action(&self, raw: &serde_json::Value) -> Option<CanonicalAction> {
        let tool_name = raw.get("name")?.as_str()?;
        let args = raw.get("arguments").unwrap_or(&serde_json::Value::Null);

        match tool_name {
            "connector_read_file" | "read_file" => {
                let path = args.get("path").and_then(|v| v.as_str())?;
                Some(CanonicalAction::FileRead { path: PathBuf::from(path) })
            }
            "connector_write_file" | "write_file" => {
                let path = args.get("path").and_then(|v| v.as_str())?;
                let content = args.get("content").and_then(|v| v.as_str()).unwrap_or("");
                use sha2::{Sha256, Digest};
                let hash = format!("{:x}", Sha256::digest(content.as_bytes()));
                Some(CanonicalAction::FileWrite {
                    path: PathBuf::from(path),
                    content_hash: hash,
                    lines_changed: content.lines().count() as u32,
                })
            }
            "connector_exec" | "run_command" => {
                let command = args.get("command")
                    .or_else(|| args.get("CommandLine"))
                    .and_then(|v| v.as_str())?;
                Some(CanonicalAction::CommandExec {
                    command: command.into(),
                    cwd: PathBuf::from("."),
                    background: false,
                })
            }
            _ => {
                let input_str = serde_json::to_string(raw).unwrap_or_default();
                use sha2::{Sha256, Digest};
                let hash = format!("{:x}", Sha256::digest(input_str.as_bytes()));
                Some(CanonicalAction::ToolInvoke {
                    tool_name: tool_name.into(),
                    input_hash: hash,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windsurf_hook_script_checks_pre_run_command_channel() {
        let adapter = WindsurfAdapter;
        let script = adapter.write_hook_script("devguard.yaml");
        let content = std::fs::read_to_string(script).expect("hook script readable");
        assert!(content.contains("pre_run_command"));
        assert!(content.contains("check exec"));
        assert!(content.contains("PAYLOAD=\"$(cat)\""));
        assert!(content.contains("handler or policy is unavailable"));
        assert!(!content.contains("fail-open is intentional"));
    }
}
