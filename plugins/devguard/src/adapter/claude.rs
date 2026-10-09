//! Claude Code / Kiro adapter.
//!
//! Integration: ANTHROPIC_BASE_URL=http://localhost:9091 claude "task"
//! Protocol: Anthropic Messages API (POST /v1/messages)
//! Tool use: tool_use content blocks (bash, file_edit, Read, Write, search)
//! Level: 0 Total — all LLM calls and tool invocations intercepted.

use super::{Adapter, ConnectionInfo};
use crate::action::{
    CanonicalAction, GitOperation, SupportLevel, ToolId,
};
use crate::connector_client::ConnectorClient;
use crate::session::SessionInfo;
use anyhow::Result;
use std::path::PathBuf;

pub struct ClaudeAdapter;

impl ClaudeAdapter {
    fn write_bash_hook_script(&self, config_path: &str) -> PathBuf {
        let cage_dir = std::path::Path::new(".devguard");
        let _ = std::fs::create_dir_all(cage_dir);
        let devguard_bin = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("devguard"));
        let script = format!(
            r#"#!/bin/bash
DG="{devguard}"
CONFIG="{config}"
CMD="$1"

if [ -z "$CMD" ]; then
  echo "[DevGuard] DENY: missing command payload" >&2
  exit 2
fi
if [ ! -f "$CONFIG" ]; then
  echo "[DevGuard] DENY: policy is unavailable" >&2
  exit 2
fi
if ! result=$("$DG" check exec "$CMD" --config "$CONFIG" 2>&1); then
  echo "[DevGuard] CLAUDE EXEC BLOCKED: $CMD"
  echo "  $result"
  exit 2
fi
exit 0
"#,
            devguard = devguard_bin.display(),
            config = config_path
        );
        let script_path = cage_dir.join("devguard_claude_bash_hook.sh");
        let _ = std::fs::write(&script_path, script);
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

    fn verify_bash_hook_script(&self, path: &std::path::Path) -> bool {
        let content_ok = std::fs::read_to_string(path)
            .map(|c| c.contains("check exec") && c.contains("CLAUDE EXEC BLOCKED"))
            .unwrap_or(false);
        let exists_ok = path.exists();
        #[cfg(unix)]
        let exec_ok = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path)
                .map(|m| (m.permissions().mode() & 0o111) != 0)
                .unwrap_or(false)
        };
        #[cfg(not(unix))]
        let exec_ok = true;
        exists_ok && content_ok && exec_ok
    }
}

impl Adapter for ClaudeAdapter {
    fn name(&self) -> &str { "Claude Code" }

    fn tool_id(&self) -> ToolId { ToolId::ClaudeCode }

    fn support_level(&self) -> SupportLevel { SupportLevel::ProxyOnly }

    fn detect(&self) -> bool {
        // Check if `claude` CLI is on PATH
        std::process::Command::new("which")
            .arg("claude")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn connect(&self, _client: &ConnectorClient, session: &SessionInfo) -> Result<ConnectionInfo> {
        let gateway_url = format!("{}", session.connector_url);
        let api_key = session
            .session_token
            .clone()
            .filter(|token| token.starts_with("cg_"))
            .unwrap_or_default();
        let hook_script = self.write_bash_hook_script("devguard.yaml");
        let hook_ok = self.verify_bash_hook_script(&hook_script);

        Ok(ConnectionInfo {
            env_vars: vec![
                ("ANTHROPIC_BASE_URL".into(), gateway_url.clone()),
                ("ANTHROPIC_API_KEY".into(), api_key),
                ("CLAUDE_BASH_HOOK".into(), hook_script.to_string_lossy().to_string()),
            ],
            instructions: format!(
                "Claude Code connected under DevGuard governance.\n\
                 Session: {}  |  Role: {}  |  Identity: {}\n\n\
                 Export the ANTHROPIC_BASE_URL and ANTHROPIC_API_KEY values shown above, then run Claude.\n\n\
                 The gateway governs model traffic. The generated bash helper is not proof that Claude Code installed it.\n\
                 Hook status: {}\n\
                 Enforcement: {}",
                session.session_id, session.role, session.identity,
                if hook_ok { "verified local hook script ready" } else { "WARNING: hook script not fully verified" },
                if session.cage { "CAGE (git hooks + FS watchdog + exec wrapper — not a kernel overlay)" } else { "HOOKS (gateway middleware)" },
            ),
            launch_command: Some("claude".to_string()),
        })
    }

    fn disconnect(&self, _client: &ConnectorClient, _session: &SessionInfo) -> Result<()> {
        // Claude Code doesn't need explicit disconnect — just stop proxying.
        let _ = std::fs::remove_file(".devguard/devguard_claude_bash_hook.sh");
        Ok(())
    }

    fn translate_action(&self, raw: &serde_json::Value) -> Option<CanonicalAction> {
        // Translate Anthropic tool_use blocks into CanonicalAction.
        let tool_name = raw.get("name")?.as_str()?;
        let input = raw.get("input")?;

        match tool_name {
            // ── Shell commands ──
            "bash" | "execute" | "shell" | "run_command" => {
                let command = input.get("command")
                    .or_else(|| input.get("CommandLine"))
                    .and_then(|v| v.as_str())?;
                let cwd = input.get("cwd")
                    .or_else(|| input.get("Cwd"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(".");

                // Detect git sub-commands
                if command.starts_with("git ") {
                    return translate_git_command(command);
                }

                // Detect package installs
                if is_package_install(command) {
                    return translate_package_install(command);
                }

                // Detect CI/CD commands
                if is_deploy_command(command) {
                    return Some(CanonicalAction::DeployAction {
                        tool: detect_deploy_tool(command).into(),
                        command: command.into(),
                        target: "unknown".into(),
                    });
                }

                Some(CanonicalAction::CommandExec {
                    command: command.into(),
                    cwd: PathBuf::from(cwd),
                    background: false,
                })
            }

            // ── File writes ──
            "file_edit" | "write" | "Write" | "edit" => {
                let path = input.get("path")
                    .or_else(|| input.get("file_path"))
                    .and_then(|v| v.as_str())?;
                let content = input.get("content")
                    .or_else(|| input.get("new_string"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                use sha2::{Sha256, Digest};
                let hash = format!("{:x}", Sha256::digest(content.as_bytes()));
                let lines = content.lines().count() as u32;

                Some(CanonicalAction::FileWrite {
                    path: PathBuf::from(path),
                    content_hash: hash,
                    lines_changed: lines,
                })
            }

            // ── File reads ──
            "Read" | "read" | "read_file" => {
                let path = input.get("path")
                    .or_else(|| input.get("file_path"))
                    .and_then(|v| v.as_str())?;
                Some(CanonicalAction::FileRead {
                    path: PathBuf::from(path),
                })
            }

            // ── Code search ──
            "search" | "grep" | "grep_search" | "code_search" | "find_by_name" => {
                let query = input.get("query")
                    .or_else(|| input.get("Query"))
                    .or_else(|| input.get("pattern"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                Some(CanonicalAction::SearchCode {
                    query: query.into(),
                    scope: vec![],
                })
            }

            // ── Generic tool invocation ──
            _ => {
                let input_str = serde_json::to_string(input).unwrap_or_default();
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

// ── Git command parsing ───────────────────────────────────────────────────

fn translate_git_command(command: &str) -> Option<CanonicalAction> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.len() < 2 { return None; }

    let args: Vec<String> = parts.iter().map(|s| s.to_string()).collect();

    let operation = match parts[1] {
        "commit" => GitOperation::Commit,
        "push" => {
            if parts.contains(&"--force") || parts.contains(&"-f") {
                GitOperation::ForcePush
            } else {
                GitOperation::Push
            }
        }
        "rebase" => GitOperation::Rebase,
        "merge" => GitOperation::Merge,
        "checkout" if parts.len() > 2 && parts[2] == "-b" => GitOperation::BranchCreate,
        "checkout" => GitOperation::Checkout,
        "branch" if parts.contains(&"-d") || parts.contains(&"-D") => GitOperation::BranchDelete,
        "branch" => GitOperation::BranchCreate,
        "tag" => GitOperation::Tag,
        "reset" if parts.contains(&"--hard") => GitOperation::Reset,
        _ => return None, // git status, log, diff etc. — not risky
    };

    Some(CanonicalAction::GitOp { operation, args })
}

fn is_package_install(command: &str) -> bool {
    let patterns = [
        "npm install", "npm i ", "npm add", "yarn add", "pnpm add",
        "pip install", "pip3 install", "pipx install",
        "cargo add", "cargo install",
        "gem install", "bundle install",
        "go get", "go install",
        "apt install", "apt-get install", "brew install",
    ];
    patterns.iter().any(|p| command.contains(p))
}

fn translate_package_install(command: &str) -> Option<CanonicalAction> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    let manager = parts.first()?.to_string();
    let package = parts.last()?.to_string();
    Some(CanonicalAction::PackageInstall {
        manager,
        package,
        version: None,
    })
}

fn is_deploy_command(command: &str) -> bool {
    let patterns = [
        "kubectl apply", "kubectl delete", "kubectl rollout",
        "terraform apply", "terraform destroy",
        "docker push", "docker compose up",
        "helm install", "helm upgrade", "helm delete",
        "cdk deploy", "cdk destroy",
        "serverless deploy",
        "flyctl deploy", "fly deploy",
    ];
    patterns.iter().any(|p| command.contains(p))
}

fn detect_deploy_tool(command: &str) -> &str {
    if command.starts_with("kubectl") { "kubernetes" }
    else if command.starts_with("terraform") { "terraform" }
    else if command.starts_with("docker") { "docker" }
    else if command.starts_with("helm") { "helm" }
    else if command.starts_with("cdk") { "cdk" }
    else { "unknown" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::ToolId;
    use crate::session::SessionInfo;

    fn test_session() -> SessionInfo {
        SessionInfo {
            session_id: "s1".into(),
            agent_pid: "a1".into(),
            identity: "local:test".into(),
            role: "intern".into(),
            tool: ToolId::ClaudeCode,
            workspace: ".".into(),
            connector_url: "http://localhost:9091".into(),
            cage: false,
            policy_fingerprint: "deadbeef".into(),
            session_token: Some("tok".into()),
            created_at: "now".into(),
        }
    }

    #[test]
    fn claude_connect_exports_bash_hook_and_exec_check() {
        let adapter = ClaudeAdapter;
        let session = test_session();
        let conn = adapter
            .connect(&ConnectorClient::new("http://localhost:9091"), &session)
            .expect("connect should succeed");
        let hook = conn
            .env_vars
            .iter()
            .find(|(k, _)| k == "CLAUDE_BASH_HOOK")
            .map(|(_, v)| v.clone())
            .expect("CLAUDE_BASH_HOOK must be exported");
        let content = std::fs::read_to_string(hook).expect("hook script readable");
        assert!(content.contains("check exec"));
        assert!(content.contains("CLAUDE EXEC BLOCKED"));
    }
}
