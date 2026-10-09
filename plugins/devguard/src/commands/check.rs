//! `devguard check` — pre-flight check an action against the active policy.
//!
//! Usage:
//!   devguard check file read src/main.rs
//!   devguard check file write src/auth/login.rs
//!   devguard check exec "cargo build"
//!   devguard check exec "rm -rf /"
//!   devguard check git push main
//!   devguard check secret DB_PASSWORD
//!
//! When `.devguard/connector.json` exists and `CONNECTOR_AGENT_TOKEN` is set,
//! checks prefer the Connector kernel (`POST /devguard/fs|exec/check`) so the
//! workstation and node share one policy source. Local YAML remains the
//! fallback and is always used for offline/unlinked checkouts.

use anyhow::Result;
use crate::action::*;
use crate::config::DevGuardConfig;
use crate::connector_client::ConnectorClient;
use crate::enforce;

pub async fn run_file(
    operation: &str,
    path: &str,
    config_path: &str,
    identity: &str,
    tool: &str,
) -> Result<()> {
    deny_without_connector_identity()?;
    match operation {
        "read" | "write" | "delete" => {}
        _ => {
            eprintln!("Unknown file operation: {}. Use read/write/delete.", operation);
            std::process::exit(1);
        }
    }
    if try_online_file_check(operation, path).await? {
        return Ok(());
    }
    let config = DevGuardConfig::load(config_path)?;
    let resolved = resolve_or_exit(&config, identity, tool);
    let check = if operation == "write" || operation == "delete" {
        crate::fs_guard::check_write(&resolved, path, operation)
    } else {
        resolved.check_file(operation, path)
    };
    println!("[{}] {}", check.verdict, check.reason);
    exit_for_permission_check(&check);
    Ok(())
}

pub async fn run_exec(
    command: &str,
    config_path: &str,
    identity: &str,
    tool: &str,
) -> Result<()> {
    deny_without_connector_identity()?;
    if try_online_exec_check(command).await? {
        return Ok(());
    }
    let config = DevGuardConfig::load(config_path)?;
    let resolved = resolve_or_exit(&config, identity, tool);

    let check = resolved.check_exec(command);
    println!("[{}] {}", check.verdict, check.reason);
    exit_for_permission_check(&check);
    Ok(())
}

pub async fn run_git(
    operation: &str,
    target: &str,
    config_path: &str,
    identity: &str,
    tool: &str,
) -> Result<()> {
    deny_without_connector_identity()?;
    let config = DevGuardConfig::load(config_path)?;
    let resolved = resolve_or_exit(&config, identity, tool);

    match operation {
        "push" | "force-push" | "commit" | "merge" | "rebase" | "branch" | "tag" => {}
        _ => {
            eprintln!("Unknown git operation: {}. Use push/commit/merge/rebase/branch/tag.", operation);
            std::process::exit(1);
        }
    }
    let check = resolved.check_git(operation, target);
    println!("[{}] {}", check.verdict, check.reason);
    exit_for_permission_check(&check);
    Ok(())
}

pub async fn run_secret(
    key_name: &str,
    config_path: &str,
    identity: &str,
    tool: &str,
) -> Result<()> {
    deny_without_connector_identity()?;
    let config = DevGuardConfig::load(config_path)?;
    let resolved = resolve_or_exit(&config, identity, tool);

    let action = CanonicalAction::SecretAccess {
        key_name: key_name.into(),
        operation: SecretOp::Read,
    };

    let decision = enforce::evaluate(&action, &resolved, &config, "check");
    println!("{}", enforce::format_decision(&decision));
    exit_for_verdict(&decision.verdict);
    Ok(())
}

/// Linked repo (local or GitHub checkout): no issued token → deny even read.
fn deny_without_connector_identity() -> Result<()> {
    if find_connector_link().is_none() {
        return Ok(());
    }
    let token = std::env::var("CONNECTOR_AGENT_TOKEN")
        .or_else(|_| std::env::var("DEVGUARD_TOKEN"))
        .unwrap_or_default();
    if token.trim().starts_with("cg_") {
        return Ok(());
    }
    eprintln!("[DevGuard] DENY — this repo is under Connector.");
    eprintln!("  No Connector agent ID + role. Even read is denied.");
    eprintln!("  Ask the node for an identity: POST /api/v1/devguard/admit");
    eprintln!("  Then: export CONNECTOR_AGENT_TOKEN=cg_…");
    std::process::exit(1);
}

fn online_check_enabled() -> bool {
    if std::env::var("DEVGUARD_ONLINE_CHECK")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off" | "no"))
        .unwrap_or(false)
    {
        return false;
    }
    find_connector_link().is_some()
        || std::env::var("DEVGUARD_ONLINE_CHECK")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
}

fn online_client_and_pid() -> Option<(ConnectorClient, String)> {
    let token = std::env::var("CONNECTOR_AGENT_TOKEN")
        .or_else(|_| std::env::var("DEVGUARD_TOKEN"))
        .ok()?;
    if !token.trim().starts_with("cg_") {
        return None;
    }
    let base = std::env::var("CONNECTOR_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            let raw = std::fs::read_to_string(find_connector_link()?).ok()?;
            let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
            v.get("gateway_base")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "http://127.0.0.1:9091".into());
    let pid = std::env::var("DEVGUARD_AGENT_PID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::fs::read_to_string(".devguard/agent_pid")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "devguard-online".into());
    let mut client = ConnectorClient::new(&base);
    client.set_bearer_token(Some(token));
    Some((client, pid))
}

/// Returns Ok(true) when the kernel answered (caller should stop). Ok(false) = fall back to local YAML.
async fn try_online_file_check(operation: &str, path: &str) -> Result<bool> {
    if !online_check_enabled() {
        return Ok(false);
    }
    let Some((client, pid)) = online_client_and_pid() else {
        if find_connector_link().is_some() {
            eprintln!("[DevGuard] DENY — linked repo requires CONNECTOR_AGENT_TOKEN for online checks");
            std::process::exit(1);
        }
        return Ok(false);
    };
    match client.fs_check(&pid, path, operation).await {
        Ok(v) => {
            let allowed = v
                .get("allowed")
                .or_else(|| v.get("ok"))
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            let verdict = v
                .get("verdict")
                .and_then(|x| x.as_str())
                .unwrap_or(if allowed { "ALLOW" } else { "DENY" });
            let reason = v
                .get("reason")
                .or_else(|| v.get("message"))
                .and_then(|x| x.as_str())
                .unwrap_or(if allowed { "kernel allow" } else { "kernel deny" });
            println!("[{}] {} (kernel)", verdict, reason);
            if allowed {
                std::process::exit(0);
            }
            std::process::exit(1);
        }
        Err(e) => {
            if find_connector_link().is_some() {
                eprintln!("[DevGuard] DENY — linked repo but kernel check failed: {e}");
                std::process::exit(1);
            }
            Ok(false)
        }
    }
}

async fn try_online_exec_check(command: &str) -> Result<bool> {
    if !online_check_enabled() {
        return Ok(false);
    }
    let Some((client, pid)) = online_client_and_pid() else {
        if find_connector_link().is_some() {
            eprintln!("[DevGuard] DENY — linked repo requires CONNECTOR_AGENT_TOKEN for online checks");
            std::process::exit(1);
        }
        return Ok(false);
    };
    match client.exec_check(&pid, command).await {
        Ok(v) => {
            let allowed = v
                .get("allowed")
                .or_else(|| v.get("ok"))
                .and_then(|x| x.as_bool())
                .unwrap_or(false);
            let verdict = v
                .get("verdict")
                .and_then(|x| x.as_str())
                .unwrap_or(if allowed { "ALLOW" } else { "DENY" });
            let reason = v
                .get("reason")
                .or_else(|| v.get("message"))
                .and_then(|x| x.as_str())
                .unwrap_or(if allowed { "kernel allow" } else { "kernel deny" });
            println!("[{}] {} (kernel)", verdict, reason);
            if allowed {
                std::process::exit(0);
            }
            std::process::exit(1);
        }
        Err(e) => {
            if find_connector_link().is_some() {
                eprintln!("[DevGuard] DENY — linked repo but kernel check failed: {e}");
                std::process::exit(1);
            }
            Ok(false)
        }
    }
}

fn find_connector_link() -> Option<std::path::PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    for _ in 0..8 {
        let p = dir.join(".devguard/connector.json");
        if p.is_file() {
            return Some(p);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

fn resolve_or_exit(config: &DevGuardConfig, identity: &str, tool: &str) -> crate::config::ResolvedRole {
    let tool_key = tool.to_lowercase().replace('-', "_");
    let identity_resolved = if identity == "auto" {
        std::env::var("USER").unwrap_or_else(|_| "*".into())
    } else {
        identity.into()
    };

    config.resolve_role(&identity_resolved, &tool_key)
        .or_else(|| {
            if !config.default_role.is_empty() {
                config.resolve_role("*", &tool_key)
            } else {
                None
            }
        })
        .unwrap_or_else(|| {
            eprintln!("No role found for identity '{}' with tool '{}'", identity_resolved, tool);
            std::process::exit(1);
        })
}

fn exit_for_verdict(verdict: &Verdict) {
    match verdict {
        Verdict::Allow => std::process::exit(0),
        Verdict::Deny { .. } => std::process::exit(1),
        Verdict::RequireApproval { .. } => std::process::exit(2),
        Verdict::HoldForReview { .. } => std::process::exit(3),
    }
}

fn exit_for_permission_check(check: &crate::config::PermissionCheck) {
    if check.allowed {
        std::process::exit(0);
    }
    if check.requires_approval {
        std::process::exit(2);
    }
    std::process::exit(1);
}
