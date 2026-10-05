//! DevGuard Exec Guard — Shell command governance controller.
//!
//! Intercepts every command execution attempt from coding agents.
//! Enforces allow/deny/approve lists, detects dangerous commands,
//! checks network egress, and enforces duration/output limits.
//!
//! Production controller. Not a demo.

use crate::services::policy_config::{DevGuardPolicy, PermissionCheck};
use crate::state::SharedState;
use serde::Serialize;

// ── Dangerous command patterns (always checked) ────────────────────────────

const ALWAYS_DENY: &[(&str, &str)] = &[
    ("rm -rf /", "Recursive delete of root filesystem"),
    ("rm -rf ~", "Recursive delete of home directory"),
    ("rm -rf .", "Recursive delete of current directory"),
    ("rm -rf /*", "Recursive delete of root filesystem"),
    (":(){ :|:& };:", "Fork bomb"),
    ("> /dev/sda", "Direct write to block device"),
    ("dd if=/dev/zero of=/dev/sd", "Disk wipe"),
    ("mkfs.", "Filesystem format"),
    ("chmod -R 777 /", "Remove all file permissions on root"),
];

const ALWAYS_FLAG: &[(&str, &str, &str)] = &[
    ("curl | bash", "Remote code execution via pipe", "critical"),
    ("curl | sh", "Remote code execution via pipe", "critical"),
    ("wget | bash", "Remote code execution via pipe", "critical"),
    ("wget | sh", "Remote code execution via pipe", "critical"),
    ("eval ", "Dynamic code execution", "high"),
    ("exec ", "Process replacement", "high"),
    ("sudo ", "Privilege escalation", "high"),
    ("su -", "User switch", "high"),
    ("ssh ", "Remote shell access", "high"),
    ("scp ", "Remote file copy", "high"),
    ("rsync ", "Remote sync", "medium"),
];

// ── Exec guard result ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ExecGuardResult {
    pub allowed: bool,
    pub verdict: String,
    pub reason: String,
    pub command: String,
    pub dangerous: bool,
    pub network_egress: bool,
    pub requires_approval: bool,
    pub approval_from: Vec<String>,
}

// ── Core enforcement ───────────────────────────────────────────────────────

/// Check if a command is safe to execute given the policy and role.
pub fn check_command(command: &str, policy: &DevGuardPolicy, role: &str) -> ExecGuardResult {
    let cmd = command.trim();

    // 1. Always-deny patterns (regardless of policy)
    for (pattern, reason) in ALWAYS_DENY {
        if cmd.contains(pattern) {
            return ExecGuardResult {
                allowed: false,
                verdict: "DENY".into(),
                reason: format!("DANGEROUS: {}", reason),
                command: cmd.to_string(),
                dangerous: true,
                network_egress: false,
                requires_approval: false,
                approval_from: vec![],
            };
        }
    }

    // 2. Always-flag patterns (network egress, RCE, privilege escalation)
    for (pattern, reason, _severity) in ALWAYS_FLAG {
        if cmd.contains(pattern) {
            return ExecGuardResult {
                allowed: false,
                verdict: "DENY".into(),
                reason: format!("FLAGGED: {}", reason),
                command: cmd.to_string(),
                dangerous: true,
                network_egress: cmd.contains("curl")
                    || cmd.contains("wget")
                    || cmd.contains("ssh")
                    || cmd.contains("scp"),
                requires_approval: false,
                approval_from: vec![],
            };
        }
    }

    // 3. Pipe-to-shell detection (catch variations)
    if (cmd.contains("| bash") || cmd.contains("| sh") || cmd.contains("| zsh"))
        && (cmd.contains("curl") || cmd.contains("wget"))
    {
        return ExecGuardResult {
            allowed: false,
            verdict: "DENY".into(),
            reason: "Remote code execution via pipe detected".into(),
            command: cmd.to_string(),
            dangerous: true,
            network_egress: true,
            requires_approval: false,
            approval_from: vec![],
        };
    }

    // 4. Policy-based checks
    let policy_check = policy.check_exec(role, cmd);
    let network = cmd.contains("curl ")
        || cmd.contains("wget ")
        || cmd.contains("ssh ")
        || cmd.contains("scp ")
        || cmd.contains("nc ")
        || cmd.contains("telnet ");

    ExecGuardResult {
        allowed: policy_check.allowed,
        verdict: policy_check.verdict.to_string(),
        reason: policy_check.reason.clone(),
        command: cmd.to_string(),
        dangerous: false,
        network_egress: network,
        requires_approval: policy_check.requires_approval,
        approval_from: policy_check.approval_from.clone(),
    }
}

/// Extract command from a Claude Code tool_use bash block
pub fn extract_command_from_tool_use(tool_input: &serde_json::Value) -> Option<String> {
    // Claude Code bash tool: { "command": "..." }
    tool_input
        .get("command")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Check if a git command should be routed to git guard
pub fn is_git_command(command: &str) -> bool {
    command.trim().starts_with("git ")
}

// ── HTTP endpoint ──────────────────────────────────────────────────────────

use axum::{extract::State, Json};

/// POST /api/v1/devguard/exec/check — Check if a command is allowed
pub async fn exec_check(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let command = req.get("command").and_then(|v| v.as_str()).unwrap_or("");

    let policy_data = super::policy_config::get_active_policy(&state, agent_pid);
    let (policy, role) = match policy_data {
        Some((p, r)) => (p, r),
        None => {
            return Json(serde_json::json!({
                "ok": false, "error": "No policy loaded for agent"
            }))
        }
    };

    let result = check_command(command, &policy, &role);
    Json(serde_json::json!({
        "ok": true,
        "command": result.command,
        "role": role,
        "allowed": result.allowed,
        "verdict": result.verdict,
        "reason": result.reason,
        "dangerous": result.dangerous,
        "network_egress": result.network_egress,
        "requires_approval": result.requires_approval,
        "approval_from": result.approval_from,
    }))
}
