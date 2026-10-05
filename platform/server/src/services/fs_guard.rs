//! DevGuard FS Guard — File visibility, write boundary, and role-based
//! file permission controller.
//!
//! Intercepts file operations in the LLM gateway pipeline. Enforces:
//! - Glob-based path visibility (visible/hidden/read_only/metadata_only)
//! - Role-level file permissions (junior cannot touch senior files)
//! - Write boundary enforcement (suggest-only, no-delete, no-rename)
//! - Secret redaction on file content before LLM prompt assembly
//!
//! Production controller. Runs in the hot path of every LLM call.

use crate::services::policy_config::{DevGuardPolicy, PermissionCheck};
use crate::services::secret_broker;
use crate::state::SharedState;
use serde::{Deserialize, Serialize};

// ── Guard result ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct FsGuardResult {
    pub allowed: bool,
    pub verdict: String,
    pub reason: String,
    pub content_modified: bool,
    pub secrets_redacted: usize,
    pub original_length: usize,
    pub sanitized_length: usize,
    #[serde(skip_serializing)]
    pub sanitized_content: String,
}

// ── File content scanning ──────────────────────────────────────────────────

/// Scan a message for file paths and check visibility policy.
/// Returns list of (path, verdict) for audit logging.
pub fn scan_message_for_files(
    content: &str,
    policy: &DevGuardPolicy,
    role: &str,
) -> Vec<(String, PermissionCheck)> {
    let mut results = Vec::new();
    // Detect file paths in common patterns:
    // 1. "File: path/to/file"
    // 2. "```language:path/to/file" or "@path/to/file"
    // 3. Explicit paths like "src/main.rs", "config/database.yaml"

    let path_patterns = [
        regex::Regex::new(r"(?m)^(?:File|file|Path|path):\s*(.+)$").ok(),
        regex::Regex::new(r"```\w*\s*@?([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,5})").ok(),
        regex::Regex::new(
            r"(?:^|\s)([a-zA-Z0-9_.-]+/[a-zA-Z0-9_./-]+\.[a-zA-Z]{1,5})(?:\s|$|:|\n)",
        )
        .ok(),
    ];

    for pat in path_patterns.iter().flatten() {
        for cap in pat.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                let path = m.as_str().trim();
                if !path.is_empty() && path.len() < 256 {
                    let check = policy.check_file(role, "read", path);
                    results.push((path.to_string(), check));
                }
            }
        }
    }
    results
}

/// Filter content by removing hidden file blocks and redacting secrets.
/// This runs on EVERY message before it goes to the LLM.
pub fn guard_content(content: &str, policy: &DevGuardPolicy, role: &str) -> FsGuardResult {
    let original_length = content.len();
    let mut sanitized = content.to_string();
    let mut secrets_redacted = 0;
    let mut content_modified = false;

    // 1. Remove content from hidden files
    // Look for file blocks and check visibility
    let file_checks = scan_message_for_files(content, policy, role);
    for (path, check) in &file_checks {
        if !check.allowed {
            // Remove the file content block from the message
            // Pattern: everything between the file reference and next file/section
            let path_escaped = regex::escape(path);
            if let Ok(re) = regex::Regex::new(&format!(
                r"(?s)(File:\s*{}.*?)(?=File:|```|\z)",
                path_escaped
            )) {
                let replacement = format!("[FILE HIDDEN BY POLICY: {} — {}]", path, check.reason);
                sanitized = re.replace_all(&sanitized, replacement.as_str()).to_string();
                content_modified = true;
            }
        }
    }

    // 2. Redact secrets
    if policy.secrets.detect_and_redact {
        let scan =
            secret_broker::scan_and_redact_with_extras(&sanitized, &policy.secrets.custom_patterns);
        if scan.redacted_count > 0 {
            sanitized = scan.sanitized;
            secrets_redacted = scan.redacted_count;
            content_modified = true;
        }
    }

    let sanitized_length = sanitized.len();
    FsGuardResult {
        allowed: true,
        verdict: "PROCESSED".into(),
        reason: if content_modified {
            format!(
                "Content filtered: {} files hidden, {} secrets redacted",
                file_checks.iter().filter(|(_, c)| !c.allowed).count(),
                secrets_redacted
            )
        } else {
            "Content clean".into()
        },
        content_modified,
        secrets_redacted,
        original_length,
        sanitized_length,
        sanitized_content: sanitized,
    }
}

/// Check if a write operation is allowed, considering role and policy.
pub fn check_write(
    policy: &DevGuardPolicy,
    role: &str,
    path: &str,
    operation: &str,
) -> PermissionCheck {
    policy.check_file(role, operation, path)
}

// ── HTTP endpoints ─────────────────────────────────────────────────────────

use axum::{extract::State, Json};

/// POST /api/v1/devguard/fs/check — Check file permission
pub async fn fs_check(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let operation = req
        .get("operation")
        .and_then(|v| v.as_str())
        .unwrap_or("read");
    let path = req.get("path").and_then(|v| v.as_str()).unwrap_or("");

    let policy_data = super::policy_config::get_active_policy(&state, agent_pid);
    let (policy, role) = match policy_data {
        Some((p, r)) => (p, r),
        None => {
            return Json(serde_json::json!({
                "ok": false, "error": "No policy loaded for agent"
            }))
        }
    };

    let check = policy.check_file(&role, operation, path);
    Json(serde_json::json!({
        "ok": true,
        "path": path,
        "operation": operation,
        "role": role,
        "allowed": check.allowed,
        "verdict": check.verdict,
        "reason": check.reason,
        "requires_approval": check.requires_approval,
    }))
}

/// POST /api/v1/devguard/fs/guard — Run full guard on content
pub async fn fs_guard_content(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let content = req.get("content").and_then(|v| v.as_str()).unwrap_or("");

    let policy_data = super::policy_config::get_active_policy(&state, agent_pid);
    let (policy, role) = match policy_data {
        Some((p, r)) => (p, r),
        None => {
            return Json(serde_json::json!({
                "ok": false, "error": "No policy loaded for agent"
            }))
        }
    };

    let result = guard_content(content, &policy, &role);
    Json(serde_json::json!({
        "ok": true,
        "content_modified": result.content_modified,
        "secrets_redacted": result.secrets_redacted,
        "original_length": result.original_length,
        "sanitized_length": result.sanitized_length,
        "reason": result.reason,
    }))
}
