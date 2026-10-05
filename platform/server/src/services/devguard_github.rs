//! DevGuard GitHub merge-gate surface.
//!
//! Honest status today: Connector can evaluate a claimed repository head SHA
//! against the bound DevGuard policy and store a check-run shaped result.
//! Publishing to GitHub Checks API requires a GitHub App (`checks:write`),
//! which is not installed yet — that capability is reported as unavailable.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::SharedState;

const CHECKS_NS: &str = "devguard_github_checks";

fn tenant_id(headers: &HeaderMap) -> String {
    crate::services::devguard::tenant_id_from_headers(headers)
}

fn sha_looks_valid(head_sha: &str) -> bool {
    let t = head_sha.trim();
    (t.len() == 40 || t.len() == 64)
        && t.chars()
            .all(|c| c.is_ascii_hexdigit())
}

/// GET /api/v1/devguard/github/status — capability honesty for GitHub App + checks.
pub async fn github_status(State(state): State<SharedState>) -> Json<Value> {
    let app_id = std::env::var("CONNECTOR_GITHUB_APP_ID")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let app_private_key = std::env::var("CONNECTOR_GITHUB_APP_PRIVATE_KEY_PATH")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let app_configured = app_id.is_some() && app_private_key.is_some();
    let stored = {
        let es = state.engine_store.lock().unwrap();
        es.folder_keys(CHECKS_NS, None)
            .map(|k| k.len())
            .unwrap_or(0)
    };
    Json(json!({
        "ok": true,
        "github_app": {
            "configured": app_configured,
            "installed": false,
            "app_id_present": app_id.is_some(),
            "private_key_path_present": app_private_key.is_some(),
            "capabilities": {
                "repository_discovery": false,
                "clone_credentials": false,
                "check_runs_publish": false,
                "ruleset_setup": false,
            },
            "honesty": "No GitHub App installation is wired yet. Local exact-head evaluation is available; publishing required checks to GitHub is not."
        },
        "local_check_evaluate": {
            "endpoint": "POST /api/v1/devguard/github/checks/evaluate",
            "stores_results": true,
            "stored_count": stored,
        }
    }))
}

/// POST /api/v1/devguard/github/checks/evaluate
///
/// Body: { "repo_id", "head_sha", "agent_pid"?, "base_sha"?, "diff_digest"? }
/// Evaluates the bound policy for the agent/repo against the claimed head SHA
/// and stores a check-run shaped result. Does not call GitHub.
pub async fn evaluate_check(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> Json<Value> {
    let tenant = tenant_id(&headers);
    let repo_id = req
        .get("repo_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let head_sha = req
        .get("head_sha")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let agent_pid = req
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let base_sha = req
        .get("base_sha")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let diff_digest = req
        .get("diff_digest")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if repo_id.is_empty() {
        return Json(json!({
            "ok": false,
            "error": "repo_id_required",
            "message": "Provide the DevGuard repo_id bound on this node.",
        }));
    }
    if !sha_looks_valid(&head_sha) {
        return Json(json!({
            "ok": false,
            "error": "head_sha_invalid",
            "message": "head_sha must be a 40- or 64-char hex commit digest.",
        }));
    }

    let repo_key = format!("{tenant}/{repo_id}");
    let repo = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("devguard_repos", &repo_key).ok().flatten()
    };
    let Some(repo) = repo else {
        return Json(json!({
            "ok": false,
            "error": "repo_not_found",
            "repo_id": repo_id,
            "message": "Bind the repo with POST /api/v1/devguard/connect first.",
        }));
    };

    let agent_pid = if agent_pid.is_empty() {
        repo.get("agents")
            .and_then(|a| a.as_array())
            .and_then(|arr| arr.last())
            .and_then(|a| a.get("agent_pid"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    } else {
        agent_pid
    };

    let policy = if agent_pid.is_empty() {
        None
    } else {
        crate::services::policy_config::get_active_policy(&state, &agent_pid)
    };

    let (conclusion, title, summary) = match &policy {
        Some((_pol, role)) => (
            "success",
            "DevGuard policy present for head SHA",
            format!(
                "Local evaluation only. Agent {agent_pid} has an active DevGuard policy (role={role}) for repo {repo_id} at {head_sha}. GitHub Check Run publish is unavailable until a GitHub App with checks:write is installed."
            ),
        ),
        None => (
            "failure",
            "No DevGuard policy for head SHA",
            format!(
                "Local evaluation only. No active policy for agent_pid on repo {repo_id} at {head_sha}. Attach an agent (POST /api/v1/devguard/repos/{repo_id}/agents) before treating this SHA as governed."
            ),
        ),
    };

    let check_id = format!(
        "dgchk_{}",
        &format!("{:x}", Sha256::digest(format!("{tenant}:{repo_id}:{head_sha}:{agent_pid}").as_bytes()))
            [..16]
    );
    let now = chrono::Utc::now().to_rfc3339();
    let check = json!({
        "ok": true,
        "name": "DevGuard / policy",
        "check_id": check_id,
        "repo_id": repo_id,
        "tenant_id": tenant,
        "head_sha": head_sha,
        "base_sha": base_sha,
        "diff_digest": diff_digest,
        "agent_pid": if agent_pid.is_empty() { Value::Null } else { json!(agent_pid) },
        "conclusion": conclusion,
        "status": "completed",
        "title": title,
        "summary": summary,
        "github_check_run": {
            "published": false,
            "reason": "github_app_not_installed",
            "required_permission": "checks:write",
        },
        "evaluated_at": now,
        "honesty": "This is a Connector-local exact-head evaluation receipt. It is not a GitHub required status until the App publishes it.",
    });

    {
        let mut es = state.engine_store.lock().unwrap();
        let key = format!("{tenant}/{repo_id}/{head_sha}");
        let _ = es.folder_put(CHECKS_NS, &key, &check);
    }

    Json(check)
}

/// GET /api/v1/devguard/github/checks/:repo_id/:head_sha
pub async fn get_check(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((repo_id, head_sha)): Path<(String, String)>,
) -> Json<Value> {
    let tenant = tenant_id(&headers);
    let key = format!("{tenant}/{repo_id}/{head_sha}");
    let es = state.engine_store.lock().unwrap();
    match es.folder_get(CHECKS_NS, &key).ok().flatten() {
        Some(v) => Json(v),
        None => Json(json!({
            "ok": false,
            "error": "check_not_found",
            "repo_id": repo_id,
            "head_sha": head_sha,
            "hint": "POST /api/v1/devguard/github/checks/evaluate",
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_git_sha_shapes() {
        assert!(sha_looks_valid("0123456789abcdef0123456789abcdef01234567"));
        assert!(!sha_looks_valid("main"));
        assert!(!sha_looks_valid("xyz"));
    }
}
