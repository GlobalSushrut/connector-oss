//! Agent-only workspace: the node holds the tree. Agents never get a raw path.
//!
//! File and git APIs are gated by Connector identity + role. No `cg_` token →
//! even read is denied. Push stays on this node until a GitHub App exists.

use std::collections::BTreeMap;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;

use crate::services::devguard::{admit_token, AdmittedIdentity};
use crate::services::policy_config::{self, PermissionCheck};
use crate::state::SharedState;

const TREE_NS: &str = "devguard_trees";
const GIT_NS: &str = "devguard_git";
const MAX_FILE_BYTES: usize = 1_000_000;
const MAX_FILES: usize = 500;

#[derive(Debug, Deserialize)]
pub struct FileQuery {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct FileBody {
    pub path: String,
    #[serde(default)]
    pub content: String,
}

#[derive(Debug, Clone, Default)]
pub struct WorkspaceGit {
    pub branch: String,
    pub commits: Vec<WorkspaceCommit>,
    pub pushed_head: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WorkspaceCommit {
    pub id: String,
    pub message: String,
    pub files: BTreeMap<String, String>,
}

pub fn normalize_workspace_path(path: &str) -> Result<String, &'static str> {
    let t = path.trim().trim_start_matches('/').replace('\\', "/");
    if t.is_empty() {
        return Err("path_required");
    }
    if t.contains('\0') || t.split('/').any(|p| p == ".." || p == ".") {
        return Err("path_rejected");
    }
    if t.len() > 512 {
        return Err("path_too_long");
    }
    Ok(t)
}

/// No identity / wrong repo / role deny → even read is denied.
pub fn workspace_file_gate(
    identity: Option<&AdmittedIdentity>,
    want_repo: &str,
    check: &PermissionCheck,
) -> Result<(), &'static str> {
    let Some(id) = identity else {
        return Err("ask_connector_for_identity");
    };
    if !id.repo_id.is_empty() && id.repo_id != want_repo {
        return Err("not_admitted_to_repo");
    }
    if !check.allowed {
        return Err("role_denied");
    }
    Ok(())
}

pub fn workspace_api_block(base: &str, repo_id: &str) -> serde_json::Value {
    let root = format!("{base}/api/v1/devguard/repos/{repo_id}");
    serde_json::json!({
        "repo_url": root,
        "tree": format!("{root}/tree"),
        "file": format!("{root}/file?path="),
        "git": format!("{root}/git"),
        "header": "X-Connector-Repo",
        "note": "This node holds the tree. Open the cage address with a cg_ token. Do not open a raw clone. A raw clone is not this repo.",
    })
}

pub fn seed_workspace_tree(state: &SharedState, tenant: &str, repo_id: &str, origin_kind: &str) {
    let prefix = format!("{tenant}/{repo_id}/");
    {
        let es = state.engine_store.lock().unwrap();
        let keys = es.folder_keys(TREE_NS, None).unwrap_or_default();
        if keys.iter().any(|k| k.starts_with(&prefix)) {
            return;
        }
    }
    let files = default_seed_files(repo_id, origin_kind);
    let mut es = state.engine_store.lock().unwrap();
    for (path, content) in &files {
        let _ = es.folder_put(
            TREE_NS,
            &format!("{prefix}{path}"),
            &serde_json::json!({
                "path": path,
                "content": content,
                "updated_at": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }
    let _ = es.folder_put(
        GIT_NS,
        &format!("{tenant}/{repo_id}"),
        &serde_json::json!({
            "branch": "main",
            "commits": [],
            "pushed_head": null,
        }),
    );
}

fn default_seed_files(repo_id: &str, origin_kind: &str) -> Vec<(String, String)> {
    let identity = "This checkout is a Connector workspace.\n\
No Connector agent ID + role → even read is denied.\n\
Ask the node: POST /api/v1/devguard/admit\n\
Do not open a raw clone. A raw clone is not this repo.\n"
        .to_string();
    let readme = if origin_kind == "generated" {
        format!("# {repo_id}\n\nThis tree lives on the Connector node. Agents use the workspace file/git APIs with a cg_ token. A raw clone is not this repo.\n")
    } else {
        format!("# {repo_id}\n\nBound on this node. The working copy is the workspace API, not a laptop folder and not a GitHub clone.\n")
    };
    vec![
        ("README.md".into(), readme),
        (".devguard/IDENTITY".into(), identity),
        (
            "devguard.yaml".into(),
            format!("# Policy is compiled on the node per agent role.\nworkspace: {repo_id}\n"),
        ),
    ]
}

fn tree_key(tenant: &str, repo_id: &str, path: &str) -> String {
    format!("{tenant}/{repo_id}/{path}")
}

fn git_key(tenant: &str, repo_id: &str) -> String {
    format!("{tenant}/{repo_id}")
}

fn extract_api_key(headers: &HeaderMap) -> String {
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").trim().to_string())
        .or_else(|| {
            headers
                .get("x-api-key")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_default()
}

fn deny(code: &str, extra: serde_json::Value) -> Json<serde_json::Value> {
    let message = match code {
        "ask_connector_for_identity" => {
            "This repo is a Connector workspace. Ask the node for an agent ID and role. Even read is denied."
        }
        "unknown_identity" => "That token is not a Connector agent identity on this node.",
        "not_admitted_to_repo" => "This identity is not admitted to that repo.",
        "role_denied" => "This role cannot perform that file or git action.",
        "path_required" | "path_rejected" | "path_too_long" => "Path is not allowed.",
        "file_too_large" => "File exceeds the workspace size cap.",
        "tree_full" => "Workspace file cap reached.",
        "file_not_found" => "File not in this workspace.",
        "commit_message_required" => "Commit needs a message.",
        "nothing_to_commit" => "Working tree matches HEAD.",
        other => other,
    };
    let mut body = serde_json::json!({
        "ok": false,
        "admitted": false,
        "error": code,
        "verdict": "DENY",
        "message": message,
        "ask": "POST /api/v1/devguard/admit",
    });
    if let Some(obj) = extra.as_object() {
        if let Some(dst) = body.as_object_mut() {
            for (k, v) in obj {
                dst.insert(k.clone(), v.clone());
            }
        }
    }
    Json(body)
}

fn admit_for_repo(
    state: &SharedState,
    headers: &HeaderMap,
    repo_id: &str,
) -> Result<AdmittedIdentity, Json<serde_json::Value>> {
    match admit_token(state, &extract_api_key(headers), Some(repo_id)) {
        Ok(id) => Ok(id),
        Err(code) => Err(deny(code, serde_json::json!({}))),
    }
}

fn resolve_tenant(headers: &HeaderMap, id: &AdmittedIdentity) -> String {
    if !id.tenant_id.is_empty() {
        return id.tenant_id.clone();
    }
    crate::services::devguard::tenant_id_from_headers(headers)
}

fn load_working_tree(state: &SharedState, tenant: &str, repo_id: &str) -> BTreeMap<String, String> {
    let prefix = format!("{tenant}/{repo_id}/");
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(TREE_NS, None).unwrap_or_default();
    let mut out = BTreeMap::new();
    for k in keys {
        if !k.starts_with(&prefix) {
            continue;
        }
        let path = k[prefix.len()..].to_string();
        if let Ok(Some(v)) = es.folder_get(TREE_NS, &k) {
            if let Some(c) = v.get("content").and_then(|x| x.as_str()) {
                out.insert(path, c.to_string());
            }
        }
    }
    out
}

fn load_git(state: &SharedState, tenant: &str, repo_id: &str) -> WorkspaceGit {
    let es = state.engine_store.lock().unwrap();
    let Some(v) = es
        .folder_get(GIT_NS, &git_key(tenant, repo_id))
        .ok()
        .flatten()
    else {
        return WorkspaceGit {
            branch: "main".into(),
            commits: vec![],
            pushed_head: None,
        };
    };
    parse_git(&v)
}

fn parse_git(v: &serde_json::Value) -> WorkspaceGit {
    let branch = v
        .get("branch")
        .and_then(|x| x.as_str())
        .unwrap_or("main")
        .to_string();
    let pushed_head = v
        .get("pushed_head")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    let commits = v
        .get("commits")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    let id = c.get("id").and_then(|x| x.as_str())?.to_string();
                    let message = c
                        .get("message")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    let mut files = BTreeMap::new();
                    if let Some(map) = c.get("files").and_then(|x| x.as_object()) {
                        for (k, val) in map {
                            if let Some(s) = val.as_str() {
                                files.insert(k.clone(), s.to_string());
                            }
                        }
                    }
                    Some(WorkspaceCommit { id, message, files })
                })
                .collect()
        })
        .unwrap_or_default();
    WorkspaceGit {
        branch,
        commits,
        pushed_head,
    }
}

fn save_git(state: &SharedState, tenant: &str, repo_id: &str, git: &WorkspaceGit) {
    let commits: Vec<serde_json::Value> = git
        .commits
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "message": c.message,
                "files": c.files,
            })
        })
        .collect();
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        GIT_NS,
        &git_key(tenant, repo_id),
        &serde_json::json!({
            "branch": git.branch,
            "commits": commits,
            "pushed_head": git.pushed_head,
        }),
    );
}

pub fn git_status(working: &BTreeMap<String, String>, git: &WorkspaceGit) -> serde_json::Value {
    let head = git.commits.last().map(|c| &c.files);
    let mut changed = Vec::new();
    let mut added = Vec::new();
    let mut deleted = Vec::new();
    match head {
        None => {
            added.extend(working.keys().cloned());
        }
        Some(h) => {
            for (p, c) in working {
                match h.get(p) {
                    None => added.push(p.clone()),
                    Some(old) if old != c => changed.push(p.clone()),
                    _ => {}
                }
            }
            for p in h.keys() {
                if !working.contains_key(p) {
                    deleted.push(p.clone());
                }
            }
        }
    }
    let head_id = git.commits.last().map(|c| c.id.clone());
    let ahead = match (&head_id, &git.pushed_head) {
        (Some(h), Some(p)) => h != p,
        (Some(_), None) => true,
        _ => false,
    };
    serde_json::json!({
        "branch": git.branch,
        "head": head_id,
        "pushed_head": git.pushed_head,
        "ahead": ahead,
        "added": added,
        "changed": changed,
        "deleted": deleted,
        "clean": added.is_empty() && changed.is_empty() && deleted.is_empty(),
    })
}

pub fn git_diff_text(working: &BTreeMap<String, String>, git: &WorkspaceGit) -> String {
    let head = git.commits.last().map(|c| &c.files);
    let mut out = String::new();
    let empty = BTreeMap::new();
    let h = head.unwrap_or(&empty);
    let mut paths: Vec<String> = working.keys().chain(h.keys()).cloned().collect();
    paths.sort();
    paths.dedup();
    for p in paths {
        let a = h.get(&p).map(String::as_str).unwrap_or("");
        let b = working.get(&p).map(String::as_str).unwrap_or("");
        if a == b {
            continue;
        }
        out.push_str(&format!("--- a/{p}\n+++ b/{p}\n"));
        if a.is_empty() {
            out.push_str(&format!("+{b}\n"));
        } else if b.is_empty() {
            out.push_str(&format!("-{a}\n"));
        } else {
            out.push_str(&format!("-{a}\n+{b}\n"));
        }
    }
    out
}

pub fn git_commit_working(
    working: &BTreeMap<String, String>,
    git: &mut WorkspaceGit,
    message: &str,
) -> Result<String, &'static str> {
    let msg = message.trim();
    if msg.is_empty() {
        return Err("commit_message_required");
    }
    let status = git_status(working, git);
    if status.get("clean").and_then(|v| v.as_bool()) == Some(true) {
        return Err("nothing_to_commit");
    }
    let id = format!(
        "wc_{}",
        &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]
    );
    git.commits.push(WorkspaceCommit {
        id: id.clone(),
        message: msg.to_string(),
        files: working.clone(),
    });
    Ok(id)
}

pub fn git_push_on_node(git: &mut WorkspaceGit) -> Result<String, &'static str> {
    let Some(head) = git.commits.last().map(|c| c.id.clone()) else {
        return Err("nothing_to_commit");
    };
    git.pushed_head = Some(head.clone());
    Ok(head)
}

fn check_role_file(
    state: &SharedState,
    agent_pid: &str,
    role: &str,
    op: &str,
    path: &str,
) -> PermissionCheck {
    match policy_config::get_active_policy(state, agent_pid) {
        Some((policy, stored_role)) => {
            let r = if stored_role.is_empty() {
                role
            } else {
                stored_role.as_str()
            };
            policy.check_file(r, op, path)
        }
        None => PermissionCheck::deny("No policy loaded — deny by default"),
    }
}

fn check_role_git(
    state: &SharedState,
    agent_pid: &str,
    role: &str,
    branch: &str,
    op: &str,
) -> PermissionCheck {
    match policy_config::get_active_policy(state, agent_pid) {
        Some((policy, stored_role)) => {
            let r = if stored_role.is_empty() {
                role
            } else {
                stored_role.as_str()
            };
            policy.check_git(r, branch, op)
        }
        None => PermissionCheck::deny("No policy loaded — deny by default"),
    }
}

/// GET /api/v1/devguard/repos/:repo_id/tree
pub async fn list_tree(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(repo_id): Path<String>,
) -> Json<serde_json::Value> {
    let id = match admit_for_repo(&state, &headers, &repo_id) {
        Ok(id) => id,
        Err(j) => return j,
    };
    let tenant = resolve_tenant(&headers, &id);
    let working = load_working_tree(&state, &tenant, &repo_id);
    let mut files = Vec::new();
    for path in working.keys() {
        let check = check_role_file(&state, &id.agent_pid, &id.role, "read", path);
        if workspace_file_gate(Some(&id), &repo_id, &check).is_ok() {
            files.push(path.clone());
        }
    }
    Json(serde_json::json!({
        "ok": true,
        "repo_id": repo_id,
        "files": files,
        "count": files.len(),
        "workspace": true,
        "note": "This node holds the tree. A raw clone is not this repo.",
    }))
}

/// GET /api/v1/devguard/repos/:repo_id/file?path=
pub async fn get_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(repo_id): Path<String>,
    Query(q): Query<FileQuery>,
) -> Json<serde_json::Value> {
    let id = match admit_for_repo(&state, &headers, &repo_id) {
        Ok(id) => id,
        Err(j) => return j,
    };
    let path = match normalize_workspace_path(&q.path) {
        Ok(p) => p,
        Err(code) => return deny(code, serde_json::json!({})),
    };
    let check = check_role_file(&state, &id.agent_pid, &id.role, "read", &path);
    if let Err(code) = workspace_file_gate(Some(&id), &repo_id, &check) {
        return deny(
            code,
            serde_json::json!({ "path": path, "reason": check.reason }),
        );
    }
    let tenant = resolve_tenant(&headers, &id);
    let es = state.engine_store.lock().unwrap();
    match es
        .folder_get(TREE_NS, &tree_key(&tenant, &repo_id, &path))
        .ok()
        .flatten()
    {
        Some(v) => Json(serde_json::json!({
            "ok": true,
            "repo_id": repo_id,
            "path": path,
            "content": v.get("content").and_then(|c| c.as_str()).unwrap_or(""),
            "workspace": true,
        })),
        None => deny("file_not_found", serde_json::json!({ "path": path })),
    }
}

/// PUT /api/v1/devguard/repos/:repo_id/file
pub async fn put_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(repo_id): Path<String>,
    Json(body): Json<FileBody>,
) -> Json<serde_json::Value> {
    let id = match admit_for_repo(&state, &headers, &repo_id) {
        Ok(id) => id,
        Err(j) => return j,
    };
    let path = match normalize_workspace_path(&body.path) {
        Ok(p) => p,
        Err(code) => return deny(code, serde_json::json!({})),
    };
    if body.content.len() > MAX_FILE_BYTES {
        return deny("file_too_large", serde_json::json!({ "path": path }));
    }
    let check = check_role_file(&state, &id.agent_pid, &id.role, "write", &path);
    if let Err(code) = workspace_file_gate(Some(&id), &repo_id, &check) {
        return deny(
            code,
            serde_json::json!({ "path": path, "reason": check.reason }),
        );
    }
    let tenant = resolve_tenant(&headers, &id);
    {
        let working = load_working_tree(&state, &tenant, &repo_id);
        if !working.contains_key(&path) && working.len() >= MAX_FILES {
            return deny("tree_full", serde_json::json!({}));
        }
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &id.agent_pid,
        "workspace",
        "save_workspace_file",
        &serde_json::json!({"repo_id": repo_id.as_str(), "path": path.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        TREE_NS,
        &tree_key(&tenant, &repo_id, &path),
        &serde_json::json!({
            "path": path,
            "content": body.content,
            "updated_at": chrono::Utc::now().to_rfc3339(),
            "agent_pid": id.agent_pid,
        }),
    );
    drop(es);
    open_proceed.finish_observed(true);
    Json(serde_json::json!({
        "ok": true,
        "repo_id": repo_id,
        "path": path,
        "workspace": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// DELETE /api/v1/devguard/repos/:repo_id/file?path=
pub async fn delete_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(repo_id): Path<String>,
    Query(q): Query<FileQuery>,
) -> Json<serde_json::Value> {
    let id = match admit_for_repo(&state, &headers, &repo_id) {
        Ok(id) => id,
        Err(j) => return j,
    };
    let path = match normalize_workspace_path(&q.path) {
        Ok(p) => p,
        Err(code) => return deny(code, serde_json::json!({})),
    };
    let check = check_role_file(&state, &id.agent_pid, &id.role, "delete", &path);
    if let Err(code) = workspace_file_gate(Some(&id), &repo_id, &check) {
        return deny(
            code,
            serde_json::json!({ "path": path, "reason": check.reason }),
        );
    }
    let tenant = resolve_tenant(&headers, &id);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &id.agent_pid,
        "workspace",
        "remove_workspace_file",
        &serde_json::json!({"repo_id": repo_id.as_str(), "path": path.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_delete(TREE_NS, &tree_key(&tenant, &repo_id, &path));
    drop(es);
    open_proceed.finish_observed(true);
    Json(serde_json::json!({
        "ok": true,
        "repo_id": repo_id,
        "path": path,
        "deleted": true,
        "workspace": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// POST /api/v1/devguard/repos/:repo_id/git/:op
pub async fn git_op(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((repo_id, op)): Path<(String, String)>,
    body: Option<Json<serde_json::Value>>,
) -> Json<serde_json::Value> {
    let id = match admit_for_repo(&state, &headers, &repo_id) {
        Ok(id) => id,
        Err(j) => return j,
    };
    let tenant = resolve_tenant(&headers, &id);
    let working = load_working_tree(&state, &tenant, &repo_id);
    let mut git = load_git(&state, &tenant, &repo_id);
    let check = check_role_git(&state, &id.agent_pid, &id.role, &git.branch, &op);
    if let Err(code) = workspace_file_gate(Some(&id), &repo_id, &check) {
        return deny(
            code,
            serde_json::json!({ "reason": check.reason, "op": op }),
        );
    }
    match op.as_str() {
        "status" => Json(serde_json::json!({
            "ok": true,
            "repo_id": repo_id,
            "git": git_status(&working, &git),
            "workspace": true,
        })),
        "diff" => Json(serde_json::json!({
            "ok": true,
            "repo_id": repo_id,
            "diff": git_diff_text(&working, &git),
            "workspace": true,
        })),
        "commit" => {
            let message = body
                .as_ref()
                .and_then(|b| b.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let admitted = match crate::substrate::pate::require_proceed(
                &state,
                &id.agent_pid,
                "workspace",
                "git_commit",
                &serde_json::json!({"repo_id": repo_id.as_str()}),
            ) {
                Ok(atu) => atu,
                Err(body) => return Json(body),
            };
            let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
            match git_commit_working(&working, &mut git, &message) {
                Ok(cid) => {
                    save_git(&state, &tenant, &repo_id, &git);
                    open_proceed.finish_observed(true);
                    Json(serde_json::json!({
                        "ok": true,
                        "repo_id": repo_id,
                        "commit": cid,
                        "message": message,
                        "workspace": true,
                        "task_id": admitted.task_id,
                        "executed": true,
                        "admits": false,
                    }))
                }
                Err(code) => {
                    open_proceed.finish_observed(false);
                    deny(
                        code,
                        serde_json::json!({
                            "task_id": admitted.task_id,
                            "executed": false,
                            "admits": false,
                        }),
                    )
                }
            }
        }
        "push" => {
            let admitted = match crate::substrate::pate::require_proceed(
                &state,
                &id.agent_pid,
                "workspace",
                "git_push",
                &serde_json::json!({"repo_id": repo_id.as_str()}),
            ) {
                Ok(atu) => atu,
                Err(body) => return Json(body),
            };
            let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
            match git_push_on_node(&mut git) {
            Ok(head) => {
                save_git(&state, &tenant, &repo_id, &git);
                open_proceed.finish_observed(true);
                Json(serde_json::json!({
                    "ok": true,
                    "repo_id": repo_id,
                    "pushed_head": head,
                    "remote": "connector-node",
                    "github": "export_only",
                    "note": "Push stays on this node until a GitHub App is installed. The agent has no GitHub token.",
                    "workspace": true,
                    "task_id": admitted.task_id,
                    "executed": true,
                    "admits": false,
                }))
            }
            Err(code) => {
                open_proceed.finish_observed(false);
                deny(
                    code,
                    serde_json::json!({
                        "task_id": admitted.task_id,
                        "executed": false,
                        "admits": false,
                    }),
                )
            }
            }
        }
        _ => deny("unknown_git_op", serde_json::json!({ "op": op })),
    }
}

/// Bound agent → workspace, not a host path. Used by MCP file/exec tools.
pub fn repo_binding_for_agent(state: &SharedState, agent_pid: &str) -> Option<(String, String)> {
    let es = state.engine_store.lock().unwrap();
    let pol = es
        .folder_get("devguard_policies", agent_pid)
        .ok()
        .flatten()?;
    let repo_id = pol
        .get("repo_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())?;
    let tenant = pol
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            let keys = es.folder_keys("devguard_repos", None).ok()?;
            keys.into_iter()
                .find(|k| k.ends_with(&format!("/{repo_id}")))
                .and_then(|k| k.split_once('/').map(|(t, _)| t.to_string()))
        })?;
    Some((tenant, repo_id.to_string()))
}

pub fn mcp_workspace_read(
    state: &SharedState,
    tenant: &str,
    repo_id: &str,
    path: &str,
) -> Result<serde_json::Value, serde_json::Value> {
    let path = normalize_workspace_path(path).map_err(
        |code| serde_json::json!({ "error": code, "verdict": "DENY", "workspace": true }),
    )?;
    let es = state.engine_store.lock().unwrap();
    match es
        .folder_get(TREE_NS, &tree_key(tenant, repo_id, &path))
        .ok()
        .flatten()
    {
        Some(v) => Ok(serde_json::json!({
            "ok": true,
            "path": path,
            "content": v.get("content").and_then(|c| c.as_str()).unwrap_or(""),
            "workspace": true,
            "repo_id": repo_id,
        })),
        None => Err(serde_json::json!({
            "error": "file_not_found",
            "path": path,
            "verdict": "DENY",
            "workspace": true,
        })),
    }
}

pub fn mcp_workspace_write(
    state: &SharedState,
    tenant: &str,
    repo_id: &str,
    path: &str,
    content: &str,
    agent_pid: &str,
) -> Result<serde_json::Value, serde_json::Value> {
    let path = normalize_workspace_path(path).map_err(
        |code| serde_json::json!({ "error": code, "verdict": "DENY", "workspace": true }),
    )?;
    if content.len() > MAX_FILE_BYTES {
        return Err(
            serde_json::json!({ "error": "file_too_large", "verdict": "DENY", "workspace": true }),
        );
    }
    let working = load_working_tree(state, tenant, repo_id);
    if !working.contains_key(&path) && working.len() >= MAX_FILES {
        return Err(
            serde_json::json!({ "error": "tree_full", "verdict": "DENY", "workspace": true }),
        );
    }
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        TREE_NS,
        &tree_key(tenant, repo_id, &path),
        &serde_json::json!({
            "path": path,
            "content": content,
            "updated_at": chrono::Utc::now().to_rfc3339(),
            "agent_pid": agent_pid,
        }),
    );
    Ok(serde_json::json!({
        "ok": true,
        "path": path,
        "workspace": true,
        "repo_id": repo_id,
    }))
}

/// Map bash/git to the workspace. Host paths are not this repo.
pub fn mcp_workspace_exec(
    state: &SharedState,
    tenant: &str,
    repo_id: &str,
    command: &str,
) -> Result<serde_json::Value, serde_json::Value> {
    let cmd = command.trim();
    let working = load_working_tree(state, tenant, repo_id);
    let mut git = load_git(state, tenant, repo_id);
    if cmd == "git status" || cmd.starts_with("git status ") {
        return Ok(serde_json::json!({
            "ok": true,
            "git": git_status(&working, &git),
            "workspace": true,
            "repo_id": repo_id,
        }));
    }
    if cmd == "git diff" || cmd.starts_with("git diff ") {
        return Ok(serde_json::json!({
            "ok": true,
            "diff": git_diff_text(&working, &git),
            "workspace": true,
            "repo_id": repo_id,
        }));
    }
    if cmd.starts_with("git commit") {
        let message = commit_message_from_cmd(cmd).unwrap_or_default();
        return match git_commit_working(&working, &mut git, &message) {
            Ok(cid) => {
                save_git(state, tenant, repo_id, &git);
                Ok(serde_json::json!({
                    "ok": true,
                    "commit": cid,
                    "workspace": true,
                    "repo_id": repo_id,
                }))
            }
            Err(code) => {
                Err(serde_json::json!({ "error": code, "verdict": "DENY", "workspace": true }))
            }
        };
    }
    if cmd == "git push" || cmd.starts_with("git push ") {
        return match git_push_on_node(&mut git) {
            Ok(head) => {
                save_git(state, tenant, repo_id, &git);
                Ok(serde_json::json!({
                    "ok": true,
                    "pushed_head": head,
                    "remote": "connector-node",
                    "github": "export_only",
                    "workspace": true,
                    "repo_id": repo_id,
                }))
            }
            Err(code) => {
                Err(serde_json::json!({ "error": code, "verdict": "DENY", "workspace": true }))
            }
        };
    }
    if cmd == "ls" || cmd == "ls -la" || cmd.starts_with("ls ") {
        return Ok(serde_json::json!({
            "ok": true,
            "files": working.keys().cloned().collect::<Vec<_>>(),
            "workspace": true,
            "repo_id": repo_id,
        }));
    }
    if let Some(path) = cmd.strip_prefix("cat ") {
        return mcp_workspace_read(state, tenant, repo_id, path.trim());
    }
    Err(serde_json::json!({
        "error": "host_exec_denied",
        "verdict": "DENY",
        "message": "This repo is a Connector workspace. Host paths and raw shell are not the repo. Use workspace file/git APIs.",
        "workspace": true,
        "repo_id": repo_id,
        "command": cmd,
    }))
}

fn commit_message_from_cmd(cmd: &str) -> Option<String> {
    if let Some(rest) = cmd.split_once(" -m ").map(|(_, r)| r) {
        let t = rest.trim().trim_matches('\'').trim_matches('"');
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_and_empty_paths() {
        assert!(normalize_workspace_path("../secret").is_err());
        assert!(normalize_workspace_path("").is_err());
        assert!(normalize_workspace_path("src/../x").is_err());
        assert_eq!(
            normalize_workspace_path("/src/lib.rs").unwrap(),
            "src/lib.rs"
        );
    }

    #[test]
    fn no_identity_cannot_read_workspace() {
        let allow = PermissionCheck::allow("ok");
        assert_eq!(
            workspace_file_gate(None, "acme", &allow),
            Err("ask_connector_for_identity")
        );
        let id = AdmittedIdentity {
            session_id: "dg_x".into(),
            agent_pid: "a".into(),
            role: "junior".into(),
            repo_id: "acme".into(),
            tenant_id: "t".into(),
            scopes: vec!["devguard:workspace".into()],
            tool: "cursor".into(),
        };
        assert!(workspace_file_gate(Some(&id), "acme", &allow).is_ok());
        assert_eq!(
            workspace_file_gate(Some(&id), "other", &allow),
            Err("not_admitted_to_repo")
        );
        let deny_ck = PermissionCheck::deny("no");
        assert_eq!(
            workspace_file_gate(Some(&id), "acme", &deny_ck),
            Err("role_denied")
        );
    }

    #[test]
    fn git_commit_and_push_stay_on_node() {
        let mut working = BTreeMap::new();
        working.insert("src/lib.rs".into(), "fn x() {}\n".into());
        let mut git = WorkspaceGit {
            branch: "main".into(),
            commits: vec![],
            pushed_head: None,
        };
        let st = git_status(&working, &git);
        assert_eq!(st["clean"], false);
        let id = git_commit_working(&working, &mut git, "init").unwrap();
        assert!(id.starts_with("wc_"));
        assert_eq!(git_status(&working, &git)["clean"], true);
        let pushed = git_push_on_node(&mut git).unwrap();
        assert_eq!(pushed, id);
        assert_eq!(git.pushed_head.as_deref(), Some(id.as_str()));
    }
}
