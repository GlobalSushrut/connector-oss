//! DevGuard **single-workstation** profile stored on the Connector node.
//!
//! One JSON document (`engine_store` folder `devguard_local_profile`, key `singleton`) models
//! the machine where DevGuard extensions / `status-api` run — not a fleet. Operators edit it
//! from the dashboard Setup tab; CLI `devguard.yaml` on disk remains the source of truth for
//! the actual agent tool. This record drives UI + onboarding hints only (DG-08): presence of
//! saved JSON must never alone produce a healthy/enforced control state.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::state::SharedState;

const FOLDER: &str = "devguard_local_profile";
const KEY: &str = "singleton";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolAccessRow {
    /// `cursor` | `windsurf` | `claude_code` | `generic`
    pub tool: String,
    /// `allow` | `block` | `neutral` (inherit / unspecified)
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleToolProfile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tool_access: Vec<ToolAccessRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalProfile {
    pub schema_version: u32,
    /// Primary IDE / agent the human uses on this workstation.
    pub primary_tool: String,
    #[serde(default)]
    pub workspace_root_hint: String,
    #[serde(default)]
    pub default_role_name: String,
    #[serde(default)]
    pub roles: Vec<RoleToolProfile>,
    /// Must be true to accept saves from the API (UI checkbox).
    #[serde(default)]
    pub single_workstation_acknowledged: bool,
    #[serde(default)]
    pub updated_at: Option<String>,
}

fn known_tools() -> [&'static str; 4] {
    ["cursor", "windsurf", "claude_code", "generic"]
}

fn normalize_tool(t: &str) -> String {
    t.trim().to_ascii_lowercase().replace('-', "_")
}

fn validate_profile(p: &LocalProfile) -> Vec<String> {
    let mut err = Vec::new();
    if p.schema_version != 1 {
        err.push(format!(
            "unsupported schema_version {} (expected 1)",
            p.schema_version
        ));
    }
    let pt = normalize_tool(&p.primary_tool);
    if pt.is_empty() {
        err.push("primary_tool is required".into());
    } else if !known_tools().iter().any(|t| *t == pt.as_str()) {
        err.push(format!("primary_tool must be one of {:?}", known_tools()));
    }
    if !p.single_workstation_acknowledged {
        err.push(
            "single_workstation_acknowledged must be true (DevGuard governs one machine)".into(),
        );
    }
    if p.roles.is_empty() {
        err.push("at least one role is required".into());
    }
    for r in &p.roles {
        if r.name.trim().is_empty() {
            err.push("role.name must not be empty".into());
            continue;
        }
        if !r
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            err.push(format!(
                "role name {:?}: use letters, digits, _ or -",
                r.name
            ));
        }
        for row in &r.tool_access {
            let tn = normalize_tool(&row.tool);
            if !known_tools().iter().any(|t| *t == tn.as_str()) {
                err.push(format!("unknown tool {:?} in role {}", row.tool, r.name));
            }
            let m = row.mode.to_ascii_lowercase();
            if !matches!(m.as_str(), "allow" | "block" | "neutral") {
                err.push(format!(
                    "role {} tool {:?}: mode must be allow|block|neutral",
                    r.name, row.tool
                ));
            }
        }
    }
    if !p.default_role_name.trim().is_empty()
        && !p.roles.iter().any(|r| r.name == p.default_role_name)
    {
        err.push(format!(
            "default_role_name {:?} does not match any role",
            p.default_role_name
        ));
    }
    err
}

fn default_profile() -> LocalProfile {
    lab_ready_default_profile()
}

/// First-run / lab profile: onboarding defaults only (DG-08 — does not imply healthy/enforced).
pub fn lab_ready_default_profile() -> LocalProfile {
    LocalProfile {
        schema_version: 1,
        primary_tool: "cursor".into(),
        workspace_root_hint: String::new(),
        default_role_name: "developer".into(),
        roles: vec![RoleToolProfile {
            name: "developer".into(),
            description: "Default local developer — tighten per tool below.".into(),
            tool_access: vec![
                ToolAccessRow {
                    tool: "cursor".into(),
                    mode: "allow".into(),
                },
                ToolAccessRow {
                    tool: "windsurf".into(),
                    mode: "neutral".into(),
                },
                ToolAccessRow {
                    tool: "claude_code".into(),
                    mode: "neutral".into(),
                },
                ToolAccessRow {
                    tool: "generic".into(),
                    mode: "block".into(),
                },
            ],
        }],
        single_workstation_acknowledged: true,
        updated_at: None,
    }
}

/// When DevGuard is enabled in deployment and no profile exists, seed the lab-ready singleton.
pub fn ensure_lab_default_local_profile(state: &SharedState) {
    if !crate::services::plugin_matrix::is_plugin_enabled("devguard") {
        return;
    }
    let es = state.engine_store.lock().unwrap();
    if es.folder_get(FOLDER, KEY).ok().flatten().is_some() {
        return;
    }
    drop(es);
    let mut p = lab_ready_default_profile();
    p.updated_at = Some(chrono::Utc::now().to_rfc3339());
    if let Ok(stored) = serde_json::to_value(&p) {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(FOLDER, KEY, &stored);
        tracing::info!(
            "DevGuard: seeded default local-workstation profile (onboarding config only)"
        );
    }
}

/// GET /api/v1/plugins/devguard/local-profile
pub async fn get_local_profile(State(state): State<SharedState>) -> Json<Value> {
    let doc = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get(FOLDER, KEY).ok().flatten()
    };
    match doc {
        Some(v) => Json(json!({
            "ok": true,
            "profile": v,
            "single_workstation_model": true,
            "hint": "DevGuard extension + status-api run on one workstation; this record is the hub-side mirror for onboarding."
        })),
        None => Json(json!({
            "ok": true,
            "profile": serde_json::to_value(default_profile()).unwrap_or_default(),
            "defaulted": true,
            "single_workstation_model": true,
        })),
    }
}

/// POST /api/v1/plugins/devguard/local-profile — upsert singleton profile (validated).
pub async fn post_local_profile(
    State(state): State<SharedState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let mut p: LocalProfile =
        match serde_json::from_value(body.get("profile").cloned().unwrap_or(body.clone())) {
            Ok(p) => p,
            Err(e) => {
                return Json(json!({
                    "ok": false,
                    "error": "invalid_json",
                    "message": e.to_string(),
                }));
            }
        };
    let errs = validate_profile(&p);
    if !errs.is_empty() {
        return Json(json!({ "ok": false, "errors": errs }));
    }
    p.primary_tool = normalize_tool(&p.primary_tool);
    for r in &mut p.roles {
        for row in &mut r.tool_access {
            row.tool = normalize_tool(&row.tool);
            row.mode = row.mode.to_ascii_lowercase();
        }
    }
    p.updated_at = Some(chrono::Utc::now().to_rfc3339());
    let stored = match serde_json::to_value(&p) {
        Ok(v) => v,
        Err(e) => {
            return Json(json!({
                "ok": false,
                "error": "serialize_failed",
                "message": e.to_string(),
            }));
        }
    };
    {
        let mut es = state.engine_store.lock().unwrap();
        if let Err(e) = es.folder_put(FOLDER, KEY, &stored) {
            return Json(json!({
                "ok": false,
                "error": "storage_failed",
                "message": e.to_string(),
            }));
        }
    }
    Json(json!({
        "ok": true,
        "profile": stored,
        "single_workstation_model": true,
    }))
}

/// GET /api/v1/devguard/workspaces/discover
///
/// Discover git checkouts on the Connector host only. In a local installation
/// this is the operator's workstation; a remote node must not claim these are
/// browser-machine paths.
pub async fn discover_workspaces() -> Json<Value> {
    let roots = discovery_roots();
    let mut seen = BTreeSet::new();
    let mut repos = Vec::new();
    let mut visited = 0usize;
    for root in &roots {
        discover_git_roots(root, 0, &mut visited, &mut seen, &mut repos);
        if repos.len() >= 100 || visited >= 2_000 {
            break;
        }
    }
    Json(json!({
        "ok": true,
        "source": "connector_node_filesystem",
        "host_scope": true,
        "repos": repos,
        "count": repos.len(),
        "roots": roots.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "note": "These paths exist on the Connector node. When the dashboard is remote, install/run the DevGuard workstation companion to discover browser-machine checkouts."
    }))
}

fn discovery_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(raw) = std::env::var("CONNECTOR_DEVGUARD_DISCOVERY_ROOTS") {
        roots.extend(
            raw.split(':')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
        );
    }
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd);
    }
    let mut unique = BTreeSet::new();
    roots
        .into_iter()
        .filter_map(|p| p.canonicalize().ok())
        .filter(|p| unique.insert(p.clone()))
        .collect()
}

fn discover_git_roots(
    dir: &Path,
    depth: usize,
    visited: &mut usize,
    seen: &mut BTreeSet<PathBuf>,
    repos: &mut Vec<Value>,
) {
    if depth > 3 || *visited >= 2_000 || repos.len() >= 100 {
        return;
    }
    *visited += 1;
    let git_marker = dir.join(".git");
    if git_marker.exists() {
        if let Ok(canonical) = dir.canonicalize() {
            if seen.insert(canonical.clone()) {
                repos.push(git_checkout_summary(&canonical, &git_marker));
            }
        }
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() || should_skip_dir(&path) {
            continue;
        }
        discover_git_roots(&path, depth + 1, visited, seen, repos);
        if *visited >= 2_000 || repos.len() >= 100 {
            break;
        }
    }
}

fn should_skip_dir(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.starts_with('.')
        || matches!(
            name,
            "node_modules" | "target" | "vendor" | "dist" | "build" | "__pycache__"
        )
}

fn git_checkout_summary(root: &Path, marker: &Path) -> Value {
    let git_dir = if marker.is_dir() {
        marker.to_path_buf()
    } else {
        std::fs::read_to_string(marker)
            .ok()
            .and_then(|s| s.trim().strip_prefix("gitdir:").map(str::trim).map(PathBuf::from))
            .map(|p| if p.is_absolute() { p } else { root.join(p) })
            .unwrap_or_else(|| marker.to_path_buf())
    };
    let branch = std::fs::read_to_string(git_dir.join("HEAD"))
        .ok()
        .and_then(|s| {
            s.trim()
                .strip_prefix("ref: refs/heads/")
                .map(ToString::to_string)
        });
    let remote = std::fs::read_to_string(git_dir.join("config"))
        .ok()
        .and_then(|s| {
            s.lines()
                .map(str::trim)
                .find_map(|line| line.strip_prefix("url = ").map(ToString::to_string))
        });
    json!({
        "name": root.file_name().and_then(|n| n.to_str()).unwrap_or("repository"),
        "path": root.display().to_string(),
        "remote": remote,
        "branch": branch,
        "worktree": marker.is_file(),
    })
}
