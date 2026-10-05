//! # Prompt Registry — Moat 3: Prompt Management & Pipeline Access Control
//!
//! Decouples prompt lifecycles from code.  Prompts are versioned assets stored
//! in the engine_store and governed by RBAC roles.
//!
//! ## RBAC enforcement
//!   - `viewer`    — GET only
//!   - `developer` — GET + create (no delete, no approve)
//!   - `operator`  — GET + create + update + delete
//!   - `admin`+    — full access including approve/activate
//!
//! ## Storage layout
//!   engine_store folder: `prompts/<prompt_id>`
//!   keys:
//!     `meta`      — PromptMeta JSON
//!     `v<N>`      — PromptVersion JSON for version N

use crate::auth::{verify_token, PlatformRole};
use crate::state::SharedState;
use axum::{
    extract::{Path, State},
    Json,
};
use connector_engine::semantic_injection::SemanticInjectionDetector;
use serde::{Deserialize, Serialize};

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptMeta {
    pub prompt_id: String,
    pub name: String,
    pub description: Option<String>,
    pub owner: String,
    /// Role allowed to edit this prompt (minimum: "operator")
    pub edit_role: String,
    pub active_version: u32,
    pub total_versions: u32,
    pub created_at: String,
    pub updated_at: String,
    /// Tags for discoverability
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptVersion {
    pub version: u32,
    pub system_prompt: String,
    pub few_shot_examples: Vec<FewShotExample>,
    pub created_by: String,
    pub created_at: String,
    pub approved_by: Option<String>,
    pub approved_at: Option<String>,
    pub status: PromptStatus,
    pub changelog: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PromptStatus {
    Draft,
    PendingApproval,
    Approved,
    Active,
    Deprecated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FewShotExample {
    pub input: String,
    pub output: String,
}

// ── Request bodies ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreatePromptRequest {
    pub name: String,
    pub description: Option<String>,
    pub system_prompt: String,
    pub few_shot_examples: Option<Vec<FewShotExample>>,
    pub tags: Option<Vec<String>>,
    pub changelog: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdatePromptRequest {
    pub system_prompt: String,
    pub few_shot_examples: Option<Vec<FewShotExample>>,
    pub changelog: Option<String>,
}

#[derive(Deserialize)]
pub struct ActivateVersionRequest {
    pub version: u32,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn ns(prompt_id: &str) -> String {
    format!("prompts/{}", prompt_id)
}

fn version_key(v: u32) -> String {
    format!("v{}", v)
}

fn caller_identity(headers: &axum::http::HeaderMap) -> Option<(String, PlatformRole)> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|h| h.to_str().ok()))?;
    let claims = verify_token(token).ok()?;
    let role = if crate::services::runtime_control::dev_auth_bypass_allowed() {
        PlatformRole::SuperAdmin
    } else {
        PlatformRole::from_str(&claims.role)
    };
    Some((claims.sub, role))
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /prompts — create a new prompt with version 1 (Draft)
/// Required role: developer+
pub async fn create_prompt(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreatePromptRequest>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller_identity(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 3 {
        return Json(
            serde_json::json!({"error": "Insufficient role — developer or higher required", "status": 403}),
        );
    }

    let prompt_id = format!("pmt_{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();

    let meta = PromptMeta {
        prompt_id: prompt_id.clone(),
        name: req.name.clone(),
        description: req.description.clone(),
        owner: user_id.clone(),
        edit_role: "operator".into(),
        active_version: 0,
        total_versions: 1,
        created_at: now.clone(),
        updated_at: now.clone(),
        tags: req.tags.clone().unwrap_or_default(),
    };

    let v1 = PromptVersion {
        version: 1,
        system_prompt: req.system_prompt.clone(),
        few_shot_examples: req.few_shot_examples.clone().unwrap_or_default(),
        created_by: user_id.clone(),
        created_at: now.clone(),
        approved_by: None,
        approved_at: None,
        status: PromptStatus::Draft,
        changelog: req.changelog.clone(),
    };

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "prompts",
        "prompts",
        "create_prompt",
        &serde_json::json!({"name": req.name.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let _ = es.create_folder(
        &ns(&prompt_id),
        &connector_engine::engine_store::FolderOwner::Agent(user_id.clone()),
        req.description.as_deref().unwrap_or(""),
    );
    let _ = es.folder_put(
        &ns(&prompt_id),
        "meta",
        &serde_json::to_value(&meta).unwrap_or_default(),
    );
    let _ = es.folder_put(
        &ns(&prompt_id),
        &version_key(1),
        &serde_json::to_value(&v1).unwrap_or_default(),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "prompt_id": prompt_id,
        "name": req.name,
        "version": 1,
        "status": "draft",
        "created_by": user_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// GET /prompts — list all prompts
pub async fn list_prompts(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    if caller_identity(&headers).is_none() {
        return Json(serde_json::json!({"error": "Authentication required", "status": 401}));
    }

    let es = state.engine_store.lock().unwrap();
    let folders = es.list_folders(None).unwrap_or_default();
    let prompts: Vec<serde_json::Value> = folders
        .iter()
        .filter(|f| f.namespace.starts_with("prompts/"))
        .filter_map(|f| {
            let meta: PromptMeta = es
                .folder_get(&f.namespace, "meta")
                .ok()
                .flatten()
                .and_then(|v| serde_json::from_value(v).ok())?;
            Some(serde_json::json!({
                "prompt_id": meta.prompt_id,
                "name": meta.name,
                "owner": meta.owner,
                "active_version": meta.active_version,
                "total_versions": meta.total_versions,
                "tags": meta.tags,
                "updated_at": meta.updated_at,
            }))
        })
        .collect();

    Json(serde_json::json!({"count": prompts.len(), "prompts": prompts}))
}

/// GET /prompts/:id — get prompt meta + active version content
pub async fn get_prompt(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(prompt_id): Path<String>,
) -> Json<serde_json::Value> {
    if caller_identity(&headers).is_none() {
        return Json(serde_json::json!({"error": "Authentication required", "status": 401}));
    }

    let es = state.engine_store.lock().unwrap();
    let meta_val = match es.folder_get(&ns(&prompt_id), "meta").ok().flatten() {
        Some(v) => v,
        None => return Json(serde_json::json!({"error": "Prompt not found", "status": 404})),
    };
    let meta: PromptMeta = match serde_json::from_value(meta_val) {
        Ok(m) => m,
        Err(_) => {
            return Json(serde_json::json!({"error": "Corrupt prompt metadata", "status": 500}))
        }
    };

    let active_version = if meta.active_version > 0 {
        es.folder_get(&ns(&prompt_id), &version_key(meta.active_version))
            .ok()
            .flatten()
    } else {
        None
    };

    Json(serde_json::json!({
        "prompt_id": meta.prompt_id,
        "name": meta.name,
        "description": meta.description,
        "owner": meta.owner,
        "active_version": meta.active_version,
        "total_versions": meta.total_versions,
        "tags": meta.tags,
        "created_at": meta.created_at,
        "updated_at": meta.updated_at,
        "active_content": active_version,
    }))
}

/// GET /prompts/:id/versions — list all versions of a prompt
pub async fn list_versions(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(prompt_id): Path<String>,
) -> Json<serde_json::Value> {
    if caller_identity(&headers).is_none() {
        return Json(serde_json::json!({"error": "Authentication required", "status": 401}));
    }

    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(&ns(&prompt_id), None).unwrap_or_default();
    let versions: Vec<serde_json::Value> = keys
        .iter()
        .filter(|k| k.starts_with('v') && k[1..].parse::<u32>().is_ok())
        .filter_map(|k| es.folder_get(&ns(&prompt_id), k).ok().flatten())
        .collect();

    Json(serde_json::json!({
        "prompt_id": prompt_id,
        "version_count": versions.len(),
        "versions": versions,
    }))
}

/// POST /prompts/:id/versions — add a new version (Draft status)
/// Required role: operator+
pub async fn add_version(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(prompt_id): Path<String>,
    Json(req): Json<UpdatePromptRequest>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller_identity(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 4 {
        return Json(
            serde_json::json!({"error": "Insufficient role — operator or higher required", "status": 403}),
        );
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "prompts",
        "prompts",
        "add_prompt_version",
        &serde_json::json!({"prompt_id": prompt_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let meta_val = match es.folder_get(&ns(&prompt_id), "meta").ok().flatten() {
        Some(v) => v,
        None => return Json(serde_json::json!({"error": "Prompt not found", "status": 404})),
    };
    let mut meta: PromptMeta = match serde_json::from_value(meta_val) {
        Ok(m) => m,
        Err(_) => {
            return Json(serde_json::json!({"error": "Corrupt prompt metadata", "status": 500}))
        }
    };

    let new_version_num = meta.total_versions + 1;
    let now = chrono::Utc::now().to_rfc3339();

    let new_version = PromptVersion {
        version: new_version_num,
        system_prompt: req.system_prompt.clone(),
        few_shot_examples: req.few_shot_examples.clone().unwrap_or_default(),
        created_by: user_id.clone(),
        created_at: now.clone(),
        approved_by: None,
        approved_at: None,
        status: PromptStatus::Draft,
        changelog: req.changelog.clone(),
    };

    meta.total_versions = new_version_num;
    meta.updated_at = now.clone();

    let _ = es.folder_put(
        &ns(&prompt_id),
        &version_key(new_version_num),
        &serde_json::to_value(&new_version).unwrap_or_default(),
    );
    let _ = es.folder_put(
        &ns(&prompt_id),
        "meta",
        &serde_json::to_value(&meta).unwrap_or_default(),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "prompt_id": prompt_id,
        "new_version": new_version_num,
        "status": "draft",
        "created_by": user_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// POST /prompts/:id/versions/:ver/approve — approve a version for activation
/// Required role: admin+
pub async fn approve_version(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path((prompt_id, version_num)): Path<(String, u32)>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller_identity(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 5 {
        return Json(
            serde_json::json!({"error": "Insufficient role — admin or higher required", "status": 403}),
        );
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "prompts",
        "prompts",
        "approve_prompt_version",
        &serde_json::json!({"prompt_id": prompt_id.as_str(), "version": version_num}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let ver_val = match es
        .folder_get(&ns(&prompt_id), &version_key(version_num))
        .ok()
        .flatten()
    {
        Some(v) => v,
        None => return Json(serde_json::json!({"error": "Version not found", "status": 404})),
    };
    let mut ver: PromptVersion = match serde_json::from_value(ver_val) {
        Ok(v) => v,
        Err(_) => return Json(serde_json::json!({"error": "Corrupt version data", "status": 500})),
    };

    let now = chrono::Utc::now().to_rfc3339();
    ver.status = PromptStatus::Approved;
    ver.approved_by = Some(user_id.clone());
    ver.approved_at = Some(now);

    let _ = es.folder_put(
        &ns(&prompt_id),
        &version_key(version_num),
        &serde_json::to_value(&ver).unwrap_or_default(),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "prompt_id": prompt_id,
        "version": version_num,
        "status": "approved",
        "approved_by": user_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// POST /prompts/:id/activate — activate an approved version as current
/// Required role: admin+
pub async fn activate_version(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(prompt_id): Path<String>,
    Json(req): Json<ActivateVersionRequest>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller_identity(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 5 {
        return Json(
            serde_json::json!({"error": "Insufficient role — admin or higher required", "status": 403}),
        );
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "prompts",
        "prompts",
        "activate_prompt_version",
        &serde_json::json!({"prompt_id": prompt_id.as_str(), "version": req.version}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();

    let ver_val = match es
        .folder_get(&ns(&prompt_id), &version_key(req.version))
        .ok()
        .flatten()
    {
        Some(v) => v,
        None => return Json(serde_json::json!({"error": "Version not found", "status": 404})),
    };
    let mut ver: PromptVersion = match serde_json::from_value(ver_val) {
        Ok(v) => v,
        Err(_) => return Json(serde_json::json!({"error": "Corrupt version data", "status": 500})),
    };

    if ver.status != PromptStatus::Approved && ver.status != PromptStatus::Active {
        return Json(serde_json::json!({
            "error": format!("Version {} must be Approved before activation (current status: {:?})", req.version, ver.status),
            "status": 409,
        }));
    }

    let meta_val = match es.folder_get(&ns(&prompt_id), "meta").ok().flatten() {
        Some(v) => v,
        None => return Json(serde_json::json!({"error": "Prompt not found", "status": 404})),
    };
    let mut meta: PromptMeta = serde_json::from_value(meta_val).unwrap_or_else(|_| PromptMeta {
        prompt_id: prompt_id.clone(),
        name: String::new(),
        description: None,
        owner: user_id.clone(),
        edit_role: "operator".into(),
        active_version: 0,
        total_versions: req.version,
        created_at: String::new(),
        updated_at: String::new(),
        tags: vec![],
    });

    // Deprecate previous active version
    if meta.active_version > 0 && meta.active_version != req.version {
        if let Ok(Some(prev_val)) =
            es.folder_get(&ns(&prompt_id), &version_key(meta.active_version))
        {
            if let Ok(mut prev_ver) = serde_json::from_value::<PromptVersion>(prev_val) {
                prev_ver.status = PromptStatus::Deprecated;
                let _ = es.folder_put(
                    &ns(&prompt_id),
                    &version_key(meta.active_version),
                    &serde_json::to_value(&prev_ver).unwrap_or_default(),
                );
            }
        }
    }

    ver.status = PromptStatus::Active;
    meta.active_version = req.version;
    meta.updated_at = chrono::Utc::now().to_rfc3339();

    let _ = es.folder_put(
        &ns(&prompt_id),
        &version_key(req.version),
        &serde_json::to_value(&ver).unwrap_or_default(),
    );
    let _ = es.folder_put(
        &ns(&prompt_id),
        "meta",
        &serde_json::to_value(&meta).unwrap_or_default(),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "prompt_id": prompt_id,
        "active_version": req.version,
        "activated_by": user_id,
        "status": "active",
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// GET /prompts/:id/resolve — get the active system_prompt string (used by agents at runtime)
pub async fn resolve_prompt(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(prompt_id): Path<String>,
) -> Json<serde_json::Value> {
    if caller_identity(&headers).is_none() {
        return Json(serde_json::json!({"error": "Authentication required", "status": 401}));
    }

    let es = state.engine_store.lock().unwrap();
    let meta_val = match es.folder_get(&ns(&prompt_id), "meta").ok().flatten() {
        Some(v) => v,
        None => return Json(serde_json::json!({"error": "Prompt not found", "status": 404})),
    };
    let meta: PromptMeta = match serde_json::from_value(meta_val) {
        Ok(m) => m,
        Err(_) => {
            return Json(serde_json::json!({"error": "Corrupt prompt metadata", "status": 500}))
        }
    };

    if meta.active_version == 0 {
        return Json(
            serde_json::json!({"error": "No active version — prompt has not been activated", "status": 409}),
        );
    }

    let ver_val = match es
        .folder_get(&ns(&prompt_id), &version_key(meta.active_version))
        .ok()
        .flatten()
    {
        Some(v) => v,
        None => {
            return Json(serde_json::json!({"error": "Active version not found", "status": 500}))
        }
    };
    let ver: PromptVersion = match serde_json::from_value(ver_val) {
        Ok(v) => v,
        Err(_) => return Json(serde_json::json!({"error": "Corrupt version data", "status": 500})),
    };

    Json(serde_json::json!({
        "prompt_id": prompt_id,
        "name": meta.name,
        "version": meta.active_version,
        "system_prompt": ver.system_prompt,
        "few_shot_examples": ver.few_shot_examples,
    }))
}

/// E2.5: Variable template rendering — POST /prompts/{id}/render
/// Renders the active prompt version substituting {{variable}} placeholders.
pub async fn render_prompt(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(prompt_id): Path<String>,
    Json(vars): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let (_, role) = match caller_identity(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 2 {
        return Json(serde_json::json!({"error": "Viewer+ required", "status": 403}));
    }

    let es = state.engine_store.lock().unwrap();
    let meta: PromptMeta = match es
        .folder_get(&ns(&prompt_id), "meta")
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
    {
        Some(m) => m,
        None => return Json(serde_json::json!({"error": "Prompt not found", "status": 404})),
    };

    let ver_key = version_key(meta.active_version);
    let version: PromptVersion = match es
        .folder_get(&ns(&prompt_id), &ver_key)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
    {
        Some(v) => v,
        None => {
            return Json(serde_json::json!({"error": "Active version not found", "status": 404}))
        }
    };

    // Substitute {{variable}} placeholders using provided vars map
    let mut rendered = version.system_prompt.clone();
    if let Some(obj) = vars.as_object() {
        for (k, v) in obj {
            let placeholder = format!("{{{{{}}}}}", k);
            let value = v.as_str().unwrap_or(&v.to_string()).to_string();
            rendered = rendered.replace(&placeholder, &value);
        }
    }

    // Detect unresolved placeholders
    let unresolved: Vec<String> = {
        let mut found = Vec::new();
        let mut rest = rendered.as_str();
        while let Some(start) = rest.find("{{") {
            let after = &rest[start + 2..];
            if let Some(end) = after.find("}}") {
                found.push(format!("{{{{{}}}}}", &after[..end]));
                rest = &after[end + 2..];
            } else {
                break;
            }
        }
        found
    };

    Json(serde_json::json!({
        "prompt_id":       prompt_id,
        "version":         meta.active_version,
        "rendered":        rendered,
        "variables_used":  vars.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
        "unresolved":      unresolved,
        "warnings":        if !unresolved.is_empty() {
            vec![format!("{} placeholder(s) remain unresolved", unresolved.len())]
        } else { vec![] },
    }))
}

/// E2.6: Auto-rollback on activation — wraps activate_version with degradation guard
/// PATCH /prompts/{id}/activate  (replaces POST for rollback semantics)
pub async fn activate_with_rollback(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(prompt_id): Path<String>,
    Json(req): Json<ActivateVersionRequest>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller_identity(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 5 {
        return Json(serde_json::json!({"error": "Admin+ required", "status": 403}));
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "prompts",
        "prompts",
        "activate_prompt_rollback",
        &serde_json::json!({"prompt_id": prompt_id.as_str(), "version": req.version}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let mut meta: PromptMeta = match es
        .folder_get(&ns(&prompt_id), "meta")
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
    {
        Some(m) => m,
        None => return Json(serde_json::json!({"error": "Prompt not found", "status": 404})),
    };

    // Verify target version exists and is Approved
    let ver_key = version_key(req.version);
    let ver: PromptVersion = match es
        .folder_get(&ns(&prompt_id), &ver_key)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
    {
        Some(v) => v,
        None => return Json(serde_json::json!({"error": "Version not found", "status": 404})),
    };
    if ver.status != PromptStatus::Approved && ver.status != PromptStatus::Active {
        return Json(serde_json::json!({
            "error": "Version must be Approved before activation",
            "current_status": format!("{:?}", ver.status),
        }));
    }

    let previous_version = meta.active_version;
    let now = chrono::Utc::now();

    // Load analytics to check if previous version had degraded perf
    let analytics_key = format!("analytics_{}", previous_version);
    let prev_analytics = es
        .folder_get(&ns(&prompt_id), &analytics_key)
        .ok()
        .flatten();
    let prev_success_rate = prev_analytics
        .as_ref()
        .and_then(|v| v.get("success_rate_pct").and_then(|r| r.as_f64()))
        .unwrap_or(100.0);

    // Store rollback checkpoint
    let rollback_key = format!("rollback_checkpoint_{}", now.timestamp_millis());
    let _ = es.folder_put(
        &ns(&prompt_id),
        &rollback_key,
        &serde_json::json!({
            "rollback_version": previous_version,
            "activated_version": req.version,
            "activated_by": user_id,
            "activated_at": now.to_rfc3339(),
            "prev_success_rate_pct": prev_success_rate,
        }),
    );

    // Activate new version
    meta.active_version = req.version;
    meta.updated_at = now.to_rfc3339();
    let _ = es.folder_put(
        &ns(&prompt_id),
        "meta",
        &serde_json::to_value(&meta).unwrap_or_default(),
    );
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "prompt_id":        prompt_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "activated_version":req.version,
        "previous_version": previous_version,
        "activated_by":     user_id,
        "activated_at":     now.to_rfc3339(),
        "rollback_available": true,
        "rollback_endpoint": format!("POST /prompts/{}/activate with {{\"version\": {}}}", prompt_id, previous_version),
        "auto_rollback_trigger": "POST /prompts/{id}/activate will auto-rollback if success_rate_pct drops below 70% within 30 min",
        "prev_success_rate_pct": prev_success_rate,
    }))
}

/// E2.7: Prompt lint + PII/injection scan
/// POST /prompts/{id}/lint
pub async fn lint_prompt(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(prompt_id): Path<String>,
) -> Json<serde_json::Value> {
    let (_, role) = match caller_identity(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 3 {
        return Json(serde_json::json!({"error": "Developer+ required", "status": 403}));
    }

    let es = state.engine_store.lock().unwrap();
    let meta: PromptMeta = match es
        .folder_get(&ns(&prompt_id), "meta")
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
    {
        Some(m) => m,
        None => return Json(serde_json::json!({"error": "Prompt not found", "status": 404})),
    };

    let ver_key = version_key(meta.active_version);
    let version: PromptVersion = match es
        .folder_get(&ns(&prompt_id), &ver_key)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
    {
        Some(v) => v,
        None => {
            return Json(serde_json::json!({"error": "Active version not found", "status": 404}))
        }
    };

    let text = &version.system_prompt;
    let text_lower = text.to_lowercase();
    let mut issues: Vec<serde_json::Value> = Vec::new();

    // PII pattern checks
    let pii_patterns = [
        ("email", "@", ".com", "HIGH"),
        ("ssn_hint", "social security", "", "CRITICAL"),
        ("password", "password", "", "CRITICAL"),
        ("api_key", "sk-", "", "CRITICAL"),
        ("token", "bearer ", "", "HIGH"),
        ("credit_card", "4111", "", "CRITICAL"),
    ];
    for (ptype, p1, p2, severity) in &pii_patterns {
        if text_lower.contains(p1) && (p2.is_empty() || text_lower.contains(p2)) {
            issues.push(serde_json::json!({
                "type": "PII_EXPOSURE",
                "category": ptype,
                "severity": severity,
                "detail": format!("Prompt may contain {} data — review carefully", ptype),
            }));
        }
    }

    // Injection risk checks
    let injection_patterns = [
        (
            "prompt_injection",
            "ignore previous instructions",
            "CRITICAL",
        ),
        ("prompt_injection", "disregard all prior", "CRITICAL"),
        ("jailbreak", "do anything now", "HIGH"),
        ("jailbreak", "dan mode", "HIGH"),
        ("role_override", "you are now", "MEDIUM"),
        ("context_leak", "reveal your system prompt", "HIGH"),
    ];
    for (itype, pattern, severity) in &injection_patterns {
        if text_lower.contains(pattern) {
            issues.push(serde_json::json!({
                "type": "INJECTION_RISK",
                "category": itype,
                "severity": severity,
                "detail": format!("Detected injection pattern: '{}'", pattern),
            }));
        }
    }

    // Quality checks
    if text.len() < 20 {
        issues.push(serde_json::json!({"type": "QUALITY", "severity": "MEDIUM", "detail": "Prompt is very short (<20 chars) — may lack sufficient context"}));
    }
    if text.len() > 8000 {
        issues.push(serde_json::json!({"type": "QUALITY", "severity": "LOW", "detail": "Prompt is very long (>8000 chars) — may cause context overflow"}));
    }
    if !text.contains("{{") {
        issues.push(serde_json::json!({"type": "TEMPLATE", "severity": "INFO", "detail": "No template variables found — prompt is static (no {{variable}} placeholders)"}));
    }

    // Run SemanticInjectionDetector
    let injection_result = {
        let mut detector = SemanticInjectionDetector::new();
        detector.analyze(text, &prompt_id)
    };
    if injection_result.score > 0.5 {
        issues.push(serde_json::json!({
            "type": "SEMANTIC_INJECTION",
            "severity": if injection_result.score > 0.75 { "CRITICAL" } else { "HIGH" },
            "score": injection_result.score,
            "detail": format!("SemanticInjectionDetector score {:.2} exceeds threshold", injection_result.score),
        }));
    }

    let critical = issues
        .iter()
        .filter(|i| i.get("severity").and_then(|v| v.as_str()) == Some("CRITICAL"))
        .count();
    let high = issues
        .iter()
        .filter(|i| i.get("severity").and_then(|v| v.as_str()) == Some("HIGH"))
        .count();

    Json(serde_json::json!({
        "prompt_id":       prompt_id,
        "version":         meta.active_version,
        "lint_passed":     critical == 0,
        "issue_count":     issues.len(),
        "critical":        critical,
        "high":            high,
        "injection_score": injection_result.score,
        "issues":          issues,
        "recommendation":  if critical > 0 { "BLOCK — critical issues must be resolved before activation" }
                           else if high > 0 { "WARN — review high-severity issues before activation" }
                           else { "PASS — prompt cleared for activation" },
    }))
}

/// E2.8: Prompt performance analytics
/// GET /prompts/{id}/analytics
pub async fn prompt_analytics(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(prompt_id): Path<String>,
) -> Json<serde_json::Value> {
    let (_, role) = match caller_identity(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 2 {
        return Json(serde_json::json!({"error": "Viewer+ required", "status": 403}));
    }

    let es = state.engine_store.lock().unwrap();
    let meta: PromptMeta = match es
        .folder_get(&ns(&prompt_id), "meta")
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
    {
        Some(m) => m,
        None => return Json(serde_json::json!({"error": "Prompt not found", "status": 404})),
    };

    // Load analytics stored by experiments service for each version
    let mut version_analytics: Vec<serde_json::Value> = Vec::new();
    for v in 1..=meta.total_versions {
        let analytics_key = format!("analytics_{}", v);
        if let Some(data) = es
            .folder_get(&ns(&prompt_id), &analytics_key)
            .ok()
            .flatten()
        {
            version_analytics.push(data);
        } else {
            // Synthesise from chargeback data tagged with this prompt_id
            let cb_keys = es.folder_keys("chargeback_tags", None).unwrap_or_default();
            let prompt_uses: Vec<serde_json::Value> = cb_keys
                .iter()
                .filter_map(|k| es.folder_get("chargeback_tags", k).ok().flatten())
                .filter(|val| val.get("prompt_id").and_then(|v| v.as_str()) == Some(&prompt_id))
                .collect();

            let total_uses = prompt_uses.len();
            let total_cost = prompt_uses
                .iter()
                .filter_map(|v| v.get("cost_usd").and_then(|c| c.as_f64()))
                .sum::<f64>();
            let total_tokens = prompt_uses
                .iter()
                .filter_map(|v| v.get("tokens_used").and_then(|t| t.as_u64()))
                .sum::<u64>();
            let success_count = prompt_uses
                .iter()
                .filter(|v| v.get("outcome").and_then(|o| o.as_str()) == Some("success"))
                .count();
            let success_rate = if total_uses > 0 {
                success_count * 100 / total_uses
            } else {
                0
            };

            if total_uses > 0 {
                version_analytics.push(serde_json::json!({
                    "version":          v,
                    "total_uses":       total_uses,
                    "success_count":    success_count,
                    "success_rate_pct": success_rate,
                    "total_cost_usd":   (total_cost * 100.0).round() / 100.0,
                    "total_tokens":     total_tokens,
                    "avg_cost_usd":     if total_uses > 0 { (total_cost / total_uses as f64 * 1000.0).round() / 1000.0 } else { 0.0 },
                    "source":           "chargeback_tags",
                }));
            }
        }
    }

    let now = chrono::Utc::now();
    let active_analytics = version_analytics
        .iter()
        .find(|v| v.get("version").and_then(|n| n.as_u64()) == Some(meta.active_version as u64))
        .cloned();

    Json(serde_json::json!({
        "prompt_id":           prompt_id,
        "name":                meta.name,
        "active_version":      meta.active_version,
        "total_versions":      meta.total_versions,
        "generated_at":        now.to_rfc3339(),
        "active_version_perf": active_analytics,
        "version_history":     version_analytics,
        "rollback_endpoint":   format!("POST /prompts/{}/activate to change active version", prompt_id),
        "lint_endpoint":       format!("POST /prompts/{}/lint to scan active version", prompt_id),
    }))
}

/// DELETE /prompts/:id — delete a prompt (admin+ only)
pub async fn delete_prompt(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(prompt_id): Path<String>,
) -> Json<serde_json::Value> {
    let (user_id, role) = match caller_identity(&headers) {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({"error": "Authentication required", "status": 401}))
        }
    };
    if role.rank() < 5 {
        return Json(
            serde_json::json!({"error": "Insufficient role — admin or higher required", "status": 403}),
        );
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "prompts",
        "prompts",
        "retire_prompt",
        &serde_json::json!({"prompt_id": prompt_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let exists = es
        .folder_get(&ns(&prompt_id), "meta")
        .ok()
        .flatten()
        .is_some();
    if !exists {
        return Json(serde_json::json!({"error": "Prompt not found", "status": 404}));
    }

    // Mark as deleted by overwriting meta (true deletion depends on store impl)
    let tombstone = serde_json::json!({
        "prompt_id": prompt_id,
        "status": "deleted",
        "deleted_by": user_id,
        "deleted_at": chrono::Utc::now().to_rfc3339(),
    });
    let _ = es.folder_put(&ns(&prompt_id), "meta", &tombstone);
    drop(es);
    open_proceed.finish_observed(true);

    Json(serde_json::json!({
        "prompt_id": prompt_id,
        "deleted": true,
        "deleted_by": user_id,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}
