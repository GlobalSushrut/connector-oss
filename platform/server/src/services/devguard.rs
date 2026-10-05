//! DevGuard — Main plugin controller for coding agent governance.
//!
//! Manages sessions, wires FS Guard + Exec Guard + Secret Broker into
//! the gateway pipeline, and provides the unified enforcement layer.
//!
//! Scope (DG-01): DevGuard applies to coding agents and agentic tools only.
//! Runtime identity is always the Connector agent principal (`cg_`), never the
//! LLM provider account and never human SSO roles.
//!
//! This is the Rust controller that backs plugins/devguard/workflows/*.yaml.
//! Production system. Not a demo.

use crate::services::exec_guard;
use crate::services::fs_guard;
use crate::services::policy_config::{self, DevGuardPolicy};
use crate::services::secret_broker;
use crate::state::SharedState;
use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};

// ── Session ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevGuardSession {
    pub session_id: String,
    pub agent_pid: String,
    pub role: String,
    pub workspace: String,
    pub tool: String, // claude_code, cursor, windsurf, kiro, generic
    pub policy_path: String,
    pub created_at: String,
    pub active: bool,
    pub stats: SessionStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionStats {
    pub llm_calls: u64,
    pub files_read: u64,
    pub files_written: u64,
    pub commands_executed: u64,
    pub commands_denied: u64,
    pub secrets_redacted: u64,
    pub approvals_requested: u64,
    pub tokens_consumed: u64,
    pub cost_usd: f64,
}

// ── Session management endpoints ───────────────────────────────────────────

/// POST /api/v1/devguard/session/start — Create a governed session
pub async fn session_start(
    State(state): State<SharedState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let role = req
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("builder");
    let workspace = req.get("workspace").and_then(|v| v.as_str()).unwrap_or(".");
    let tool = req
        .get("tool")
        .and_then(|v| v.as_str())
        .unwrap_or("generic");
    let policy_yaml = req
        .get("policy_yaml")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let policy_path = req
        .get("policy_path")
        .and_then(|v| v.as_str())
        .unwrap_or(".connector/policy.yaml");

    // Load policy
    let policy = if !policy_yaml.is_empty() {
        match DevGuardPolicy::load_from_str(policy_yaml) {
            Ok(p) => p,
            Err(e) => return Json(serde_json::json!({ "ok": false, "error": e })),
        }
    } else {
        // Try loading from file
        match DevGuardPolicy::load_from_file(policy_path) {
            Ok(p) => p,
            Err(_) => DevGuardPolicy::default(), // no policy = use defaults (deny-by-default)
        }
    };

    let errors = policy.validate();
    if !errors.is_empty() {
        return Json(serde_json::json!({ "ok": false, "errors": errors }));
    }

    // Create session
    let session_id = format!(
        "dg_{}",
        uuid::Uuid::new_v4().to_string().replace('-', "")[..12].to_string()
    );
    let agent_pid = format!("devguard-{}-{}", tool, &session_id[3..]);

    let session = DevGuardSession {
        session_id: session_id.clone(),
        agent_pid: agent_pid.clone(),
        role: role.into(),
        workspace: workspace.into(),
        tool: tool.into(),
        policy_path: policy_path.into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        active: true,
        stats: SessionStats::default(),
    };

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "devguard",
        "devguard",
        "devguard_session_start",
        &serde_json::json!({"session_id": session_id.as_str(), "tool": tool}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    // Store policy for agent
    {
        let mut es = state.engine_store.lock().unwrap();
        let _ = es.folder_put(
            "devguard_policies",
            &agent_pid,
            &serde_json::json!({
                "policy": serde_json::to_value(&policy).unwrap_or_default(),
                "role": role,
                "loaded_at": chrono::Utc::now().to_rfc3339(),
            }),
        );
        let _ = es.folder_put(
            "devguard_sessions",
            &session_id,
            &serde_json::to_value(&session).unwrap_or_default(),
        );
    }

    let vendor_cut = crate::kernel::llm_vendor_cut::engage(
        state.as_ref(),
        &session_id,
        &agent_pid,
        tool,
        "devguard_session_start",
    );

    // Generate session token (for API auth) — coding-tool principal only (DG-01/DG-05).
    let session_token = mint_cg_token();
    let tool_class = tool.to_string();
    {
        let mut es = state.engine_store.lock().unwrap();
        put_cg_token_record(
            es.as_mut(),
            &session_token,
            cg_token_record(
                &session_id,
                &agent_pid,
                role,
                "",
                "",
                &tool_class,
                default_cg_scopes(),
            ),
        );
    }

    // Record audit entry
    record_audit(
        &state,
        &session_id,
        "session.start",
        &serde_json::json!({
            "role": role,
            "tool": tool,
            "workspace": workspace,
            "vendor_cut": vendor_cut.clone(),
        }),
    );

    open_proceed.finish_observed(true);
    Json(serde_json::json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "session_id": session_id,
        "agent_pid": agent_pid,
        "session_token": session_token,
        "role": role,
        "tool": tool,
        "vendor_cut": vendor_cut,
        "instructions": match tool {
            "claude_code" => format!(
                "Run: ANTHROPIC_BASE_URL=http://localhost:9091 ANTHROPIC_API_KEY={} claude \"your task\"",
                session_token
            ),
            "cursor" => format!(
                "Set in Cursor: Override OpenAI Base URL = http://localhost:9091, API Key = {}",
                session_token
            ),
            "windsurf" => format!(
                "Add to .windsurf/mcp_config.json or set OpenAI Base URL = http://localhost:9091, Key = {}",
                session_token
            ),
            _ => format!(
                "Set OPENAI_BASE_URL=http://localhost:9091 OPENAI_API_KEY={} or ANTHROPIC_BASE_URL=http://localhost:9091 ANTHROPIC_API_KEY={}",
                session_token, session_token
            ),
        },
    }))
}

/// DELETE /api/v1/devguard/session/:id — End session (mounted as POST …/sessions/:id/end)
pub async fn session_end(
    State(state): State<SharedState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let session_data = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("devguard_sessions", &session_id)
            .ok()
            .flatten()
    };

    let session: Option<DevGuardSession> =
        session_data.and_then(|d| serde_json::from_value(d).ok());

    match session {
        Some(mut sess) => {
            let admitted = match crate::substrate::pate::require_proceed(
                &state,
                &sess.agent_pid,
                "devguard",
                "devguard_session_end",
                &serde_json::json!({"session_id": session_id.as_str()}),
            ) {
                Ok(atu) => atu,
                Err(body) => return Json(body),
            };
            let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
            sess.active = false;
            let revoked = {
                let mut es = state.engine_store.lock().unwrap();
                let _ = es.folder_put(
                    "devguard_sessions",
                    &session_id,
                    &serde_json::to_value(&sess).unwrap_or_default(),
                );
                revoke_tokens_for_session(es.as_mut(), &session_id)
            };
            let vendor_cut = crate::kernel::llm_vendor_cut::release(state.as_ref(), &session_id);

            record_audit(
                &state,
                &session_id,
                "session.end",
                &serde_json::json!({
                    "stats": sess.stats,
                    "tokens_revoked": revoked,
                }),
            );

            open_proceed.finish_observed(true);
            Json(serde_json::json!({
                "ok": true,
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
                "session_id": session_id,
                "stats": sess.stats,
                "tokens_revoked": revoked,
                "vendor_cut": vendor_cut,
            }))
        }
        None => Json(serde_json::json!({
            "ok": false,
            "error": format!("Session '{}' not found", session_id),
        })),
    }
}

/// POST /api/v1/devguard/tokens/:token_key/revoke — admin revoke of a cg_ record (DG-05).
pub async fn revoke_token(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(token_key): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let role = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| {
            let token = auth.strip_prefix("Bearer ").unwrap_or(auth).trim();
            crate::auth::verify_token(token)
                .ok()
                .map(|c| crate::auth::PlatformRole::from_str(&c.role))
        });
    match role {
        Some(r) if r.rank() >= crate::auth::PlatformRole::Admin.rank() => {}
        Some(_) => {
            return Json(serde_json::json!({
                "ok": false,
                "error": "admin_required",
                "status": 403,
            }));
        }
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "error": "authentication_required",
                "status": 401,
            }));
        }
    }

    let key = token_key.trim().to_string();
    if key.is_empty() {
        return Json(serde_json::json!({ "ok": false, "error": "token_key_required" }));
    }

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "devguard",
        "lifecycle",
        "revoke_session_token",
        &serde_json::json!({"store": "devguard_tokens"}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = match crate::util_lock::mutex_lock(&state.engine_store, "engine_store") {
        Ok(g) => g,
        Err(e) => {
            open_proceed.finish_observed(false);
            return Json(serde_json::json!({
                "ok": false,
                "error": e,
                "status": 503,
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }));
        }
    };

    let candidates: Vec<String> = {
        let mut out = vec![key.clone(), cg_token_store_key(&key)];
        if let Some(rest) = key.strip_prefix("cg_") {
            out.push(rest.to_string());
            if rest.len() > 12 {
                out.push(format!("cg_{}", &rest[..12]));
                out.push(rest[..12].to_string());
            }
        }
        let keys = es.folder_keys("devguard_tokens", None).unwrap_or_default();
        for k in keys {
            if k == key || k.starts_with(&key) || key.starts_with(&k) {
                out.push(k.clone());
            }
            if let Ok(Some(data)) = es.folder_get("devguard_tokens", &k) {
                let prefix = data
                    .get("token_prefix")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !prefix.is_empty() && (key.starts_with(prefix) || prefix.starts_with(&key)) {
                    out.push(k);
                }
            }
        }
        out.sort();
        out.dedup();
        out
    };

    let mut revoked = 0usize;
    let mut matched_keys = Vec::new();
    for k in candidates {
        if let Ok(Some(mut data)) = es.folder_get("devguard_tokens", &k) {
            let already = data
                .get("revoked")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if let Some(obj) = data.as_object_mut() {
                obj.insert("revoked".into(), serde_json::json!(true));
                obj.insert(
                    "revoked_at".into(),
                    serde_json::json!(chrono::Utc::now().timestamp()),
                );
                obj.insert("revoked_by".into(), serde_json::json!("admin_api"));
            }
            let _ = es.folder_put("devguard_tokens", &k, &data);
            matched_keys.push(k);
            if !already {
                revoked += 1;
            }
        }
    }

    drop(es);
    open_proceed.finish_observed(true);
    Json(serde_json::json!({
        "ok": true,
        "revoked_count": revoked,
        "matched_keys": matched_keys,
        "honesty": "Token material is marked revoked; store keys are SHA-256 (cg_h_*) with legacy plaintext migration (DG-05).",
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
}

/// GET /api/v1/devguard/session/:id — Get session status
pub async fn session_status(
    State(state): State<SharedState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let session_data = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("devguard_sessions", &session_id)
            .ok()
            .flatten()
    };
    match session_data {
        Some(d) => Json(serde_json::json!({ "ok": true, "session": d })),
        None => Json(serde_json::json!({ "ok": false, "error": "Session not found" })),
    }
}

/// GET /api/v1/devguard/sessions — List active sessions
pub async fn session_list(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let sessions: Vec<serde_json::Value> = {
        let es = state.engine_store.lock().unwrap();
        let keys = es
            .folder_keys("devguard_sessions", None)
            .unwrap_or_default();
        keys.iter()
            .filter_map(|k| es.folder_get("devguard_sessions", k).ok().flatten())
            .collect()
    };
    Json(serde_json::json!({
        "ok": true,
        "sessions": sessions,
        "count": sessions.len(),
    }))
}

// ── Gateway pipeline hooks ─────────────────────────────────────────────────
// These functions are called FROM the existing gateway.rs and anthropic_gateway.rs

/// Resolve session from API key/token header.
/// Returns (agent_pid, role) if found.
pub fn resolve_session(state: &SharedState, api_key: &str) -> Option<(String, String, String)> {
    admit_token(state, api_key, None)
        .ok()
        .map(|a| (a.session_id, a.agent_pid, a.role))
}

#[derive(Debug, Clone)]
pub struct AdmittedIdentity {
    pub session_id: String,
    pub agent_pid: String,
    pub role: String,
    pub repo_id: String,
    pub tenant_id: String,
    pub scopes: Vec<String>,
    pub tool: String,
}

/// Default TTL for cg_ coding-tool tokens (seconds). Override with CONNECTOR_CG_TOKEN_TTL_SECS.
fn cg_token_ttl_secs() -> i64 {
    std::env::var("CONNECTOR_CG_TOKEN_TTL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(86_400)
}

fn mint_cg_token() -> String {
    format!("cg_{}", uuid::Uuid::new_v4().as_simple())
}

/// DG-05 — store key is SHA-256 of the bearer token (never the raw cg_ string).
fn cg_token_store_key(token: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("cg_h_{:x}", Sha256::digest(token.as_bytes()))
}

fn cg_token_prefix(token: &str) -> String {
    token.chars().take(12).collect()
}

fn lookup_cg_token_record(
    es: &dyn connector_engine::engine_store::EngineStore,
    token: &str,
) -> Option<(String, serde_json::Value)> {
    let hashed = cg_token_store_key(token);
    if let Ok(Some(d)) = es.folder_get("devguard_tokens", &hashed) {
        return Some((hashed, d));
    }
    // Legacy plaintext key (pre-hash migration).
    if let Ok(Some(d)) = es.folder_get("devguard_tokens", token) {
        return Some((token.to_string(), d));
    }
    None
}

fn put_cg_token_record(
    es: &mut dyn connector_engine::engine_store::EngineStore,
    token: &str,
    mut record: serde_json::Value,
) {
    if let Some(obj) = record.as_object_mut() {
        obj.insert(
            "token_prefix".into(),
            serde_json::json!(cg_token_prefix(token)),
        );
        obj.insert("storage".into(), serde_json::json!("sha256_at_rest"));
        obj.remove("token");
        obj.remove("session_token");
    }
    let key = cg_token_store_key(token);
    let _ = es.folder_put("devguard_tokens", &key, &record);
}

fn default_cg_scopes() -> Vec<&'static str> {
    // DevGuard is coding/agentic tools only — not human SSO / org IdP authority (DG-01).
    vec!["devguard:workspace", "devguard:gateway", "devguard:admit"]
}

fn cg_token_record(
    session_id: &str,
    agent_pid: &str,
    role: &str,
    repo_id: &str,
    tenant_id: &str,
    tool: &str,
    scopes: Vec<&str>,
) -> serde_json::Value {
    let now = chrono::Utc::now().timestamp();
    serde_json::json!({
        "session_id": session_id,
        "agent_pid": agent_pid,
        "role": role,
        "repo_id": repo_id,
        "tenant_id": tenant_id,
        "tool": tool,
        "tool_class": "coding_agent",
        "scopes": scopes,
        "issued_at": now,
        "expires_at": now + cg_token_ttl_secs(),
        "revoked": false,
        "identity_kind": "connector_agent_principal",
        "scope_note": "DevGuard cg_ tokens authorize coding/agentic tools under a Connector agent principal — not LLM identity and not human SSO roles.",
    })
}

fn revoke_tokens_for_session(
    es: &mut dyn connector_engine::engine_store::EngineStore,
    session_id: &str,
) -> usize {
    let keys = es.folder_keys("devguard_tokens", None).unwrap_or_default();
    let mut n = 0usize;
    for key in keys {
        if let Ok(Some(mut data)) = es.folder_get("devguard_tokens", &key) {
            let sid = data
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if sid == session_id {
                if let Some(obj) = data.as_object_mut() {
                    obj.insert("revoked".into(), serde_json::json!(true));
                    obj.insert(
                        "revoked_at".into(),
                        serde_json::json!(chrono::Utc::now().timestamp()),
                    );
                }
                let _ = es.folder_put("devguard_tokens", &key, &data);
                n += 1;
            }
        }
    }
    n
}

/// Machine-readable DevGuard HTTP contract shared with the CLI client (DG-02).
pub fn devguard_http_contract() -> &'static [(&'static str, &'static str)] {
    &[
        ("POST", "/api/v1/devguard/connect"),
        ("GET", "/api/v1/devguard/connect/info"),
        ("POST", "/api/v1/devguard/admit"),
        ("GET", "/api/v1/devguard/workspaces/discover"),
        ("GET", "/api/v1/devguard/repos"),
        ("GET", "/api/v1/devguard/repos/:repo_id"),
        ("POST", "/api/v1/devguard/repos/:repo_id/agents"),
        ("POST", "/api/v1/devguard/repos/:repo_id/roles"),
        ("GET", "/api/v1/devguard/repos/:repo_id/tree"),
        ("GET", "/api/v1/devguard/repos/:repo_id/file"),
        ("PUT", "/api/v1/devguard/repos/:repo_id/file"),
        ("DELETE", "/api/v1/devguard/repos/:repo_id/file"),
        ("POST", "/api/v1/devguard/repos/:repo_id/git/:op"),
        ("GET", "/api/v1/devguard/github/status"),
        ("POST", "/api/v1/devguard/github/checks/evaluate"),
        ("GET", "/api/v1/devguard/github/checks/:repo_id/:head_sha"),
        ("POST", "/api/v1/devguard/sessions"),
        ("GET", "/api/v1/devguard/sessions"),
        ("GET", "/api/v1/devguard/sessions/:session_id"),
        ("POST", "/api/v1/devguard/sessions/:session_id/end"),
        ("GET", "/api/v1/devguard/sessions/:session_id/audit"),
        ("POST", "/api/v1/devguard/tokens/:token_key/revoke"),
        ("POST", "/api/v1/devguard/fs/check"),
        ("POST", "/api/v1/devguard/fs/guard"),
        ("POST", "/api/v1/devguard/exec/check"),
        ("POST", "/api/v1/devguard/secrets/scan"),
        ("POST", "/api/v1/devguard/policy/load"),
        ("POST", "/api/v1/devguard/policy/validate"),
        ("POST", "/api/v1/devguard/policy/check"),
        ("POST", "/api/v1/devguard/policy/history"),
        ("POST", "/api/v1/devguard/policy/rollback"),
    ]
}

/// No Connector token + role → not admitted. Even read is denied.
pub fn evaluate_admit(
    has_valid_token: bool,
    token_repo: Option<&str>,
    claimed_repo: Option<&str>,
) -> Result<(), &'static str> {
    if claimed_repo.is_some() && !has_valid_token {
        return Err("ask_connector_for_identity");
    }
    if !has_valid_token {
        return Ok(());
    }
    if let (Some(have), Some(want)) = (token_repo, claimed_repo) {
        if !have.is_empty() && !want.is_empty() && have != want {
            return Err("not_admitted_to_repo");
        }
    }
    Ok(())
}

/// Linked repo on this node: cg_ token, explicit repo claim, or tenant already bound → must present identity.
pub fn must_require_identity(
    has_cg_token: bool,
    claimed_repo: bool,
    tenant_has_linked_repo: bool,
) -> bool {
    has_cg_token || claimed_repo || tenant_has_linked_repo
}

pub fn infer_claimed_repo(headers: &HeaderMap) -> Option<String> {
    const NAMES: &[&str] = &[
        "x-connector-repo",
        "x-devguard-repo",
        "x-github-repo",
        "x-repo-id",
    ];
    for name in NAMES {
        if let Some(v) = headers
            .get(*name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Some(v.to_string());
        }
    }
    None
}

fn workspace_hints(headers: &HeaderMap) -> Vec<String> {
    const NAMES: &[&str] = &[
        "x-connector-workspace",
        "x-workspace",
        "x-cwd",
        "x-cursor-cwd",
        "x-project-path",
    ];
    NAMES
        .iter()
        .filter_map(|n| {
            headers
                .get(*n)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        })
        .collect()
}

fn request_tenant_for_gate(headers: &HeaderMap) -> Option<String> {
    // AUTH-02: verified claims / API key binding only — never prefer X-Tenant-ID.
    crate::substrate::outbound::verified_tenant_id(headers)
        .or_else(|| crate::middleware::tenant::jwt_or_key_tenant_id(headers))
}

fn tenant_linked_repos(state: &SharedState, tenant: &str) -> Vec<serde_json::Value> {
    let prefix = format!("{tenant}/");
    let es = match state.engine_store.lock() {
        Ok(es) => es,
        Err(_) => return Vec::new(),
    };
    let keys = es.folder_keys("devguard_repos", None).unwrap_or_default();
    keys.iter()
        .filter(|k| k.starts_with(&prefix))
        .filter_map(|k| es.folder_get("devguard_repos", k).ok().flatten())
        .collect()
}

fn match_hint_to_repo(repos: &[serde_json::Value], hint: &str) -> Option<String> {
    let hint_l = hint.trim().trim_end_matches('/').to_ascii_lowercase();
    if hint_l.is_empty() {
        return None;
    }
    for repo in repos {
        let id = repo.get("repo_id").and_then(|v| v.as_str()).unwrap_or("");
        let gh = repo
            .get("github_url")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let ws = repo.get("workspace").and_then(|v| v.as_str()).unwrap_or("");
        if !id.is_empty()
            && (hint_l == id.to_ascii_lowercase() || hint_l.contains(&id.to_ascii_lowercase()))
        {
            return Some(id.to_string());
        }
        if !gh.is_empty() {
            let gh_l = gh.to_ascii_lowercase();
            if hint_l.contains(&gh_l) || gh_l.contains(&hint_l) {
                return Some(if id.is_empty() {
                    hint.trim().to_string()
                } else {
                    id.to_string()
                });
            }
        }
        if !ws.is_empty() {
            let ws_l = ws.to_ascii_lowercase();
            if hint_l == ws_l || hint_l.starts_with(&ws_l) || ws_l.contains(&hint_l) {
                return Some(if id.is_empty() {
                    hint.trim().to_string()
                } else {
                    id.to_string()
                });
            }
        }
    }
    None
}

/// Gateway / Anthropic / MCP: no Connector agent ID + role on a linked repo → deny, even read.
pub fn require_repo_identity(
    state: &SharedState,
    api_key: &str,
    headers: &HeaderMap,
) -> Result<Option<AdmittedIdentity>, &'static str> {
    let cg = api_key.trim().starts_with("cg_");
    let mut claimed = infer_claimed_repo(headers);
    let tenant = request_tenant_for_gate(headers);
    let repos = tenant
        .as_deref()
        .map(|t| tenant_linked_repos(state, t))
        .unwrap_or_default();
    if claimed.is_none() {
        for hint in workspace_hints(headers) {
            if let Some(id) = match_hint_to_repo(&repos, &hint) {
                claimed = Some(id);
                break;
            }
        }
    } else if let Some(id) = claimed
        .as_deref()
        .and_then(|c| match_hint_to_repo(&repos, c))
    {
        claimed = Some(id);
    }
    let tenant_bound = !repos.is_empty();
    if !must_require_identity(cg, claimed.is_some(), tenant_bound) {
        return Ok(None);
    }
    admit_token(state, api_key, claimed.as_deref()).map(Some)
}

pub fn admit_token(
    state: &SharedState,
    api_key: &str,
    claimed_repo: Option<&str>,
) -> Result<AdmittedIdentity, &'static str> {
    let key = api_key.trim();
    if key.is_empty() || !key.starts_with("cg_") {
        return Err("ask_connector_for_identity");
    }
    let es = state.engine_store.lock().unwrap();
    let data = match lookup_cg_token_record(es.as_ref(), key) {
        Some((_, d)) => d,
        None => {
            drop(es);
            crate::services::security_signals::record_signal(
                state,
                "revoked_token_use",
                serde_json::json!({
                    "reason": "unknown_identity",
                    "token_prefix": cg_token_prefix(key),
                }),
            );
            return Err("unknown_identity");
        }
    };
    if data
        .get("revoked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        drop(es);
        crate::services::security_signals::record_signal(
            state,
            "revoked_token_use",
            serde_json::json!({
                "reason": "identity_revoked",
                "token_prefix": data.get("token_prefix").cloned().unwrap_or(serde_json::json!(cg_token_prefix(key))),
            }),
        );
        return Err("identity_revoked");
    }
    if let Some(exp) = data.get("expires_at").and_then(|v| v.as_i64()) {
        if chrono::Utc::now().timestamp() >= exp {
            return Err("identity_expired");
        }
    }
    let session_id = data
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let agent_pid = data
        .get("agent_pid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let role = data
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let repo_id = data
        .get("repo_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let tenant_id = data
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let tool = data
        .get("tool")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let scopes = data
        .get("scopes")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if session_id.is_empty() || agent_pid.is_empty() {
        return Err("unknown_identity");
    }
    if let Ok(Some(sess)) = es.folder_get("devguard_sessions", &session_id) {
        if sess.get("active").and_then(|v| v.as_bool()) == Some(false) {
            return Err("identity_revoked");
        }
    }
    evaluate_admit(
        true,
        Some(repo_id.as_str()).filter(|s| !s.is_empty()),
        claimed_repo,
    )?;
    Ok(AdmittedIdentity {
        session_id,
        agent_pid,
        role,
        repo_id,
        tenant_id,
        scopes,
        tool,
    })
}

/// POST /api/v1/devguard/admit — Ask this node for entry. No ID + role → deny even read.
pub async fn admit(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let token = req
        .get("token")
        .or_else(|| req.get("api_key"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let token = if token.is_empty() {
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_start_matches("Bearer ").trim().to_string())
            .unwrap_or_default()
    } else {
        token.to_string()
    };
    let claimed = req
        .get("repo_id")
        .and_then(|v| v.as_str())
        .or_else(|| {
            headers
                .get("x-connector-repo")
                .and_then(|v| v.to_str().ok())
        })
        .or_else(|| headers.get("x-devguard-repo").and_then(|v| v.to_str().ok()));
    match admit_token(&state, &token, claimed) {
        Ok(id) => Json(serde_json::json!({
            "ok": true,
            "admitted": true,
            "agent_pid": id.agent_pid,
            "role": id.role,
            "repo_id": id.repo_id,
            "session_id": id.session_id,
            "note": "This identity may enter the repo under its role. No identity → even read is denied.",
        })),
        Err(code) => Json(serde_json::json!({
            "ok": false,
            "admitted": false,
            "error": code,
            "message": match code {
                "ask_connector_for_identity" => "This repo is under Connector. Ask the node owner for an agent ID and role. Even read is denied without it.",
                "unknown_identity" => "That token is not a Connector agent identity on this node.",
                "identity_revoked" => "That coding-tool identity was revoked (session ended or administrator revocation).",
                "identity_expired" => "That coding-tool identity has expired. Attach or start a new session.",
                "not_admitted_to_repo" => "This identity is not admitted to that repo.",
                other => other,
            },
            "ask": "POST /devguard/repos/:repo_id/agents with a role, or use an issued token.",
        })),
    }
}

pub fn install_gateway_hooks() {
    use std::sync::{Arc, OnceLock};
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        crate::services::gateway_hooks::register_session_resolver(Arc::new(
            |state: &SharedState, api_key: &str| {
                resolve_session(state, api_key).map(|(session_id, agent_pid, role)| {
                    crate::services::gateway_hooks::SessionContext {
                        session_id,
                        agent_pid,
                        role,
                    }
                })
            },
        ));
        crate::services::gateway_hooks::register_message_guard(Arc::new(
            |state: &SharedState, agent_pid: &str, content: &str| {
                guard_message_content(state, agent_pid, content)
            },
        ));
        crate::services::gateway_hooks::register_command_guard(Arc::new(
            |state: &SharedState, agent_pid: &str, command: &str| {
                let result = guard_command(state, agent_pid, command);
                crate::services::gateway_hooks::CommandGuardResult {
                    allowed: result.allowed,
                    verdict: result.verdict,
                    reason: result.reason,
                    dangerous: result.dangerous,
                    network_egress: result.network_egress,
                    requires_approval: result.requires_approval,
                }
            },
        ));
        crate::services::gateway_hooks::register_file_guard(Arc::new(
            |state: &SharedState, agent_pid: &str, operation: &str, path: &str| {
                let check = guard_file_op(state, agent_pid, operation, path);
                crate::services::gateway_hooks::FileGuardResult {
                    allowed: check.allowed,
                    verdict: check.verdict.to_string(),
                    reason: check.reason,
                    requires_approval: check.requires_approval,
                }
            },
        ));
        crate::services::gateway_hooks::register_llm_call_recorder(Arc::new(
            |state: &SharedState,
             session_id: &str,
             agent_pid: &str,
             input_tokens: u32,
             output_tokens: u32| {
                record_llm_call(state, session_id, agent_pid, input_tokens, output_tokens)
            },
        ));
    });
}

pub fn install_mcp_tools() {
    use std::sync::{Arc, OnceLock};
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        fn ok(text: String) -> connector_protocols::mcp_server::McpToolResult {
            connector_protocols::mcp_server::McpToolResult {
                content: vec![connector_protocols::mcp_server::McpContent {
                    content_type: "text".into(),
                    text,
                }],
                is_error: None,
            }
        }
        fn err(text: String) -> connector_protocols::mcp_server::McpToolResult {
            connector_protocols::mcp_server::McpToolResult {
                content: vec![connector_protocols::mcp_server::McpContent {
                    content_type: "text".into(),
                    text,
                }],
                is_error: Some(true),
            }
        }

        crate::services::mcp_hosting::register_tool(
            "devguard_session_start",
            "Start a governed DevGuard session with role-based policy. Returns session_id and agent_pid for subsequent guard calls.",
            serde_json::json!({"type":"object","required":["role"],"properties":{
                "role":{"type":"string","description":"Role for this session: builder, reviewer, release"},
                "tool":{"type":"string","default":"windsurf","description":"Tool: windsurf, cursor, claude_code, generic"},
                "workspace":{"type":"string","default":".","description":"Workspace directory path"},
                "policy_yaml":{"type":"string","description":"Policy YAML content (or omit for default deny-all)"}
            }}),
            Arc::new(|state: &SharedState, _agent_pid: &str, args: serde_json::Value| {
                let role = args.get("role").and_then(|v| v.as_str()).unwrap_or("builder");
                let tool = args.get("tool").and_then(|v| v.as_str()).unwrap_or("windsurf");
                let workspace = args.get("workspace").and_then(|v| v.as_str()).unwrap_or(".");
                let policy_yaml = args.get("policy_yaml").and_then(|v| v.as_str()).unwrap_or("");

                let policy = if !policy_yaml.is_empty() {
                    match crate::services::policy_config::DevGuardPolicy::load_from_str(policy_yaml) {
                        Ok(p) => p,
                        Err(e) => return err(format!("Policy error: {}", e)),
                    }
                } else {
                    crate::services::policy_config::DevGuardPolicy::default()
                };

                let session_id =
                    format!("dg_{}", uuid::Uuid::new_v4().to_string().replace('-', "")[..12].to_string());
                let dg_agent_pid = format!("devguard-{}-{}", tool, &session_id[3..]);

                {
                    let mut es = state.engine_store.lock().unwrap();
                    let _ = es.folder_put("devguard_policies", &dg_agent_pid, &serde_json::json!({
                        "policy": serde_json::to_value(&policy).unwrap_or_default(),
                        "role": role,
                        "loaded_at": chrono::Utc::now().to_rfc3339(),
                    }));
                    let _ = es.folder_put("devguard_sessions", &session_id, &serde_json::json!({
                        "session_id": session_id,
                        "agent_pid": dg_agent_pid,
                        "role": role, "tool": tool, "workspace": workspace,
                        "created_at": chrono::Utc::now().to_rfc3339(),
                        "active": true,
                        "stats": {"llm_calls":0,"files_read":0,"files_written":0,"commands_executed":0,"commands_denied":0,"secrets_redacted":0},
                    }));
                }

                ok(serde_json::json!({
                    "session_id": session_id,
                    "agent_pid": dg_agent_pid,
                    "role": role,
                    "tool": tool,
                    "workspace": workspace,
                    "status": "active",
                }).to_string())
            }),
        );

        crate::services::mcp_hosting::register_tool(
            "devguard_file_check",
            "Check if a file operation (read/write/delete) is allowed by the loaded policy for the agent's role. Use BEFORE any file operation.",
            serde_json::json!({"type":"object","required":["agent_pid","path","operation"],"properties":{
                "agent_pid":{"type":"string"},
                "path":{"type":"string","description":"File path to check"},
                "operation":{"type":"string","enum":["read","write","delete","rename"],"description":"Operation to check"}
            }}),
            Arc::new(|state: &SharedState, caller_agent_pid: &str, args: serde_json::Value| {
                let target = args.get("agent_pid").and_then(|v| v.as_str()).unwrap_or(caller_agent_pid);
                let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let operation = args.get("operation").and_then(|v| v.as_str()).unwrap_or("read");
                if path.is_empty() {
                    return err("path required".into());
                }
                let check = guard_file_op(state, target, operation, path);
                ok(serde_json::json!({
                    "path": path,
                    "operation": operation,
                    "allowed": check.allowed,
                    "verdict": check.verdict,
                    "reason": check.reason,
                    "requires_approval": check.requires_approval,
                }).to_string())
            }),
        );

        crate::services::mcp_hosting::register_tool(
            "devguard_exec_check",
            "Check if a shell command is allowed by policy. Returns ALLOW, DENY, or NEEDS_APPROVAL. Use BEFORE running any command.",
            serde_json::json!({"type":"object","required":["agent_pid","command"],"properties":{
                "agent_pid":{"type":"string"},
                "command":{"type":"string","description":"Shell command to check"}
            }}),
            Arc::new(|state: &SharedState, caller_agent_pid: &str, args: serde_json::Value| {
                let target = args.get("agent_pid").and_then(|v| v.as_str()).unwrap_or(caller_agent_pid);
                let command = args.get("command").and_then(|v| v.as_str()).unwrap_or("");
                if command.is_empty() {
                    return err("command required".into());
                }
                let result = guard_command(state, target, command);
                ok(serde_json::json!({
                    "command": command,
                    "allowed": result.allowed,
                    "verdict": result.verdict,
                    "reason": result.reason,
                    "dangerous": result.dangerous,
                    "network_egress": result.network_egress,
                    "requires_approval": result.requires_approval,
                }).to_string())
            }),
        );

        crate::services::mcp_hosting::register_tool(
            "devguard_secret_scan",
            "Scan text content for secrets (API keys, tokens, private keys, connection strings). Returns sanitized content with secrets redacted.",
            serde_json::json!({"type":"object","required":["content"],"properties":{
                "content":{"type":"string","description":"Text content to scan for secrets"}
            }}),
            Arc::new(|_state: &SharedState, _agent_pid: &str, args: serde_json::Value| {
                let content = args.get("content").and_then(|v| v.as_str()).unwrap_or("");
                if content.is_empty() {
                    return err("content required".into());
                }
                let result = crate::services::secret_broker::scan_and_redact(content);
                ok(serde_json::json!({
                    "redacted_count": result.redacted_count,
                    "findings": result.findings.iter().map(|f| serde_json::json!({
                        "name": f.pattern_name, "severity": f.severity, "replaced_with": f.replaced_with
                    })).collect::<Vec<_>>(),
                    "sanitized": result.sanitized,
                }).to_string())
            }),
        );

        crate::services::mcp_hosting::register_tool(
            "devguard_session_status",
            "Get current DevGuard session status: stats, role, policy, enforcement counters.",
            serde_json::json!({"type":"object","required":["session_id"],"properties":{
                "session_id":{"type":"string"}
            }}),
            Arc::new(|state: &SharedState, _agent_pid: &str, args: serde_json::Value| {
                let sid = args.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
                if sid.is_empty() {
                    return err("session_id required".into());
                }
                let es = state.engine_store.lock().unwrap();
                match es.folder_get("devguard_sessions", sid).ok().flatten() {
                    Some(d) => ok(d.to_string()),
                    None => err(format!("Session {} not found", sid)),
                }
            }),
        );

        crate::services::mcp_hosting::register_tool(
            "devguard_audit",
            "Get audit trail for a DevGuard session: all file checks, exec checks, secret scans, denials.",
            serde_json::json!({"type":"object","required":["session_id"],"properties":{
                "session_id":{"type":"string"}
            }}),
            Arc::new(|state: &SharedState, _agent_pid: &str, args: serde_json::Value| {
                let sid = args.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
                if sid.is_empty() {
                    return err("session_id required".into());
                }
                let es = state.engine_store.lock().unwrap();
                let keys = es.folder_keys("devguard_audit", Some(sid)).unwrap_or_default();
                let entries: Vec<serde_json::Value> = keys
                    .iter()
                    .filter_map(|k| es.folder_get("devguard_audit", k).ok().flatten())
                    .collect();
                ok(serde_json::json!({
                    "session_id": sid,
                    "entries": entries,
                    "count": entries.len()
                }).to_string())
            }),
        );
    });
}

/// Run FS Guard + Secret Broker on a message before sending to LLM.
/// Returns sanitized content.
pub fn guard_message_content(
    state: &SharedState,
    agent_pid: &str,
    content: &str,
) -> (String, usize) {
    let policy_data = policy_config::get_active_policy(state, agent_pid);
    let (policy, role) = match policy_data {
        Some((p, r)) => (p, r),
        None => return (String::new(), 0), // no Connector identity/policy → deny even the prompt
    };

    let result = fs_guard::guard_content(content, &policy, &role);
    if result.content_modified {
        // Update session stats
        update_session_stat(state, agent_pid, |s| {
            s.secrets_redacted += result.secrets_redacted as u64;
        });
        return (result.sanitized_content, result.secrets_redacted);
    }

    // If guard_content only returns metadata, re-run secret scan on raw content
    if policy.secrets.detect_and_redact {
        let scan =
            secret_broker::scan_and_redact_with_extras(content, &policy.secrets.custom_patterns);
        if scan.redacted_count > 0 {
            update_session_stat(state, agent_pid, |s| {
                s.secrets_redacted += scan.redacted_count as u64;
            });
            return (scan.sanitized, scan.redacted_count);
        }
    }

    (content.to_string(), 0)
}

/// Run Exec Guard on a command before execution.
pub fn guard_command(
    state: &SharedState,
    agent_pid: &str,
    command: &str,
) -> exec_guard::ExecGuardResult {
    let policy_data = policy_config::get_active_policy(state, agent_pid);
    let (policy, role) = match policy_data {
        Some((p, r)) => (p, r),
        None => {
            // No policy = deny by default
            return exec_guard::ExecGuardResult {
                allowed: false,
                verdict: "DENY".into(),
                reason: "No policy loaded — deny by default".into(),
                command: command.to_string(),
                dangerous: false,
                network_egress: false,
                requires_approval: false,
                approval_from: vec![],
            };
        }
    };

    let result = exec_guard::check_command(command, &policy, &role);

    // Update session stats
    update_session_stat(state, agent_pid, |s| {
        if result.allowed {
            s.commands_executed += 1;
        } else {
            s.commands_denied += 1;
        }
    });

    // Record audit
    let session_id = find_session_for_agent(state, agent_pid).unwrap_or_default();
    record_audit(
        state,
        &session_id,
        if result.allowed {
            "exec.allow"
        } else {
            "exec.deny"
        },
        &serde_json::json!({
            "command": command,
            "verdict": result.verdict,
            "reason": result.reason,
            "dangerous": result.dangerous,
        }),
    );

    result
}

/// Run File Guard check on a file operation.
pub fn guard_file_op(
    state: &SharedState,
    agent_pid: &str,
    operation: &str,
    path: &str,
) -> policy_config::PermissionCheck {
    let policy_data = policy_config::get_active_policy(state, agent_pid);
    let (policy, role) = match policy_data {
        Some((p, r)) => (p, r),
        None => return policy_config::PermissionCheck::deny("No policy loaded — deny by default"),
    };

    let check = policy.check_file(&role, operation, path);

    // Update session stats
    update_session_stat(state, agent_pid, |s| match operation {
        "read" => s.files_read += 1,
        "write" | "delete" | "rename" => {
            if check.allowed {
                s.files_written += 1;
            }
        }
        _ => {}
    });

    // Record audit
    let session_id = find_session_for_agent(state, agent_pid).unwrap_or_default();
    record_audit(
        state,
        &session_id,
        &format!("file.{}", operation),
        &serde_json::json!({
            "path": path,
            "verdict": check.verdict,
            "reason": check.reason,
            "role": role,
        }),
    );

    check
}

// ── Audit recording ────────────────────────────────────────────────────────

fn record_audit(state: &SharedState, session_id: &str, action: &str, details: &serde_json::Value) {
    let entry = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "session_id": session_id,
        "action": action,
        "details": details,
    });

    let key = format!("{}:{}", session_id, chrono::Utc::now().timestamp_millis());
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put("devguard_audit", &key, &entry);
}

// ── Connect endpoint ───────────────────────────────────────────────────────

/// Resolve the base URL this node is reachable at (gateway-facing, not management).
/// Priority: CONNECTOR_PUBLIC_URL > CONNECTOR_HOST:CONNECTOR_PORT > localhost:9091.
fn node_gateway_base() -> String {
    if let Ok(pub_url) = std::env::var("CONNECTOR_PUBLIC_URL") {
        let u = pub_url.trim_end_matches('/').to_string();
        if !u.is_empty() {
            return u;
        }
    }
    let host = std::env::var("CONNECTOR_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("CONNECTOR_PORT").unwrap_or_else(|_| "9091".into());
    let scheme =
        if host.contains("localhost") || host.starts_with("127.") || host.starts_with("0.0.0.0") {
            "http"
        } else {
            "https"
        };
    format!("{scheme}://{host}:{port}")
}

/// Build per-tool connection instructions given a gateway base URL and session token.
fn tool_connect_instructions(base: &str, token: &str, tool: &str) -> serde_json::Value {
    match tool {
        "cursor" => serde_json::json!({
            "tool": "cursor",
            "display": "Cursor",
            "steps": [
                format!("Open Cursor → Settings → Models"),
                format!("Set  OpenAI Base URL  →  {}/v1", base),
                format!("Set  API Key  →  {}", token),
                "Open the cage address. The working copy is this node's workspace — not a laptop clone."
            ],
            "env_snippet": format!("OPENAI_BASE_URL={}/v1\nOPENAI_API_KEY={}", base, token),
        }),
        "windsurf" => serde_json::json!({
            "tool": "windsurf",
            "display": "Windsurf / Cascade",
            "steps": [
                "Open Windsurf → Settings → AI Providers",
                format!("Set  OpenAI Base URL  →  {}/v1", base),
                format!("Set  API Key  →  {}", token),
                "Or add to .windsurf/mcp_config.json (see env_snippet below)."
            ],
            "env_snippet": format!("OPENAI_BASE_URL={}/v1\nOPENAI_API_KEY={}", base, token),
        }),
        "claude_code" => serde_json::json!({
            "tool": "claude_code",
            "display": "Claude Code",
            "steps": [
                format!("Run with:  ANTHROPIC_BASE_URL={}/v1  ANTHROPIC_API_KEY={}  claude \"your task\"", base, token),
                "Or export permanently:",
                format!("  export ANTHROPIC_BASE_URL={}/v1", base),
                format!("  export ANTHROPIC_API_KEY={}", token),
            ],
            "env_snippet": format!("export ANTHROPIC_BASE_URL={}/v1\nexport ANTHROPIC_API_KEY={}", base, token),
        }),
        "codex" => serde_json::json!({
            "tool": "codex",
            "display": "Codex / OpenAI",
            "steps": [
                format!("Set  OPENAI_BASE_URL  →  {}/v1", base),
                format!("Set  OPENAI_API_KEY  →  {}", token),
                "Open your repo and work. Requests go through DevGuard."
            ],
            "env_snippet": format!("OPENAI_BASE_URL={}/v1\nOPENAI_API_KEY={}", base, token),
        }),
        "kiro" => serde_json::json!({
            "tool": "kiro",
            "display": "Kiro",
            "steps": [
                "Open Kiro → Settings → LLM Provider",
                format!("Set  Base URL  →  {}/v1", base),
                format!("Set  API Key  →  {}", token),
            ],
            "env_snippet": format!("OPENAI_BASE_URL={}/v1\nOPENAI_API_KEY={}", base, token),
        }),
        _ => serde_json::json!({
            "tool": "generic",
            "display": "Any OpenAI-compatible tool",
            "steps": [
                format!("Set OPENAI_BASE_URL={}/v1", base),
                format!("Set OPENAI_API_KEY={}", token),
                "Or for Anthropic-compatible tools:",
                format!("  ANTHROPIC_BASE_URL={}/v1  ANTHROPIC_API_KEY={}", base, token),
            ],
            "env_snippet": format!("OPENAI_BASE_URL={}/v1\nOPENAI_API_KEY={}", base, token),
        }),
    }
}

/// Workspace bind capabilities advertised to the operator UI (honest flags).
fn workspace_bind_capabilities() -> serde_json::Value {
    serde_json::json!({
        "local_folder": true,
        "github_checkout": true,
        "github_oauth_clone": false,
        "host_cage": "cli_only",
        "team_project_crud": false,
        "graph_firewall_separate": true,
        "repo_address": true,
        "repo_config": true,
        "multi_agent_same_address": true,
        "story": [
            "1. Git / GitHub manages the repo. Clone it on your machine — hub does not OAuth-clone.",
            "2. DevGuard binds that repo and issues one address + config for the checkout.",
            "3. Cage the checkout once (`devguard init && devguard cage start`). Any agent in that folder follows the rules.",
            "4. Point Cursor, Claude Code, Codex, or any other agent at the same address."
        ]
    })
}

fn cage_firewall_checklist(workspace: &str, _tool: &str) -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "id": "checkout",
            "label": "Clone or open the repo on your machine",
            "done_by": "git",
            "command": format!("cd {workspace}"),
            "note": "Git / GitHub manages the files. Hub does not OAuth-clone."
        }),
        serde_json::json!({
            "id": "address",
            "label": "Drop the repo address into .devguard/connector.json",
            "done_by": "config",
            "command": format!("mkdir -p {workspace}/.devguard"),
            "note": "Same address for Cursor, Claude Code, Codex, or any other agent."
        }),
        serde_json::json!({
            "id": "init",
            "label": "Write repo policy",
            "done_by": "cli",
            "command": format!("cd {workspace} && devguard init"),
            "note": "Writes devguard.yaml — the rules every agent in this checkout must follow."
        }),
        serde_json::json!({
            "id": "cage",
            "label": "Cage the checkout",
            "done_by": "cli",
            "command": format!("cd {workspace} && devguard cage start"),
            "note": "Git hooks, FS watchdog, exec guard. After this, any agent in the folder is bound. Browser cannot install cage."
        }),
        serde_json::json!({
            "id": "status",
            "label": "Verify cage",
            "done_by": "cli",
            "command": format!("cd {workspace} && devguard cage status"),
            "note": "Confirm enforcement before letting agents touch the repo."
        }),
    ]
}

fn slugify_project(raw: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
        if out.len() >= 48 {
            break;
        }
    }
    out.trim_matches('-').to_string()
}

fn github_project_slug(url: &str) -> String {
    let trimmed = url
        .trim()
        .trim_end_matches(".git")
        .replace("https://github.com/", "")
        .replace("http://github.com/", "")
        .replace("git@github.com:", "")
        .replace("github.com/", "");
    slugify_project(&trimmed)
}

/// GitHub URL, `github.com/org/repo`, or `org/repo`.
fn normalize_github_input(input: &str) -> Option<String> {
    let t = input.trim().trim_end_matches('/').trim_end_matches(".git");
    if t.starts_with("https://github.com/") {
        return Some(t.to_string());
    }
    if t.starts_with("http://github.com/") {
        return Some(t.replacen("http://", "https://", 1));
    }
    if let Some(rest) = t.strip_prefix("git@github.com:") {
        return Some(format!("https://github.com/{rest}"));
    }
    let rest = t.strip_prefix("github.com/").unwrap_or(t);
    let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() == 2
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        })
    {
        return Some(format!("https://github.com/{}/{}", parts[0], parts[1]));
    }
    None
}

pub(crate) fn tenant_id_from_headers(headers: &HeaderMap) -> String {
    if let Some(tid) = crate::substrate::outbound::verified_tenant_id(headers) {
        return tid;
    }
    if let Some(tid) = crate::middleware::tenant::jwt_or_key_tenant_id(headers) {
        return tid;
    }
    // Header only in lab bypass — never in production-like.
    if crate::services::runtime_control::dev_auth_bypass_allowed()
        && !crate::connector_profile::is_productionish_env()
    {
        if let Some(tid) = crate::middleware::tenant::header_tenant_id(headers) {
            return tid;
        }
    }
    std::env::var("CONNECTOR_DEFAULT_TENANT_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".into())
}

fn repo_id_for(workspace: &str, github_url: &str) -> String {
    if !github_url.is_empty() {
        let slug = github_project_slug(github_url);
        if !slug.is_empty() {
            return slug;
        }
    }
    let trimmed = workspace.trim_start_matches("/projects/").trim_matches('/');
    let slug = slugify_project(trimmed);
    if slug.is_empty() {
        "repo".into()
    } else {
        slug
    }
}

fn repo_connector_json(
    base: &str,
    token: Option<&str>,
    repo_id: &str,
    workspace: &str,
    github_url: &str,
) -> serde_json::Value {
    let attached = token.is_some_and(|t| t.starts_with("cg_"));
    serde_json::json!({
        "schema": "devguard.connector/v1",
        "repo_id": repo_id,
        "gateway_base": base,
        "openai_base_url": format!("{base}/v1"),
        "anthropic_base_url": format!("{base}/v1"),
        "api_key": serde_json::Value::Null,
        "credential_source": "CONNECTOR_AGENT_TOKEN",
        "attach_required": !attached,
        "require_identity": true,
        "admit": format!("{base}/api/v1/devguard/admit"),
        "header": "X-Connector-Repo",
        "workspace": workspace,
        "github_url": if github_url.is_empty() { serde_json::Value::Null } else { serde_json::json!(github_url) },
        "rule": "No Connector agent ID + role → even read is denied. Ask the node for an identity. Attach an agent to receive a cg_ token.",
    })
}

/// Accept a GitHub URL, org/repo, project name, or absolute path.
/// Playground visitors do not have a path on the Fly host — GitHub is enough.
fn resolve_project_bind(req: &serde_json::Value) -> Result<(String, String, String), String> {
    let workspace = req
        .get("workspace")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let project = req
        .get("project")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let github = req
        .get("github_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let input = if !workspace.is_empty() {
        workspace
    } else if !github.is_empty() {
        github
    } else {
        project
    };
    if input.is_empty() || input == "." {
        return Err("Paste a GitHub URL or org/repo — or name the repo to generate.".into());
    }
    let generate = req
        .get("generate")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if generate && normalize_github_input(input).is_none() && !input.starts_with('/') {
        let slug = slugify_project(input);
        if slug.is_empty() {
            return Err("Name the repo to generate.".into());
        }
        return Ok((
            format!("/projects/{slug}"),
            "generated".into(),
            String::new(),
        ));
    }
    if let Some(url) = normalize_github_input(input) {
        let slug = github_project_slug(&url);
        if slug.is_empty() {
            return Err("That GitHub URL does not look like org/repo.".into());
        }
        return Ok((format!("/projects/{slug}"), "github_checkout".into(), url));
    }
    if input.starts_with('/') && input != "/" && input != "/workspace" {
        let origin = match req
            .get("origin_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
        {
            "github" | "github_checkout" | "gh" => "github_checkout",
            _ => "local_folder",
        };
        return Ok((input.to_string(), origin.into(), github.to_string()));
    }
    let slug = slugify_project(input);
    if slug.is_empty() {
        return Err("Use letters, numbers, or a GitHub URL.".into());
    }
    Ok((
        format!("/projects/{slug}"),
        "local_folder".into(),
        String::new(),
    ))
}

/// POST /api/v1/devguard/connect — Bind a repo and return one address +
/// config + cage for every coding agent in that checkout.
///
/// Body:
/// ```json
/// {
///   "project": "https://github.com/acme/repo" | "acme/repo" | "name",
///   "tool": "cursor" | "generic",
///   "role": "developer",
///   "workspace": "/home/you/Projects/repo",
///   "github_url": "https://github.com/acme/repo"
/// }
/// ```
pub async fn connect(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let tool_owned = req
        .get("tool")
        .and_then(|v| v.as_str())
        .unwrap_or("generic")
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_");
    let tool = match tool_owned.as_str() {
        "claude" | "claude_code" => "claude_code",
        "openai" | "gpt" => "codex",
        other if other.is_empty() => "generic",
        other => other,
    };
    let role = normalize_role(
        req.get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("builder"),
    );
    let (workspace, origin_kind, github_url) = match resolve_project_bind(&req) {
        Ok(t) => t,
        Err(message) => {
            return Json(serde_json::json!({
                "ok": false,
                "error": "project_required",
                "message": message,
                "capabilities": workspace_bind_capabilities(),
            }));
        }
    };
    let workspace = workspace.as_str();
    let tenant_id = tenant_id_from_headers(&headers);
    let repo_id = repo_id_for(workspace, &github_url);
    let repo_key = format!("{tenant_id}/{repo_id}");

    let owner_roles = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("devguard_repos", &repo_key)
            .ok()
            .flatten()
            .and_then(|v| v.get("owner_roles").cloned())
            .unwrap_or_else(owner_role_catalog)
    };
    let path_exists_locally = std::path::Path::new(workspace).is_dir();
    let now = chrono::Utc::now().to_rfc3339();

    let (bind_id, reused, agents) = {
        let mut es = state.engine_store.lock().unwrap();
        let existing = es.folder_get("devguard_repos", &repo_key).ok().flatten();
        let reused = existing.is_some();
        let agents = existing
            .as_ref()
            .and_then(|ex| ex.get("agents").cloned())
            .unwrap_or_else(|| serde_json::json!([]));
        let bind_id = existing
            .as_ref()
            .and_then(|ex| ex.get("bind_id").and_then(|v| v.as_str()))
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                format!(
                    "bind_{}",
                    &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]
                )
            });
        // Drop phantom repo-level identity minted by older connect(). Attached agents keep theirs.
        if let Some(ex) = existing.as_ref() {
            let attached_token = |tok: &str| {
                agents.as_array().is_some_and(|arr| {
                    arr.iter()
                        .any(|a| a.get("token").and_then(|v| v.as_str()) == Some(tok))
                })
            };
            let attached_sid = |sid: &str| {
                agents.as_array().is_some_and(|arr| {
                    arr.iter()
                        .any(|a| a.get("session_id").and_then(|v| v.as_str()) == Some(sid))
                })
            };
            let attached_pid = |pid: &str| {
                agents.as_array().is_some_and(|arr| {
                    arr.iter()
                        .any(|a| a.get("agent_pid").and_then(|v| v.as_str()) == Some(pid))
                })
            };
            if let Some(tok) = ex.get("token").and_then(|v| v.as_str()) {
                if tok.starts_with("cg_") && !attached_token(tok) {
                    let _ = es.folder_delete("devguard_tokens", tok);
                }
            }
            if let Some(sid) = ex.get("session_id").and_then(|v| v.as_str()) {
                if sid.starts_with("dg_") && !attached_sid(sid) {
                    let _ = es.folder_delete("devguard_sessions", sid);
                }
            }
            if let Some(pid) = ex.get("agent_pid").and_then(|v| v.as_str()) {
                if !pid.is_empty() && !attached_pid(pid) {
                    let _ = es.folder_delete("devguard_policies", pid);
                }
            }
        }
        let _ = es.folder_put("devguard_repos", &repo_key, &serde_json::json!({
            "repo_id": repo_id,
            "tenant_id": tenant_id,
            "workspace": workspace,
            "origin_kind": origin_kind,
            "github_url": if github_url.is_empty() { serde_json::Value::Null } else { serde_json::json!(github_url) },
            "bind_id": bind_id.clone(),
            "role": role,
            "agents": agents.clone(),
            "owner_roles": owner_roles.clone(),
            "identity": "attach_required",
            "updated_at": now,
        }));
        (bind_id, reused, agents)
    };

    record_audit(
        &state,
        &bind_id,
        "session.connect",
        &serde_json::json!({
            "role": role, "tool": tool, "workspace": workspace,
            "origin_kind": origin_kind, "github_url": github_url,
            "repo_id": repo_id, "reused": reused, "identity": "attach_required",
        }),
    );

    let base = node_gateway_base();
    let placeholder = "<attach-an-agent-for-cg-token>";
    let instructions = tool_connect_instructions(&base, placeholder, tool);
    let all_tools: Vec<serde_json::Value> = [
        "cursor",
        "windsurf",
        "claude_code",
        "codex",
        "kiro",
        "generic",
    ]
    .iter()
    .map(|t| tool_connect_instructions(&base, placeholder, t))
    .collect();

    crate::services::devguard_workspace::seed_workspace_tree(
        &state,
        &tenant_id,
        &repo_id,
        &origin_kind,
    );
    let workspace_api = crate::services::devguard_workspace::workspace_api_block(&base, &repo_id);
    let clone_hint = String::new();
    let connector_json = repo_connector_json(&base, None, &repo_id, workspace, &github_url);
    let connector_json_text =
        serde_json::to_string_pretty(&connector_json).unwrap_or_else(|_| "{}".into());
    let cage_cmd = "devguard init && devguard cage start".to_string();
    let write_cmd = format!(
        "mkdir -p .devguard && cat > .devguard/connector.json <<'EOF'\n{connector_json_text}\nEOF\n{cage_cmd}"
    );

    let vendor_cut = crate::kernel::llm_vendor_cut::engage(
        state.as_ref(),
        &bind_id,
        "devguard-bind",
        tool,
        "devguard_connect",
    );

    Json(serde_json::json!({
        "ok": true,
        "bind_id": bind_id,
        "vendor_cut": vendor_cut,
        "session_id": serde_json::Value::Null,
        "agent_pid": serde_json::Value::Null,
        "token": serde_json::Value::Null,
        "gateway_base": base,
        "openai_base_url": format!("{}/v1", base),
        "anthropic_base_url": format!("{}/v1", base),
        "tool": tool,
        "role": role,
        "workspace": workspace,
        "origin_kind": origin_kind,
        "github_url": if github_url.is_empty() { serde_json::Value::Null } else { serde_json::json!(github_url) },
        "repo_id": repo_id,
        "reused": reused,
        "path_exists_on_platform_host": path_exists_locally,
        "path_exists_note": "This node holds the working tree. Attach an agent to get a cg_ token. Do not open a raw clone. A raw clone is not this repo.",
        "workspace_api": workspace_api,
        "repo": {
            "repo_id": repo_id,
            "workspace": workspace,
            "origin_kind": origin_kind,
            "github_url": if github_url.is_empty() { serde_json::Value::Null } else { serde_json::json!(github_url) },
            "managed_by": if origin_kind == "github_checkout" { "github" } else { "git" },
        },
        "agents": agents,
        "owner_roles": owner_roles,
        "identity": {
            "required": true,
            "admit": "/api/v1/devguard/admit",
            "header": "X-Connector-Repo",
            "ask": "Attach an agent with a name and role. Without that ID, even read is denied — local checkout or GitHub.",
        },
        "enforcement": enforcement_contract(),
        "scaffold": if origin_kind == "generated" { generate_scaffold(&repo_id) } else { serde_json::Value::Null },
        "repo_address": {
            "gateway_base": base,
            "openai_base_url": format!("{base}/v1"),
            "anthropic_base_url": format!("{base}/v1"),
            "api_key": serde_json::Value::Null,
            "note": "Cage address for this repo. Attach an agent to receive a cg_ token. The working copy is the workspace API on this node — not a laptop folder.",
        },
        "repo_config": {
            "path": ".devguard/connector.json",
            "policy_path": "devguard.yaml",
            "connector_json": connector_json,
            "write_command": write_cmd,
        },
        "repo_cage": {
            "active": false,
            "enforcer": "devguard_cli",
            "command": cage_cmd,
            "note": "Run once after attaching an agent. Browser cannot install cage.",
        },
        "instructions": instructions,
        "all_tools": all_tools,
        "capabilities": workspace_bind_capabilities(),
        "cage_firewall": {
            "active": false,
            "enforcer": "devguard_cli",
            "checklist": cage_firewall_checklist(workspace, tool),
            "clone_hint": clone_hint,
        },
        "host_cage_note": "The repo is this node's workspace. Agents use the issued address + cg_ token from attach. A leftover clone on disk is not this repo.",
    }))
}

/// GET /api/v1/devguard/connect/info — Node connection info (no session created).
/// Returns gateway URI and instructions for all supported tools.
pub async fn connect_info() -> Json<serde_json::Value> {
    let base = node_gateway_base();
    let placeholder = "<your-session-token>";
    let tools: Vec<serde_json::Value> = ["cursor", "windsurf", "claude_code", "kiro", "generic"]
        .iter()
        .map(|t| tool_connect_instructions(&base, placeholder, t))
        .collect();
    Json(serde_json::json!({
        "ok": true,
        "gateway_base": base,
        "openai_base_url": format!("{}/v1", base),
        "anthropic_base_url": format!("{}/v1", base),
        "hint": "POST /devguard/connect binds a repo only. Attach an agent (POST /devguard/repos/:repo_id/agents) to receive a cg_ token. Connect never mints identity.",
        "scope": {
            "product": "DevGuard",
            "applies_to": ["coding_agents", "agentic_tools"],
            "identity": "connector_agent_principal",
            "not": ["human_sso", "llm_provider_identity"],
            "note": "The LLM is not the identity. The Connector agent principal (cg_) is.",
        },
        "workspace_models": {
            "schema": "connector.devguard_workspace_models.v1",
            "local_workstation": {
                "id": "local_workstation",
                "meaning": "Developer laptop path used only for onboarding / cage CLI — not the node's authoritative working copy.",
                "ui_must_not_claim": ["github_clone_completed", "provisioned_remote_repo", "laptop_is_node_workspace"],
            },
            "node_hosted_virtual": {
                "id": "node_hosted_virtual",
                "meaning": "Authoritative repo workspace on this Connector node (workspace API + cg_ identity).",
                "api": "/api/v1/devguard/repos/:repo_id/tree|file|git/:op",
            },
            "honesty": "DG-12 — UI must never imply a GitHub clone/provision that did not occur. Path existence on disk ≠ node workspace.",
        },
        "connect_flow": [
            "bind_repo",
            "create_or_choose_chartered_agent",
            "attach_agent",
            "issue_repo_bound_cg_token",
            "verify_admit",
        ],
        "tools": tools,
        "node_host": std::env::var("CONNECTOR_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
        "node_port": std::env::var("CONNECTOR_PORT").unwrap_or_else(|_| "9091".into()),
        "capabilities": workspace_bind_capabilities(),
        "accounting_mode": "action",
        "http_contract": crate::services::devguard::devguard_http_contract()
            .iter()
            .map(|(m, p)| serde_json::json!({"method": m, "path": p}))
            .collect::<Vec<_>>(),
    }))
}

/// GET /api/v1/devguard/repos — Repos bound for this tenant.
pub async fn list_repos(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let tenant = tenant_id_from_headers(&headers);
    let prefix = format!("{tenant}/");
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys("devguard_repos", None).unwrap_or_default();
    let repos: Vec<serde_json::Value> = keys
        .iter()
        .filter(|k| k.starts_with(&prefix))
        .filter_map(|k| es.folder_get("devguard_repos", k).ok().flatten())
        .collect();
    Json(serde_json::json!({ "ok": true, "repos": repos, "count": repos.len() }))
}

/// GET /api/v1/devguard/repos/:repo_id
pub async fn get_repo(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(repo_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let tenant = tenant_id_from_headers(&headers);
    let key = format!("{tenant}/{repo_id}");
    let es = state.engine_store.lock().unwrap();
    match es.folder_get("devguard_repos", &key).ok().flatten() {
        Some(repo) => Json(serde_json::json!({ "ok": true, "repo": repo })),
        None => {
            Json(serde_json::json!({ "ok": false, "error": "repo_not_found", "repo_id": repo_id }))
        }
    }
}

/// POST /api/v1/devguard/repos/:repo_id/agents — Attach one more agent to
/// the same caged repo, with its own token and rules.
pub async fn attach_agent(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(repo_id): axum::extract::Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let tenant = tenant_id_from_headers(&headers);
    let key = format!("{tenant}/{repo_id}");
    let name = req
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let role = normalize_role(
        req.get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("builder"),
    );
    let tool = req
        .get("tool")
        .and_then(|v| v.as_str())
        .unwrap_or("generic")
        .trim()
        .to_string();
    if name.is_empty() {
        return Json(
            serde_json::json!({ "ok": false, "error": "name_required", "message": "Name this agent." }),
        );
    }
    let now = chrono::Utc::now().to_rfc3339();
    let session_id = format!(
        "dg_{}",
        &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]
    );
    let agent_pid = format!("devguard-{}-{}", slugify_project(&name), &session_id[3..]);
    let token = mint_cg_token();
    let base = node_gateway_base();

    let (workspace, origin_kind, github_url, agent_row) = {
        let mut es = state.engine_store.lock().unwrap();
        let Some(mut repo) = es.folder_get("devguard_repos", &key).ok().flatten() else {
            return Json(
                serde_json::json!({ "ok": false, "error": "repo_not_found", "repo_id": repo_id }),
            );
        };
        let workspace = repo
            .get("workspace")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let catalog = repo
            .get("owner_roles")
            .cloned()
            .unwrap_or_else(owner_role_catalog);
        if catalog.get(&role).is_none() {
            return Json(serde_json::json!({
                "ok": false,
                "error": "unknown_role",
                "message": format!("Node owner has no role '{role}'. Use junior, builder, reviewer, senior, devops, or owner."),
                "owner_roles": catalog,
            }));
        }
        let policy = compile_policy_for_assigned_role(&catalog, &role, &workspace);
        let origin_kind = repo
            .get("origin_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("local_folder")
            .to_string();
        let github_url = repo
            .get("github_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let summary = catalog
            .get(&role)
            .and_then(|r| r.get("summary"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let row = serde_json::json!({
            "name": name,
            "role": role,
            "tool": tool,
            "summary": summary,
            "agent_pid": agent_pid,
            "session_id": session_id,
            "token_prefix": cg_token_prefix(&token),
            "openai_base_url": format!("{base}/v1"),
            "anthropic_base_url": format!("{base}/v1"),
            "workspace_api": crate::services::devguard_workspace::workspace_api_block(&base, &repo_id),
            "created_at": now,
        });
        let mut agents = repo
            .get("agents")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();
        agents.push(row.clone());
        if let Some(obj) = repo.as_object_mut() {
            obj.insert("agents".into(), serde_json::Value::Array(agents.clone()));
            obj.insert("updated_at".into(), serde_json::json!(now));
        }
        let _ = es.folder_put("devguard_repos", &key, &repo);
        let _ = es.folder_put(
            "devguard_policies",
            &agent_pid,
            &serde_json::json!({
                "policy": serde_json::to_value(&policy).unwrap_or_default(),
                "role": role,
                "repo_id": repo_id,
                "tenant_id": tenant,
                "loaded_at": now,
            }),
        );
        let _ = es.folder_put(
            "devguard_sessions",
            &session_id,
            &serde_json::json!({
                "session_id": session_id,
                "agent_pid": agent_pid,
                "role": role,
                "tool": tool,
                "workspace": workspace,
                "repo_id": repo_id,
                "created_at": now,
                "active": true,
            }),
        );
        put_cg_token_record(
            es.as_mut(),
            &token,
            cg_token_record(
                &session_id,
                &agent_pid,
                &role,
                &repo_id,
                &tenant,
                &tool,
                default_cg_scopes(),
            ),
        );
        let mut agent_out = row;
        if let Some(obj) = agent_out.as_object_mut() {
            // One-time issuance only — not persisted on the repo record.
            obj.insert("token".into(), serde_json::json!(token));
            obj.insert(
                "token_storage".into(),
                serde_json::json!("sha256_at_rest — save this token now; store keeps hash only"),
            );
        }
        (workspace, origin_kind, github_url, agent_out)
    };

    record_audit(
        &state,
        &session_id,
        "repo.attach_agent",
        &serde_json::json!({
            "repo_id": repo_id, "name": name, "role": role, "tool": tool,
        }),
    );

    let vendor_cut = crate::kernel::llm_vendor_cut::engage(
        state.as_ref(),
        &session_id,
        &agent_pid,
        &tool,
        "devguard_attach_agent",
    );

    Json(serde_json::json!({
        "ok": true,
        "repo_id": repo_id,
        "workspace": workspace,
        "origin_kind": origin_kind,
        "github_url": github_url,
        "agent": agent_row,
        "vendor_cut": vendor_cut,
        "identity": {
            "required": true,
            "admit": "/api/v1/devguard/admit",
            "header": "X-Connector-Repo",
            "ask": "This ID + role is how the agent enters the repo. Without it, even read is denied.",
        },
        "workspace_api": crate::services::devguard_workspace::workspace_api_block(&base, &repo_id),
        "enforcement": enforcement_contract(),
        "note": "This agent must use its own token at the cage address. The working copy is the workspace API — not a raw clone.",
    }))
}

fn enforcement_contract() -> serde_json::Value {
    serde_json::json!({
        "llm_must_use_issued_token": true,
        "llm_vendor_cut": true,
        "per_agent_rules": true,
        "shared_repo_cage": true,
        "host_cage": "cli_only",
        "workspace_is_the_repo": true,
        "direct_vendor_is_not_this_node": true,
        "github_oauth_clone": false,
        "story": [
            "Setup DevGuard once on the repo. Attach N agents — 1, 30, or 100.",
            "Each agent gets its own token and role. The working copy is this node's workspace API.",
            "No Connector agent ID + role → even read is denied. Ask this node for an identity.",
            "A raw clone on a laptop or GitHub.com is not this repo. An agent that never uses the address is not this node's agent."
        ]
    })
}

fn normalize_role(role: &str) -> String {
    match role.trim().to_ascii_lowercase().as_str() {
        "intern" | "junior" | "jr" => "junior".into(),
        "developer" | "builder" | "dev" => "builder".into(),
        "reviewer" | "review" => "reviewer".into(),
        "senior" | "sr" | "release" => "senior".into(),
        "devops" | "sre" | "ops" => "devops".into(),
        "owner" | "admin" | "root" => "owner".into(),
        other if other.is_empty() => "builder".into(),
        other => other.into(),
    }
}

/// Node-owner role catalog. Owner can replace this on the repo; agents inherit it.
fn owner_role_catalog() -> serde_json::Value {
    serde_json::json!({
        "junior": {
            "label": "Junior engineer",
            "summary": "Codes in src/ and tests/ only. No infra, no secrets, no prod.",
            "policy": {
                "clearance": 2,
                "files": { "read": ["src/**", "tests/**", "docs/**", "*.md"], "write": ["src/**", "tests/**"] },
                "execution": {
                    "allow": ["cargo test", "cargo check", "cargo clippy", "npm test", "npm run lint", "git status", "git diff", "git add", "git commit", "git log"],
                    "deny": ["rm -rf*", "sudo*", "curl *", "wget *", "ssh *", "terraform *", "kubectl *"]
                }
            }
        },
        "builder": {
            "label": "Builder",
            "summary": "src/, tests/, docs/. Still no infra, secrets, or prod.",
            "policy": {
                "clearance": 4,
                "files": { "read": ["src/**", "tests/**", "docs/**", "*.md", "*.toml", "*.json"], "write": ["src/**", "tests/**", "docs/**"] },
                "execution": {
                    "allow": ["cargo *", "npm *", "git status", "git diff", "git add", "git commit", "git log", "git checkout*", "make"],
                    "deny": ["rm -rf*", "sudo*", "terraform *", "kubectl *"]
                }
            }
        },
        "reviewer": {
            "label": "Reviewer",
            "summary": "Read the repo. Cannot write files or run mutating commands.",
            "policy": {
                "clearance": 3,
                "files": { "read": ["src/**", "tests/**", "docs/**", "*.md"], "write": [] },
                "execution": { "allow": ["git status", "git diff", "git log", "cargo test", "cargo check"], "deny": ["git push*", "rm *", "sudo*"] }
            }
        },
        "senior": {
            "label": "Senior engineer",
            "summary": "Most of the repo except secrets. Can touch .github.",
            "policy": {
                "clearance": 7,
                "files": { "read": ["src/**", "tests/**", "docs/**", ".github/**", "*.md", "*.toml", "*.json", "*.yaml"], "write": ["src/**", "tests/**", "docs/**", ".github/**"] },
                "execution": {
                    "allow": ["cargo *", "npm *", "git *", "make"],
                    "deny": ["sudo*", "rm -rf /"]
                }
            }
        },
        "devops": {
            "label": "DevOps",
            "summary": "infra/, deploy/, .github/, Docker. Not application secrets.",
            "policy": {
                "clearance": 6,
                "files": { "read": ["infra/**", "deploy/**", ".github/**", "Dockerfile*", "docker-compose*", "*.yaml", "*.toml"], "write": ["infra/**", "deploy/**", ".github/**", "Dockerfile*", "docker-compose*"] },
                "execution": {
                    "allow": ["terraform *", "docker *", "kubectl *", "git *", "make"],
                    "deny": ["sudo rm -rf*", "cat .env*"]
                }
            }
        },
        "owner": {
            "label": "Node owner",
            "summary": "Everything except raw secret files. This is the root of the node.",
            "policy": {
                "clearance": 10,
                "files": { "read": ["**"], "write": ["**"] },
                "execution": { "allow": ["*"], "deny": [] }
            }
        }
    })
}

fn compile_policy_for_assigned_role(
    catalog: &serde_json::Value,
    role: &str,
    workspace: &str,
) -> crate::services::policy_config::DevGuardPolicy {
    use crate::services::policy_config::{DevGuardPolicy, FilePolicy, RolePolicy};
    let mut p = DevGuardPolicy::default();
    p.workspace = workspace.to_string();
    p.default_role = role.to_string();
    p.files = FilePolicy {
        hidden: vec![
            ".env".into(),
            ".env*".into(),
            "secrets/**".into(),
            "*.pem".into(),
            "*.key".into(),
        ],
        ..Default::default()
    };
    if let Some(map) = catalog.as_object() {
        for (name, entry) in map {
            let policy_v = entry
                .get("policy")
                .cloned()
                .unwrap_or_else(|| entry.clone());
            if let Ok(rp) = serde_json::from_value::<RolePolicy>(policy_v) {
                p.roles.insert(name.clone(), rp);
            }
        }
    }
    p
}

/// POST /api/v1/devguard/repos/:repo_id/roles — Node owner replaces the role catalog
/// and recompiles every attached agent's policy.
pub async fn put_owner_roles(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(repo_id): axum::extract::Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let tenant = tenant_id_from_headers(&headers);
    let key = format!("{tenant}/{repo_id}");
    let incoming = req.get("owner_roles").cloned().unwrap_or(req);
    if !incoming.is_object() {
        return Json(serde_json::json!({ "ok": false, "error": "owner_roles must be an object" }));
    }
    let now = chrono::Utc::now().to_rfc3339();
    let mut es = state.engine_store.lock().unwrap();
    let Some(mut repo) = es.folder_get("devguard_repos", &key).ok().flatten() else {
        return Json(
            serde_json::json!({ "ok": false, "error": "repo_not_found", "repo_id": repo_id }),
        );
    };
    let workspace = repo
        .get("workspace")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let agents = repo
        .get("agents")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let mut bundle_ids = Vec::new();
    for agent in &agents {
        let Some(pid) = agent.get("agent_pid").and_then(|v| v.as_str()) else {
            continue;
        };
        let role = agent
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("builder");
        let policy = compile_policy_for_assigned_role(&incoming, role, &workspace);
        let bundle_id = crate::services::policy_config::policy_bundle_id_with_source(
            &policy,
            role,
            "owner_roles_compile",
        );
        let record = serde_json::json!({
            "policy": serde_json::to_value(&policy).unwrap_or_default(),
            "role": role,
            "repo_id": repo_id,
            "tenant_id": tenant,
            "policy_bundle_id": bundle_id,
            "source": "owner_roles_compile",
            "loaded_at": now,
            "honesty": "Compiled from owner_roles catalog — not from local-profile JSON (DG-06/DG-08)",
        });
        let _ = es.folder_put("devguard_policies", pid, &record);
        crate::services::policy_config::store_policy_version(es.as_mut(), pid, &record);
        bundle_ids.push(serde_json::json!({ "agent_pid": pid, "policy_bundle_id": bundle_id }));
    }
    if let Some(obj) = repo.as_object_mut() {
        obj.insert("owner_roles".into(), incoming.clone());
        obj.insert("updated_at".into(), serde_json::json!(now));
        obj.insert(
            "policy_schema".into(),
            serde_json::json!("connector.devguard_policy_bundle.v1"),
        );
    }
    let _ = es.folder_put("devguard_repos", &key, &repo);
    Json(serde_json::json!({
        "ok": true,
        "repo_id": repo_id,
        "owner_roles": incoming,
        "agents_recompiled": agents.len(),
        "bundles": bundle_ids,
        "schema": "connector.devguard_policy_bundle.v1",
    }))
}

fn generate_scaffold(repo_id: &str) -> serde_json::Value {
    serde_json::json!({
        "kind": "generated",
        "files": {
            "README.md": format!("# {repo_id}\n\nUnder Connector DevGuard. No agent ID + role → even read is denied. Ask the node for an identity.\n"),
            ".devguard/IDENTITY": "Ask POST /api/v1/devguard/admit for a Connector agent ID + role.\n",
            "devguard.yaml": "# Run `devguard init` in this folder to write the full policy.\nworkspace: {repo_id}\n",
        },
        "git": "Workspace git lives on this node. POST /api/v1/devguard/repos/:id/git/commit — do not git init a laptop clone as the working copy.",
    })
}

/// GET /api/v1/devguard/audit/:session_id — Get audit trail
pub async fn audit_trail(
    State(state): State<SharedState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let es = state.engine_store.lock().unwrap();
    let keys = es
        .folder_keys("devguard_audit", Some(&session_id))
        .unwrap_or_default();
    let all: Vec<serde_json::Value> = keys
        .iter()
        .filter_map(|k| es.folder_get("devguard_audit", k).ok().flatten())
        .collect();

    let entries: Vec<&serde_json::Value> = all
        .iter()
        .filter(|e| e.get("session_id").and_then(|v| v.as_str()) == Some(&session_id))
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "session_id": session_id,
        "entries": entries,
        "count": entries.len(),
    }))
}

// ── Helper functions ───────────────────────────────────────────────────────

fn update_session_stat(
    state: &SharedState,
    agent_pid: &str,
    update: impl FnOnce(&mut SessionStats),
) {
    let session_id = find_session_for_agent(state, agent_pid).unwrap_or_default();
    if session_id.is_empty() {
        return;
    }

    let mut es = state.engine_store.lock().unwrap();
    if let Ok(Some(data)) = es.folder_get("devguard_sessions", &session_id) {
        if let Ok(mut session) = serde_json::from_value::<DevGuardSession>(data) {
            update(&mut session.stats);
            let _ = es.folder_put(
                "devguard_sessions",
                &session_id,
                &serde_json::to_value(&session).unwrap_or_default(),
            );
        }
    }
}

/// Record an LLM call in session stats and audit.
pub fn record_llm_call(
    state: &SharedState,
    session_id: &str,
    agent_pid: &str,
    input_tokens: u32,
    output_tokens: u32,
) {
    update_session_stat(state, agent_pid, |s| {
        s.llm_calls += 1;
        s.tokens_consumed += (input_tokens + output_tokens) as u64;
    });
    record_audit(
        state,
        session_id,
        "llm.call",
        &serde_json::json!({
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        }),
    );
}

fn find_session_for_agent(state: &SharedState, agent_pid: &str) -> Option<String> {
    let es = state.engine_store.lock().unwrap();
    let keys = es
        .folder_keys("devguard_sessions", None)
        .unwrap_or_default();
    for k in &keys {
        if let Ok(Some(s)) = es.folder_get("devguard_sessions", k) {
            if s.get("agent_pid").and_then(|v| v.as_str()) == Some(agent_pid) {
                return s
                    .get("session_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bind(project: &str) -> (String, String, String) {
        resolve_project_bind(&serde_json::json!({ "project": project })).expect("bind")
    }

    #[test]
    fn github_url_is_the_repo() {
        let (ws, kind, url) = bind("https://github.com/acme/checkout");
        assert_eq!(kind, "github_checkout");
        assert_eq!(url, "https://github.com/acme/checkout");
        assert_eq!(ws, "/projects/acme-checkout");
    }

    #[test]
    fn org_repo_is_github() {
        let (ws, kind, url) = bind("acme/checkout");
        assert_eq!(kind, "github_checkout");
        assert_eq!(url, "https://github.com/acme/checkout");
        assert_eq!(ws, "/projects/acme-checkout");
    }

    #[test]
    fn project_name_still_works() {
        let (ws, kind, url) = bind("checkout");
        assert_eq!(kind, "local_folder");
        assert!(url.is_empty());
        assert_eq!(ws, "/projects/checkout");
    }

    #[test]
    fn generate_is_a_new_repo() {
        let (ws, kind, url) = resolve_project_bind(&serde_json::json!({
            "project": "acme-api",
            "generate": true,
        }))
        .expect("generate");
        assert_eq!(kind, "generated");
        assert!(url.is_empty());
        assert_eq!(ws, "/projects/acme-api");
    }

    #[test]
    fn junior_cannot_write_infra_or_secrets() {
        let catalog = owner_role_catalog();
        let p = compile_policy_for_assigned_role(&catalog, "junior", "/projects/acme");
        assert!(!p.check_file("junior", "write", "infra/prod.tf").allowed);
        assert!(!p.check_file("junior", "write", ".env").allowed);
        assert!(!p.check_file("junior", "read", "secrets/api.pem").allowed);
        assert!(p.check_file("junior", "write", "src/lib.rs").allowed);
        assert!(p.check_file("junior", "read", "src/lib.rs").allowed);
        assert!(!p.check_exec("junior", "sudo rm -rf /").allowed);
        assert!(p.check_exec("junior", "cargo test").allowed);
    }

    #[test]
    fn senior_and_devops_and_reviewer_differ() {
        let catalog = owner_role_catalog();
        let senior = compile_policy_for_assigned_role(&catalog, "senior", "/projects/acme");
        let devops = compile_policy_for_assigned_role(&catalog, "devops", "/projects/acme");
        let reviewer = compile_policy_for_assigned_role(&catalog, "reviewer", "/projects/acme");
        assert!(senior.check_file("senior", "write", "src/lib.rs").allowed);
        assert!(
            senior
                .check_file("senior", "write", ".github/workflows/ci.yml")
                .allowed
        );
        assert!(
            !reviewer
                .check_file("reviewer", "write", "src/lib.rs")
                .allowed
        );
        assert!(
            reviewer
                .check_file("reviewer", "read", "src/lib.rs")
                .allowed
        );
        assert!(
            devops
                .check_file("devops", "write", "infra/prod.tf")
                .allowed
        );
        assert!(!devops.check_file("devops", "write", "src/lib.rs").allowed);
        assert!(!senior.check_file("senior", "read", ".env.local").allowed);
    }

    #[test]
    fn no_identity_cannot_even_read_a_linked_repo() {
        assert_eq!(
            evaluate_admit(false, None, Some("acme")),
            Err("ask_connector_for_identity")
        );
        assert_eq!(
            evaluate_admit(true, Some("acme"), Some("other")),
            Err("not_admitted_to_repo")
        );
        assert!(evaluate_admit(true, Some("acme"), Some("acme")).is_ok());
        assert!(evaluate_admit(true, Some("acme"), None).is_ok());
        assert!(evaluate_admit(false, None, None).is_ok());
        assert!(must_require_identity(true, false, false));
        assert!(must_require_identity(false, true, false));
        assert!(must_require_identity(false, false, true));
        assert!(!must_require_identity(false, false, false));
        let mut h = HeaderMap::new();
        h.insert("x-connector-repo", "acme".parse().unwrap());
        assert_eq!(infer_claimed_repo(&h).as_deref(), Some("acme"));
    }

    #[test]
    fn connect_json_has_no_key_until_attach() {
        let j = repo_connector_json("https://node.example", None, "acme", "/ws", "");
        assert!(j.get("api_key").is_some_and(|v| v.is_null()));
        assert_eq!(
            j.get("attach_required").and_then(|v| v.as_bool()),
            Some(true)
        );
        let j2 = repo_connector_json("https://node.example", Some("cg_abc"), "acme", "/ws", "");
        assert!(j2.get("api_key").is_some_and(|v| v.is_null()));
        assert_eq!(
            j2.get("attach_required").and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn cg_token_record_binds_expiry_scopes_and_tool_class() {
        let rec = cg_token_record(
            "dg_abc",
            "devguard-cursor-abc",
            "builder",
            "acme",
            "tenant-1",
            "cursor",
            default_cg_scopes(),
        );
        assert_eq!(rec.get("revoked").and_then(|v| v.as_bool()), Some(false));
        assert!(
            rec.get("expires_at").and_then(|v| v.as_i64()).unwrap()
                > chrono::Utc::now().timestamp()
        );
        assert_eq!(
            rec.get("identity_kind").and_then(|v| v.as_str()),
            Some("connector_agent_principal")
        );
        assert_eq!(
            rec.get("tool_class").and_then(|v| v.as_str()),
            Some("coding_agent")
        );
        assert_eq!(rec.get("repo_id").and_then(|v| v.as_str()), Some("acme"));
        assert_eq!(
            rec.get("tenant_id").and_then(|v| v.as_str()),
            Some("tenant-1")
        );
        let scopes = rec.get("scopes").and_then(|v| v.as_array()).unwrap();
        assert!(scopes
            .iter()
            .any(|s| s.as_str() == Some("devguard:workspace")));
        assert!(mint_cg_token().starts_with("cg_"));
    }

    #[test]
    fn devguard_http_contract_matches_cli_expectations() {
        let paths: Vec<&str> = devguard_http_contract().iter().map(|(_, p)| *p).collect();
        assert!(paths.contains(&"/api/v1/devguard/sessions"));
        assert!(paths.contains(&"/api/v1/devguard/sessions/:session_id/end"));
        assert!(paths.contains(&"/api/v1/devguard/fs/check"));
        assert!(paths.contains(&"/api/v1/devguard/exec/check"));
        assert!(paths.contains(&"/api/v1/devguard/policy/check"));
        assert!(paths.contains(&"/api/v1/devguard/connect"));
        assert!(paths.contains(&"/api/v1/devguard/github/status"));
        assert!(paths.contains(&"/api/v1/devguard/github/checks/evaluate"));
        assert!(!paths.iter().any(|p| p.contains("/devguard/session/start")));
        assert!(!paths
            .iter()
            .any(|p| *p == "/api/v1/devguard/audit/:session_id"));
    }

    #[test]
    fn devguard_http_contract_paths_are_mounted_in_router() {
        let router = include_str!("../router.rs");
        // Param names differ (`:session_id` vs `:id`); compare shape only.
        let normalize = |path: &str| -> String {
            path.split('/')
                .map(|s| if s.starts_with(':') { ":" } else { s })
                .collect::<Vec<_>>()
                .join("/")
        };
        let mounted: Vec<String> = router
            .lines()
            .filter_map(|line| {
                let t = line.trim();
                let start = t.find("\"/api/v1/devguard")?;
                let rest = &t[start + 1..];
                let end = rest.find('"')?;
                Some(normalize(&rest[..end]))
            })
            .collect();
        for (method, path) in devguard_http_contract() {
            let shape = normalize(path);
            assert!(
                mounted.iter().any(|m| m == &shape),
                "router must mount {method} {path} (shape={shape})"
            );
        }
    }

    /// Demo repo: junior Cursor on acme-demo. Some folders must not open.
    #[test]
    fn demo_repo_junior_cannot_access_locked_folders() {
        let catalog = owner_role_catalog();
        let junior = compile_policy_for_assigned_role(&catalog, "junior", "/workspace/acme-demo");
        let files = [
            ("src/lib.rs", "read", true),
            ("src/lib.rs", "write", true),
            ("tests/smoke.rs", "read", true),
            ("tests/smoke.rs", "write", true),
            ("docs/guide.md", "read", true),
            ("docs/guide.md", "write", false),
            ("README.md", "read", true),
            ("README.md", "write", false),
            ("infra/prod.tf", "read", false),
            ("infra/prod.tf", "write", false),
            ("deploy/k8s.yaml", "read", false),
            ("deploy/k8s.yaml", "write", false),
            (".env", "read", false),
            (".env", "write", false),
            (".env.local", "read", false),
            ("secrets/api.pem", "read", false),
            ("secrets/api.pem", "write", false),
        ];
        let mut failed = 0usize;
        println!("\n=== DEMO repo acme-demo · junior ===");
        for (path, op, want) in files {
            let got = junior.check_file("junior", op, path).allowed;
            let mark = if got == want { "OK" } else { "FAIL" };
            if got != want {
                failed += 1;
            }
            println!(
                "  [{mark}] {op:5} {path:22} → {} (want {})",
                if got { "ALLOW" } else { "DENY" },
                if want { "ALLOW" } else { "DENY" }
            );
        }
        let no_id = crate::services::devguard_workspace::workspace_file_gate(
            None,
            "acme-demo",
            &crate::services::policy_config::PermissionCheck::allow("n/a"),
        );
        println!(
            "  [{}] no cg_ token read           → {:?}",
            if no_id == Err("ask_connector_for_identity") {
                "OK"
            } else {
                "FAIL"
            },
            no_id
        );
        if no_id != Err("ask_connector_for_identity") {
            failed += 1;
        }
        let other = crate::services::devguard::AdmittedIdentity {
            session_id: "dg_other".into(),
            agent_pid: "cursor-other".into(),
            role: "junior".into(),
            repo_id: "other-repo".into(),
            tenant_id: "pg-demo".into(),
            scopes: vec!["devguard:workspace".into()],
            tool: "cursor".into(),
        };
        let cross = crate::services::devguard_workspace::workspace_file_gate(
            Some(&other),
            "acme-demo",
            &crate::services::policy_config::PermissionCheck::allow("n/a"),
        );
        println!(
            "  [{}] token for other-repo        → {:?}",
            if cross == Err("not_admitted_to_repo") {
                "OK"
            } else {
                "FAIL"
            },
            cross
        );
        if cross != Err("not_admitted_to_repo") {
            failed += 1;
        }
        println!(
            "=== {} ===\n",
            if failed == 0 {
                "DEMO 100% — locked folders hold"
            } else {
                "DEMO FAILED"
            }
        );
        assert_eq!(
            failed, 0,
            "demo repo access matrix failed {failed} check(s)"
        );
    }
}
