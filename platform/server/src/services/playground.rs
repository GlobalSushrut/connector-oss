//! Playground session service — vendor-hosted SaaS trial mode
//!
//! Provides ephemeral sessions so anyone can try Connector OS without installing.
//! Each session gets:
//!   - A unique `tenant_id` (namespace isolation — agents/memory/workflows are per-session)
//!   - A scoped `cpk_*` API key valid for `session_ttl_secs` (default 90 min)
//!   - Hard caps on agents, LLM token budget, and concurrent sessions
//!
//! Routes (wired in router.rs):
//!   POST   /api/v1/playground/session          — start session (email required; isolated tenant + 1 demo agent)
//!   GET    /api/v1/playground/session/:id       — session status + remaining TTL
//!   DELETE /api/v1/playground/session/:id       — end session early
//!   GET    /api/v1/playground/status            — node-level playground info (caps, active count)
//!
//! Guard (`is_playground_mode`):
//!   Returns true when CONNECTOR_PLAYGROUND=1. Used by middleware to enforce caps.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::state::SharedState;

// ── Types ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaygroundSession {
    pub session_id: String,
    pub tenant_id: String,
    /// Scoped cpk_* API key — returned once at creation, not re-derivable
    pub api_key: String,
    pub created_at: u64,  // unix secs
    pub expires_at: u64,  // unix secs
    pub last_active: u64, // unix secs (updated on each request)
    pub email: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    pub agents_created: u32,
    pub tokens_used: u64,
    #[serde(default)]
    pub agent_pids: Vec<String>,
    /// Operator deleted the last agent — do not auto-seed Demo again.
    #[serde(default)]
    pub agents_cleared_by_user: bool,
    #[serde(default)]
    pub workflow_ids: Vec<String>,
    #[serde(default)]
    pub cleanup: Option<PlaygroundCleanupReceipt>,
    pub ended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlaygroundCleanupReceipt {
    pub cleaned_at: u64,
    pub agents_deleted: u32,
    pub workflows_deleted: u32,
    pub memory_keys_deleted: u32,
    pub folders_deleted: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PlaygroundEmailLedgerEntry {
    sessions_started: u32,
    last_started_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlaygroundQueueEntry {
    email: String,
    label: Option<String>,
    enqueued_at: u64,
    last_seen_at: u64,
}

/// In-memory session store; persisted to CONNECTOR_DATA_DIR/playground/sessions.json
/// so keys survive process restarts (Fly deploys) until TTL expiry.
pub type PlaygroundStore = Arc<Mutex<HashMap<String, PlaygroundSession>>>;

fn sessions_file() -> PathBuf {
    let base = std::env::var("CONNECTOR_DATA_DIR").unwrap_or_else(|_| "./data".into());
    PathBuf::from(base).join("playground").join("sessions.json")
}

fn ledger_file() -> PathBuf {
    let base = std::env::var("CONNECTOR_DATA_DIR").unwrap_or_else(|_| "./data".into());
    PathBuf::from(base).join("playground").join("quota_ledger.json")
}

fn queue_file() -> PathBuf {
    let base = std::env::var("CONNECTOR_DATA_DIR").unwrap_or_else(|_| "./data".into());
    PathBuf::from(base).join("playground").join("wait_queue.json")
}

fn load_sessions_from_disk() -> HashMap<String, PlaygroundSession> {
    let path = sessions_file();
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return HashMap::new();
    };
    match serde_json::from_str::<HashMap<String, PlaygroundSession>>(&raw) {
        Ok(map) => {
            let now = now_secs();
            let active: HashMap<String, PlaygroundSession> = map
                .into_iter()
                .filter(|(_, s)| !s.ended && s.expires_at > now)
                .collect();
            tracing::info!(
                path = %path.display(),
                active = active.len(),
                "playground: restored sessions from disk"
            );
            active
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "playground: could not parse sessions file — starting fresh");
            HashMap::new()
        }
    }
}

/// Write sessions to disk. Caller must not hold `store`'s mutex (use
/// `persist_sessions_unlocked` when the lock is already held).
pub fn persist_sessions(store: &PlaygroundStore) {
    let Ok(sessions) = store.lock() else { return };
    persist_sessions_unlocked(&sessions);
}

/// Persist while the store mutex is already held (avoids re-entrant deadlock).
pub fn persist_sessions_unlocked(sessions: &HashMap<String, PlaygroundSession>) {
    let path = sessions_file();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(sessions) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                tracing::warn!(path = %path.display(), error = %e, "playground: failed to persist sessions");
            }
        }
        Err(e) => tracing::warn!(error = %e, "playground: failed to serialize sessions"),
    }
}

pub fn new_store() -> PlaygroundStore {
    Arc::new(Mutex::new(load_sessions_from_disk()))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn is_playground_mode() -> bool {
    std::env::var("CONNECTOR_PLAYGROUND")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn lock_sessions(
    store: &PlaygroundStore,
) -> Result<MutexGuard<'_, HashMap<String, PlaygroundSession>>, Response> {
    store.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": "session store unavailable"})),
        )
            .into_response()
    })
}

/// Session id from a playground JWT (`pg_…` / `playground_key`).
pub fn playground_session_id_from_headers(headers: &HeaderMap) -> Option<String> {
    let claims = crate::auth::extract_claims(headers)?;
    if claims.token_type == "playground_key" || claims.sub.starts_with("pg_") {
        Some(claims.sub)
    } else {
        None
    }
}

fn session_ttl_secs() -> u64 {
    std::env::var("CONNECTOR_PLAYGROUND_SESSION_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5400) // 90 minutes
}

fn queue_wait_secs() -> u64 {
    std::env::var("CONNECTOR_PLAYGROUND_QUEUE_WAIT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1800)
}

fn session_limit_per_email() -> u32 {
    std::env::var("CONNECTOR_PLAYGROUND_SESSION_LIMIT_PER_EMAIL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3)
}

fn privileged_emails() -> HashSet<String> {
    std::env::var("CONNECTOR_PLAYGROUND_UNLIMITED_EMAILS")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "umeshlamton@gmail.com".into())
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn max_agents() -> u32 {
    std::env::var("CONNECTOR_PLAYGROUND_MAX_AGENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
}

pub fn max_sessions() -> usize {
    std::env::var("CONNECTOR_PLAYGROUND_MAX_SESSIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10)
}

/// Kernel-wide agent pool so each session can hold `max_agents()` without
/// the Indie node license (3 total) starving later visitors.
pub fn kernel_agent_pool_cap() -> u32 {
    std::env::var("CONNECTOR_PLAYGROUND_KERNEL_AGENT_CAP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            max_agents()
                .saturating_mul(max_sessions() as u32)
                .saturating_mul(3)
                .max(64)
        })
}

pub fn token_budget() -> u64 {
    std::env::var("CONNECTOR_PLAYGROUND_TOKEN_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn generate_session_id() -> String {
    format!("pg_{}", uuid::Uuid::new_v4().simple())
}

fn generate_api_key(_session_id: &str) -> String {
    format!("cpk_pg_{}", uuid::Uuid::new_v4().simple())
}

fn secs_to_iso(secs: u64) -> String {
    // Simple ISO 8601 without chrono dependency (playground doesn't need timezone)
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .unwrap_or_else(chrono::Utc::now);
    dt.to_rfc3339()
}

fn load_json_file<T: for<'de> Deserialize<'de> + Default>(path: &PathBuf) -> T {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return T::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn persist_json_file<T: Serialize>(path: &PathBuf, value: &T, what: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(value) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, json) {
                tracing::warn!(path = %path.display(), error = %e, target = what, "playground: failed to persist state");
            }
        }
        Err(e) => tracing::warn!(error = %e, target = what, "playground: failed to serialize state"),
    }
}

fn load_ledger() -> HashMap<String, PlaygroundEmailLedgerEntry> {
    load_json_file(&ledger_file())
}

fn persist_ledger(ledger: &HashMap<String, PlaygroundEmailLedgerEntry>) {
    persist_json_file(&ledger_file(), ledger, "quota ledger");
}

fn load_queue() -> Vec<PlaygroundQueueEntry> {
    load_json_file(&queue_file())
}

fn persist_queue(queue: &[PlaygroundQueueEntry]) {
    persist_json_file(&queue_file(), &queue, "wait queue");
}

fn email_has_unlimited_access(email: &str) -> bool {
    privileged_emails().contains(&email.trim().to_ascii_lowercase())
}

fn queue_position(queue: &[PlaygroundQueueEntry], email: &str) -> Option<usize> {
    queue.iter()
        .position(|e| e.email.eq_ignore_ascii_case(email))
        .map(|i| i + 1)
}

fn prune_queue(queue: &mut Vec<PlaygroundQueueEntry>, now: u64) {
    let max_age = queue_wait_secs();
    queue.retain(|q| now.saturating_sub(q.last_seen_at.max(q.enqueued_at)) <= max_age);
}

fn queue_allows_email(queue: &[PlaygroundQueueEntry], email: &str) -> bool {
    queue.is_empty() || queue.first().map(|q| q.email.eq_ignore_ascii_case(email)).unwrap_or(false)
}

fn session_quota_payload(email: &str, ledger: &HashMap<String, PlaygroundEmailLedgerEntry>) -> Value {
    let unlimited = email_has_unlimited_access(email);
    let used = ledger.get(email).map(|x| x.sessions_started).unwrap_or(0);
    let limit = session_limit_per_email();
    let remaining = if unlimited {
        None
    } else {
        Some(limit.saturating_sub(used))
    };
    json!({
        "email": email,
        "unlimited": unlimited,
        "sessions_started": used,
        "session_limit": if unlimited { Value::Null } else { json!(limit) },
        "sessions_remaining": remaining,
    })
}

fn session_to_public_with_quota(
    s: &PlaygroundSession,
    ledger: &HashMap<String, PlaygroundEmailLedgerEntry>,
) -> Value {
    let mut payload = session_to_public(s);
    if let Some(email) = s.email.as_deref() {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("quota".into(), session_quota_payload(email, ledger));
        }
    }
    payload
}

/// Drop one playground agent from kernel + engine_store (intelligence folders, meta maps).
pub fn purge_playground_agent(state: &SharedState, api_pid: &str) -> u32 {
    if api_pid.trim().is_empty() {
        return 0;
    }
    let kernel_pid = {
        let es = state.engine_store.lock().unwrap();
        es.folder_get("agent_meta", api_pid)
            .ok()
            .flatten()
            .and_then(|m| {
                m.get("kernel_pid")
                    .and_then(|x| x.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| api_pid.to_string())
    };
    let purge = crate::kernel::intelligence_purge::purge_intelligence(
        state.as_ref(),
        api_pid,
        &kernel_pid,
    );
    let folders = purge
        .get("deleted_folders")
        .and_then(|v| v.as_array())
        .map(|a| a.len() as u32)
        .unwrap_or(0);
    {
        let mut k = state.kernel.lock().unwrap();
        let _ = k.remove_agent(&kernel_pid);
    }
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_delete("agent_meta", api_pid);
    let _ = es.folder_delete("agent_cost_ledger", api_pid);
    let _ = es.folder_delete("agent_pid_map", &kernel_pid);
    folders.saturating_add(1)
}

fn cleanup_session_resources(state: &SharedState, session: &PlaygroundSession) -> PlaygroundCleanupReceipt {
    let mut receipt = PlaygroundCleanupReceipt {
        cleaned_at: now_secs(),
        ..PlaygroundCleanupReceipt::default()
    };
    let mut deleted_folders = 0_u32;
    let mut deleted_workflows = 0_u32;
    let mut deleted_memory = 0_u32;
    {
        let mut es = state.engine_store.lock().unwrap();
        for workflow_id in &session.workflow_ids {
            for folder in [
                "workflow_runtime",
                "workflow_runtime_versions",
                "workflow_runtime_dry_run_index",
                crate::operator::surface_merge::OPERATOR_SURFACE_FOLDER,
            ] {
                if es.folder_get(folder, workflow_id).ok().flatten().is_some() {
                    let _ = es.folder_delete(folder, workflow_id);
                    deleted_folders = deleted_folders.saturating_add(1);
                }
            }
            deleted_workflows = deleted_workflows.saturating_add(1);
        }
        if let Ok(keys) = es.folder_keys("memory", None) {
            for key in keys {
                if let Ok(Some(v)) = es.folder_get("memory", &key) {
                    let ns = v.get("namespace").and_then(|x| x.as_str()).unwrap_or("");
                    if ns.contains(&session.tenant_id) {
                        let _ = es.folder_delete("memory", &key);
                        deleted_memory = deleted_memory.saturating_add(1);
                    }
                }
            }
        }
    }
    receipt.workflows_deleted = deleted_workflows;
    receipt.memory_keys_deleted = deleted_memory;
    receipt.folders_deleted = deleted_folders;
    for api_pid in &session.agent_pids {
        let folders = purge_playground_agent(state, api_pid);
        receipt.folders_deleted = receipt.folders_deleted.saturating_add(folders);
        receipt.agents_deleted = receipt.agents_deleted.saturating_add(1);
    }
    receipt
}

/// Expired sessions dropped at load never ran cleanup — purge their agents on boot.
pub fn cleanup_expired_sessions_on_disk(state: &SharedState) -> usize {
    let path = sessions_file();
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return 0;
    };
    let Ok(map) = serde_json::from_str::<HashMap<String, PlaygroundSession>>(&raw) else {
        return 0;
    };
    let now = now_secs();
    let mut cleaned = 0_usize;
    let mut active = HashMap::new();
    for (id, s) in map {
        if s.ended || s.expires_at <= now {
            let receipt = cleanup_session_resources(state, &s);
            tracing::info!(
                session_id = %s.session_id,
                tenant_id = %s.tenant_id,
                agents_deleted = receipt.agents_deleted,
                "playground: cleaned expired session skipped at load"
            );
            cleaned = cleaned.saturating_add(1);
        } else {
            active.insert(id, s);
        }
    }
    if cleaned > 0 {
        persist_sessions_unlocked(&active);
        if let Ok(mut sessions) = state.playground_sessions.lock() {
            *sessions = active;
        }
    }
    cleaned
}

/// Agent pids owned by live (non-expired) playground sessions.
pub fn protected_playground_agent_pids(store: &PlaygroundStore) -> HashSet<String> {
    let now = now_secs();
    let Ok(sessions) = store.lock() else {
        return HashSet::new();
    };
    sessions
        .values()
        .filter(|s| !s.ended && s.expires_at > now)
        .flat_map(|s| s.agent_pids.iter().cloned())
        .filter(|p| !p.trim().is_empty())
        .collect()
}

fn reap_inactive_sessions(state: &SharedState, sessions: &mut HashMap<String, PlaygroundSession>) -> usize {
    let now = now_secs();
    let expired: Vec<String> = sessions
        .iter()
        .filter(|(_, s)| s.ended || s.expires_at <= now)
        .map(|(id, _)| id.clone())
        .collect();
    let mut cleaned = 0_usize;
    for id in expired {
        if let Some(mut s) = sessions.remove(&id) {
            s.cleanup = Some(cleanup_session_resources(state, &s));
            cleaned += 1;
        }
    }
    cleaned
}

/// Reap expired/ended sessions with full resource cleanup (agents, memory, workflows).
pub fn reap_expired_sessions(state: &SharedState) -> usize {
    let Ok(mut sessions) = state.playground_sessions.lock() else {
        return 0;
    };
    let cleaned = reap_inactive_sessions(state, &mut sessions);
    if cleaned > 0 {
        persist_sessions_unlocked(&sessions);
    }
    cleaned
}

fn session_to_public(s: &PlaygroundSession) -> Value {
    let now = now_secs();
    let remaining = if s.expires_at > now {
        s.expires_at - now
    } else {
        0
    };
    json!({
        "session_id": s.session_id,
        "tenant_id": s.tenant_id,
        "created_at": secs_to_iso(s.created_at),
        "expires_at": secs_to_iso(s.expires_at),
        "remaining_secs": remaining,
        "ended": s.ended || remaining == 0,
        "agents_created": s.agents_created,
        "tokens_used": s.tokens_used,
        "workflow_count": s.workflow_ids.len(),
        "agent_pids": s.agent_pids.clone(),
        "cleanup": s.cleanup.clone(),
        "token_budget": token_budget(),
        "max_agents": max_agents(),
        "caps": {
            "max_agents": max_agents(),
            "token_budget": token_budget(),
            "session_ttl_secs": session_ttl_secs(),
        }
    })
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct StartSessionRequest {
    /// Optional — used for "remember my session" and abuse control
    pub email: Option<String>,
    /// Visitor-supplied label (e.g. "Jordan testing TraceTramp")
    pub label: Option<String>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /api/v1/playground/session
/// Creates a new playground session. Returns api_key exactly once.
pub async fn start_session(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    body: Option<Json<StartSessionRequest>>,
) -> Response {
    if !is_playground_mode() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "playground mode not enabled on this node (CONNECTOR_PLAYGROUND=1 required)"})),
        ).into_response();
    }

    let store = state.playground_sessions.clone();
    let mut sessions = match lock_sessions(&store) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let mut ledger = load_ledger();
    let mut queue = load_queue();

    // Expire stale sessions first and drop abandoned queue entries.
    let now = now_secs();
    let ttl = session_ttl_secs();
    let _ = reap_inactive_sessions(&state, &mut sessions);
    prune_queue(&mut queue, now);

    let req = body.map(|b| b.0).unwrap_or(StartSessionRequest {
        email: None,
        label: None,
    });
    let email = req
        .email
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| s.contains('@') && s.contains('.'));
    if email.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "email is required — each email gets its own 90-minute playground",
                "code": "PLAYGROUND_EMAIL_REQUIRED",
            })),
        )
            .into_response();
    }
    let email = email.unwrap();

    let quota = session_quota_payload(&email, &ledger);
    let unlimited = quota.get("unlimited").and_then(|v| v.as_bool()) == Some(true);
    let remaining = quota
        .get("sessions_remaining")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if !unlimited && remaining == 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "error": "trial quota exhausted for this email",
                "code": "PLAYGROUND_QUOTA_EXHAUSTED",
                "quota": quota,
            })),
        )
            .into_response();
    }

    let active_sessions = sessions.len();
    let current_queue_pos = queue_position(&queue, &email);
    let queue_has_others = !queue_allows_email(&queue, &email);
    let should_queue = active_sessions >= max_sessions() || queue_has_others;
    if should_queue {
        let position = if let Some(pos) = current_queue_pos {
            if let Some(entry) = queue.iter_mut().find(|q| q.email.eq_ignore_ascii_case(&email)) {
                entry.last_seen_at = now;
            }
            pos
        } else {
            queue.push(PlaygroundQueueEntry {
                email: email.clone(),
                label: req.label.clone(),
                enqueued_at: now,
                last_seen_at: now,
            });
            queue.len()
        };
        persist_queue(&queue);
        persist_ledger(&ledger);
        persist_sessions_unlocked(&sessions);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "ok": false,
                "queued": true,
                "error": format!(
                    "{} people are already in session — please wait in queue (max {})",
                    active_sessions,
                    max_sessions()
                ),
                "code": "PLAYGROUND_QUEUED",
                "queue_position": position,
                "active_sessions": active_sessions,
                "max_sessions": max_sessions(),
                "quota": quota,
                "hint": "Retry start session while this page is open. When your email reaches the front and a slot is free, Connector will open your 90-minute isolated playground.",
            })),
        ).into_response();
    }

    queue.retain(|q| !q.email.eq_ignore_ascii_case(&email));

    // Same email may start again: always a new tenant (isolated sandbox of the same software).
    let session_id = generate_session_id();
    let tenant_id = format!("pg-{}", &session_id[3..11]);
    let api_key = generate_api_key(&session_id);

    let session = PlaygroundSession {
        session_id: session_id.clone(),
        tenant_id: tenant_id.clone(),
        api_key: api_key.clone(),
        created_at: now,
        expires_at: now + ttl,
        last_active: now,
        email: Some(email.clone()),
        label: req.label.clone(),
        agents_created: 0,
        tokens_used: 0,
        agent_pids: Vec::new(),
        agents_cleared_by_user: false,
        workflow_ids: Vec::new(),
        cleanup: None,
        ended: false,
    };

    sessions.insert(session_id.clone(), session.clone());
    let entry = ledger.entry(email.clone()).or_default();
    entry.sessions_started = entry.sessions_started.saturating_add(1);
    entry.last_started_at = now;
    persist_ledger(&ledger);
    persist_queue(&queue);
    persist_sessions_unlocked(&sessions);
    drop(sessions);

    let reaped = reap_expired_sessions(&state);
    let compacted = crate::services::agents::compact_stale_playground_agents(&state);
    crate::services::agents::compact_orphan_kernel_agents(&state);
    if reaped > 0 || compacted > 0 {
        tracing::info!(
            reaped,
            compacted,
            cap = kernel_agent_pool_cap(),
            "playground: pre-seed hygiene before demo agent mint"
        );
        state.refresh_health_snapshot();
    }

    crate::services::workflow_runtime::seed_devguard_cage_workflow(&state);
    // Default: one demo Talk agent per session. SEED_TRIO remains opt-in lab.
    let seed_trio = std::env::var("CONNECTOR_PLAYGROUND_SEED_TRIO")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let seed_demo = std::env::var("CONNECTOR_PLAYGROUND_SEED_DEMO")
        .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false")))
        .unwrap_or(true);
    let agents = if seed_trio {
        crate::services::agents::provision_playground_trio(&state, &tenant_id, &session_id)
    } else if seed_demo {
        crate::services::agents::provision_playground_demo(&state, &tenant_id, &session_id)
    } else {
        Vec::new()
    };
    let agent_pids: Vec<String> = agents
        .iter()
        .filter_map(|a| a.get("pid").and_then(|x| x.as_str()).map(str::to_string))
        .collect();
    if !agents.is_empty() {
        if let Ok(mut sessions) = store.lock() {
            if let Some(s) = sessions.get_mut(&session_id) {
                s.agents_created = agents.len() as u32;
                s.agent_pids = agent_pids.clone();
            }
            persist_sessions_unlocked(&sessions);
        }
    } else if seed_demo || seed_trio {
        tracing::error!(
            session_id = %session_id,
            tenant_id = %tenant_id,
            "playground: demo agent seed failed — session has no Talk agent"
        );
        // Fail loud: remove the empty session so the visitor can retry instead of a dead UI.
        if let Ok(mut sessions) = store.lock() {
            sessions.remove(&session_id);
            persist_sessions_unlocked(&sessions);
        }
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "error": "playground_demo_seed_failed",
                "hint": "Kernel agent pool may be full — wait for reaper compact, then retry POST /playground/session",
            })),
        )
            .into_response();
    }

    let node_public_url = std::env::var("CONNECTOR_PUBLIC_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let host = std::env::var("CONNECTOR_HOST").unwrap_or_else(|_| "127.0.0.1".into());
            let port = std::env::var("CONNECTOR_PORT").unwrap_or_else(|_| "9091".into());
            format!("http://{host}:{port}")
        });

    let demo_pid = agent_pids.first().cloned().unwrap_or_default();
    let mut next_steps = vec![
        format!("Open dashboard: {node_public_url}/run"),
        "Your session is a private tenant — other playground visitors cannot see your agents or memory.".into(),
        "Set header Authorization: Bearer <api_key> on API calls".into(),
        format!("JWT tenant_id is {tenant_id}. Do not send a mismatched X-Tenant-Id."),
    ];
    if !demo_pid.is_empty() {
        next_steps.insert(
            1,
            format!(
                "Open agent {demo_pid} → Workbench. Score / Hold / Decide / Ledger (and Isolate / Prove) need no LLM key. Admit runs PATE → ToolDispatch. Cease fences the generation."
            ),
        );
    }

    Json(json!({
        "ok": true,
        "session_id": session_id,
        "tenant_id": tenant_id,
        "owner_email": email,
        // api_key is returned ONCE here — not stored retrievable again
        "api_key": api_key,
        "expires_at": secs_to_iso(session.expires_at),
        "remaining_secs": ttl,
        "quota": session_quota_payload(&email, &ledger),
        "caps": {
            "max_agents": max_agents(),
            "token_budget": token_budget(),
            "session_ttl_secs": ttl,
            "max_concurrent_sessions": max_sessions(),
            "isolation": "tenant_namespace — each session is a private sandbox of the same software; no cross-session visibility",
        },
        "node": {
            "public_url": node_public_url,
            "api_url": format!("{node_public_url}/api/v1"),
            "gateway_url": format!("{node_public_url}/v1"),
            "dashboard_url": node_public_url.clone(),
        },
        "agents": agents,
        "demo_agent_pid": if demo_pid.is_empty() { Value::Null } else { json!(demo_pid) },
        "next_steps": next_steps,
        "hint": "This playground is yours for 90 minutes. Other sessions cannot see it. BankOps agent: Score/Hold/Decide on Workbench Admit; optional real LLM via Settings.",
        "agents_honesty": if agents.is_empty() {
            "No agents auto-created (SEED_DEMO=0)."
        } else if seed_trio {
            "Seeded DevGuard/TraceTramp/WitnessCtl trio (SEED_TRIO=1)."
        } else {
            "BankOps seeded — Score/Hold/Decide/Ledger + Isolate/Prove on Workbench. Tenant-isolated from other sessions."
        },
    })).into_response()
}

/// GET /api/v1/playground/session/:id
pub async fn get_session(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    if !is_playground_mode() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "playground not enabled"})),
        )
            .into_response();
    }
    let store = state.playground_sessions.clone();
    let mut sessions = match lock_sessions(&store) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let _ = reap_inactive_sessions(&state, &mut sessions);
    let ledger = load_ledger();
    match sessions.get(&id) {
        Some(s) => Json(json!({"ok": true, "session": session_to_public_with_quota(s, &ledger)})).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "session not found or expired"})),
        )
            .into_response(),
    }
}

/// DELETE /api/v1/playground/session/:id
pub async fn end_session(State(state): State<SharedState>, Path(id): Path<String>) -> Response {
    if !is_playground_mode() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "playground not enabled"})),
        )
            .into_response();
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "playground",
        "playground",
        "end_playground_session",
        &json!({"session_id": id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body).into_response(),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let store = state.playground_sessions.clone();
    let mut sessions = match lock_sessions(&store) {
        Ok(s) => s,
        Err(r) => {
            open_proceed.finish_observed(false);
            return r;
        }
    };
    match sessions.get_mut(&id) {
        Some(s) => {
            s.ended = true;
            let cleanup = cleanup_session_resources(&state, s);
            s.cleanup = Some(cleanup.clone());
            let queue = load_queue();
            persist_sessions_unlocked(&sessions);
            drop(sessions);
            open_proceed.finish_observed(true);
            Json(json!({
                "ok": true,
                "session_id": id,
                "ended": true,
                "cleanup": cleanup,
                "queue_depth": queue.len(),
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
            })).into_response()
        }
        None => {
            drop(sessions);
            open_proceed.finish_observed(false);
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "ok": false,
                    "error": "session not found",
                    "task_id": admitted.task_id,
                    "executed": false,
                    "admits": false,
                })),
            )
                .into_response()
        }
    }
}

/// GET /api/v1/playground/status — public endpoint, no auth required
pub async fn playground_status(State(state): State<SharedState>) -> Json<Value> {
    let enabled = is_playground_mode();
    if !enabled {
        return Json(json!({
            "ok": true,
            "playground": false,
            "message": "This node is not in playground mode. Self-hosted nodes run the full product — see connectorctl init to set up your own.",
        }));
    }

    let store = state.playground_sessions.clone();
    let mut sessions = match store.lock() {
        Ok(s) => s,
        Err(_) => return Json(json!({"ok": false, "error": "session store unavailable"})),
    };
    let _ = reap_inactive_sessions(&state, &mut sessions);
    let mut queue = load_queue();
    let now = now_secs();
    prune_queue(&mut queue, now);
    let ledger = load_ledger();
    let active: usize = sessions
        .values()
        .filter(|s| !s.ended && s.expires_at > now)
        .count();

    Json(json!({
        "ok": true,
        "playground": true,
        "active_sessions": active,
        "max_sessions": max_sessions(),
        "available": active < max_sessions(),
        "queue_depth": queue.len(),
        "queue_full": active >= max_sessions(),
        "default_session_limit_per_email": session_limit_per_email(),
        "privileged_unlimited_configured": !privileged_emails().is_empty(),
        "quota_example": session_quota_payload("example@company.com", &ledger),
        "session_ttl_secs": session_ttl_secs(),
        "llm_mode": {
            "mode": if std::env::var("CONNECTOR_LLM_STUB").map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")).unwrap_or(false) {
                "simulation"
            } else {
                "live_or_unconfigured"
            },
            "honesty": "simulation = CONNECTOR_LLM_STUB canned replies; not a live governed model",
        },
        "agents_default": "one_demo",
        "agents_honesty": "BankOps per session: Score/Hold/Decide/Ledger (+ Isolate/Prove) on Workbench (no LLM key). Tenant-isolated. SEED_TRIO remains opt-in lab only.",
        "caps": {
            "max_agents_per_session": max_agents(),
            "token_budget_per_session": token_budget(),
            "session_ttl_secs": session_ttl_secs(),
            "max_concurrent_sessions": max_sessions(),
            "session_limit_per_email": session_limit_per_email(),
            "isolation": "tenant_namespace — each session is a private sandbox of the same software",
        },
        "hint": format!(
            "POST /api/v1/playground/session to start a free trial. When {} people are already active, the email waits in queue.",
            max_sessions()
        ),
        "self_host": "Download Connector OS: connectorctl init — runs on Linux, macOS, any server.",
    }))
}

/// GET /api/v1/playground/sessions — admin-only: lists all sessions with emails
/// Protected by admin auth middleware in router.rs
pub async fn list_sessions(State(state): State<SharedState>) -> Json<Value> {
    if !is_playground_mode() {
        return Json(json!({"ok": false, "error": "playground not enabled"}));
    }
    let store = state.playground_sessions.clone();
    let mut sessions = match store.lock() {
        Ok(s) => s,
        Err(_) => return Json(json!({"ok": false, "error": "session store unavailable"})),
    };
    let _ = reap_inactive_sessions(&state, &mut sessions);
    let ledger = load_ledger();
    let queue = load_queue();
    let now = now_secs();

    let mut all: Vec<Value> = sessions
        .values()
        .map(|s| {
            let remaining = if s.expires_at > now {
                s.expires_at - now
            } else {
                0
            };
            json!({
                "session_id": s.session_id,
                "tenant_id": s.tenant_id,
                "email": s.email,
                "created_at": secs_to_iso(s.created_at),
                "expires_at": secs_to_iso(s.expires_at),
                "last_active": secs_to_iso(s.last_active),
                "remaining_secs": remaining,
                "active": !s.ended && remaining > 0,
                "ended": s.ended,
                "agents_created": s.agents_created,
                "tokens_used": s.tokens_used,
                "workflow_count": s.workflow_ids.len(),
                "quota": s.email.as_deref().map(|e| session_quota_payload(e, &ledger)),
            })
        })
        .collect();

    // Sort by created_at descending (newest first)
    all.sort_by(|a, b| b["created_at"].as_str().cmp(&a["created_at"].as_str()));

    let active_count = all
        .iter()
        .filter(|s| s["active"].as_bool().unwrap_or(false))
        .count();
    let emails: Vec<&str> = all.iter().filter_map(|s| s["email"].as_str()).collect();
    let unique_emails: std::collections::HashSet<&str> = emails.iter().copied().collect();

    Json(json!({
        "ok": true,
        "total_sessions": all.len(),
        "active_sessions": active_count,
        "unique_emails": unique_emails.len(),
        "queue_depth": queue.len(),
        "sessions": all,
    }))
}

/// Validate a playground API key from Authorization: Bearer header.
/// Returns Some(session_id) if valid and not expired, None otherwise.
/// Look up a live session by API key. Returns (session_id, tenant_id, email).
pub fn lookup_session_expires_at(store: &PlaygroundStore, session_id: &str) -> Option<u64> {
    let sessions = store.lock().ok()?;
    let s = sessions.get(session_id)?;
    if s.ended {
        return None;
    }
    Some(s.expires_at)
}

pub fn lookup_playground_session(
    store: &PlaygroundStore,
    key: &str,
) -> Option<(String, String, Option<String>)> {
    let id = validate_playground_key(store, key)?;
    let sessions = store.lock().ok()?;
    let s = sessions.get(&id)?;
    Some((s.session_id.clone(), s.tenant_id.clone(), s.email.clone()))
}

pub fn validate_playground_key(store: &PlaygroundStore, key: &str) -> Option<String> {
    let mut sessions = store.lock().ok()?;
    let now = now_secs();
    // Find session by api_key
    let session_id = sessions
        .values()
        .find(|s| s.api_key == key && !s.ended && s.expires_at > now)
        .map(|s| s.session_id.clone())?;
    // Touch last_active
    if let Some(s) = sessions.get_mut(&session_id) {
        s.last_active = now;
        // Extend TTL on activity (sliding window)
        let new_expiry = now + session_ttl_secs();
        if new_expiry > s.expires_at {
            s.expires_at = new_expiry;
        }
    }
    Some(session_id)
}

pub fn record_workflow_created(store: &PlaygroundStore, session_id: &str, workflow_id: &str) {
    let Ok(mut sessions) = store.lock() else {
        return;
    };
    if let Some(s) = sessions.get_mut(session_id) {
        if !s.workflow_ids.iter().any(|w| w == workflow_id) {
            s.workflow_ids.push(workflow_id.to_string());
        }
        persist_sessions_unlocked(&sessions);
    }
}

/// Check playground caps for an agent creation attempt.
/// Does not increment — call [`record_agent_created`] after a successful register.
pub fn check_agent_cap(store: &PlaygroundStore, session_id: &str) -> Result<(), Value> {
    let sessions = store
        .lock()
        .map_err(|_| json!({"ok": false, "error": "session store unavailable"}))?;
    let s = sessions
        .get(session_id)
        .ok_or_else(|| json!({"ok": false, "error": "session expired"}))?;
    if s.agents_created >= max_agents() {
        return Err(json!({
            "ok": false,
            "error": format!("playground cap: max {} agents per session", max_agents()),
            "code": "PLAYGROUND_AGENT_CAP",
            "agents_created": s.agents_created,
            "max_agents": max_agents(),
            "agent_pids": s.agent_pids.clone(),
            "existing_pid": s.agent_pids.first().cloned(),
            "hint": "Open Workbench on BankOps already in this session. Score/Hold/Decide/Ledger need no LLM key.",
        }));
    }
    Ok(())
}

/// Live sessions after restart: session id, tenant, remembered agent pids.
pub fn live_session_agent_targets(store: &PlaygroundStore) -> Vec<(String, String, Vec<String>)> {
    let Ok(sessions) = store.lock() else {
        return Vec::new();
    };
    let now = now_secs();
    sessions
        .values()
        .filter(|s| !s.ended && s.expires_at > now)
        .map(|s| (s.session_id.clone(), s.tenant_id.clone(), s.agent_pids.clone()))
        .collect()
}

/// Remember agent pids after kernel rehydrate without incrementing the cap.
pub fn sync_session_agent_pids(store: &PlaygroundStore, session_id: &str, pids: &[String]) {
    let Ok(mut sessions) = store.lock() else {
        return;
    };
    if let Some(s) = sessions.get_mut(session_id) {
        for pid in pids {
            if !pid.trim().is_empty() && !s.agent_pids.iter().any(|p| p == pid) {
                s.agent_pids.push(pid.clone());
            }
        }
        if s.agents_created < s.agent_pids.len() as u32 {
            s.agents_created = s.agent_pids.len() as u32;
        }
        persist_sessions_unlocked(&sessions);
    }
}

/// Drop a deleted agent from the session cap so Create can mint another.
pub fn record_agent_deleted(store: &PlaygroundStore, session_id: &str, api_pid: &str) {
    let Ok(mut sessions) = store.lock() else {
        return;
    };
    if let Some(s) = sessions.get_mut(session_id) {
        s.agent_pids.retain(|p| p != api_pid);
        s.agents_created = s.agent_pids.len() as u32;
        s.agents_cleared_by_user = s.agent_pids.is_empty();
        persist_sessions_unlocked(&sessions);
    }
}

pub fn session_cleared_by_user(store: &PlaygroundStore, session_id: &str) -> bool {
    store
        .lock()
        .ok()
        .and_then(|sessions| {
            sessions
                .get(session_id)
                .map(|s| s.agents_cleared_by_user)
        })
        .unwrap_or(false)
}

/// Count a successful kernel-agent registration against the session cap.
pub fn record_agent_created(store: &PlaygroundStore, session_id: &str, api_pid: Option<&str>) {
    let Ok(mut sessions) = store.lock() else {
        return;
    };
    if let Some(s) = sessions.get_mut(session_id) {
        s.agents_created = s.agents_created.saturating_add(1);
        if let Some(pid) = api_pid.filter(|p| !p.trim().is_empty()) {
            if !s.agent_pids.iter().any(|p| p == pid) {
                s.agent_pids.push(pid.to_string());
            }
        }
        s.agents_cleared_by_user = false;
        persist_sessions_unlocked(&sessions);
    }
}

/// Record token usage for a session. Returns true if still within budget.
pub fn record_token_usage(store: &PlaygroundStore, session_id: &str, tokens: u64) -> bool {
    let Ok(mut sessions) = store.lock() else {
        return false;
    };
    let Some(s) = sessions.get_mut(session_id) else {
        return !session_id.starts_with("pg_");
    };
    let next = s.tokens_used.saturating_add(tokens);
    if next > token_budget() {
        return false;
    }
    s.tokens_used = next;
    persist_sessions_unlocked(&sessions);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn playground_ids_are_uuid_csprng() {
        let a = generate_session_id();
        let b = generate_session_id();
        assert!(a.starts_with("pg_"));
        assert_ne!(a, b);
        assert_eq!(a.len(), 3 + 32);
        let k = generate_api_key(&a);
        assert!(k.starts_with("cpk_pg_"));
        assert_eq!(k.len(), 7 + 32);
        assert_ne!(k, generate_api_key(&a));
    }

    #[test]
    fn privileged_email_has_unlimited_access() {
        assert!(email_has_unlimited_access("umeshlamton@gmail.com"));
        assert!(!email_has_unlimited_access("person@example.com"));
    }

    #[test]
    fn queue_prune_evicts_stale_entries() {
        let now = 10_000;
        let mut queue = vec![
            PlaygroundQueueEntry {
                email: "fresh@example.com".into(),
                label: None,
                enqueued_at: now - 10,
                last_seen_at: now - 10,
            },
            PlaygroundQueueEntry {
                email: "stale@example.com".into(),
                label: None,
                enqueued_at: now - queue_wait_secs() - 1,
                last_seen_at: now - queue_wait_secs() - 1,
            },
        ];
        prune_queue(&mut queue, now);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].email, "fresh@example.com");
    }

    #[test]
    fn session_quota_counts_down_for_normal_email() {
        let mut ledger = HashMap::new();
        ledger.insert(
            "person@example.com".into(),
            PlaygroundEmailLedgerEntry {
                sessions_started: 2,
                last_started_at: 100,
            },
        );
        let quota = session_quota_payload("person@example.com", &ledger);
        assert_eq!(quota.get("unlimited").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(
            quota.get("sessions_remaining").and_then(|v| v.as_u64()),
            Some(1)
        );
    }

    #[test]
    fn public_status_does_not_list_unlimited_emails() {
        let src = include_str!("playground.rs");
        assert!(
            !src.contains("\"privileged_unlimited_emails\""),
            "public playground status must not list operator emails"
        );
        assert!(src.contains("\"privileged_unlimited_configured\""));
    }
}
