//! Phase 5.5 — shared "plugin condo" registry: many plugins → one microVM slot (orchestration only; guest multi-tenant TBD).

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::auth;
use crate::services::kernel_host::{ScheduleAgentRequest, UpsertCellRequest, UpsertShardRequest};
use crate::services::plugin_cpkg::safe_plugin_id;
use crate::services::runtime_control;
use crate::state::SharedState;

const STORE_FOLDER: &str = "plugin_condos";
/// Roadmap §5.5 target: ≥50 plugins per condo.
pub const MAX_PLUGINS_PER_CONDO: usize = 50;

fn default_placement_state() -> String {
    "unassigned".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CondoPlacementAction {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub target_pool: String,
    #[serde(default)]
    pub members_snapshot: usize,
    #[serde(default)]
    pub at_unix_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CondoGuestStatus {
    #[serde(default)]
    pub guest_id: String,
    #[serde(default)]
    pub vm_id: String,
    #[serde(default)]
    pub target_pool: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub heartbeat_at_unix_ms: i64,
}

/// Orchestration stub until **5.5.2** guest **vm-agent** + real microVM placement (persisted per condo).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CondoPlacement {
    #[serde(default = "default_placement_state")]
    pub state: String,
    #[serde(default)]
    pub target_pool: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub updated_at_unix_ms: i64,
    /// Recent runtime-intent actions generated from placement transitions (5.5.2 bridge scaffold).
    #[serde(default)]
    pub actions: Vec<CondoPlacementAction>,
    #[serde(default)]
    pub guest: CondoGuestStatus,
}

impl Default for CondoPlacement {
    fn default() -> Self {
        Self {
            state: default_placement_state(),
            target_pool: String::new(),
            notes: String::new(),
            updated_at_unix_ms: 0,
            actions: Vec::new(),
            guest: CondoGuestStatus::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CondoRecord {
    pub condo_id: String,
    pub members: Vec<String>,
    pub updated_at_unix_ms: i64,
    #[serde(default)]
    pub placement: CondoPlacement,
}

fn require_admin_or_dev(headers: &HeaderMap) -> Result<(), Value> {
    if runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = auth::extract_claims(headers) else {
        return Err(json!({"ok": false, "error": "Unauthorized"}));
    };
    let role = auth::PlatformRole::from_str(&claims.role);
    if role.rank() < auth::PlatformRole::Admin.rank() {
        return Err(json!({"ok": false, "error": "Admin privileges required"}));
    }
    Ok(())
}

fn require_auth_or_dev(headers: &HeaderMap) -> Result<(), Value> {
    if runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    if auth::extract_claims(headers).is_some() {
        return Ok(());
    }
    Err(json!({"ok": false, "error": "Unauthorized"}))
}

fn require_condo_guest_heartbeat_auth(headers: &HeaderMap) -> Result<(), Value> {
    let token = std::env::var("CONNECTOR_CONDO_GUEST_HEARTBEAT_TOKEN")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let Some(expected) = token else {
        // Fallback for local/dev unless operator enables scoped heartbeat token.
        return require_admin_or_dev(headers);
    };
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();
    let mut provided = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .unwrap_or("")
        .trim()
        .to_string();
    if provided.is_empty() {
        provided = headers
            .get("x-connector-condo-heartbeat-token")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_string();
    }
    if provided == expected {
        Ok(())
    } else {
        Err(json!({"ok": false, "error": "Unauthorized guest heartbeat token"}))
    }
}

fn sanitize_condo_id(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return None;
    }
    Some(s.to_string())
}

fn valid_plugin_id(plugin_id: &str) -> bool {
    let t = plugin_id.trim();
    !t.is_empty() && t.split('/').count() == 2
}

fn load_condo(state: &SharedState, condo_key: &str) -> Option<CondoRecord> {
    let es = state.engine_store.lock().unwrap();
    es.folder_get(STORE_FOLDER, condo_key)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value(v).ok())
}

fn save_condo(state: &SharedState, rec: &CondoRecord) {
    let mut es = state.engine_store.lock().unwrap();
    let key = safe_plugin_id(&rec.condo_id);
    let _ = es.folder_put(
        STORE_FOLDER,
        &key,
        &serde_json::to_value(rec).unwrap_or_default(),
    );
}

fn list_condo_keys(state: &SharedState) -> Vec<String> {
    let es = state.engine_store.lock().unwrap();
    es.folder_keys(STORE_FOLDER, None).unwrap_or_default()
}

/// Remove `plugin_id` from every condo (used before assign).
fn remove_plugin_from_all(state: &SharedState, plugin_id: &str) {
    let keys = list_condo_keys(state);
    for k in keys {
        if let Some(mut rec) = load_condo(state, &k) {
            let before = rec.members.len();
            rec.members.retain(|m| m != plugin_id);
            if rec.members.len() != before {
                rec.updated_at_unix_ms = chrono::Utc::now().timestamp_millis();
                save_condo(state, &rec);
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CondoCreateBody {
    pub condo_id: String,
}

#[derive(Debug, Deserialize)]
pub struct CondoAssignBody {
    pub condo_id: String,
    pub plugin_id: String,
}

pub async fn get_plugin_condos(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_auth_or_dev(&headers) {
        return Err((StatusCode::UNAUTHORIZED, Json(e)));
    }
    let keys = list_condo_keys(&state);
    let mut condos = Vec::new();
    for k in keys {
        if let Some(rec) = load_condo(&state, &k) {
            condos.push(json!({
                "condo_id": rec.condo_id,
                "member_count": rec.members.len(),
                "max_members": MAX_PLUGINS_PER_CONDO,
                "members": rec.members,
                "updated_at_unix_ms": rec.updated_at_unix_ms,
                "placement": rec.placement,
            }));
        }
    }
    Ok(Json(json!({
        "ok": true,
        "condos": condos,
        "hint": "Phase 5.5: assignment + cap + placement bridge (POST …/plugin-condos/placement). runtime_action fields capture intended guest orchestration; vm-agent + microVM pool execution remains TBD (5.5.2)."
    })))
}

pub async fn post_plugin_condo_create(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CondoCreateBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let Some(condo_id) = sanitize_condo_id(&body.condo_id) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "condo_id must be 1–64 chars [a-zA-Z0-9._-]"})),
        ));
    };
    let key = safe_plugin_id(&condo_id);
    let es = state.engine_store.lock().unwrap();
    if es.folder_get(STORE_FOLDER, &key).ok().flatten().is_some() {
        drop(es);
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"ok": false, "error": "condo_id already exists"})),
        ));
    }
    drop(es);
    let rec = CondoRecord {
        condo_id: condo_id.clone(),
        members: Vec::new(),
        updated_at_unix_ms: chrono::Utc::now().timestamp_millis(),
        placement: CondoPlacement::default(),
    };
    save_condo(&state, &rec);
    Ok(Json(json!({"ok": true, "condo": rec})))
}

pub async fn post_plugin_condo_assign(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CondoAssignBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let Some(condo_id) = sanitize_condo_id(&body.condo_id) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid condo_id"})),
        ));
    };
    let plugin_id = body.plugin_id.trim().to_string();
    if !valid_plugin_id(&plugin_id) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "plugin_id must be vendor/slug"})),
        ));
    }
    let key = safe_plugin_id(&condo_id);
    let rec = match load_condo(&state, &key) {
        Some(r) if r.condo_id == condo_id => r,
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({"ok": false, "error": "condo not found"})),
            ));
        }
    };
    if rec.members.len() >= MAX_PLUGINS_PER_CONDO && !rec.members.contains(&plugin_id) {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "error": format!("condo full (max {} plugins)", MAX_PLUGINS_PER_CONDO),
            })),
        ));
    }
    remove_plugin_from_all(&state, &plugin_id);
    let mut rec = load_condo(&state, &key).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": "condo disappeared after remap"})),
        )
    })?;
    if !rec.members.contains(&plugin_id) {
        rec.members.push(plugin_id.clone());
    }
    rec.updated_at_unix_ms = chrono::Utc::now().timestamp_millis();
    save_condo(&state, &rec);
    Ok(Json(json!({"ok": true, "condo": rec})))
}

fn sanitize_placement_state(raw: &str) -> Option<String> {
    let t = raw.trim().to_ascii_lowercase();
    match t.as_str() {
        "unassigned" | "microvm_pending" | "microvm_pool" | "reserved" => Some(t),
        _ => None,
    }
}

fn can_transition_placement_state(from: &str, to: &str) -> bool {
    if from == to {
        return true;
    }
    match from {
        "unassigned" => matches!(to, "microvm_pending" | "reserved"),
        "microvm_pending" => matches!(to, "microvm_pool" | "reserved" | "unassigned"),
        "microvm_pool" => matches!(to, "reserved" | "unassigned"),
        "reserved" => matches!(to, "microvm_pending" | "unassigned"),
        _ => false,
    }
}

fn allowed_next_placement_states(from: &str) -> Vec<&'static str> {
    match from {
        "unassigned" => vec!["unassigned", "microvm_pending", "reserved"],
        "microvm_pending" => vec!["microvm_pending", "microvm_pool", "reserved", "unassigned"],
        "microvm_pool" => vec!["microvm_pool", "reserved", "unassigned"],
        "reserved" => vec!["reserved", "microvm_pending", "unassigned"],
        _ => vec![],
    }
}

fn placement_state_requires_target_pool(state: &str) -> bool {
    matches!(state, "microvm_pending" | "microvm_pool")
}

fn placement_runtime_action(
    prev_state: &str,
    next_state: &str,
    target_pool: &str,
    member_count: usize,
    now: i64,
) -> CondoPlacementAction {
    let pool = target_pool.trim().to_string();
    let (kind, detail) = if prev_state == next_state {
        (
            "placement_noop",
            format!("placement unchanged ({next_state})"),
        )
    } else if next_state == "microvm_pending" {
        (
            "placement_enqueue_pool_warmup",
            format!(
                "queue condo warmup in pool '{}' for {} members",
                if pool.is_empty() { "-" } else { &pool },
                member_count
            ),
        )
    } else if next_state == "microvm_pool" {
        (
            "placement_mark_pool_ready",
            format!(
                "mark condo active in pool '{}' for {} members",
                if pool.is_empty() { "-" } else { &pool },
                member_count
            ),
        )
    } else if next_state == "reserved" {
        (
            "placement_reserve_capacity",
            format!(
                "reserve capacity for {} members (from {})",
                member_count, prev_state
            ),
        )
    } else {
        (
            "placement_release_assignment",
            format!("release condo assignment from {}", prev_state),
        )
    };
    CondoPlacementAction {
        kind: kind.to_string(),
        detail,
        target_pool: pool,
        members_snapshot: member_count,
        at_unix_ms: now,
    }
}

fn parse_target_pool_cell_shard(target_pool: &str) -> Result<(String, String), String> {
    let raw = target_pool.trim();
    if raw.is_empty() {
        return Err("target_pool is empty".to_string());
    }
    let mut it = raw.split('/');
    let cell = it.next().unwrap_or("").trim();
    let shard = it.next().unwrap_or("").trim();
    if it.next().is_some() || cell.is_empty() || shard.is_empty() {
        return Err("target_pool must be in the form <cell_id>/<shard_id>".to_string());
    }
    let Some(cell_id) = sanitize_condo_id(cell) else {
        return Err("target_pool cell_id must match [a-zA-Z0-9._-]".to_string());
    };
    let Some(shard_id) = sanitize_condo_id(shard) else {
        return Err("target_pool shard_id must match [a-zA-Z0-9._-]".to_string());
    };
    Ok((cell_id, shard_id))
}

fn execute_runtime_action_for_condo(
    state: &SharedState,
    rec: &CondoRecord,
    action: &CondoPlacementAction,
) -> Result<Value, String> {
    match action.kind.as_str() {
        "placement_noop" => Ok(json!({
            "kind": action.kind,
            "executed": true,
            "noop": true,
        })),
        "placement_release_assignment" => {
            let host = state.kernel_host.lock().unwrap();
            let released = rec
                .members
                .iter()
                .filter(|plugin_id| host.unschedule_agent_microvm(plugin_id))
                .count();
            Ok(json!({
                "kind": action.kind,
                "executed": true,
                "released_members": released,
                "members_total": rec.members.len(),
            }))
        }
        "placement_enqueue_pool_warmup"
        | "placement_mark_pool_ready"
        | "placement_reserve_capacity" => {
            let (cell_id, shard_id) = parse_target_pool_cell_shard(&action.target_pool)?;
            let host = state.kernel_host.lock().unwrap();
            host.upsert_cell(UpsertCellRequest {
                cell_id: cell_id.clone(),
                core_id: cell_id.clone(),
                max_cells_per_core: None,
                shard_cpu_limit_pct: None,
                async_batch_enabled: None,
            })?;
            host.upsert_shard(UpsertShardRequest {
                cell_id: cell_id.clone(),
                shard_id: shard_id.clone(),
                replicas: None,
                max_agents: None,
                cpu_limit_pct: None,
            })?;
            if action.kind == "placement_reserve_capacity" {
                return Ok(json!({
                    "kind": action.kind,
                    "executed": true,
                    "cell_id": cell_id,
                    "shard_id": shard_id,
                    "reserved_member_slots": rec.members.len(),
                }));
            }
            let mut scheduled: Vec<String> = Vec::new();
            let per_member_cpu = if action.kind == "placement_enqueue_pool_warmup" {
                0.2
            } else {
                1.0
            };
            for plugin_id in &rec.members {
                let req = ScheduleAgentRequest {
                    cell_id: cell_id.clone(),
                    shard_id: shard_id.clone(),
                    replica_ordinal: Some(0),
                    requested_cpu_pct: Some(per_member_cpu),
                    async_batch: Some(action.kind == "placement_enqueue_pool_warmup"),
                };
                match host.schedule_agent_microvm(plugin_id, req) {
                    Ok(_) => scheduled.push(plugin_id.clone()),
                    Err(e) => {
                        for p in &scheduled {
                            let _ = host.unschedule_agent_microvm(p);
                        }
                        return Err(format!(
                            "schedule failed for {} in {}/{}: {}",
                            plugin_id, cell_id, shard_id, e
                        ));
                    }
                }
            }
            Ok(json!({
                "kind": action.kind,
                "executed": true,
                "cell_id": cell_id,
                "shard_id": shard_id,
                "scheduled_members": scheduled.len(),
                "members": scheduled,
            }))
        }
        other => Err(format!("unsupported runtime action kind: {}", other)),
    }
}

fn runtime_preflight_for_condo(
    state: &SharedState,
    rec: &CondoRecord,
    action: &CondoPlacementAction,
) -> Result<Value, String> {
    match action.kind.as_str() {
        "placement_noop" | "placement_release_assignment" => Ok(json!({
            "kind": action.kind,
            "ok": true,
            "requires_pool_capacity": false,
        })),
        "placement_enqueue_pool_warmup"
        | "placement_mark_pool_ready"
        | "placement_reserve_capacity" => {
            let (cell_id, shard_id) = parse_target_pool_cell_shard(&action.target_pool)?;
            let ttl_ms = condo_guest_heartbeat_ttl_ms();
            let now = chrono::Utc::now().timestamp_millis();
            let hb_age_ms = if rec.placement.guest.heartbeat_at_unix_ms > 0 {
                now.saturating_sub(rec.placement.guest.heartbeat_at_unix_ms)
            } else {
                i64::MAX
            };
            if action.kind == "placement_mark_pool_ready" {
                if rec.placement.guest.heartbeat_at_unix_ms <= 0 {
                    return Err(
                        "guest heartbeat missing; vm-agent must report before microvm_pool"
                            .to_string(),
                    );
                }
                if hb_age_ms > ttl_ms {
                    return Err(format!(
                        "guest heartbeat stale (age={}ms > ttl={}ms)",
                        hb_age_ms, ttl_ms
                    ));
                }
                if rec.placement.guest.target_pool.trim() != action.target_pool.trim() {
                    return Err(format!(
                        "guest heartbeat target_pool mismatch: {} != {}",
                        rec.placement.guest.target_pool, action.target_pool
                    ));
                }
            }
            let per_member_cpu = if action.kind == "placement_enqueue_pool_warmup" {
                0.2
            } else if action.kind == "placement_mark_pool_ready" {
                1.0
            } else {
                0.0
            };
            let host = state.kernel_host.lock().unwrap();
            let capacity = host.preview_schedule_capacity(
                &cell_id,
                &shard_id,
                rec.members.len() as u32,
                per_member_cpu,
            )?;
            Ok(json!({
                "kind": action.kind,
                "ok": true,
                "requires_pool_capacity": true,
                "pool": { "cell_id": cell_id, "shard_id": shard_id },
                "guest_heartbeat": {
                    "ttl_ms": ttl_ms,
                    "age_ms": if hb_age_ms == i64::MAX { serde_json::Value::Null } else { json!(hb_age_ms) },
                    "last_at_unix_ms": rec.placement.guest.heartbeat_at_unix_ms,
                    "target_pool": rec.placement.guest.target_pool,
                },
                "capacity": capacity,
            }))
        }
        other => Err(format!("unsupported runtime action kind: {}", other)),
    }
}

#[derive(Debug, Deserialize)]
pub struct CondoPlacementBody {
    pub condo_id: String,
    pub state: String,
    #[serde(default)]
    pub target_pool: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CondoPlacementPlanBody {
    pub condo_id: String,
    #[serde(default)]
    pub desired_state: Option<String>,
    #[serde(default)]
    pub target_pool: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CondoGuestHeartbeatBody {
    pub condo_id: String,
    #[serde(default)]
    pub guest_id: Option<String>,
    #[serde(default)]
    pub vm_id: Option<String>,
    #[serde(default)]
    pub target_pool: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

fn condo_guest_heartbeat_ttl_ms() -> i64 {
    std::env::var("CONNECTOR_CONDO_GUEST_HEARTBEAT_TTL_MS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(60_000)
        .clamp(5_000, 3_600_000)
}

/// Phase **5.5.2** scaffold — persist orchestration **placement** (guest vm-agent still TBD).
pub async fn post_plugin_condo_placement(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CondoPlacementBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let Some(condo_id) = sanitize_condo_id(&body.condo_id) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid condo_id"})),
        ));
    };
    let Some(state_s) = sanitize_placement_state(&body.state) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "state must be unassigned | microvm_pending | microvm_pool | reserved",
            })),
        ));
    };
    let key = safe_plugin_id(&condo_id);
    let mut rec = match load_condo(&state, &key) {
        Some(r) if r.condo_id == condo_id => r,
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({"ok": false, "error": "condo not found"})),
            ));
        }
    };
    let prev_state = rec.placement.state.trim().to_ascii_lowercase();
    if !can_transition_placement_state(&prev_state, &state_s) {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "error": format!(
                    "invalid placement transition: {} -> {}",
                    prev_state, state_s
                ),
                "allowed_from_current": allowed_next_placement_states(&prev_state),
            })),
        ));
    }
    let requested_target_pool = body
        .target_pool
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let mut next_target_pool = requested_target_pool
        .clone()
        .unwrap_or_else(|| rec.placement.target_pool.clone());
    if state_s == "unassigned" {
        next_target_pool.clear();
    }
    if placement_state_requires_target_pool(&state_s) && next_target_pool.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "target_pool is required when state is microvm_pending or microvm_pool",
            })),
        ));
    }
    let now = chrono::Utc::now().timestamp_millis();
    let preview_action = placement_runtime_action(
        &prev_state,
        &state_s,
        &next_target_pool,
        rec.members.len(),
        now,
    );
    let runtime_preflight =
        runtime_preflight_for_condo(&state, &rec, &preview_action).map_err(|e| {
            (
                StatusCode::CONFLICT,
                Json(json!({
                    "ok": false,
                    "error": format!("runtime preflight failed: {}", e),
                    "runtime_action": preview_action,
                })),
            )
        })?;
    rec.placement.state = state_s;
    rec.placement.target_pool = next_target_pool;
    rec.placement.notes = body
        .notes
        .as_ref()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    rec.placement.updated_at_unix_ms = now;
    let action = preview_action;
    rec.placement.actions.push(action.clone());
    if rec.placement.actions.len() > 10 {
        let drop_n = rec.placement.actions.len().saturating_sub(10);
        rec.placement.actions.drain(0..drop_n);
    }
    rec.updated_at_unix_ms = now;
    let runtime_execution =
        execute_runtime_action_for_condo(&state, &rec, &action).map_err(|e| {
            (
                StatusCode::CONFLICT,
                Json(json!({
                    "ok": false,
                    "error": format!("runtime action failed: {}", e),
                    "runtime_action": action,
                })),
            )
        })?;
    save_condo(&state, &rec);
    Ok(Json(json!({
        "ok": true,
        "condo": rec,
        "runtime_action": action,
        "runtime_preflight": runtime_preflight,
        "runtime_execution": runtime_execution,
        "hint": "5.5.2 runtime bridge executes against kernel_host microvm placement primitives; guest vm-agent integration remains pending."
    })))
}

/// Placement dry-run endpoint for automation callers before mutating condo state.
pub async fn post_plugin_condo_placement_plan(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CondoPlacementPlanBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let Some(condo_id) = sanitize_condo_id(&body.condo_id) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid condo_id"})),
        ));
    };
    let key = safe_plugin_id(&condo_id);
    let rec = match load_condo(&state, &key) {
        Some(r) if r.condo_id == condo_id => r,
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({"ok": false, "error": "condo not found"})),
            ));
        }
    };

    let current_state = rec.placement.state.trim().to_ascii_lowercase();
    let desired_state = if let Some(raw) = &body.desired_state {
        let Some(clean) = sanitize_placement_state(raw) else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "ok": false,
                    "error": "desired_state must be unassigned | microvm_pending | microvm_pool | reserved",
                })),
            ));
        };
        Some(clean)
    } else {
        None
    };

    let requested_target_pool = body
        .target_pool
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let requested_notes = body.notes.as_ref().map(|s| s.trim().to_string());
    let next_state = desired_state
        .clone()
        .unwrap_or_else(|| current_state.clone());

    let transition_allowed = can_transition_placement_state(&current_state, &next_state);
    let mut effective_target_pool = requested_target_pool
        .clone()
        .unwrap_or_else(|| rec.placement.target_pool.clone());
    if next_state == "unassigned" {
        effective_target_pool.clear();
    }
    let requires_target_pool = placement_state_requires_target_pool(&next_state);
    let target_pool_missing = requires_target_pool && effective_target_pool.trim().is_empty();
    let would_update = current_state != next_state
        || rec.placement.target_pool != effective_target_pool
        || requested_notes
            .as_ref()
            .is_some_and(|n| rec.placement.notes != *n);
    let runtime_action_preview = placement_runtime_action(
        &current_state,
        &next_state,
        &effective_target_pool,
        rec.members.len(),
        chrono::Utc::now().timestamp_millis(),
    );
    let runtime_preflight = runtime_preflight_for_condo(&state, &rec, &runtime_action_preview);
    let runtime_preflight_ok = runtime_preflight.is_ok();
    let runtime_preflight_json = match runtime_preflight {
        Ok(v) => v,
        Err(e) => json!({ "ok": false, "error": e }),
    };

    Ok(Json(json!({
        "ok": true,
        "condo_id": rec.condo_id,
        "current": {
            "state": current_state,
            "target_pool": rec.placement.target_pool,
            "notes": rec.placement.notes,
            "updated_at_unix_ms": rec.placement.updated_at_unix_ms,
            "member_count": rec.members.len(),
        },
        "requested": {
            "desired_state": desired_state,
            "target_pool": requested_target_pool,
            "notes": requested_notes,
        },
        "plan": {
            "next_state": next_state,
            "allowed_next_states": allowed_next_placement_states(&current_state),
            "transition_allowed": transition_allowed,
            "requires_target_pool": requires_target_pool,
            "target_pool_missing": target_pool_missing,
            "effective_target_pool": effective_target_pool,
            "would_update": would_update,
            "runtime_preflight_ok": runtime_preflight_ok,
            "valid": transition_allowed && !target_pool_missing && runtime_preflight_ok,
            "runtime_action_preview": runtime_action_preview,
            "runtime_preflight": runtime_preflight_json,
        },
        "hint": "Apply with POST /api/v1/kernel/plugin-condos/placement using the same desired state/target_pool.",
    })))
}

pub async fn post_plugin_condo_guest_heartbeat(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CondoGuestHeartbeatBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_condo_guest_heartbeat_auth(&headers) {
        return Err((StatusCode::UNAUTHORIZED, Json(e)));
    }
    let Some(condo_id) = sanitize_condo_id(&body.condo_id) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid condo_id"})),
        ));
    };
    let key = safe_plugin_id(&condo_id);
    let mut rec = match load_condo(&state, &key) {
        Some(r) if r.condo_id == condo_id => r,
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(json!({"ok": false, "error": "condo not found"})),
            ));
        }
    };
    let now = chrono::Utc::now().timestamp_millis();
    if let Some(g) = body
        .guest_id
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        rec.placement.guest.guest_id = g.to_string();
    }
    if let Some(v) = body
        .vm_id
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        rec.placement.guest.vm_id = v.to_string();
    }
    if let Some(p) = body
        .target_pool
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        rec.placement.guest.target_pool = p.to_string();
    }
    rec.placement.guest.status = body
        .status
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "healthy".to_string());
    rec.placement.guest.heartbeat_at_unix_ms = now;
    rec.updated_at_unix_ms = now;
    rec.placement.updated_at_unix_ms = now;
    save_condo(&state, &rec);
    Ok(Json(json!({
        "ok": true,
        "condo_id": rec.condo_id,
        "guest": rec.placement.guest,
        "ttl_ms": condo_guest_heartbeat_ttl_ms(),
    })))
}

#[cfg(test)]
mod tests {
    use super::{
        allowed_next_placement_states, can_transition_placement_state, default_placement_state,
        parse_target_pool_cell_shard, placement_runtime_action,
        placement_state_requires_target_pool, sanitize_placement_state,
    };

    #[test]
    fn placement_default_state_is_unassigned() {
        assert_eq!(default_placement_state(), "unassigned");
    }

    #[test]
    fn placement_state_accepts_all_valid_values_case_insensitive() {
        assert_eq!(
            sanitize_placement_state("UNASSIGNED"),
            Some("unassigned".to_string())
        );
        assert_eq!(
            sanitize_placement_state("microvm_pending"),
            Some("microvm_pending".to_string())
        );
        assert_eq!(
            sanitize_placement_state(" MicroVM_Pool "),
            Some("microvm_pool".to_string())
        );
        assert_eq!(
            sanitize_placement_state("reserved"),
            Some("reserved".to_string())
        );
    }

    #[test]
    fn placement_state_rejects_invalid_values() {
        assert_eq!(sanitize_placement_state(""), None);
        assert_eq!(sanitize_placement_state("pending"), None);
        assert_eq!(sanitize_placement_state("microvm-active"), None);
    }

    #[test]
    fn placement_transition_matrix_is_guarded() {
        assert!(can_transition_placement_state(
            "unassigned",
            "microvm_pending"
        ));
        assert!(can_transition_placement_state(
            "microvm_pending",
            "microvm_pool"
        ));
        assert!(can_transition_placement_state("microvm_pool", "reserved"));
        assert!(can_transition_placement_state("reserved", "unassigned"));

        assert!(!can_transition_placement_state(
            "unassigned",
            "microvm_pool"
        ));
        assert!(!can_transition_placement_state("reserved", "microvm_pool"));
        assert!(!can_transition_placement_state(
            "microvm_pool",
            "microvm_pending"
        ));
    }

    #[test]
    fn placement_target_pool_required_only_for_microvm_states() {
        assert!(placement_state_requires_target_pool("microvm_pending"));
        assert!(placement_state_requires_target_pool("microvm_pool"));
        assert!(!placement_state_requires_target_pool("unassigned"));
        assert!(!placement_state_requires_target_pool("reserved"));
    }

    #[test]
    fn allowed_next_states_reflect_transition_rules() {
        assert_eq!(
            allowed_next_placement_states("unassigned"),
            vec!["unassigned", "microvm_pending", "reserved"]
        );
        assert_eq!(
            allowed_next_placement_states("microvm_pool"),
            vec!["microvm_pool", "reserved", "unassigned"]
        );
        assert!(allowed_next_placement_states("unknown").is_empty());
    }

    #[test]
    fn placement_runtime_action_kinds_follow_state() {
        let a = placement_runtime_action("unassigned", "microvm_pending", "pool-a", 3, 1);
        assert_eq!(a.kind, "placement_enqueue_pool_warmup");
        let b = placement_runtime_action("microvm_pending", "microvm_pool", "pool-a", 3, 2);
        assert_eq!(b.kind, "placement_mark_pool_ready");
        let c = placement_runtime_action("microvm_pool", "unassigned", "", 3, 3);
        assert_eq!(c.kind, "placement_release_assignment");
    }

    #[test]
    fn parse_target_pool_requires_cell_and_shard() {
        let (cell, shard) = parse_target_pool_cell_shard("cell-a/shard-1").expect("valid");
        assert_eq!(cell, "cell-a");
        assert_eq!(shard, "shard-1");
        assert!(parse_target_pool_cell_shard("cell-only").is_err());
        assert!(parse_target_pool_cell_shard("a/b/c").is_err());
    }
}
