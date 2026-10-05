//! DevGuard Team Management API — Team-based multi-tenancy with role-based access.
//!
//! Team = Tenant. Each team is isolated. Members have roles (admin, senior, junior, observer).
//! This provides the "Command Center" for managing agentic AI teams.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::state::SharedState;

const TEAM_FOLDER: &str = "devguard_teams";
const MEMBER_FOLDER: &str = "devguard_members";
const ACTION_FOLDER: &str = "devguard_actions";

// ═════════════════════════════════════════════════════════════════════════════
// Data Models
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamRole {
    Admin,
    Senior,
    Junior,
    Observer,
}

impl TeamRole {
    pub fn clearance(&self) -> u32 {
        match self {
            TeamRole::Admin => 100,
            TeamRole::Senior => 75,
            TeamRole::Junior => 50,
            TeamRole::Observer => 25,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: TeamRole,
    pub team_id: String,
    pub joined_at: String,
    pub last_active: Option<String>,
    pub provider: String,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: String,
    pub name: String,
    pub tenant_id: String, // Links to Connector tenant
    pub created_at: String,
    pub created_by: String,
    pub settings: TeamSettings,
    pub member_count: u32,
    pub project_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamSettings {
    pub default_role: TeamRole,
    pub require_mfa: bool,
    pub budget_limit_usd: Option<f64>,
    pub retention_days: u32,
    pub auto_approve_senior: bool,
    pub require_approval_for: Vec<String>,
}

impl Default for TeamSettings {
    fn default() -> Self {
        Self {
            default_role: TeamRole::Junior,
            require_mfa: false,
            budget_limit_usd: None,
            retention_days: 30,
            auto_approve_senior: true,
            require_approval_for: vec![
                "shell_execute".into(),
                "git_push".into(),
                "file_delete".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticAction {
    pub id: String,
    pub team_id: String,
    pub member_id: String,
    pub member_name: String,
    pub member_role: TeamRole,
    pub action_type: String,
    pub description: String,
    pub timestamp: String,
    pub resources: Vec<String>,
    pub approved: bool,
    pub approved_by: Option<String>,
    pub violations: Vec<String>,
    pub cost_usd: Option<f64>,
    pub tokens: Option<u64>,
    pub session_id: String,
}

// ═════════════════════════════════════════════════════════════════════════════
// Request/Response Types
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
    pub admin_email: String,
    pub admin_name: String,
    pub settings: Option<TeamSettings>,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub email: String,
    pub name: String,
    pub role: TeamRole,
    pub provider: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub role: TeamRole,
}

#[derive(Deserialize)]
pub struct LogActionRequest {
    pub member_id: String,
    pub action_type: String,
    pub description: String,
    pub resources: Vec<String>,
    pub session_id: String,
    pub cost_usd: Option<f64>,
    pub tokens: Option<u64>,
}

#[derive(Deserialize)]
pub struct TeamQuery {
    pub tenant_id: Option<String>,
    pub limit: Option<usize>,
}

// ═════════════════════════════════════════════════════════════════════════════
// Helpers
// ═════════════════════════════════════════════════════════════════════════════

fn tenant_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn json_err(status: StatusCode, body: Value) -> axum::response::Response {
    (status, Json(body)).into_response()
}

// ═════════════════════════════════════════════════════════════════════════════
// API Endpoints
// ═════════════════════════════════════════════════════════════════════════════

/// POST /api/v1/plugins/devguard/teams — Create a new team
pub async fn create_team(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateTeamRequest>,
) -> impl IntoResponse {
    let tenant_id = tenant_from_headers(&headers).unwrap_or_else(|| "default".to_string());
    let team_id = format!("team-{}", uuid::Uuid::new_v4());
    let member_id = format!("mem-{}", uuid::Uuid::new_v4());

    let now = Utc::now().to_rfc3339();

    let team = Team {
        id: team_id.clone(),
        name: req.name,
        tenant_id: tenant_id.clone(),
        created_at: now.clone(),
        created_by: member_id.clone(),
        settings: req.settings.unwrap_or_default(),
        member_count: 1,
        project_count: 0,
    };

    let admin = TeamMember {
        id: member_id,
        email: req.admin_email,
        name: req.admin_name,
        role: TeamRole::Admin,
        team_id: team_id.clone(),
        joined_at: now,
        last_active: Some(Utc::now().to_rfc3339()),
        provider: "local".to_string(),
        active: true,
    };

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "devguard-team",
        "devguard",
        "create_team",
        &json!({"team_id": team_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body).into_response(),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    // Store in engine store
    {
        let mut es = state.engine_store.lock().unwrap();
        let team_key = format!("{}/{}", tenant_id, team_id);
        if let Err(e) = es.folder_put(TEAM_FOLDER, &team_key, &json!(team)) {
            return json_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "ok": false,
                    "error": "storage_failed",
                    "message": e.to_string(),
                }),
            );
        }
        let member_key = format!("{}/{}/{}", tenant_id, team_id, admin.id);
        if let Err(e) = es.folder_put(MEMBER_FOLDER, &member_key, &json!(admin)) {
            return json_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "ok": false,
                    "error": "storage_failed",
                    "message": e.to_string(),
                }),
            );
        }
    }
    open_proceed.finish_observed(true);

    Json(json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "team": team,
        "admin": admin,
        "message": "Team created successfully. Use this team_id for all team operations.",
    }))
    .into_response()
}

/// GET /api/v1/plugins/devguard/teams — List teams for tenant
pub async fn list_teams(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<TeamQuery>,
) -> impl IntoResponse {
    let tenant_id = q
        .tenant_id
        .or_else(|| tenant_from_headers(&headers))
        .unwrap_or_else(|| "default".to_string());

    let es = state.engine_store.lock().unwrap();
    let pattern = format!("{}/", tenant_id);

    let mut teams = Vec::new();
    // List all keys in team folder matching tenant
    if let Ok(keys) = es.folder_keys(TEAM_FOLDER, Some(&pattern)) {
        for key in keys {
            if let Ok(Some(doc)) = es.folder_get(TEAM_FOLDER, &key) {
                if let Ok(team) = serde_json::from_value::<Team>(doc) {
                    teams.push(team);
                }
            }
        }
    }

    let limit = q.limit.unwrap_or(100);
    teams.truncate(limit);

    Json(json!({
        "ok": true,
        "teams": teams,
        "count": teams.len(),
        "tenant_id": tenant_id,
    }))
    .into_response()
}

/// GET /api/v1/plugins/devguard/teams/:team_id — Get team details
pub async fn get_team(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(team_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = tenant_from_headers(&headers).unwrap_or_else(|| "default".to_string());
    let team_key = format!("{}/{}", tenant_id, team_id);

    let es = state.engine_store.lock().unwrap();

    let team: Team = match es.folder_get(TEAM_FOLDER, &team_key) {
        Ok(Some(doc)) => match serde_json::from_value(doc) {
            Ok(t) => t,
            Err(e) => {
                return json_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({
                        "ok": false,
                        "error": "parse_error",
                        "message": e.to_string(),
                    }),
                )
            }
        },
        _ => {
            return json_err(
                StatusCode::NOT_FOUND,
                json!({
                    "ok": false,
                    "error": "team_not_found",
                    "message": format!("Team {} not found", team_id),
                }),
            )
        }
    };

    // Load members
    let mut members = Vec::new();
    let member_prefix = format!("{}/{}/", tenant_id, team_id);
    if let Ok(keys) = es.folder_keys(MEMBER_FOLDER, Some(&member_prefix)) {
        for key in keys {
            if let Ok(Some(doc)) = es.folder_get(MEMBER_FOLDER, &key) {
                if let Ok(member) = serde_json::from_value::<TeamMember>(doc) {
                    members.push(member);
                }
            }
        }
    }

    Json(json!({
        "ok": true,
        "team": team,
        "members": members,
        "member_count": members.len(),
    }))
    .into_response()
}

/// POST /api/v1/plugins/devguard/teams/:team_id/members — Add member
pub async fn add_member(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(team_id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> impl IntoResponse {
    let tenant_id = tenant_from_headers(&headers).unwrap_or_else(|| "default".to_string());
    let team_key = format!("{}/{}", tenant_id, team_id);

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "devguard-team",
        "devguard",
        "add_team_member",
        &json!({"team_id": team_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body).into_response(),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();

    // Verify team exists
    if let Ok(None) = es.folder_get(TEAM_FOLDER, &team_key) {
        return json_err(
            StatusCode::NOT_FOUND,
            json!({
                "ok": false,
                "error": "team_not_found",
            }),
        );
    }

    let member_id = format!("mem-{}", uuid::Uuid::new_v4());
    let now = Utc::now().to_rfc3339();

    let member = TeamMember {
        id: member_id.clone(),
        email: req.email,
        name: req.name,
        role: req.role,
        team_id: team_id.clone(),
        joined_at: now,
        last_active: None,
        provider: req.provider.unwrap_or_else(|| "local".to_string()),
        active: true,
    };

    let member_key = format!("{}/{}/{}", tenant_id, team_id, member_id);
    if let Err(e) = es.folder_put(MEMBER_FOLDER, &member_key, &json!(member)) {
        drop(es);
        open_proceed.finish_observed(false);
        return json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({
                "ok": false,
                "error": "storage_failed",
                "message": e.to_string(),
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }),
        );
    }
    drop(es);
    open_proceed.finish_observed(true);

    Json(json!({
        "ok": true,
        "member": member,
        "message": "Member added to team",
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
    .into_response()
}

/// GET /api/v1/plugins/devguard/teams/:team_id/members — List members
pub async fn list_members(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(team_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = tenant_from_headers(&headers).unwrap_or_else(|| "default".to_string());
    let prefix = format!("{}/{}/", tenant_id, team_id);

    let es = state.engine_store.lock().unwrap();
    let mut members = Vec::new();

    if let Ok(keys) = es.folder_keys(MEMBER_FOLDER, Some(&prefix)) {
        for key in keys {
            if let Ok(Some(doc)) = es.folder_get(MEMBER_FOLDER, &key) {
                if let Ok(m) = serde_json::from_value::<TeamMember>(doc) {
                    members.push(m);
                }
            }
        }
    }

    Json(json!({
        "ok": true,
        "members": members,
        "count": members.len(),
    }))
    .into_response()
}

/// PUT /api/v1/plugins/devguard/teams/:team_id/members/:member_id/role — Update role
pub async fn update_member_role(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path((team_id, member_id)): Path<(String, String)>,
    Json(req): Json<UpdateRoleRequest>,
) -> impl IntoResponse {
    let tenant_id = tenant_from_headers(&headers).unwrap_or_else(|| "default".to_string());
    let member_key = format!("{}/{}/{}", tenant_id, team_id, member_id);

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "devguard-team",
        "devguard",
        "update_team_role",
        &json!({"team_id": team_id.as_str(), "member_id": member_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body).into_response(),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();

    let mut member: TeamMember = match es.folder_get(MEMBER_FOLDER, &member_key) {
        Ok(Some(doc)) => match serde_json::from_value(doc) {
            Ok(m) => m,
            Err(e) => {
                return json_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({
                        "ok": false,
                        "error": "parse_error",
                        "message": e.to_string(),
                    }),
                )
            }
        },
        _ => {
            return json_err(
                StatusCode::NOT_FOUND,
                json!({
                    "ok": false,
                    "error": "member_not_found",
                }),
            )
        }
    };

    member.role = req.role;

    if let Err(e) = es.folder_put(MEMBER_FOLDER, &member_key, &json!(member)) {
        drop(es);
        open_proceed.finish_observed(false);
        return json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({
                "ok": false,
                "error": "storage_failed",
                "message": e.to_string(),
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }),
        );
    }
    drop(es);
    open_proceed.finish_observed(true);

    Json(json!({
        "ok": true,
        "member": member,
        "message": "Role updated",
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
    .into_response()
}

/// POST /api/v1/plugins/devguard/teams/:team_id/actions — Log an action
pub async fn log_action(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(team_id): Path<String>,
    Json(req): Json<LogActionRequest>,
) -> impl IntoResponse {
    let tenant_id = tenant_from_headers(&headers).unwrap_or_else(|| "default".to_string());

    // Get member details
    let member_key = format!("{}/{}/{}", tenant_id, team_id, req.member_id);
    let es = state.engine_store.lock().unwrap();

    let (member_name, member_role) = match es.folder_get(MEMBER_FOLDER, &member_key) {
        Ok(Some(doc)) => {
            let m: TeamMember = serde_json::from_value(doc).unwrap();
            (m.name, m.role)
        }
        _ => ("Unknown".to_string(), TeamRole::Junior),
    };
    drop(es);

    let action_id = format!("act-{}", uuid::Uuid::new_v4());
    let action = AgenticAction {
        id: action_id.clone(),
        team_id: team_id.clone(),
        member_id: req.member_id,
        member_name,
        member_role,
        action_type: req.action_type,
        description: req.description,
        timestamp: Utc::now().to_rfc3339(),
        resources: req.resources,
        approved: true, // Auto-approved for now, can add workflow later
        approved_by: None,
        violations: Vec::new(),
        cost_usd: req.cost_usd,
        tokens: req.tokens,
        session_id: req.session_id,
    };

    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "devguard-team",
        "devguard",
        "log_team_action",
        &json!({"team_id": team_id.as_str(), "action_id": action_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body).into_response(),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);

    let mut es = state.engine_store.lock().unwrap();
    let action_key = format!("{}/{}/{}", tenant_id, team_id, action_id);
    if let Err(e) = es.folder_put(ACTION_FOLDER, &action_key, &json!(action)) {
        drop(es);
        open_proceed.finish_observed(false);
        return json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({
                "ok": false,
                "error": "storage_failed",
                "message": e.to_string(),
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }),
        );
    }
    drop(es);
    open_proceed.finish_observed(true);

    Json(json!({
        "ok": true,
        "action_id": action_id,
        "message": "Action logged",
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
    }))
    .into_response()
}

/// GET /api/v1/plugins/devguard/teams/:team_id/actions — List actions
pub async fn list_actions(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(team_id): Path<String>,
    Query(q): Query<TeamQuery>,
) -> impl IntoResponse {
    let tenant_id = tenant_from_headers(&headers).unwrap_or_else(|| "default".to_string());
    let prefix = format!("{}/{}/", tenant_id, team_id);

    let es = state.engine_store.lock().unwrap();
    let mut actions = Vec::new();

    if let Ok(keys) = es.folder_keys(ACTION_FOLDER, Some(&prefix)) {
        for key in keys {
            if let Ok(Some(doc)) = es.folder_get(ACTION_FOLDER, &key) {
                if let Ok(a) = serde_json::from_value::<AgenticAction>(doc) {
                    actions.push(a);
                }
            }
        }
    }

    // Sort by timestamp desc
    actions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let limit = q.limit.unwrap_or(100);
    actions.truncate(limit);

    Json(json!({
        "ok": true,
        "actions": actions,
        "count": actions.len(),
    }))
    .into_response()
}

/// GET /api/v1/plugins/devguard/teams/:team_id/command-center — Dashboard data
pub async fn command_center(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(team_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = tenant_from_headers(&headers).unwrap_or_else(|| "default".to_string());

    // Get team
    let team_key = format!("{}/{}", tenant_id, team_id);
    let es = state.engine_store.lock().unwrap();

    let team: Team = match es.folder_get(TEAM_FOLDER, &team_key) {
        Ok(Some(doc)) => serde_json::from_value(doc).unwrap(),
        _ => {
            return json_err(
                StatusCode::NOT_FOUND,
                json!({
                    "ok": false,
                    "error": "team_not_found",
                }),
            )
        }
    };

    // Get members
    let member_prefix = format!("{}/{}/", tenant_id, team_id);
    let mut members = Vec::new();
    let mut active_now = Vec::new();

    if let Ok(keys) = es.folder_keys(MEMBER_FOLDER, Some(&member_prefix)) {
        for key in keys {
            if let Ok(Some(doc)) = es.folder_get(MEMBER_FOLDER, &key) {
                if let Ok(m) = serde_json::from_value::<TeamMember>(doc) {
                    if m.active {
                        active_now.push(json!({
                            "member_id": m.id,
                            "name": m.name,
                            "role": m.role,
                            "last_active": m.last_active,
                        }));
                    }
                    members.push(m);
                }
            }
        }
    }

    // Get recent actions
    let action_prefix = format!("{}/{}/", tenant_id, team_id);
    let mut recent_actions = Vec::new();
    let mut violations_today = 0u32;
    let mut pending_approvals = Vec::new();

    if let Ok(keys) = es.folder_keys(ACTION_FOLDER, Some(&action_prefix)) {
        for key in keys {
            if let Ok(Some(doc)) = es.folder_get(ACTION_FOLDER, &key) {
                if let Ok(a) = serde_json::from_value::<AgenticAction>(doc) {
                    if !a.approved {
                        pending_approvals.push(json!({
                            "request_id": a.id,
                            "requested_by": a.member_name,
                            "action_type": a.action_type,
                            "description": a.description,
                        }));
                    }
                    if !a.violations.is_empty() {
                        violations_today += 1;
                    }
                    recent_actions.push(json!({
                        "id": a.id,
                        "member": a.member_name,
                        "role": a.member_role,
                        "type": a.action_type,
                        "description": a.description,
                        "timestamp": a.timestamp,
                        "cost_usd": a.cost_usd,
                    }));
                }
            }
        }
    }

    recent_actions.sort_by(|a: &Value, b: &Value| {
        b.get("timestamp")
            .and_then(|v| v.as_str())
            .cmp(&a.get("timestamp").and_then(|v| v.as_str()))
    });
    recent_actions.truncate(20);

    Json(json!({
        "ok": true,
        "command_center": {
            "team": team,
            "members_total": members.len(),
            "members_active_now": active_now.len(),
            "active_sessions": active_now,
            "recent_actions": recent_actions,
            "pending_approvals": pending_approvals,
            "pending_count": pending_approvals.len(),
            "violations_today": violations_today,
            "budget_remaining": team.settings.budget_limit_usd.map(|b| {
                let used: f64 = recent_actions.iter()
                    .filter_map(|a| a.get("cost_usd").and_then(|v| v.as_f64()))
                    .sum();
                b - used
            }),
        }
    }))
    .into_response()
}

/// GET /api/v1/plugins/devguard/roles — Get role definitions
pub async fn get_roles() -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "roles": [
            {
                "id": "admin",
                "name": "Team Admin",
                "clearance": 100,
                "can_manage_team": true,
                "can_approve_all": true,
                "capabilities": [
                    "Manage team members and roles",
                    "View all team activity",
                    "Configure policies",
                    "Approve any action",
                    "Manage projects",
                    "Full file access",
                    "Full shell access",
                ],
            },
            {
                "id": "senior",
                "name": "Senior Member",
                "clearance": 75,
                "can_manage_team": false,
                "can_approve_all": true,
                "can_approve": ["junior"],
                "capabilities": [
                    "Full file access",
                    "Full shell access",
                    "Approve junior actions",
                    "View team activity",
                    "Create projects",
                ],
            },
            {
                "id": "junior",
                "name": "Junior Member",
                "clearance": 50,
                "can_manage_team": false,
                "can_approve_all": false,
                "requires_approval_for": ["shell_execute", "git_push", "file_delete"],
                "capabilities": [
                    "Read files",
                    "Write files (reviewed)",
                    "Basic shell commands",
                    "LLM assistance",
                    "Request approval for sensitive ops",
                ],
            },
            {
                "id": "observer",
                "name": "Observer",
                "clearance": 25,
                "can_manage_team": false,
                "can_approve_all": false,
                "capabilities": [
                    "View files",
                    "View activity logs",
                    "Read-only access",
                ],
            },
        ],
    }))
    .into_response()
}
