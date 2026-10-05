//! TG-4 — Fabric task HTTP surface (shared SoT with multiagent dispatch / A2A).

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::PlatformRole;
use crate::kernel::fabric_task::{self, FabricTaskState};
use crate::services::agents::caller;
use crate::state::SharedState;

/// GET /fabric/tasks/:task_id
pub async fn get_task(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "Authentication required", "status": 401}));
    }
    match fabric_task::load_task(state.as_ref(), &task_id) {
        Some(t) => Json(fabric_task::task_json(&t)),
        None => Json(json!({"ok": false, "error": "task_not_found", "status": 404})),
    }
}

#[derive(Debug, Deserialize)]
pub struct ContextQuery {
    pub context_id: String,
}

/// GET /fabric/tasks?context_id=
pub async fn list_by_context(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<ContextQuery>,
) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "Authentication required", "status": 401}));
    }
    let tasks = fabric_task::list_by_context(state.as_ref(), &q.context_id);
    Json(json!({
        "ok": true,
        "context_id": q.context_id,
        "count": tasks.len(),
        "tasks": tasks.iter().map(fabric_task::task_json).collect::<Vec<_>>(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct TransitionBody {
    pub state: String,
    pub reason: Option<String>,
}

/// POST /fabric/tasks/:task_id/transition
pub async fn transition_task(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
    Json(body): Json<TransitionBody>,
) -> Json<Value> {
    let (_uid, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(json!({"ok": false, "error": "Authentication required", "status": 401}));
        }
    };
    if role.rank() < PlatformRole::Developer.rank() {
        return Json(json!({"ok": false, "error": "developer_required", "status": 403}));
    }
    let Some(new_state) = FabricTaskState::parse(&body.state) else {
        return Json(json!({
            "ok": false,
            "error": "invalid_state",
            "allowed": ["SUBMITTED","WORKING","INPUT_REQUIRED","AUTH_REQUIRED","COMPLETED","FAILED","CANCELED","REJECTED"],
            "status": 400,
        }));
    };
    match fabric_task::transition(state.as_ref(), &task_id, new_state, body.reason.as_deref()) {
        Ok(t) => Json(fabric_task::task_json(&t)),
        Err(e) => Json(json!({"ok": false, "error": e, "status": 409})),
    }
}

/// POST /fabric/tasks/:task_id/resume — INPUT_REQUIRED / AUTH_REQUIRED → WORKING (same taskId).
pub async fn resume_task(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Json<Value> {
    let (_uid, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(json!({"ok": false, "error": "Authentication required", "status": 401}));
        }
    };
    if role.rank() < PlatformRole::Developer.rank() {
        return Json(json!({"ok": false, "error": "developer_required", "status": 403}));
    }
    let input = body.get("input").cloned().unwrap_or(body);
    match fabric_task::resume_with_input(state.as_ref(), &task_id, input) {
        Ok(t) => Json(fabric_task::task_json(&t)),
        Err(e) => Json(json!({"ok": false, "error": e, "status": 409})),
    }
}

/// POST /fabric/tasks/:task_id/cancel
pub async fn cancel_task(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(task_id): Path<String>,
) -> Json<Value> {
    let (_uid, role) = match caller(&headers) {
        Some(c) => c,
        None => {
            return Json(json!({"ok": false, "error": "Authentication required", "status": 401}));
        }
    };
    if role.rank() < PlatformRole::Developer.rank() {
        return Json(json!({"ok": false, "error": "developer_required", "status": 403}));
    }
    match fabric_task::transition(
        state.as_ref(),
        &task_id,
        FabricTaskState::Canceled,
        Some("operator_cancel"),
    ) {
        Ok(t) => Json(fabric_task::task_json(&t)),
        Err(e) => Json(json!({"ok": false, "error": e, "status": 409})),
    }
}
