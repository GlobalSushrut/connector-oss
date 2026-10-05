//! HTTP — intelligence council (root mint, μ-attributed floor).

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::kernel::council;
use crate::services::agents::caller;
use crate::state::SharedState;

fn agent_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-connector-agent-pid")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn root_gate(headers: &HeaderMap, role_rank: u8, pass: &str) -> Result<(), String> {
    crate::kernel::share_portal::require_human_root(headers, role_rank)?;
    crate::kernel::world_gateway::verify_root_passcode(pass)
}

#[derive(Deserialize)]
pub struct MintBody {
    pub name: String,
    pub members: Vec<String>,
    pub justification: String,
    pub root_passcode: String,
}

/// POST /intelligence/council — human+root mints a council of chartered I.
pub async fn mint(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<MintBody>,
) -> Json<Value> {
    let Some((_, role)) = caller(&headers) else {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    };
    if let Err(e) = root_gate(&headers, role.rank(), &body.root_passcode) {
        return Json(json!({"ok": false, "error": e, "status": 403}));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "council",
        "lifecycle",
        "mint_council",
        &json!({"name": body.name.as_str(), "members": body.members.len()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match council::mint(
        state.as_ref(),
        &body.name,
        &body.members,
        &body.justification,
    ) {
        Ok(c) => {
            open_proceed.finish_observed(true);
            Json(json!({
                "ok": true,
                "council_id": c.council_id,
                "name": c.name,
                "members": c.members,
                "honesty": "Pairwise pores minted. Isolated WM. Floor is who-said-what. Identity is μ.",
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
            }))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({"ok": false, "error": e, "task_id": admitted.task_id, "executed": false, "admits": false}))
        }
    }
}

/// GET /intelligence/council — operator sees all; an I sees only memberships.
pub async fn list(State(state): State<SharedState>, headers: HeaderMap) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    let pid = agent_header(&headers);
    let items = council::list(state.as_ref(), pid.as_deref());
    Json(json!({
        "ok": true,
        "councils": items,
        "count": items.len(),
        "honesty": "No ambient mesh. Membership is root-minted."
    }))
}

/// GET /intelligence/council/:id
pub async fn get(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    match council::snapshot(state.as_ref(), &id) {
        Ok(v) => {
            if let Some(agent) = agent_header(&headers) {
                let members = v
                    .get("members")
                    .and_then(|m| m.as_array())
                    .cloned()
                    .unwrap_or_default();
                let ok = members
                    .iter()
                    .any(|m| m.get("I").and_then(|x| x.as_str()) == Some(agent.as_str()));
                if !ok {
                    return Json(json!({"ok": false, "error": "not_a_member", "status": 403}));
                }
            }
            Json(v)
        }
        Err(e) => Json(json!({"ok": false, "error": e})),
    }
}

/// GET /intelligence/council/:id/floor
pub async fn floor(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    if let Some(agent) = agent_header(&headers) {
        match council::load(state.as_ref(), &id) {
            Some(c) if council::is_member(&c, &agent) => {}
            Some(_) => return Json(json!({"ok": false, "error": "not_a_member", "status": 403})),
            None => return Json(json!({"ok": false, "error": "council_not_found"})),
        }
    }
    match council::floor(state.as_ref(), &id, 80) {
        Ok(v) => Json(v),
        Err(e) => Json(json!({"ok": false, "error": e})),
    }
}

#[allow(non_snake_case)]
#[derive(Deserialize)]
pub struct SpeakBody {
    pub from_I: String,
    #[serde(default)]
    pub from_mu: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    pub body: String,
    #[serde(default)]
    pub task_id: Option<String>,
}

/// POST /intelligence/council/:id/speak — this I only. μ recomputed; spoof refused.
pub async fn speak(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<SpeakBody>,
) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    let Some(agent) = agent_header(&headers) else {
        return Json(json!({
            "ok": false,
            "error": "agent_pid_required",
            "status": 403,
            "honesty": "X-Connector-Agent-Pid required. Root mints the council; members speak as themselves."
        }));
    };
    let from = body.from_I.trim();
    if agent != from {
        return Json(json!({
            "ok": false,
            "error": "cannot_speak_as_another_I",
            "status": 403,
            "honesty": "Header I must match from_I. Identity mix-up refused."
        }));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        from,
        "lifecycle",
        "council_floor",
        &json!({"council_id": id.as_str(), "kind": body.kind.as_deref().unwrap_or("speak")}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match council::speak(
        state.as_ref(),
        &id,
        from,
        body.to.as_deref().unwrap_or("floor"),
        body.kind.as_deref().unwrap_or("speak"),
        &body.body,
        body.from_mu.as_deref(),
        body.task_id.as_deref(),
    ) {
        Ok(e) => {
            open_proceed.finish_observed(true);
            Json(json!({
                "ok": true,
                "seq": e.seq,
                "from_I": e.from_I,
                "from_mu": e.from_mu,
                "from_name": e.from_name,
                "to": e.to,
                "kind": e.kind,
                "task_id": admitted.task_id,
                "floor_task_id": e.task_id,
                "record_hash": e.record_hash,
                "prev_hash": e.prev_hash,
                "executed": true,
                "admits": false,
            }))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({"ok": false, "error": e, "task_id": admitted.task_id, "executed": false, "admits": false}))
        }
    }
}

#[allow(non_snake_case)]
#[derive(Deserialize)]
pub struct MemberBody {
    pub I: String,
    pub root_passcode: String,
}

/// POST /intelligence/council/:id/members — root adds an I.
pub async fn add_member(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<MemberBody>,
) -> Json<Value> {
    let Some((_, role)) = caller(&headers) else {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    };
    if let Err(e) = root_gate(&headers, role.rank(), &body.root_passcode) {
        return Json(json!({"ok": false, "error": e, "status": 403}));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "council",
        "lifecycle",
        "add_council_member",
        &json!({"council_id": id.as_str(), "member": body.I.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match council::add_member(state.as_ref(), &id, &body.I) {
        Ok(c) => {
            open_proceed.finish_observed(true);
            Json(json!({"ok": true, "members": c.members, "task_id": admitted.task_id, "executed": true, "admits": false}))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({"ok": false, "error": e, "task_id": admitted.task_id, "executed": false, "admits": false}))
        }
    }
}

#[derive(Deserialize)]
pub struct CloseBody {
    pub root_passcode: String,
}

/// POST /intelligence/council/:id/close — root. Pores closed. Floor stays as evidence.
pub async fn close(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<CloseBody>,
) -> Json<Value> {
    let Some((_, role)) = caller(&headers) else {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    };
    if let Err(e) = root_gate(&headers, role.rank(), &body.root_passcode) {
        return Json(json!({"ok": false, "error": e, "status": 403}));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "council",
        "lifecycle",
        "close_council",
        &json!({"council_id": id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match council::close(state.as_ref(), &id) {
        Ok(c) => {
            open_proceed.finish_observed(true);
            Json(json!({
                "ok": true,
                "closed": c.closed,
                "council_id": c.council_id,
                "honesty": "Pores closed. Floor remains who-did-what.",
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
            }))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({"ok": false, "error": e, "task_id": admitted.task_id, "executed": false, "admits": false}))
        }
    }
}

/// GET /intelligence/council/inbox — this I's desk (open tasks + recent floor).
pub async fn inbox(State(state): State<SharedState>, headers: HeaderMap) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    let Some(agent) = agent_header(&headers) else {
        return Json(json!({
            "ok": false,
            "error": "agent_pid_required",
            "status": 403,
            "honesty": "Desk is per I. Header required."
        }));
    };
    Json(council::inbox(state.as_ref(), &agent))
}

/// GET /intelligence/council/:id/tasks — named work with owner μ.
pub async fn tasks(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    match council::load(state.as_ref(), &id) {
        Some(c) => {
            if let Some(agent) = agent_header(&headers) {
                if !council::is_member(&c, &agent) {
                    return Json(json!({"ok": false, "error": "not_a_member", "status": 403}));
                }
            }
            Json(json!({
                "ok": true,
                "council_id": c.council_id,
                "tasks": council::list_tasks(state.as_ref(), &id),
                "honesty": "Each task has a living owner μ. Not a shared crew backlog."
            }))
        }
        None => Json(json!({"ok": false, "error": "council_not_found"})),
    }
}
