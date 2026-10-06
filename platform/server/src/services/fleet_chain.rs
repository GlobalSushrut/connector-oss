//! HTTP surface for the fleet action chain.
//!
//! Browser navigate and this effect route both call `kernel::fleet_chain`.
//! `http_api` and `a2a_task` do not get a second decision language.

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::kernel::fleet_chain;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct StatusQuery {
    pub goal_id: Option<String>,
    pub agent_pid: Option<String>,
}

fn authorized(headers: &HeaderMap) -> bool {
    crate::services::agents::caller(headers).is_some()
        || crate::services::runtime_control::dev_auth_bypass_allowed()
}

pub async fn verbs() -> Json<Value> {
    Json(json!({
        "ok": true,
        "verbs": fleet_chain::LOGIC_VERBS,
        "count": fleet_chain::VERB_COUNT,
        "fence": "cease",
        "decision": "robustness",
    }))
}

pub async fn status(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<StatusQuery>,
) -> Json<Value> {
    if !authorized(&headers) {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    let goal = q.goal_id.unwrap_or_default();
    let agent = q.agent_pid.unwrap_or_default();
    if goal.trim().is_empty() || agent.trim().is_empty() {
        return Json(json!({
            "ok": true,
            "verbs": fleet_chain::LOGIC_VERBS,
            "fence": "cease",
            "walk": Value::Null,
            "charters": [],
        }));
    }
    Json(fleet_chain::status(state.as_ref(), goal.trim(), agent.trim()))
}

pub async fn put_charter(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    if !authorized(&headers) {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    match fleet_chain::put_charter(state.as_ref(), &body) {
        Ok(v) => Json(v),
        Err(v) => Json(v),
    }
}

pub async fn post_step(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    if !authorized(&headers) {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    match fleet_chain::step(state.as_ref(), &body) {
        Ok(v) => Json(v),
        Err(v) => Json(v),
    }
}

/// Same evaluator as browser navigate, for `http_api` and `a2a_task`.
/// This records a projection when robustness is nonnegative. It does not fetch.
pub async fn post_effect(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    if !authorized(&headers) {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    let address_type = body
        .get("address_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if address_type != "http_api" && address_type != "a2a_task" && address_type != "browser" {
        return Json(json!({
            "ok": false,
            "error": "address_type_unsupported",
            "supported": ["browser", "http_api", "a2a_task"],
        }));
    }
    match fleet_chain::step(state.as_ref(), &body) {
        Ok(v) => Json(v),
        Err(v) => Json(v),
    }
}
