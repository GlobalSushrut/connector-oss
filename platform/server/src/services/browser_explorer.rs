//! HTTP + MCP surface for the Connector-native browser world.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::kernel::browser_world;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct NavigateBody {
    pub agent_pid: String,
    pub url: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub max_bytes: Option<usize>,
    #[serde(default)]
    pub goal_id: Option<String>,
    #[serde(default)]
    pub situation: Option<Vec<f64>>,
}

#[derive(Debug, Deserialize)]
pub struct SessionQuery {
    pub agent_pid: Option<String>,
}

/// GET /world/browser — posture (not Chromium computer-use).
pub async fn status() -> Json<Value> {
    Json(json!({
        "ok": true,
        "posture": browser_world::posture(),
    }))
}

/// POST /world/browser/navigate — governed one-hop document GET.
pub async fn navigate(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<NavigateBody>,
) -> Json<Value> {
    if crate::services::agents::caller(&headers).is_none()
        && !crate::services::runtime_control::dev_auth_bypass_allowed()
    {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &body.agent_pid,
        "lifecycle",
        "open_page",
        &json!({"agent_pid": body.agent_pid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    if let Err(e) = crate::kernel::action_binding::admit_tool_or_ask(
        &state,
        &body.agent_pid,
        "browser",
        browser_world::CAP_NAVIGATE,
        &json!({"url": body.url}),
    ) {
        open_proceed.finish_observed(false);
        return Json(json!({
            "ok": false,
            "error": "browse_governance_denied",
            "detail": e,
            "task_id": admitted.task_id,
            "executed": false,
            "admits": false,
        }));
    }
    let st = state.clone();
    let pid = body.agent_pid.clone();
    let url = body.url.clone();
    let sid = body.session_id.clone();
    let max = body.max_bytes;
    let goal = body.goal_id.clone();
    let situation = body.situation.clone();
    match tokio::task::spawn_blocking(move || {
        browser_world::navigate(
            st.as_ref(),
            &pid,
            &url,
            sid.as_deref(),
            max,
            goal.as_deref(),
            situation.as_deref(),
        )
    })
    .await
    {
        Ok(Ok(mut v)) => {
            open_proceed.finish_observed(true);
            if let Some(obj) = v.as_object_mut() {
                obj.insert("task_id".into(), json!(admitted.task_id));
                obj.insert("executed".into(), json!(true));
                obj.insert("admits".into(), json!(false));
            }
            Json(v)
        }
        Ok(Err(e)) => {
            open_proceed.finish_observed(false);
            Json(e)
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({"ok": false, "error": format!("browse_join:{e}"), "task_id": admitted.task_id, "executed": false, "admits": false}))
        }
    }
}

/// GET /world/browser/sessions
pub async fn list_sessions(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<SessionQuery>,
) -> Json<Value> {
    if crate::services::agents::caller(&headers).is_none()
        && !crate::services::runtime_control::dev_auth_bypass_allowed()
    {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let items = browser_world::list_sessions(state.as_ref(), q.agent_pid.as_deref());
    Json(json!({"ok": true, "sessions": items, "count": items.len()}))
}

/// GET /world/browser/sessions/:id
pub async fn get_session(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Json<Value> {
    if crate::services::agents::caller(&headers).is_none()
        && !crate::services::runtime_control::dev_auth_bypass_allowed()
    {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    match browser_world::get_session(state.as_ref(), &id) {
        Some(s) => Json(json!({"ok": true, "session": s})),
        None => Json(json!({"ok": false, "error": "session_not_found"})),
    }
}

pub fn install_mcp_tools() {
    use std::sync::{Arc, OnceLock};
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        crate::services::mcp_hosting::register_tool(
            "connector.browser.navigate",
            "Governed browser world: GET one URL on a granted origin. Connector records title, excerpt, links, digest. Redirects are not followed.",
            json!({
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string"},
                    "session_id": {"type": "string"},
                    "max_bytes": {"type": "integer"},
                    "goal_id": {"type": "string"},
                    "situation": {"type": "array", "items": {"type": "number"}}
                }
            }),
            Arc::new(|state: &SharedState, agent_pid: &str, args: Value| {
                let url = args.get("url").and_then(|v| v.as_str()).unwrap_or("");
                let sid = args.get("session_id").and_then(|v| v.as_str());
                let max = args.get("max_bytes").and_then(|v| v.as_u64()).map(|n| n as usize);
                let goal = args.get("goal_id").and_then(|v| v.as_str());
                let situation: Option<Vec<f64>> = args.get("situation").and_then(|v| v.as_array()).map(|arr| {
                    arr.iter().filter_map(|n| n.as_f64()).collect()
                });
                if let Err(e) = crate::kernel::action_binding::admit_tool_or_ask(
                    state,
                    agent_pid,
                    "browser",
                    browser_world::CAP_NAVIGATE,
                    &json!({"url": url}),
                ) {
                    return connector_protocols::mcp_server::McpToolResult {
                        content: vec![connector_protocols::mcp_server::McpContent {
                            content_type: "text".into(),
                            text: e.to_string(),
                        }],
                        is_error: Some(true),
                    };
                }
                match browser_world::navigate(
                    state.as_ref(),
                    agent_pid,
                    url,
                    sid,
                    max,
                    goal,
                    situation.as_deref(),
                ) {
                    Ok(v) | Err(v) => connector_protocols::mcp_server::McpToolResult {
                        content: vec![connector_protocols::mcp_server::McpContent {
                            content_type: "text".into(),
                            text: v.to_string(),
                        }],
                        is_error: v.get("ok").and_then(|x| x.as_bool()).map(|ok| !ok),
                    },
                }
            }),
        );
    });
}
