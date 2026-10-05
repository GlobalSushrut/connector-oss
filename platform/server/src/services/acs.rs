//! Top-level ACS + NS FS HTTP surface.

use axum::{extract::State, http::HeaderMap, Json};
use serde_json::{json, Value};

use crate::kernel::{acs, nsfs, share_portal};
use crate::services::agents::{agent_header, caller, require_self_or_operator};
use crate::state::SharedState;

/// GET /runtime/acs/:pid — Agentic Character Surface (own pid if caller is an agent).
pub async fn get_acs(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(pid): axum::extract::Path<String>,
) -> Json<Value> {
    if let Err(e) = require_self_or_operator(&headers, &pid, "acs_isolated") {
        return Json(e);
    }
    Json(acs::render(state.as_ref(), &pid))
}

/// GET /runtime/cage/:pid — address cage + isolated identity (own pid if caller is an agent).
pub async fn get_cage(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(pid): axum::extract::Path<String>,
) -> Json<Value> {
    if let Err(e) = require_self_or_operator(&headers, &pid, "cage_isolated") {
        return Json(e);
    }
    Json(crate::kernel::address_cage::cage_snapshot(state.as_ref(), &pid))
}

/// GET /runtime/nsfs/:pid
pub async fn get_nsfs(
    headers: HeaderMap,
    axum::extract::Path(pid): axum::extract::Path<String>,
) -> Json<Value> {
    if let Err(e) = require_self_or_operator(&headers, &pid, "nsfs_isolated") {
        return Json(e);
    }
    Json(nsfs::snapshot(&pid))
}

/// POST /runtime/nsfs/:pid/ensure — mkdir the light NS FS tree.
pub async fn ensure_nsfs(
    headers: HeaderMap,
    axum::extract::Path(pid): axum::extract::Path<String>,
) -> Json<Value> {
    let Some((_, role)) = caller(&headers) else {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    };
    if role.rank() < 3 {
        return Json(json!({"ok": false, "error": "developer_required", "status": 403}));
    }
    match nsfs::ensure_tree(&pid) {
        Ok(v) => Json(v),
        Err(e) => Json(json!({"ok": false, "error": e})),
    }
}

#[derive(serde::Deserialize)]
pub struct ShareContractBody {
    pub from_pid: String,
    pub to_pid: String,
    pub what: String,
    #[serde(default)]
    pub r#where: String,
    #[serde(default)]
    pub bytes_max: u64,
    #[serde(default)]
    pub packets_max: u64,
    #[serde(default)]
    pub ttl_ms: i64,
    #[serde(default)]
    pub permissions: Vec<String>,
    pub justification: String,
    pub root_passcode: String,
}

/// POST /intelligence/share-contract — human+root only. Mints a shared portal.
pub async fn put_share_contract(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<ShareContractBody>,
) -> Json<Value> {
    let Some((_, role)) = caller(&headers) else {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    };
    if let Err(e) = share_portal::require_human_root(&headers, role.rank()) {
        return Json(json!({"ok": false, "error": e, "status": 403}));
    }
    if let Err(e) = crate::kernel::world_gateway::verify_root_passcode(&body.root_passcode) {
        return Json(json!({"ok": false, "error": e}));
    }
    let contract = share_portal::ShareContractV1 {
        from_pid: body.from_pid,
        to_pid: body.to_pid,
        what: body.what,
        r#where: body.r#where,
        bytes_max: body.bytes_max,
        packets_max: body.packets_max,
        ttl_ms: body.ttl_ms,
        permissions: body.permissions,
        justification: body.justification,
    };
    match share_portal::put_portal(state.as_ref(), &contract) {
        Ok(p) => Json(json!({
            "ok": true,
            "portal_id": p.portal_id,
            "bind": p.bind,
            "from_pid": p.from_pid,
            "to_pid": p.to_pid,
            "what": p.what,
            "bytes_max": p.bytes_max,
            "packets_max": p.packets_max,
            "expires_at_ms": p.expires_at_ms,
            "honesty": "Portal is the only cross-agent window. Isolated by default otherwise.",
        })),
        Err(e) => Json(json!({"ok": false, "error": e})),
    }
}

/// GET /intelligence/share-portals?agent_pid=
pub async fn list_share_portals(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<crate::services::world_gateway::GrantQuery>,
) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let pid = q.agent_pid.clone();
    if let Some(agent) = agent_header(&headers) {
        if pid.as_deref().unwrap_or("") != agent {
            return Json(json!({"ok": false, "error": "share_portals_isolated", "status": 403}));
        }
    }
    let items = share_portal::list_portals(state.as_ref(), pid.as_deref());
    Json(json!({"ok": true, "portals": items, "count": items.len()}))
}

#[derive(serde::Deserialize)]
pub struct ClosePortalBody {
    pub portal_id: String,
    pub root_passcode: String,
}

/// POST /intelligence/share-portals/close — compensating undo (U7). Human+root.
pub async fn close_share_portal(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<ClosePortalBody>,
) -> Json<Value> {
    let Some((_, role)) = caller(&headers) else {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    };
    if let Err(e) = share_portal::require_human_root(&headers, role.rank()) {
        return Json(json!({"ok": false, "error": e, "status": 403}));
    }
    if let Err(e) = crate::kernel::world_gateway::verify_root_passcode(&body.root_passcode) {
        return Json(json!({"ok": false, "error": e}));
    }
    match share_portal::close_portal(state.as_ref(), &body.portal_id) {
        Ok(v) => Json(v),
        Err(e) => Json(json!({"ok": false, "error": e})),
    }
}
