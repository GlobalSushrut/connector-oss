//! Owner gateway — register CNP addresses and per-(agent × address) grants.
//! Grants require kernel root passcode (Linux-like).

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::kernel::world_gateway::{self, WorldAddressV1, WorldGrantV1};
use crate::services::agents::caller;
use crate::state::SharedState;

/// Hosted trial: the session JWT is the tenant owner for 90 minutes.
/// Cone/App grants on that tenant do not require admin rank or a kernel root passcode.
fn playground_session_owner(headers: &HeaderMap) -> bool {
    crate::services::playground::is_playground_mode() && caller(headers).is_some()
}

fn verify_root_or_playground(headers: &HeaderMap, passcode: &str) -> Result<(), String> {
    if playground_session_owner(headers) {
        return Ok(());
    }
    world_gateway::verify_root_passcode(passcode)
}

fn session_tenant_id(headers: &HeaderMap) -> Option<String> {
    crate::middleware::tenant::extract_tenant_from_headers(headers)
        .map(|t| t.tenant_id)
        .filter(|s| !s.trim().is_empty())
}

fn agent_tenant_id(state: &SharedState, agent_pid: &str) -> Option<String> {
    let pid = agent_pid.trim();
    if pid.is_empty() {
        return None;
    }
    let es = state.engine_store.lock().ok()?;
    es.folder_get("agent_meta", pid)
        .ok()
        .flatten()
        .and_then(|m| {
            m.get("tenant_id")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
        .filter(|s| !s.is_empty())
}

/// Playground: the caller may only mint/list grants for agents in their session tenant.
fn playground_owns_agent(
    session_tenant: &str,
    agent_tenant: Option<&str>,
) -> Result<(), String> {
    match agent_tenant {
        Some(t) if t == session_tenant => Ok(()),
        Some(_) => Err("agent_not_in_session_tenant".into()),
        None => Err("agent_not_found".into()),
    }
}

fn assert_playground_owns_agent(
    state: &SharedState,
    headers: &HeaderMap,
    agent_pid: &str,
) -> Result<(), String> {
    if !crate::services::playground::is_playground_mode() {
        return Ok(());
    }
    let session = session_tenant_id(headers).ok_or("tenant_required")?;
    let pid = agent_pid.trim();
    if pid.is_empty() {
        return Err("agent_pid_required".into());
    }
    playground_owns_agent(&session, agent_tenant_id(state, pid).as_deref())
}

fn is_playground_demo_address(address: &str) -> bool {
    matches!(
        address.trim(),
        crate::services::playground_demo::ECHO_TOOL
            | crate::services::playground_demo::DENY_TOOL
            | crate::services::playground_demo::RECEIPTS_TOOL
            | "tool:demo/echo"
            | "tool:demo/http_get"
            | "mcp:demo"
            | "tool:cls"
            | "tool:workbench.admit"
    )
}

fn assert_playground_app_allow(address: &str, app_allow: &[String], layer: &str, effect: &str) -> Result<(), String> {
    if !crate::services::playground::is_playground_mode() {
        return Ok(());
    }
    let app_power = layer.eq_ignore_ascii_case("app")
        || effect.eq_ignore_ascii_case("allow")
        || !app_allow.is_empty();
    if !app_power {
        return Ok(());
    }
    let wildcard = app_allow.iter().any(|c| c.trim() == "*");
    if wildcard && !is_playground_demo_address(address) {
        return Err(
            "playground_wildcard_app_allow_demo_only — App Allow * is trial-only for hosted Demo tools"
                .into(),
        );
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct RootBody {
    pub root_passcode: String,
    #[serde(default)]
    pub new_root_passcode: Option<String>,
}

/// GET /intelligence/gateway/status
pub async fn gateway_status() -> Json<Value> {
    Json(json!({
        "ok": true,
        "schema": "connector.world.gateway.v1",
        "model": "Every outer-world target is an address: this computer (local:host / host_fs / host_proc), HTTP APIs, MCP tools, IoT, robots. Access is a grant per (agent_pid × address). A hosted agent on this machine has an isolated Connector identity — not host USER/HOME/uid. Agent A→P is not Agent A→Q and not Agent B→P.",
        "root_passcode_set": world_gateway::root_is_set(),
        "playground_owner_grants": crate::services::playground::is_playground_mode(),
        "types": world_gateway::types_catalog(),
        "cage_types": crate::kernel::address_cage::types_catalog(),
        "local_host_address": crate::kernel::address_cage::LOCAL_HOST_ADDR,
        "layers": crate::kernel::admission_layers::catalog(),
        "honesty": if crate::services::playground::is_playground_mode() {
            "Playground: session JWT is tenant owner. Grants bind to this tenant's agents only. Unscoped grant list is refused. Kernel root is disabled on the trial. Cone Ask is the default. App Allow * is Demo tools only. Shared VM — not court-grade."
        } else {
            "Three layers: (1) Root HITL — human is root. (2) Cone — AI suggests, human approves. (3) App — automation only for justified (agent × address × cap). Browser world: POST /world/browser/navigate on a granted origin. Same machine is still an address. No bypass of admit_*. Default grant is Cone Ask."
        },
    }))
}

/// POST /intelligence/gateway/root — init or rotate kernel root passcode (admin+).
pub async fn set_root(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<RootBody>,
) -> Json<Value> {
    let Some((_, role)) = caller(&headers) else {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    };
    let playground = crate::services::playground::is_playground_mode();
    if playground {
        return Json(json!({
            "ok": false,
            "error": "playground_root_disabled",
            "status": 403,
            "honesty": "Kernel root is node-global on the shared Fly volume. The trial never sets or rotates it. Session JWT owns tenant grants instead.",
        }));
    }
    if role.rank() < 5 {
        return Json(json!({"ok": false, "error": "admin_required", "status": 403}));
    }
    if world_gateway::root_is_set() {
        if let Err(e) = world_gateway::verify_root_passcode(&body.root_passcode) {
            return Json(json!({"ok": false, "error": e}));
        }
        let Some(new) = body.new_root_passcode.as_deref() else {
            return Json(
                json!({"ok": true, "root_passcode_ok": true, "rotated": false, "honesty": "CRYPTO-05 — passcode check only; not a cryptographic verification claim"}),
            );
        };
        let admitted = match crate::substrate::pate::require_proceed(
            &state,
            "world",
            "lifecycle",
            "set_world_root",
            &json!({"rotated": true}),
        ) {
            Ok(atu) => atu,
            Err(err_body) => return Json(err_body),
        };
        let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
        return match world_gateway::set_root_passcode(new) {
            Ok(()) => {
                open_proceed.finish_observed(true);
                Json(json!({"ok": true, "rotated": true, "task_id": admitted.task_id, "executed": true, "admits": false}))
            }
            Err(e) => {
                open_proceed.finish_observed(false);
                Json(json!({"ok": false, "error": e, "task_id": admitted.task_id, "executed": false, "admits": false}))
            }
        };
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "world",
        "lifecycle",
        "set_world_root",
        &json!({"initialized": true}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match world_gateway::set_root_passcode(&body.root_passcode) {
        Ok(()) => {
            open_proceed.finish_observed(true);
            Json(json!({"ok": true, "initialized": true, "task_id": admitted.task_id, "executed": true, "admits": false}))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({"ok": false, "error": e, "task_id": admitted.task_id, "executed": false, "admits": false}))
        }
    }
}

#[derive(Deserialize)]
pub struct AddressBody {
    pub address: String,
    #[serde(rename = "type")]
    pub address_type: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub cnp_capabilities: Vec<String>,
    #[serde(default)]
    pub root_passcode: String,
}

/// POST /intelligence/gateway/address — register a world address (owner + root).
pub async fn put_address(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<AddressBody>,
) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    if let Err(e) = verify_root_or_playground(&headers, &body.root_passcode) {
        return Json(json!({"ok": false, "error": e}));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        "world",
        "lifecycle",
        "put_world_address",
        &json!({"address": body.address.trim()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let addr = WorldAddressV1 {
        address: body.address.trim().to_string(),
        address_type: body.address_type,
        label: body.label,
        params: body.params,
        cnp_capabilities: body.cnp_capabilities,
    };
    match world_gateway::put_address(state.as_ref(), &addr) {
        Ok(()) => {
            open_proceed.finish_observed(true);
            Json(json!({"ok": true, "address": addr.address, "type": addr.address_type, "task_id": admitted.task_id, "executed": true, "admits": false}))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({"ok": false, "error": e, "task_id": admitted.task_id, "executed": false, "admits": false}))
        }
    }
}

/// GET /intelligence/gateway/addresses
pub async fn list_addresses(State(state): State<SharedState>, headers: HeaderMap) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    let items = world_gateway::list_addresses(state.as_ref());
    Json(json!({"ok": true, "addresses": items, "count": items.len()}))
}

#[derive(Deserialize)]
pub struct GrantBody {
    pub agent_pid: String,
    pub address: String,
    #[serde(default)]
    pub address_type: String,
    #[serde(default)]
    pub access: Vec<String>,
    #[serde(default)]
    pub effect: Option<String>,
    #[serde(default)]
    pub layer: Option<String>,
    #[serde(default)]
    pub app_allow: Vec<String>,
    #[serde(default)]
    pub cone_ask: Vec<String>,
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub root_passcode: String,
}

/// POST /intelligence/gateway/grant — Agent × address setup (owner + root).
pub async fn put_grant(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<GrantBody>,
) -> Json<Value> {
    let Some((_, role)) = caller(&headers) else {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    };
    if role.rank() < 3 {
        return Json(json!({"ok": false, "error": "developer_required", "status": 403}));
    }
    if let Err(e) = verify_root_or_playground(&headers, &body.root_passcode) {
        return Json(json!({"ok": false, "error": e}));
    }
    let effect = body.effect.unwrap_or_else(|| "ask".into());
    let layer = body
        .layer
        .unwrap_or_else(|| match effect.to_ascii_lowercase().as_str() {
            "allow" => "app".into(),
            "block" => "cone".into(),
            _ => "cone".into(),
        });
    let app_power = layer.eq_ignore_ascii_case("app")
        || effect.eq_ignore_ascii_case("allow")
        || !body.app_allow.is_empty();
    if app_power && !playground_session_owner(&headers) {
        if let Err(e) = crate::kernel::share_portal::require_human_root(&headers, role.rank()) {
            return Json(json!({"ok": false, "error": e, "status": 403}));
        }
    }
    if let Err(e) = crate::kernel::admission_layers::validate_grant_layers(
        &layer,
        &effect,
        &body.app_allow,
        body.justification.as_deref(),
    ) {
        return Json(json!({"ok": false, "error": e, "status": 400}));
    }
    if let Err(e) = assert_playground_owns_agent(&state, &headers, &body.agent_pid) {
        return Json(json!({"ok": false, "error": e, "status": 403}));
    }
    if let Err(e) = assert_playground_app_allow(&body.address, &body.app_allow, &layer, &effect) {
        return Json(json!({"ok": false, "error": e, "status": 400}));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        body.agent_pid.trim(),
        "lifecycle",
        "put_world_grant",
        &json!({"agent_pid": body.agent_pid.trim(), "address": body.address.trim()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let grant = WorldGrantV1 {
        agent_pid: body.agent_pid.trim().to_string(),
        address: body.address.trim().to_string(),
        address_type: body.address_type,
        access: body.access,
        effect,
        layer,
        app_allow: body.app_allow,
        cone_ask: body.cone_ask,
        justification: body.justification,
        params: body.params,
        note: body.note,
    };
    let key = world_gateway::grant_key(&grant.agent_pid, &grant.address);
    match world_gateway::put_grant(state.as_ref(), &grant) {
        Ok(()) => {
            open_proceed.finish_observed(true);
            Json(json!({
            "ok": true,
            "grant_key": key,
            "task_id": admitted.task_id,
            "executed": true,
            "admits": false,
            "agent_pid": grant.agent_pid,
            "address": grant.address,
            "effect": grant.effect,
            "layer": grant.layer,
            "honesty": if crate::services::playground::is_playground_mode() {
                "This grant is only this agent at this address, bound to your session tenant. Cone Ask is the default. App Allow * is Demo tools only. Agents cannot mint skip-HITL for other visitors."
            } else {
                "This grant is only this agent at this address. Cone/root = Ask until HITL. App Allow is human+root only (agents cannot mint skip-HITL). Other agents need their own form."
            },
        }))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({"ok": false, "error": e, "task_id": admitted.task_id, "executed": false, "admits": false}))
        }
    }
}

#[derive(Deserialize)]
pub struct GrantQuery {
    pub agent_pid: Option<String>,
}

/// GET /intelligence/gateway/grants?agent_pid=
pub async fn list_grants(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<GrantQuery>,
) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required"}));
    }
    if crate::services::playground::is_playground_mode() {
        let Some(pid) = q.agent_pid.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
            return Json(json!({
                "ok": false,
                "error": "agent_pid_required",
                "status": 400,
                "honesty": "Unscoped grant list is refused on the shared playground node.",
            }));
        };
        if let Err(e) = assert_playground_owns_agent(&state, &headers, pid) {
            return Json(json!({"ok": false, "error": e, "status": 403}));
        }
        let items = world_gateway::list_grants(state.as_ref(), Some(pid));
        return Json(json!({"ok": true, "grants": items, "count": items.len()}));
    }
    let items = world_gateway::list_grants(state.as_ref(), q.agent_pid.as_deref());
    Json(json!({"ok": true, "grants": items, "count": items.len()}))
}

#[derive(Deserialize)]
pub struct RevokeGrantBody {
    pub agent_pid: String,
    pub address: String,
    #[serde(default)]
    pub root_passcode: String,
}

/// POST /intelligence/gateway/grant/revoke — compensating undo (U7).
pub async fn revoke_grant(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<RevokeGrantBody>,
) -> Json<Value> {
    let Some((_, role)) = caller(&headers) else {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    };
    if role.rank() < 3 {
        return Json(json!({"ok": false, "error": "developer_required", "status": 403}));
    }
    if headers
        .get("x-connector-agent-pid")
        .and_then(|v| v.to_str().ok())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return Json(json!({"ok": false, "error": "human_operator_only", "status": 403}));
    }
    if let Err(e) = verify_root_or_playground(&headers, &body.root_passcode) {
        return Json(json!({"ok": false, "error": e}));
    }
    if let Err(e) = assert_playground_owns_agent(&state, &headers, &body.agent_pid) {
        return Json(json!({"ok": false, "error": e, "status": 403}));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        body.agent_pid.trim(),
        "lifecycle",
        "revoke_world_grant",
        &json!({"agent_pid": body.agent_pid.trim(), "address": body.address.trim()}),
    ) {
        Ok(atu) => atu,
        Err(err_body) => return Json(err_body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match world_gateway::revoke_grant(state.as_ref(), &body.agent_pid, &body.address) {
        Ok(mut v) => {
            open_proceed.finish_observed(true);
            if let Some(obj) = v.as_object_mut() {
                obj.insert("task_id".into(), json!(admitted.task_id));
                obj.insert("executed".into(), json!(true));
                obj.insert("admits".into(), json!(false));
            }
            Json(v)
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({"ok": false, "error": e, "task_id": admitted.task_id, "executed": false, "admits": false}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn playground_owns_agent_same_tenant() {
        assert!(playground_owns_agent("pg-aaaa", Some("pg-aaaa")).is_ok());
    }

    #[test]
    fn playground_owns_agent_rejects_foreign() {
        let err = playground_owns_agent("pg-aaaa", Some("pg-bbbb")).unwrap_err();
        assert_eq!(err, "agent_not_in_session_tenant");
    }

    #[test]
    fn playground_owns_agent_missing_meta() {
        let err = playground_owns_agent("pg-aaaa", None).unwrap_err();
        assert_eq!(err, "agent_not_found");
    }

    #[test]
    fn demo_addresses_are_known() {
        assert!(is_playground_demo_address("demo_echo"));
        assert!(is_playground_demo_address("tool:workbench.admit"));
        assert!(!is_playground_demo_address("https://evil.example"));
    }
}
