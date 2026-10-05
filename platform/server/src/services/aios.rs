//! AIOS kernel HTTP — syscall ABI, claim readiness, kill-switch SLA.

use axum::{extract::State, http::HeaderMap, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Instant;

use crate::kernel::aios;
use crate::services::agents::{caller, require_self_or_operator};
use crate::state::SharedState;

/// GET /kernel/aios/claim-readiness
pub async fn claim_readiness() -> Json<Value> {
    Json(aios::claim_readiness())
}

/// GET /kernel/aios/modules
pub async fn modules() -> Json<Value> {
    Json(aios::modules())
}

/// GET /kernel/aios/crossings — completion + syscall + world, vendor-blind.
pub async fn crossings() -> Json<Value> {
    Json(crate::kernel::operating_layer::recent_json(64))
}

/// GET /kernel/aios/fleet — many I cells; does not replace list_agents.
pub async fn fleet(State(state): State<SharedState>) -> Json<Value> {
    Json(crate::kernel::operating_layer::fleet_snapshot(
        state.as_ref(),
    ))
}

/// GET /kernel/aios/absorb — how vLLM/Ollama/future tools enter. Existing llm link unchanged.
pub async fn absorb() -> Json<Value> {
    Json(json!({
        "ok": true,
        "schema": "connector.operating_layer.absorb.v1",
        "absorb": crate::kernel::operating_layer::absorb_catalog(),
    }))
}

/// GET /kernel/aios/infra — complete AI infra operate plane (aggregates existing subsystems).
pub async fn infra(State(state): State<SharedState>) -> Json<Value> {
    let mut body = crate::kernel::operating_layer::infra_plane(state.as_ref());
    if let Some(cells) = body
        .pointer_mut("/fleet/cells")
        .and_then(|v| v.as_array_mut())
    {
        for c in cells {
            if let Some(pid) = c.get("I").and_then(|x| x.as_str()) {
                let n = crate::services::agents::hitl_pending_count(pid);
                if let Some(obj) = c.as_object_mut() {
                    obj.insert("hitl_pending".into(), json!(n));
                }
            }
        }
    }
    if let Some(obj) = body.as_object_mut() {
        let mut mesh = crate::kernel::node_fabric::snapshot(state.as_ref());
        let ram = crate::services::membership_heartbeat::last_peers_seen().saturating_sub(1) as usize;
        if let Some(obj) = mesh.as_object_mut() {
            let durable = obj.get("live_peers").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
            let peers = durable.max(ram);
            obj.insert("live_peers".into(), json!(peers));
            let env_mesh = obj.get("mesh_fabric").and_then(|x| x.as_bool()).unwrap_or(false);
            let mesh_on = env_mesh && peers >= 1;
            obj.insert("mesh_fabric".into(), json!(mesh_on));
            obj.insert(
                "product_sot".into(),
                json!(if mesh_on { "cell_mesh" } else { "single_node" }),
            );
        }
        obj.insert("topology".into(), mesh);
        obj.insert(
            "vj".into(),
            crate::kernel::aios::claim_readiness()["vj"].clone(),
        );
    }
    Json(body)
}

/// GET /kernel/aios/cell/:pid — one I operate card (ACS stays the character surface).
pub async fn cell(
    State(state): State<SharedState>,
    axum::extract::Path(pid): axum::extract::Path<String>,
) -> Json<Value> {
    let mut body = crate::kernel::operating_layer::cell_operate(state.as_ref(), &pid);
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "hitl_pending".into(),
            json!(crate::services::agents::hitl_pending_count(&pid)),
        );
    }
    Json(body)
}

#[derive(Deserialize)]
pub struct OperateBody {
    pub op: String,
    pub agent_pid: String,
    #[serde(default)]
    pub args: Value,
}

/// POST /kernel/aios/operate — interrupt / retrieve / fleet. Stop stays kill-switch.
pub async fn operate(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<OperateBody>,
) -> Json<Value> {
    let pid = body.agent_pid.trim();
    if matches!(body.op.as_str(), "retrieve" | "interrupt" | "compensate") {
        if let Err(e) = require_self_or_operator(&headers, pid, "operate_isolated") {
            return Json(e);
        }
    } else if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    match body.op.as_str() {
        "interrupt" => {
            if let Err(e) = aios::syscall_contract_gate(state.as_ref(), pid, "llm.interrupt") {
                return Json(
                    json!({"ok": false, "error": e, "denial_reason": "contract_denied", "status": 403}),
                );
            }
            Json(aios::interrupt_generation(pid, None))
        }
        "retrieve" => {
            if let Err(e) = aios::syscall_contract_gate(state.as_ref(), pid, "wm.retrieve") {
                return Json(
                    json!({"ok": false, "error": e, "denial_reason": "contract_denied", "status": 403}),
                );
            }
            let q = body
                .args
                .get("query")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Json(crate::kernel::operating_layer::wm_retrieve(
                Some(state.as_ref()),
                pid,
                q,
                8,
            ))
        }
        "fleet" => Json(crate::kernel::operating_layer::fleet_snapshot(
            state.as_ref(),
        )),
        "infra" => Json(crate::kernel::operating_layer::infra_plane(state.as_ref())),
        "compensate" => Json(compensate(state.as_ref(), &headers, pid, &body.args)),
        "stop" => Json(json!({
            "ok": false,
            "error": "use_existing_path",
            "hint": format!("POST /api/v1/agents/{pid}/kill-switch")
        })),
        other => Json(json!({
            "ok": false,
            "error": "unknown_operate_op",
            "op": other,
            "catalog": ["interrupt", "retrieve", "fleet", "infra", "compensate", "stop"]
        })),
    }
}

/// Compensating undo (U7): revoke grant, close portal, deny tool. Not world rewind.
fn compensate(
    state: &crate::state::PlatformState,
    headers: &HeaderMap,
    pid: &str,
    args: &Value,
) -> Value {
    let Some((_, role)) = caller(headers) else {
        return json!({"ok": false, "error": "auth_required", "status": 401});
    };
    if headers
        .get("x-connector-agent-pid")
        .and_then(|v| v.to_str().ok())
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return json!({
            "ok": false,
            "error": "human_operator_only",
            "honesty": "An I cannot compensate itself. Operator revokes grant / closes portal / denies tool."
        });
    }
    let mut done = Vec::new();
    if let Some(addr) = args
        .get("grant_address")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        let pass = args
            .get("root_passcode")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Err(e) = crate::kernel::world_gateway::verify_root_passcode(pass) {
            return json!({"ok": false, "error": e, "step": "revoke_grant"});
        }
        match crate::kernel::world_gateway::revoke_grant(state, pid, addr) {
            Ok(v) => done.push(json!({"revoke_grant": v})),
            Err(e) => return json!({"ok": false, "error": e, "step": "revoke_grant", "done": done}),
        }
    }
    if let Some(portal_id) = args
        .get("portal_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        let pass = args
            .get("root_passcode")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Err(e) = crate::kernel::share_portal::require_human_root(headers, role.rank()) {
            return json!({"ok": false, "error": e, "step": "close_portal", "status": 403});
        }
        if let Err(e) = crate::kernel::world_gateway::verify_root_passcode(pass) {
            return json!({"ok": false, "error": e, "step": "close_portal"});
        }
        match crate::kernel::share_portal::close_portal(state, portal_id) {
            Ok(v) => done.push(json!({"close_portal": v})),
            Err(e) => return json!({"ok": false, "error": e, "step": "close_portal", "done": done}),
        }
    }
    if let Some(tool) = args
        .get("deny_tool")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        if role.rank() < 3 {
            return json!({"ok": false, "error": "developer_required", "step": "deny_tool", "status": 403});
        }
        match deny_tool(state, pid, tool) {
            Ok(v) => done.push(json!({"deny_tool": v})),
            Err(e) => return json!({"ok": false, "error": e, "step": "deny_tool", "done": done}),
        }
    }
    if done.is_empty() {
        return json!({
            "ok": false,
            "error": "nothing_to_compensate",
            "hint": "args.grant_address and/or args.portal_id and/or args.deny_tool (+ root_passcode for grant/portal)"
        });
    }
    let note = format!(
        "compensate: {}",
        serde_json::to_string(&done).unwrap_or_else(|_| "ok".into())
    );
    let clip: String = note.chars().take(2000).collect();
    let _ = crate::kernel::aios::recall_append(pid, "system", &clip);
    json!({
        "ok": true,
        "agent_pid": pid,
        "compensated": done,
        "wm": "recall_append system — undo is in the world model",
        "honesty": "Compensating rollback. Not world-state rewind."
    })
}

fn deny_tool(state: &crate::state::PlatformState, pid: &str, tool: &str) -> Result<Value, String> {
    let contract = crate::kernel::agent_principal::load_contract(state, pid)
        .ok_or_else(|| "contract_not_found".to_string())?;
    let mut denied = contract.denied_operations.clone();
    let t = tool.trim().to_string();
    if !denied.iter().any(|d| d.eq_ignore_ascii_case(&t)) {
        denied.push(t.clone());
    }
    let r = crate::kernel::agent_principal::update_contract(
        state,
        pid,
        crate::kernel::agent_principal::ContractPatchV2 {
            denied_operations: Some(denied),
            ..Default::default()
        },
    )?;
    Ok(json!({
        "ok": true,
        "denied": t,
        "contract_version": r.contract.contract_version,
        "revoked_quanta": r.revoked_quanta,
        "needs_reactivate": r.needs_reactivate,
        "honesty": "Tool added to denied_operations. Quanta voided; re-activate if it was Active."
    }))
}

#[derive(Deserialize)]
pub struct SyscallBody {
    pub agent_pid: String,
    pub op: String,
    #[serde(default)]
    pub args: Value,
}

/// POST /kernel/syscall — agents do not touch primitives.
pub async fn syscall(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<SyscallBody>,
) -> Json<Value> {
    if let Err(e) = require_self_or_operator(&headers, body.agent_pid.trim(), "agent_may_only_syscall_self") {
        return Json(e);
    }
    if let Err(e) = aios::syscall_contract_gate(state.as_ref(), &body.agent_pid, &body.op) {
        return Json(json!({
            "ok": false,
            "error": e,
            "denial_reason": "contract_denied",
            "status": 403,
            "honesty": "U6 — syscalls are charter-gated. Talk inject still writes WM as SP, not this ABI."
        }));
    }
    Json(aios::dispatch_with(
        Some(state.as_ref()),
        &body.agent_pid,
        &body.op,
        &body.args,
    ))
}

/// GET /agents/:pid/memory/os
pub async fn memory_os(
    headers: HeaderMap,
    axum::extract::Path(pid): axum::extract::Path<String>,
) -> Json<Value> {
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    match aios::ensure_memory_os(&pid) {
        Ok(v) => Json(v),
        Err(e) => Json(json!({"ok": false, "error": e})),
    }
}

/// POST /agents/:pid/kill-switch — Gartner 5-minute stop: interrupt Talk then kill.
pub async fn kill_switch(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Path(pid): axum::extract::Path<String>,
) -> Json<Value> {
    let started = Instant::now();
    if caller(&headers).is_none() {
        return Json(json!({"ok": false, "error": "auth_required", "status": 401}));
    }
    let interrupted = aios::interrupt_generation(&pid, None);
    let kill = crate::services::agents::kill_agent(
        State(state),
        headers,
        axum::extract::Path(pid.clone()),
    )
    .await;
    let elapsed_ms = started.elapsed().as_millis();
    let killed = kill
        .0
        .get("killed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || kill.0.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    aios::record_kill_switch(&pid, elapsed_ms, killed);
    Json(json!({
        "ok": killed,
        "schema": "connector.aios.kill_switch.v1",
        "agent_pid": pid,
        "elapsed_ms": elapsed_ms,
        "within_5min": elapsed_ms < 300_000,
        "interrupted": interrupted,
        "kill": kill.0,
        "honesty": "Stops this pid on this node. Compensating rollback = revoke grants / close portals / disable tools. Not world-state rewind."
    }))
}
