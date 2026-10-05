//! MATERIALIZE orchestration — semantic intent → PATE → lease → RESOLVE → CDP (no parallel admit).

use connector_trust::{
    BrokerDecision, BrokerDecisionCode, MaterializationRequest, MaterializeMode, ResolveRequest,
    BROKER_DECISION_SCHEMA, MATERIALIZATION_REQUEST_SCHEMA, RESOLVE_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use crate::state::SharedState;

use super::{
    assert_cdp_thawed, broker_epoch, materialize, resolve, svf_enabled,
};

/// Full MATERIALIZE path for opaque tool args already admitted OR for operator API.
/// Prefer tools.rs live path; this is the explicit SVF entry for semantic intents.
pub fn materialize_with_resolve(
    state: &SharedState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    handle: &str,
    purpose: &str,
    opaque_args: &Value,
    pate_task_id: &str,
    action_digest: &str,
    value: &mut Value,
) -> Result<Value, Value> {
    if !svf_enabled() {
        return Err(json!({
            "ok": false,
            "error": "svf_disabled",
            "decision": BrokerDecision {
                schema: BROKER_DECISION_SCHEMA.to_string(),
                code: BrokerDecisionCode::Block,
                message: "svf_disabled".into(),
                denial_reason: Some("Set CONNECTOR_SVF=1".into()),
                redo_hints: None,
            },
        }));
    }
    assert_cdp_thawed(state, agent_pid)?;

    let req = ResolveRequest {
        schema: RESOLVE_REQUEST_SCHEMA.to_string(),
        handle: handle.to_string(),
        agent_vid: agent_pid.to_string(),
        purpose: purpose.to_string(),
        broker_epoch: broker_epoch(state, agent_pid),
    };
    let resolved = resolve::resolve(state, &req);
    if !resolved.resolved {
        return Err(json!({
            "ok": false,
            "error": "resolve_failed",
            "resolve": resolved,
            "decision": {
                "schema": BROKER_DECISION_SCHEMA,
                "code": "expand_denied",
                "message": resolved.denial_reason.clone().unwrap_or_else(|| "unresolved".into()),
            },
        }));
    }

    // Materialize CDP on the provided value (post-Admit caller).
    let (n, mode) = materialize::materialize_after_admit(
        state,
        agent_pid,
        bridge_id,
        tool_name,
        value,
        pate_task_id,
        action_digest,
    )?;

    crate::substrate::arc::copg::record_svf_edge(
        agent_pid,
        pate_task_id,
        &resolved
            .private_binding_digest
            .clone()
            .unwrap_or_else(|| handle.to_string()),
        "svf_materialize",
        json!({
            "handle": handle,
            "mode": mode,
            "materialized_refs": n,
            "world_grant_pore": resolved.world_grant_pore,
            "opaque_digest": format!("{:x}", {
                use sha2::{Digest, Sha256};
                Sha256::digest(serde_json::to_vec(opaque_args).unwrap_or_default())
            }),
        }),
    );

    let mat_req = MaterializationRequest {
        schema: MATERIALIZATION_REQUEST_SCHEMA.to_string(),
        handle: handle.to_string(),
        agent_vid: agent_pid.to_string(),
        mode,
        pate_task_id: pate_task_id.to_string(),
        action_digest: action_digest.to_string(),
        sink: format!("{bridge_id}:{tool_name}"),
    };

    Ok(json!({
        "ok": true,
        "schema": "connector.svf.materialize_result.v1",
        "resolve": resolved,
        "materialization": mat_req,
        "materialized_refs": n,
        "mode": mode,
        "decision": BrokerDecision {
            schema: BROKER_DECISION_SCHEMA.to_string(),
            code: BrokerDecisionCode::Allow,
            message: "materialized".into(),
            denial_reason: None,
            redo_hints: None,
        },
    }))
}

/// Operator/API: admit + lease + resolve + CDP for a semantic handle (ActionBroker).
/// Does not dispatch the world effect — returns expanded args for a subsequent tool call.
pub fn admit_resolve_materialize(
    state: &SharedState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    handle: &str,
    purpose: &str,
    opaque_args: &Value,
) -> Result<Value, Value> {
    if !svf_enabled() {
        return Err(json!({ "ok": false, "error": "svf_disabled" }));
    }
    assert_cdp_thawed(state, agent_pid)?;

    let tool_atu = crate::substrate::pate::admit_tool(
        state,
        agent_pid,
        bridge_id,
        tool_name,
        opaque_args,
        None,
    )
    .map_err(|e| {
        json!({
            "ok": false,
            "error": e.denial_reason.slug(),
            "denial_reason": e.human_readable,
            "decision": "block",
        })
    })?;

    let mut arc_lease = crate::substrate::arc::lease::LeaseSinkGuard::begin(
        agent_pid,
        &tool_atu.action_digest,
        &tool_atu.task_id,
        tool_atu.iac_epoch,
    )
    .map_err(|e| {
        json!({
            "ok": false,
            "error": "arc_lease_required",
            "denial_reason": e.human_readable,
            "hint": e.hint,
            "honesty": "NoLease ⇒ NoEffect when CONNECTOR_ARC_LEASE=1",
        })
    })?;

    let mut expanded = crate::substrate::llm_broker_gate::expand_after_admit(
        state,
        agent_pid,
        opaque_args,
    )?;

    let mat = match materialize_with_resolve(
        state,
        agent_pid,
        bridge_id,
        tool_name,
        handle,
        purpose,
        opaque_args,
        &tool_atu.task_id,
        &tool_atu.action_digest,
        &mut expanded,
    ) {
        Ok(v) => v,
        Err(e) => {
            arc_lease.fail();
            return Err(e);
        }
    };

    let _ = crate::substrate::pate::complete_augmented_task(
        state,
        &tool_atu,
        "svf_materialize_ready",
        json!({
            "handle": handle,
            "bridge_id": bridge_id,
            "tool": tool_name,
            "mode": MaterializeMode::ActionBroker,
            "honesty": "CDP ready — world effect still requires tools dispatch / exclusivity",
        }),
    );

    arc_lease.success();

    Ok(json!({
        "ok": true,
        "pate_task_id": tool_atu.task_id,
        "action_digest": tool_atu.action_digest,
        "expanded_args": expanded,
        "materialize": mat,
        "honesty": "ATU completed for materialize readiness; effect exclusivity still gates world dispatch",
    }))
}
