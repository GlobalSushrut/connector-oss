//! CDP materialize — post-Admit only, WorldGrant pore, quarantine freezes CDP.
//! Default mode: ActionBroker (platform holds secret; never guest env).

use connector_trust::{
    DisclosureLevel, DisclosureReceipt, EffectReceipt, MaterializeMode, DISCLOSURE_RECEIPT_SCHEMA,
    EFFECT_RECEIPT_SCHEMA,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::state::SharedState;

use super::{broker_epoch, now_ms, store, svf_enabled};

/// Refuse CDP when agent brain is quarantined (maps voided; no expand/materialize).
pub fn assert_cdp_thawed(state: &SharedState, agent_pid: &str) -> Result<(), Value> {
    if crate::substrate::llm_sealed_context::agent_brain_quarantined(state, agent_pid) {
        return Err(serde_json::json!({
            "ok": false,
            "error": "svf_cdp_frozen",
            "denial_reason": "quarantine_freezes_cdp",
            "message": "Quarantine freezes CDP — no expand/materialize until human approval",
            "human_approval": true,
        }));
    }
    Ok(())
}

/// Prefer ActionBroker: materialize vault handles on the platform plane after Admit.
/// When `CONNECTOR_SVF` is on, requires a WorldGrant pore for the MCP tool sink.
pub fn materialize_after_admit(
    state: &SharedState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    value: &mut Value,
    pate_task_id: &str,
    action_digest: &str,
) -> Result<(usize, MaterializeMode), Value> {
    assert_cdp_thawed(state, agent_pid)?;

    if !value_has_vault_refs(value) {
        return Ok((0, MaterializeMode::ActionBroker));
    }

    if svf_enabled() {
        let address = format!("mcp_tool:{bridge_id}");
        if let Err(e) = crate::kernel::world_gateway::assert_grant_allows(
            state.as_ref(),
            agent_pid,
            &address,
            "tool.dispatch",
        ) {
            // Fallback: bridge:tool address form
            let alt = format!("{bridge_id}:{tool_name}");
            if crate::kernel::world_gateway::assert_grant_allows(
                state.as_ref(),
                agent_pid,
                &alt,
                "tool.dispatch",
            )
            .is_err()
            {
                return Err(serde_json::json!({
                    "ok": false,
                    "error": "world_grant_denied",
                    "denial_reason": e,
                    "address": address,
                    "bridge_id": bridge_id,
                    "tool": tool_name,
                    "pate_task_id": pate_task_id,
                    "honesty": "SVF CDP does not invent WorldGrant pores",
                }));
            }
        }
    }

    let mode = MaterializeMode::ActionBroker;
    let n = crate::kernel::credential_proxy::materialize_secret_refs(state.as_ref(), value)
        .map_err(|e| {
            serde_json::json!({
                "error": format!("credential_proxy: {e}"),
                "denial_reason": "vault_resolve_failed",
                "bridge_id": bridge_id,
                "tool": tool_name,
                "pate_task_id": pate_task_id,
            })
        })?;

    if svf_enabled() {
        record_effect_receipt(state, agent_pid, pate_task_id, n > 0, mode);
        if n > 0 {
            record_materialize_disclosure(
                state,
                agent_pid,
                value,
                pate_task_id,
                action_digest,
            );
        }
    }

    Ok((n, mode))
}

fn value_has_vault_refs(value: &Value) -> bool {
    match value {
        Value::String(s) => s.starts_with("vault:handle:") || s.contains("vault:handle:"),
        Value::Object(map) => {
            if map.get("$vault_handle").and_then(|v| v.as_str()).is_some() {
                return true;
            }
            map.values().any(value_has_vault_refs)
        }
        Value::Array(arr) => arr.iter().any(value_has_vault_refs),
        _ => false,
    }
}

fn record_effect_receipt(
    state: &SharedState,
    agent_pid: &str,
    pate_task_id: &str,
    materialized: bool,
    mode: MaterializeMode,
) {
    let receipt = EffectReceipt {
        schema: EFFECT_RECEIPT_SCHEMA.to_string(),
        receipt_id: format!("er-{pate_task_id}"),
        pate_task_id: pate_task_id.to_string(),
        materialized,
        mode,
        issued_at_ms: now_ms(),
    };
    if let Ok(v) = serde_json::to_value(&receipt) {
        store::put_json(
            state,
            store::EFFECT_RECEIPT_FOLDER,
            &format!("{agent_pid}:{pate_task_id}"),
            &v,
        );
    }
}

fn record_materialize_disclosure(
    state: &SharedState,
    agent_pid: &str,
    value: &Value,
    pate_task_id: &str,
    action_digest: &str,
) {
    let blob = serde_json::to_string(value).unwrap_or_default();
    let digest = format!("{:x}", Sha256::digest(blob.as_bytes()));
    let receipt_id = format!("dr-mat-{}", &digest[..16.min(digest.len())]);
    let receipt = DisclosureReceipt {
        schema: DISCLOSURE_RECEIPT_SCHEMA.to_string(),
        receipt_id: receipt_id.clone(),
        agent_vid: agent_pid.to_string(),
        object_refs: vec![],
        level: DisclosureLevel::S5Materialize,
        sink: "cdp.action_broker".to_string(),
        purpose: "post_admit_materialize".to_string(),
        broker_epoch: broker_epoch(state, agent_pid),
        issued_at_ms: now_ms(),
        pate_task_id: Some(pate_task_id.to_string()),
        action_digest: Some(action_digest.to_string()),
    };
    if let Ok(v) = serde_json::to_value(&receipt) {
        store::put_json(
            state,
            store::RECEIPT_FOLDER,
            &format!("{agent_pid}:{receipt_id}"),
            &v,
        );
    }
}

/// Expand-path disclosure (opaque → world) — called from tools after expand_after_admit.
pub fn record_expand_receipt(
    state: &SharedState,
    agent_pid: &str,
    opaque: &Value,
    _expanded: &Value,
    pate_task_id: Option<&str>,
) {
    if !svf_enabled() {
        return;
    }
    let refs = collect_opaque_refs(opaque);
    if refs.is_empty() {
        return;
    }
    let epoch = broker_epoch(state, agent_pid);
    let digest = format!("{:x}", Sha256::digest(refs.join("|").as_bytes()));
    let receipt_id = format!("dr-{}", &digest[..16.min(digest.len())]);
    let receipt = DisclosureReceipt {
        schema: DISCLOSURE_RECEIPT_SCHEMA.to_string(),
        receipt_id: receipt_id.clone(),
        agent_vid: agent_pid.to_string(),
        object_refs: refs,
        level: DisclosureLevel::S5Materialize,
        sink: "tool.world.expand_after_admit".to_string(),
        purpose: "post_admit_cdp".to_string(),
        broker_epoch: epoch,
        issued_at_ms: now_ms(),
        pate_task_id: pate_task_id.map(|s| s.to_string()),
        action_digest: None,
    };
    if let Ok(v) = serde_json::to_value(&receipt) {
        store::put_json(
            state,
            store::RECEIPT_FOLDER,
            &format!("{agent_pid}:{receipt_id}"),
            &v,
        );
    }
}

fn collect_opaque_refs(value: &Value) -> Vec<String> {
    let blob = serde_json::to_string(value).unwrap_or_default();
    let mut refs = Vec::new();
    for re in [
        regex::Regex::new(r"⟦seal:v1:[a-f0-9]+⟧").ok(),
        regex::Regex::new(r"⟦conn:[a-z]+:[a-f0-9]+⟧").ok(),
        regex::Regex::new(r"vault:handle:[A-Za-z0-9_\-:./]+").ok(),
        regex::Regex::new(r"\{\{obj:[A-Za-z0-9_.\-]+\}\}").ok(),
    ]
    .into_iter()
    .flatten()
    {
        for m in re.find_iter(&blob) {
            let s = m.as_str().to_string();
            if !refs.contains(&s) {
                refs.push(s);
            }
        }
    }
    refs
}
