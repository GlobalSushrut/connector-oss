//! AAPI post-commit audit bridge — sidecar only; never replaces ActionBinding.
//! Persists durable ledger + BehaviorInvocation (S16/A23).

use serde_json::{json, Value};

use crate::state::SharedState;
use crate::substrate::aapi_effect_field;
use crate::substrate::pate::{AugmentedTaskUnit, EffectKind};

/// Record a settled ATU into the AAPI action log (audit plane) + durable ledger.
pub fn record_atu_commit(
    state: &SharedState,
    atu: &AugmentedTaskUnit,
    outcome: &str,
    evidence: Vec<String>,
) -> Value {
    let intent = match atu.effect_kind {
        EffectKind::LlmChat => "llm.chat",
        EffectKind::ToolDispatch => "tool.dispatch",
        EffectKind::ConpCommand => "conp.command",
        EffectKind::CnpSend => "cnp.send",
        EffectKind::MemoryWrite => "memory.write",
        EffectKind::Other => "other",
    };
    let mut aapi = match state.aapi.lock() {
        Ok(g) => g,
        Err(_) => {
            return json!({"ok": false, "error": "aapi_lock"});
        }
    };
    let entry = aapi.record_action(
        intent,
        &atu.action_digest,
        atu.tool_footprint
            .write_refs
            .first()
            .map(|s| s.as_str())
            .unwrap_or("effect"),
        &atu.agent_pid,
        outcome,
        evidence,
        None,
        vec!["sdb".into(), "pate".into()],
    );
    drop(aapi);

    aapi_effect_field::persist_action(state.as_ref(), &entry);
    let invocation = aapi_effect_field::record_behavior_invocation(
        state.as_ref(),
        &atu.agent_pid,
        &atu.action_digest,
        intent,
        atu.tool_footprint
            .write_refs
            .first()
            .map(|s| s.as_str())
            .unwrap_or("effect"),
        None,
        outcome,
    );

    // Best-effort CLS compile hint (loader surface — not hot-path gate).
    let cls_hint = json!({
        "schema": "connector.aapi.cls_hint.v1",
        "task_id": atu.task_id,
        "effect_kind": format!("{:?}", atu.effect_kind),
        "reversibility": atu.tool_footprint.reversibility,
        "honesty": "CLS compile loader is advisory; ActionBinding remains SoT",
    });
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put("aapi_cls_hints", &atu.task_id, &cls_hint);
    }
    json!({
        "ok": true,
        "record_id": entry.record_id,
        "invocation_id": invocation.invocation_id,
        "durable": true,
        "cls_hint": cls_hint,
    })
}
