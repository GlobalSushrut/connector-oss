//! MomentProof — forensic entry point + auto-mint on effects (§24–§26, §56).

use connector_trust::{MomentProof, ProofLevel, MOMENT_PROOF_SCHEMA};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::state::PlatformState;
use crate::substrate::pate::{AugmentedTaskUnit, EffectKind};

use super::context_store;
use super::evidence;
use super::rollup::{metrics, skeleton};

pub const MOMENT_FOLDER: &str = "agent_memory_moments";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn assemble(
    state: &PlatformState,
    agent_vid: &str,
    execution_id: &str,
    trigger: &str,
    proposed_action: &str,
    connector_decision: &str,
    actual_effect: &str,
    transition_id: Option<String>,
    checkpoint_id: Option<String>,
) -> MomentProof {
    assemble_with_levels(
        state,
        agent_vid,
        execution_id,
        trigger,
        proposed_action,
        connector_decision,
        actual_effect,
        transition_id,
        checkpoint_id,
        ProofLevel::P0Full,
        ProofLevel::P0Full,
    )
}

fn assemble_with_levels(
    state: &PlatformState,
    agent_vid: &str,
    execution_id: &str,
    trigger: &str,
    proposed_action: &str,
    connector_decision: &str,
    actual_effect: &str,
    transition_id: Option<String>,
    checkpoint_id: Option<String>,
    proof_at_creation: ProofLevel,
    current_proof: ProofLevel,
) -> MomentProof {
    let ctx = context_store::load_state(state, agent_vid);
    let ev_root = evidence::evidence_root(state, agent_vid)
        .unwrap_or_else(|| ctx.evidence_root.clone());
    let mp = MomentProof {
        schema: MOMENT_PROOF_SCHEMA.into(),
        moment_id: format!("M-{}", Uuid::new_v4().simple()),
        timestamp_ms: now_ms(),
        agent_vid: agent_vid.into(),
        execution_id: execution_id.into(),
        previous_context_root: ctx.context_root.clone(),
        current_context_root: ctx.context_root.clone(),
        authority_root: ctx.authority_root.clone(),
        owner_context_root: ctx.authority_root.clone(),
        agent_self_root: ctx.context_root.clone(),
        world_root: "world:observed".into(),
        policy_root: "policy:v1".into(),
        evidence_root: ev_root,
        trigger: trigger.into(),
        proposed_action: proposed_action.into(),
        connector_decision: connector_decision.into(),
        actual_effect: actual_effect.into(),
        transition_id,
        checkpoint_id,
        epistemic_summary: json!({
            "E0_authoritative": 0,
            "E1_observed": 1,
            "E2_derived": 0,
            "E3_inferred": 0,
            "E4_predicted": 0,
        }),
        node_signature: None,
        proof_level_at_creation: proof_at_creation,
        current_proof_level: current_proof,
        skeleton_id: None,
        decision_id: None,
    };
    persist_moment(state, &mp);
    let sk = skeleton::from_moment(state, &mp, vec![trigger.to_string()], None);
    let mut stored = mp.clone();
    stored.skeleton_id = Some(sk.skeleton_id);
    persist_moment(state, &stored);
    metrics::record_moment(state, agent_vid, current_proof);
    stored
}

fn persist_moment(state: &PlatformState, mp: &MomentProof) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            MOMENT_FOLDER,
            &mp.moment_id,
            &serde_json::to_value(mp).unwrap_or_default(),
        );
    }
}

/// Auto-mint MomentProof after PATE effect completion (Phase 8).
pub fn record_atu_outcome(
    state: &PlatformState,
    atu: &AugmentedTaskUnit,
    outcome: &str,
    detail: &Value,
) -> Option<MomentProof> {
    if !super::enabled() {
        return None;
    }
    let (trigger, proposed, decision, effect) = atu_moment_fields(atu, outcome, detail);
    let execution_id = atu.task_id.clone();
    let cp = context_store::maybe_checkpoint(state, &atu.agent_pid, &effect);
    Some(assemble(
        state,
        &atu.agent_pid,
        &execution_id,
        &trigger,
        &proposed,
        &decision,
        &effect,
        None,
        cp.map(|c| c.checkpoint_id),
    ))
}

fn atu_moment_fields(
    atu: &AugmentedTaskUnit,
    outcome: &str,
    detail: &Value,
) -> (String, String, String, String) {
    let trigger = match atu.effect_kind {
        EffectKind::LlmChat => "talk_completion".into(),
        EffectKind::ToolDispatch => "tool_dispatch".into(),
        EffectKind::ConpCommand => "conp_command".into(),
        EffectKind::MemoryWrite => "memory_write".into(),
        _ => "effect".into(),
    };
    let proposed = match atu.effect_kind {
        EffectKind::LlmChat => format!("llm_chat:{}", atu.action_digest),
        EffectKind::ToolDispatch => format!("tool:{}", atu.action_digest),
        EffectKind::ConpCommand => format!("conp:{}", atu.action_digest),
        EffectKind::CnpSend => format!("cnp:{}", atu.action_digest),
        EffectKind::MemoryWrite => format!("mem_write:{}", atu.action_digest),
        EffectKind::Other => format!("other:{}", atu.action_digest),
    };
    let decision = atu
        .autonomy
        .as_ref()
        .map(|a| format!("{:?}:{}", a.verdict, a.reason_code))
        .unwrap_or_else(|| "proceed".into());
    let effect = format!(
        "{outcome} tokens={} model={}",
        detail
            .get("output_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        detail
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
    );
    (trigger, proposed, decision, effect)
}

pub fn get(state: &PlatformState, moment_id: &str) -> Option<MomentProof> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(MOMENT_FOLDER, moment_id).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn proof_json(state: &PlatformState, moment_id: &str) -> Option<Value> {
    let mp = get(state, moment_id)?;
    let sk = mp
        .skeleton_id
        .as_deref()
        .and_then(|id| skeleton::get(state, id))
        .or_else(|| skeleton::for_moment(state, moment_id));
    let proof = mp.current_proof_level;
    Some(json!({
        "schema": "connector.moment_proof.export.v1",
        "moment": mp,
        "chain_verified": evidence::verify_chain(state, &mp.agent_vid),
        "tracetramp": tracetramp_view(&mp, sk.as_ref()),
    }))
}

pub fn tracetramp_view(
    mp: &MomentProof,
    sk: Option<&connector_trust::CausalMemorySkeleton>,
) -> Value {
    let pl = mp.current_proof_level;
    json!({
        "moment_id": mp.moment_id,
        "proof_level": pl.as_str(),
        "proof_symbol": pl.tracetramp_symbol(),
        "proof_at_creation": mp.proof_level_at_creation.as_str(),
        "evidence_resolution": pl.as_str(),
        "original_raw": matches!(pl, ProofLevel::P0Full),
        "critical_facts_retained": !matches!(pl, ProofLevel::P3Commitment),
        "original_source_hash": mp.evidence_root,
        "decision_reconstruction": !matches!(pl, ProofLevel::P3Commitment),
        "exact_original_pages": matches!(pl, ProofLevel::P0Full),
        "trigger": mp.trigger,
        "connector_decision": mp.connector_decision,
        "actual_effect": mp.actual_effect,
        "causal_skeleton": sk,
        "rollup_honesty": "proof level reflects current fade state — not original capture fidelity",
        "svf_honesty": {
            "disclosure_vs_materialize": "EXPAND/model-plane disclosure (S0–S4) is not CDP materialize (S5 ActionBroker)",
            "s5_never_model_plane": true,
            "sinks": {
                "expand": "svf.expand.model",
                "materialize": "cdp.action_broker",
            },
            "docs": "platform/docs/arch/CONNECTOR_SVF.md",
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracetramp_p2_honest() {
        let mp = MomentProof {
            schema: MOMENT_PROOF_SCHEMA.into(),
            moment_id: "M-test".into(),
            timestamp_ms: 0,
            agent_vid: "a".into(),
            execution_id: "e".into(),
            previous_context_root: "p".into(),
            current_context_root: "c".into(),
            authority_root: "auth".into(),
            owner_context_root: "o".into(),
            agent_self_root: "s".into(),
            world_root: "w".into(),
            policy_root: "pol".into(),
            evidence_root: "hash".into(),
            trigger: "budget".into(),
            proposed_action: "reject".into(),
            connector_decision: "deny".into(),
            actual_effect: "search_alternatives".into(),
            transition_id: None,
            checkpoint_id: None,
            epistemic_summary: json!({}),
            node_signature: None,
            proof_level_at_creation: ProofLevel::P0Full,
            current_proof_level: ProofLevel::P2Contextual,
            skeleton_id: None,
            decision_id: None,
        };
        let v = tracetramp_view(&mp, None);
        assert_eq!(v["exact_original_pages"], false);
        assert_eq!(v["decision_reconstruction"], true);
        assert_eq!(v["svf_honesty"]["s5_never_model_plane"], true);
        assert!(
            v["svf_honesty"]["disclosure_vs_materialize"]
                .as_str()
                .unwrap_or("")
                .contains("EXPAND")
        );
    }
}
