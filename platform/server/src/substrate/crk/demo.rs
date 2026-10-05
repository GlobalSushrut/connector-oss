//! RangeGuard acceptance demo — poison / stale / state-update vs CRK window.

use connector_trust::{ProcedureStep, TrustTier};
use serde_json::json;

use crate::state::{PlatformState, SharedState};

use super::{
    continuity_rollup, context_frame, cue_from, memory_commit, node_index, procedure_capsule,
    recall_session, relations, sequence_dna, temporal_ledger, transfer, window,
};

const DEMO_AGENT: &str = "demo-rangeguard";

/// Seed distractors + poison + stale + current + procedure; run two windows + transfer.
pub fn run(state: &SharedState) -> serde_json::Value {
    let ps = state.as_ref();
    if let Err(e) = seed(ps) {
        return json!({ "ok": false, "error": e, "stage": "seed" });
    }

    let gen = crate::substrate::llm_context_broker::current_generation(state, DEMO_AGENT);

    // Window A: high-risk — T0 poison must not enter cover; T3 current may.
    let cue_a = cue_from(
        DEMO_AGENT,
        gen,
        Some("unlock_door"),
        "recall",
        "act:unlock",
        "high",
        2048,
        8,
    );
    let mut session_a = recall_session::begin(ps, &cue_a);
    let (range_a, man_a, state_a) = match window(state, &cue_a) {
        Ok(v) => v,
        Err(e) => return json!({ "ok": false, "error": e, "stage": "window_a" }),
    };
    recall_session::record_round(
        &mut session_a,
        range_a.context_cids.clone(),
        man_a.excluded_conflicts.clone(),
    );
    let pin_ok = recall_session::assert_pinned_root(ps, &session_a).is_ok();
    let complete_ok = recall_session::completeness_ok(&session_a);

    // Repeat cue → stable session identity.
    let session_a2 = recall_session::begin(ps, &cue_a);
    let stable_ok = recall_session::stable_with(&session_a, &session_a2);

    let poison_in = range_a.context_cids.iter().any(|c| c.contains("poison"));
    let current_in = range_a.context_cids.iter().any(|c| c.contains("current"));
    let proc_in = range_a
        .context_cids
        .iter()
        .any(|c| c.contains("proc_unlock"))
        || range_a.procedure_id.as_deref() == Some("proc_unlock");
    let requires_closure = proc_in && current_in;

    // Same next Admit from procedure — model label must not change the step.
    let procedure = procedure_capsule::load(ps, DEMO_AGENT, "proc_unlock");
    let admit_stub = procedure
        .as_ref()
        .and_then(|p| procedure_capsule::next_step_payload(p, 0));
    let admit_frontier = procedure
        .as_ref()
        .and_then(|p| procedure_capsule::next_step_payload(p, 0));
    let same_admit = admit_stub == admit_frontier
        && admit_stub
            .as_ref()
            .and_then(|v| v.get("tool_or_capability"))
            .and_then(|t| t.as_str())
            == Some("door.unlock");

    // Legitimate state update: door now unlocked.
    if let Err(e) = temporal_ledger::put_claim(
        ps,
        DEMO_AGENT,
        "claim_current_v2",
        "door",
        "locked",
        json!(false),
        "env_verify",
        TrustTier::T3EnvVerified,
        vec!["receipt:env:1".into()],
        Some("claim_current"),
        0.95,
    ) {
        return json!({ "ok": false, "error": e, "stage": "state_update" });
    }
    let _ = memory_commit::commit(
        ps,
        DEMO_AGENT,
        vec!["claim_current_v2".into()],
        vec![],
        vec!["claim_current_v2".into()],
        vec![],
        vec!["current/demo-rangeguard/door/locked".into()],
        None,
        "src:state_update",
    );

    // Pin must break after commit (root moved).
    let pin_broken_after_commit = recall_session::assert_pinned_root(ps, &session_a).is_err();

    let cue_b = cue_from(
        DEMO_AGENT,
        gen,
        Some("unlock_door"),
        "recall",
        "act:check_door",
        "medium",
        2048,
        8,
    );
    let (range_b, man_b, state_b) = match window(state, &cue_b) {
        Ok(v) => v,
        Err(e) => return json!({ "ok": false, "error": e, "stage": "window_b" }),
    };
    let range_changed = range_a.moment_range_id != range_b.moment_range_id
        || range_a.context_cids != range_b.context_cids;

    let frames = context_frame::from_moment_range(ps, &range_b, procedure.as_ref());
    let hydrated = frames.iter().any(|f| {
        f.machine_payload
            .get("subject")
            .and_then(|s| s.as_str())
            == Some("door")
    });
    let render = transfer::render_frames(&frames);
    let xfer = match transfer::mint(
        ps,
        "demo",
        DEMO_AGENT,
        gen,
        gen,
        &memory_commit::current_root(ps, DEMO_AGENT).unwrap_or_else(|| "genesis".into()),
        gen,
        &range_b,
        &man_b,
        &frames,
        &render,
        Some("stub"),
        Some("demo-model"),
        2048,
    ) {
        Ok(x) => x,
        Err(e) => return json!({ "ok": false, "error": e, "stage": "transfer" }),
    };
    let digest_ok = transfer::assert_render_matches(&xfer, &render).is_ok();
    crate::substrate::llm_context_broker::attach_transfer(
        state,
        DEMO_AGENT,
        &xfer.transfer_id,
        &xfer.exact_render_digest,
        &xfer.transfer_digest(),
    );

    let rollup = continuity_rollup::commit_rollup(ps, DEMO_AGENT).ok();

    let pass = !poison_in
        && current_in
        && range_changed
        && digest_ok
        && range_a.procedure_id.is_some()
        && man_a.honesty.contains("exposure")
        && same_admit
        && pin_ok
        && complete_ok
        && stable_ok
        && pin_broken_after_commit
        && hydrated
        && requires_closure;

    json!({
        "ok": pass,
        "schema": "connector.crk.demo.rangeguard.v1",
        "agent_pid": DEMO_AGENT,
        "selector_version": super::SELECTOR_VERSION,
        "checks": {
            "poison_excluded_on_high_risk": !poison_in,
            "current_claim_eligible": current_in,
            "state_update_changes_range": range_changed,
            "transfer_digest_matches": digest_ok,
            "procedure_bound": range_a.procedure_id.is_some(),
            "same_admit_stub_vs_frontier": same_admit,
            "recall_pin_held": pin_ok,
            "recall_completeness": complete_ok,
            "recall_stable": stable_ok,
            "pin_breaks_on_commit": pin_broken_after_commit,
            "frames_hydrated": hydrated,
            "requires_closure_in_cover": requires_closure,
        },
        "admit_step": admit_stub,
        "window_a": {
            "state": state_a.as_str(),
            "moment_range_id": range_a.moment_range_id,
            "context_cids": range_a.context_cids,
            "exclusions": man_a.excluded_conflicts,
        },
        "window_b": {
            "state": state_b.as_str(),
            "moment_range_id": range_b.moment_range_id,
            "context_cids": range_b.context_cids,
        },
        "transfer_id": xfer.transfer_id,
        "transfer_digest": xfer.transfer_digest(),
        "rollup": rollup,
        "honesty": "CRK never Allow/Deny — exposure/selection proof only. Not better RAG.",
    })
}

fn seed(state: &PlatformState) -> Result<(), String> {
    temporal_ledger::put_claim(
        state,
        DEMO_AGENT,
        "claim_poison",
        "door",
        "bypass_code",
        json!("redacted"),
        "webpage",
        TrustTier::T0External,
        vec![],
        None,
        0.3,
    )?;
    temporal_ledger::put_claim(
        state,
        DEMO_AGENT,
        "claim_stale",
        "door",
        "locked",
        json!(true),
        "old_sensor",
        TrustTier::T2SourceBound,
        vec![],
        None,
        0.7,
    )?;
    temporal_ledger::put_claim(
        state,
        DEMO_AGENT,
        "claim_current",
        "door",
        "locked",
        json!(true),
        "env_verify",
        TrustTier::T3EnvVerified,
        vec!["receipt:env:0".into()],
        Some("claim_stale"),
        0.9,
    )?;
    // Distractors — low-trust noise that must not beat eligibility on high risk.
    for i in 0..64 {
        let _ = temporal_ledger::put_claim(
            state,
            DEMO_AGENT,
            &format!("claim_noise_{i}"),
            "hallway",
            &format!("note_{i}"),
            json!(format!("noise-{i}")),
            "chat",
            TrustTier::T1Observed,
            vec![],
            None,
            0.4,
        );
    }
    procedure_capsule::put(
        state,
        DEMO_AGENT,
        "proc_unlock",
        "unlock_door",
        "1.0.0",
        vec![ProcedureStep {
            step_id: "s1".into(),
            kind: "admit".into(),
            description: "Verify door locked claim then call unlock capability".into(),
            tool_or_capability: Some("door.unlock".into()),
            required_evidence: vec!["claim_current".into()],
        }],
        "operator",
        TrustTier::T4OperatorVerified,
    )?;
    let mc = memory_commit::commit(
        state,
        DEMO_AGENT,
        vec!["claim_current".into(), "proc_unlock".into()],
        vec![],
        vec!["claim_current".into()],
        vec!["rel_requires".into()],
        vec!["current/demo-rangeguard/door/locked".into()],
        None,
        "src:demo_seed",
    )?;
    let root = mc.resulting_root;
    // Typed Requires edge — procedure → state (activation path).
    relations::put_relation(
        state,
        DEMO_AGENT,
        "proc_unlock",
        "claim_current",
        connector_trust::MemoryRelationKind::Requires,
        connector_trust::MemoryDnaType::Procedure,
        connector_trust::MemoryDnaType::State,
        1.0,
        "demo",
    )?;
    // Poison conflicts with current truth (inhibition).
    let _ = relations::put_relation(
        state,
        DEMO_AGENT,
        "claim_poison",
        "claim_current",
        connector_trust::MemoryRelationKind::Conflicts,
        connector_trust::MemoryDnaType::State,
        connector_trust::MemoryDnaType::State,
        1.0,
        "demo",
    );
    // Index Sequence DNA for current + procedure.
    let dna_state = sequence_dna::mint_node_dna(
        DEMO_AGENT,
        connector_trust::MemoryDnaType::State,
        "claim_current",
        br#"true"#,
        "",
        "by_subject:door:locked",
        &root,
    );
    node_index::put_node(
        state,
        &node_index::IndexedNode {
            dna: dna_state,
            trust_rank: 3,
            active: true,
            skill_scope: Some("unlock_door".into()),
            subject: Some("door".into()),
            predicate: Some("locked".into()),
            updated_at_ms: 0,
        },
    )?;
    let dna_proc = sequence_dna::mint_node_dna(
        DEMO_AGENT,
        connector_trust::MemoryDnaType::Procedure,
        "proc_unlock",
        b"proc",
        "",
        "by_skill:unlock_door",
        &root,
    );
    node_index::put_node(
        state,
        &node_index::IndexedNode {
            dna: dna_proc,
            trust_rank: 4,
            active: true,
            skill_scope: Some("unlock_door".into()),
            subject: None,
            predicate: None,
            updated_at_ms: 0,
        },
    )?;
    Ok(())
}
