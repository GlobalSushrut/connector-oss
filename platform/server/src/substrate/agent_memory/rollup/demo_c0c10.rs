//! C0–C10 vendor-selection aging acceptance (§70).
//!
//! After aging: low-value research fades; C7 budget change and C10 denied purchase
//! remain reconstructable via DecisionMemory / MomentProof.

use connector_trust::{
    EpistemicClass, EvidenceClass, EvidenceRecord, FadeState, ProofLevel, EVIDENCE_RECORD_SCHEMA,
};
use serde_json::json;

use crate::state::PlatformState;

use super::eligibility::{load_meta, save_meta, EvidenceMeta};
use super::execute::execute_fade;
use super::policy;
use super::skeleton;
use super::super::context_store;
use super::super::moment;
use super::super::reducer;

const DEMO_AGENT: &str = "demo-vendor-c0c10";

struct ScenarioStep {
    id: &'static str,
    content: &'static str,
    class: EvidenceClass,
    consequence: f32,
    decision_refs: u64,
}

fn steps() -> Vec<ScenarioStep> {
    vec![
        ScenarioStep {
            id: "C0",
            content: "start vendor research",
            class: EvidenceClass::Research,
            consequence: 0.1,
            decision_refs: 0,
        },
        ScenarioStep {
            id: "C1",
            content: "web result page 1 duplicate",
            class: EvidenceClass::Research,
            consequence: 0.05,
            decision_refs: 0,
        },
        ScenarioStep {
            id: "C2",
            content: "web result page 2 noise",
            class: EvidenceClass::Research,
            consequence: 0.05,
            decision_refs: 0,
        },
        ScenarioStep {
            id: "C3",
            content: "API pricing poll unchanged",
            class: EvidenceClass::Telemetry,
            consequence: 0.02,
            decision_refs: 0,
        },
        ScenarioStep {
            id: "C4",
            content: "intermediate ranking candidates",
            class: EvidenceClass::Research,
            consequence: 0.08,
            decision_refs: 0,
        },
        ScenarioStep {
            id: "C5",
            content: "non-decisive research source",
            class: EvidenceClass::Research,
            consequence: 0.1,
            decision_refs: 0,
        },
        ScenarioStep {
            id: "C6",
            content: "recommend Vendor X acceptable",
            class: EvidenceClass::Research,
            consequence: 0.55,
            decision_refs: 1,
        },
        ScenarioStep {
            id: "C7",
            content: "owner budget <= $10k annual",
            class: EvidenceClass::OwnerInstruction,
            consequence: 0.95,
            decision_refs: 2,
        },
        ScenarioStep {
            id: "C8",
            content: "search Vendor Z alternatives",
            class: EvidenceClass::Research,
            consequence: 0.35,
            decision_refs: 1,
        },
        ScenarioStep {
            id: "C9",
            content: "security review Vendor Z",
            class: EvidenceClass::Security,
            consequence: 0.7,
            decision_refs: 1,
        },
        ScenarioStep {
            id: "C10",
            content: "purchase denied — over budget / policy",
            class: EvidenceClass::FinancialAction,
            consequence: 0.99,
            decision_refs: 3,
        },
    ]
}

fn seed_evidence(state: &PlatformState, step: &ScenarioStep) -> EvidenceRecord {
    let evidence_id = format!("E-{}", step.id);
    let rec = EvidenceRecord {
        schema: EVIDENCE_RECORD_SCHEMA.into(),
        evidence_id: evidence_id.clone(),
        source_id: step.id.into(),
        agent_vid: DEMO_AGENT.into(),
        event_time_ms: chrono::Utc::now().timestamp_millis(),
        ingest_time_ms: chrono::Utc::now().timestamp_millis() - 60 * 86_400_000, // age 60d
        content_hash: format!("hash-{}", step.id),
        schema_hash: "demo".into(),
        previous_event_hash: None,
        raw_location: format!("demo://{}", step.id),
        epistemic_class: match step.class {
            EvidenceClass::OwnerInstruction => EpistemicClass::Authoritative,
            EvidenceClass::FinancialAction => EpistemicClass::Observed,
            _ => EpistemicClass::Observed,
        },
        signature_status: "demo".into(),
        fade_state: FadeState::F0Full,
        proof_level: ProofLevel::P0Full,
        bytes: 10_000,
    };
    let key = format!("{DEMO_AGENT}:{evidence_id}");
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            super::super::evidence::EVIDENCE_INDEX_FOLDER,
            &key,
            &serde_json::to_value(&rec).unwrap_or_default(),
        );
    }
    let mut meta = EvidenceMeta {
        fade_state: FadeState::F0Full,
        bytes: 10_000,
        consequence: step.consequence,
        decision_ref_count: step.decision_refs,
        authority_ref_count: if matches!(step.class, EvidenceClass::OwnerInstruction) {
            1
        } else {
            0
        },
        evidence_class: Some(step.class.as_str().into()),
        ..Default::default()
    };
    if step.decision_refs > 0 {
        meta.causal_ref_count = step.decision_refs;
    }
    save_meta(state, DEMO_AGENT, &evidence_id, &meta);
    let _ = policy::put_class_override(state, DEMO_AGENT, step.class);
    rec
}

/// Seed C0–C10, run aging, assert C7/C10 reconstructable.
pub fn run_acceptance(state: &PlatformState) -> serde_json::Value {
    policy::put_agent_policy(state, DEMO_AGENT, connector_trust::FadePolicy::default());

    let mut seeded = Vec::new();
    for step in steps() {
        seeded.push(seed_evidence(state, &step));
    }

    // Decision memories for consequential steps
    let ctx = context_store::load_state(state, DEMO_AGENT);
    let d7 = reducer::store_decision(
        state,
        DEMO_AGENT,
        "Vendor X",
        "X recommended",
        "owner budget <= $10k",
        "X rejected",
        "cost $12.4k > budget",
        vec!["E-C7".into()],
        0.95,
        "financial",
        ctx.context_epoch,
        EpistemicClass::Authoritative,
    );
    let d10 = reducer::store_decision(
        state,
        DEMO_AGENT,
        "Purchase",
        "draft purchase",
        "policy gate",
        "purchase denied",
        "Connector denied purchase",
        vec!["E-C10".into()],
        0.99,
        "financial",
        ctx.context_epoch,
        EpistemicClass::Observed,
    );

    let m7 = moment::assemble(
        state,
        DEMO_AGENT,
        "EX-C7",
        "owner budget <= $10k",
        "reject Vendor X",
        "deny_recommendation",
        "research Vendor Z",
        None,
        None,
    );
    let m10 = moment::assemble(
        state,
        DEMO_AGENT,
        "EX-C10",
        "purchase attempt",
        "execute purchase",
        "deny",
        "draft created instead",
        None,
        None,
    );

    // Aggressive aging: force several fade steps on low-value C0–C5
    let mut fade_counts = json!({});
    for rec in &seeded {
        let step_id = rec.source_id.clone();
        let mut applied = 0u32;
        // Up to 3 fade steps (F0→F1→F2→F3)
        for _ in 0..3 {
            let r = execute_fade(state, rec, 0.85);
            if r.ok {
                applied += 1;
            } else {
                break;
            }
        }
        fade_counts[step_id] = json!(applied);
    }

    let meta_c7 = load_meta(state, DEMO_AGENT, "E-C7");
    let meta_c10 = load_meta(state, DEMO_AGENT, "E-C10");
    let meta_c3 = load_meta(state, DEMO_AGENT, "E-C3");

    let c7_ok = moment::get(state, &m7.moment_id).is_some()
        && !d7.trigger.is_empty()
        && meta_c7.decision_ref_count > 0;
    let c10_ok = moment::get(state, &m10.moment_id).is_some()
        && !d10.trigger.is_empty()
        && meta_c10.decision_ref_count > 0;
    // Telemetry should have faded more than owner/financial
    let telemetry_faded = meta_c3.fade_state != FadeState::F0Full
        || fade_counts.get("C3").and_then(|v| v.as_u64()).unwrap_or(0) > 0;

    let sk7 = skeleton::for_moment(state, &m7.moment_id);
    let sk10 = skeleton::for_moment(state, &m10.moment_id);

    json!({
        "schema": "connector.rollup.c0c10.acceptance.v1",
        "agent_vid": DEMO_AGENT,
        "assertions": {
            "c7_reconstructable": c7_ok,
            "c10_reconstructable": c10_ok,
            "telemetry_faded_or_attempted": telemetry_faded,
            "c7_decision_id": d7.decision_id,
            "c10_decision_id": d10.decision_id,
            "c7_moment_id": m7.moment_id,
            "c10_moment_id": m10.moment_id,
            "c7_skeleton": sk7.as_ref().map(|s| s.skeleton_id.clone()),
            "c10_skeleton": sk10.as_ref().map(|s| s.skeleton_id.clone()),
            "c7_fade_state": meta_c7.fade_state.as_str(),
            "c10_fade_state": meta_c10.fade_state.as_str(),
            "c3_fade_state": meta_c3.fade_state.as_str(),
        },
        "fade_steps_applied": fade_counts,
        "pass": c7_ok && c10_ok,
        "honesty": "C7/C10 must remain reconstructable after aging low-value research",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_has_eleven_steps() {
        assert_eq!(steps().len(), 11);
        assert_eq!(steps()[7].id, "C7");
        assert_eq!(steps()[10].id, "C10");
    }
}
