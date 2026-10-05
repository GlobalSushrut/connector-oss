//! Authority-critical evidence — link Talk/Effect turns into decision traces.
//!
//! Telemetry may be async; these writes are best-effort durable before ACK
//! (INV-15). Failures are logged, not fatal to the operator response path.

use serde_json::json;

use crate::kernel::decision_trace::{append_trace_result, TraceAppendOpts};
use crate::state::PlatformState;
use crate::substrate::turn_envelope::TurnEnvelope;

/// Record a completed Talk turn against the hash-chained decision journal.
pub fn record_talk_turn(
    state: &PlatformState,
    envelope: &TurnEnvelope,
    outcome: &str,
    model_ref: Option<&str>,
    projection_outcome: Option<&str>,
) {
    let opts = TraceAppendOpts {
        gateway: format!("talk.{}", envelope.plane.as_str()),
        action_digest: Some(envelope.request_hash.clone()),
        approval_resolution_id: None,
        model_ref: model_ref.map(str::to_string),
        rag_context_hashes: vec![],
        outcome: outcome.into(),
        policy_version: Some(format!("snapshot:{}", envelope.snapshot_version)),
        message_type: Some("turn_envelope".into()),
        capability_id: Some(envelope.turn_id.clone()),
        cnp_message_id: Some(format!(
            "wu:{}|sess:{}|proj:{}",
            envelope.work_unit_id,
            envelope.session_id,
            projection_outcome.unwrap_or("n/a")
        )),
    };
    if let Err(e) = append_trace_result(state, &envelope.principal_id, opts) {
        tracing::warn!(
            turn_id = %envelope.turn_id,
            error = %e,
            "authority_evidence: decision_trace append failed"
        );
    }
}

/// Record Admit / EffectIntent compilation against the decision journal.
pub fn record_effect_intents(
    state: &PlatformState,
    principal_id: &str,
    session_id: &str,
    snapshot_version: u64,
    intent_digests: &[String],
) {
    let digest = intent_digests.first().cloned().unwrap_or_default();
    let opts = TraceAppendOpts {
        gateway: "effect.workbench.admit".into(),
        action_digest: if digest.is_empty() {
            None
        } else {
            Some(digest)
        },
        approval_resolution_id: None,
        model_ref: None,
        rag_context_hashes: intent_digests.to_vec(),
        outcome: "effect_intents_compiled".into(),
        policy_version: Some(format!("snapshot:{snapshot_version}")),
        message_type: Some("effect_intent".into()),
        capability_id: Some(session_id.into()),
        cnp_message_id: Some(json!({ "count": intent_digests.len() }).to_string()),
    };
    if let Err(e) = append_trace_result(state, principal_id, opts) {
        tracing::warn!(
            principal = %principal_id,
            error = %e,
            "authority_evidence: effect intent trace failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::substrate::turn_envelope::{TurnDeadline, TurnEnvelope};

    #[test]
    fn plane_labels_stable() {
        let d = TurnDeadline::from_now(1_000, 100);
        let e = TurnEnvelope::mint_talk("t", "a", "s", 1, 1, 1, 0, d, "hi");
        assert_eq!(e.plane.as_str(), "talk");
    }
}
