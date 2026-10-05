//! OBSERVE remask — tool/world results re-enter the model plane as opaque tokens only.

use connector_trust::{ObservationRemaskReport, OBSERVATION_REMASK_SCHEMA};
use serde_json::{json, Value};

use crate::state::SharedState;

use super::{broker_epoch, store, svf_enabled};

/// Tokenize observation for the next LLM turn; record `ObservationRemaskReport`.
/// Always safe to call — no-ops (returns 0) when tokenization is off.
pub fn remask_observation(
    state: &SharedState,
    agent_pid: &str,
    value: &mut Value,
) -> ObservationRemaskReport {
    let tokens_minted =
        crate::substrate::data_tokenization::tokenize_json_for_llm(state, agent_pid, value) as u32;

    // Residual redact on string leaves (protect opaque spans) when SVF on.
    let mut residual_redacted = false;
    if svf_enabled() {
        residual_redacted = residual_redact_json(value);
    }

    let report = ObservationRemaskReport {
        schema: OBSERVATION_REMASK_SCHEMA.to_string(),
        agent_vid: agent_pid.to_string(),
        tokens_minted,
        residual_redacted,
        broker_epoch: broker_epoch(state, agent_pid),
    };

    if svf_enabled() {
        let key = format!(
            "{}:{}",
            agent_pid,
            report.broker_epoch
        );
        if let Ok(v) = serde_json::to_value(&report) {
            store::put_json(state, store::REMASK_FOLDER, &key, &v);
        }
    }

    report
}

fn residual_redact_json(value: &mut Value) -> bool {
    let mut any = false;
    match value {
        Value::String(s) => {
            let (out, redacted) =
                crate::substrate::llm_broker_gate::residual_redact_protecting_opaque(s);
            if redacted {
                *s = out;
                any = true;
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                any |= residual_redact_json(v);
            }
        }
        Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                any |= residual_redact_json(v);
            }
        }
        _ => {}
    }
    any
}

/// JSON fragment for tool response metadata (optional attach).
pub fn remask_meta(report: &ObservationRemaskReport) -> Value {
    json!({
        "svf_remask": report,
    })
}
