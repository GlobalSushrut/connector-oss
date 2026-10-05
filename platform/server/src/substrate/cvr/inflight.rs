//! In-flight AAPI effect classification on interrupt (Phase F5).
//!
//! On quarantine/stop/pause interrupt, classify open BCR reservations and
//! behavior invocations as committed / indeterminate / aborted — truthfully.

use serde_json::{json, Value};

use crate::substrate::aapi_effect_field::{self, RESERVATION_FOLDER, INVOCATION_FOLDER};
use crate::state::PlatformState;

pub const CLASSIFY_FOLDER: &str = "cvr_inflight_classify";
pub const CLASSIFY_SCHEMA: &str = "connector.cvr.inflight_interrupt.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectClass {
    Committed,
    Indeterminate,
    Aborted,
}

impl EffectClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Indeterminate => "indeterminate",
            Self::Aborted => "aborted",
        }
    }
}

fn class_from_status(status: &str) -> EffectClass {
    match status.trim().to_ascii_lowercase().as_str() {
        "committed" | "spent" | "final" => EffectClass::Committed,
        "released" | "aborted" | "cancelled" | "rolled_back" => EffectClass::Aborted,
        // Reserved / indeterminate / unknown mid-flight → indeterminate
        _ => EffectClass::Indeterminate,
    }
}

/// Classify open AAPI spend/invocations for `agent_pid` at interrupt time.
pub fn classify_on_interrupt(state: &PlatformState, agent_pid: &str, reason: &str) -> Value {
    let mut reservations = Vec::new();
    let mut invocations = Vec::new();
    let mut counts = json!({
        "committed": 0u64,
        "indeterminate": 0u64,
        "aborted": 0u64,
    });

    if let Ok(es) = state.engine_store.lock() {
        if let Ok(keys) = es.folder_keys(RESERVATION_FOLDER, None) {
            for k in keys {
                if let Ok(Some(v)) = es.folder_get(RESERVATION_FOLDER, &k) {
                    if v.get("agent_pid").and_then(|x| x.as_str()) != Some(agent_pid) {
                        continue;
                    }
                    let status = v
                        .get("status")
                        .and_then(|x| x.as_str())
                        .unwrap_or("reserved");
                    let class = class_from_status(status);
                    bump(&mut counts, class);
                    reservations.push(json!({
                        "reservation_id": v.get("reservation_id"),
                        "resource": v.get("resource"),
                        "status": status,
                        "class": class.as_str(),
                    }));
                }
            }
        }
        if let Ok(keys) = es.folder_keys(INVOCATION_FOLDER, None) {
            for k in keys.into_iter().rev().take(64) {
                if let Ok(Some(v)) = es.folder_get(INVOCATION_FOLDER, &k) {
                    if v.get("agent_pid").and_then(|x| x.as_str()) != Some(agent_pid) {
                        continue;
                    }
                    let status = v.get("status").and_then(|x| x.as_str()).unwrap_or("open");
                    let class = class_from_status(status);
                    bump(&mut counts, class);
                    invocations.push(json!({
                        "invocation_id": v.get("invocation_id"),
                        "action_digest": v.get("action_digest"),
                        "status": status,
                        "class": class.as_str(),
                    }));
                }
            }
        }
    }

    // Also surface DIM pressure for indeterminate spend.
    let indeterminate_n = counts
        .get("indeterminate")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if indeterminate_n > 0 {
        let mut z = crate::substrate::dim::persist::load(state, agent_pid);
        z.consequence_pressure =
            (z.consequence_pressure + 0.05 * indeterminate_n as f32).min(1.0);
        let _ = crate::substrate::dim::persist::save(state, &z);
    }

    let report = json!({
        "schema": CLASSIFY_SCHEMA,
        "agent_pid": agent_pid,
        "reason": reason,
        "at_ms": chrono::Utc::now().timestamp_millis(),
        "counts": counts,
        "reservations": reservations,
        "invocations": invocations,
        "honesty": "Interrupt classification is truthful — indeterminate means outcome unknown, not silently committed",
    });

    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!(
            "{}:{}",
            agent_pid,
            chrono::Utc::now().timestamp_millis()
        );
        let _ = es.folder_put(CLASSIFY_FOLDER, &key, &report);
    }

    // Touch aapi inverse registry visibility (compensation path remains operator).
    let _ = aapi_effect_field::list_durable_actions(state, agent_pid, 1);

    report
}

fn bump(counts: &mut Value, class: EffectClass) {
    if let Some(obj) = counts.as_object_mut() {
        let k = class.as_str();
        let n = obj.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        obj.insert(k.into(), json!(n + 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping() {
        assert_eq!(class_from_status("committed"), EffectClass::Committed);
        assert_eq!(class_from_status("released"), EffectClass::Aborted);
        assert_eq!(class_from_status("reserved"), EffectClass::Indeterminate);
    }
}
