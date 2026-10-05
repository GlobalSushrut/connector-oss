//! Decision / Evidence Ledger — no raw CoT / reasoning_content in VAC.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::PlatformState;

pub const LEDGER_SCHEMA: &str = "connector.decision_ledger.v1";
pub const LEDGER_FOLDER: &str = "decision_evidence_ledger";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub schema: String,
    pub record_id: String,
    pub agent_pid: String,
    pub mission_id: Option<String>,
    pub action_digest: String,
    pub evidence_cids: Vec<String>,
    pub outcome: String,
    /// Opaque digest of provider reasoning — never the raw text.
    pub reasoning_digest: Option<String>,
    pub at_ms: i64,
}

pub fn reasoning_digest(reasoning: Option<&str>) -> Option<String> {
    reasoning
        .filter(|s| !s.trim().is_empty())
        .map(|s| format!("{:x}", Sha256::digest(s.as_bytes())))
}

pub fn record(
    state: &PlatformState,
    agent_pid: &str,
    mission_id: Option<&str>,
    action_digest: &str,
    evidence_cids: Vec<String>,
    outcome: &str,
    reasoning: Option<&str>,
) -> DecisionRecord {
    let at_ms = chrono::Utc::now().timestamp_millis();
    let record_id = format!(
        "dec_{}",
        &format!(
            "{:x}",
            Sha256::digest(format!("{agent_pid}|{action_digest}|{at_ms}").as_bytes())
        )[..16]
    );
    let rec = DecisionRecord {
        schema: LEDGER_SCHEMA.into(),
        record_id: record_id.clone(),
        agent_pid: agent_pid.into(),
        mission_id: mission_id.map(|s| s.into()),
        action_digest: action_digest.into(),
        evidence_cids,
        outcome: outcome.into(),
        reasoning_digest: reasoning_digest(reasoning),
        at_ms,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            LEDGER_FOLDER,
            &record_id,
            &serde_json::to_value(&rec).unwrap_or(Value::Null),
        );
    }
    rec
}

pub fn to_json(r: &DecisionRecord) -> Value {
    serde_json::to_value(r).unwrap_or(json!({ "ok": false }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_stores_raw_reasoning() {
        let d = reasoning_digest(Some("secret chain of thought"));
        assert!(d.is_some());
        assert!(!d.unwrap().contains("secret"));
    }
}
