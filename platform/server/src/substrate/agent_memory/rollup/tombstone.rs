//! Evidence tombstones — permanent metadata when raw fades (§23–§24).

use connector_trust::{
    EvidenceRecord, EvidenceTombstone, ProofLevel, EVIDENCE_TOMBSTONE_SCHEMA,
};
use uuid::Uuid;

use crate::state::PlatformState;

pub const TOMBSTONE_FOLDER: &str = "agent_memory_tombstones";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn create(
    state: &PlatformState,
    rec: &EvidenceRecord,
    meta_bytes: u64,
    previous: ProofLevel,
    final_level: ProofLevel,
    policy_id: &str,
    context_refs: Vec<String>,
    decision_refs: Vec<String>,
    moment_refs: Vec<String>,
    reason: &str,
) -> EvidenceTombstone {
    let tomb = EvidenceTombstone {
        schema: EVIDENCE_TOMBSTONE_SCHEMA.into(),
        evidence_id: rec.evidence_id.clone(),
        agent_vid: rec.agent_vid.clone(),
        original_hash: rec.content_hash.clone(),
        source_id: rec.source_id.clone(),
        event_time_ms: rec.event_time_ms,
        ingest_time_ms: rec.ingest_time_ms,
        original_size_bytes: meta_bytes,
        fade_time_ms: now_ms(),
        fade_policy: policy_id.into(),
        previous_proof_level: previous,
        final_proof_level: final_level,
        retained_context_refs: context_refs,
        retained_decision_refs: decision_refs,
        retained_moment_refs: moment_refs,
        deletion_reason: reason.into(),
        node_signature: None,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            TOMBSTONE_FOLDER,
            &tomb.evidence_id,
            &serde_json::to_value(&tomb).unwrap_or_default(),
        );
    }
    tomb
}

pub fn get(state: &PlatformState, evidence_id: &str) -> Option<EvidenceTombstone> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(TOMBSTONE_FOLDER, evidence_id).ok().flatten()?;
    serde_json::from_value(v).ok()
}
