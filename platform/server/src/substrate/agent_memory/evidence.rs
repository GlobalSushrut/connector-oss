//! Evidence plane — append-only hash chain per agent (§8–§9).

use connector_trust::{
    EpistemicClass, EvidenceRecord, EVIDENCE_RECORD_SCHEMA,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::state::PlatformState;

pub const EVIDENCE_CHAIN_FOLDER: &str = "agent_memory_evidence_chain";
pub const EVIDENCE_INDEX_FOLDER: &str = "agent_memory_evidence_index";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn content_hash(content: &str) -> String {
    format!("{:x}", Sha256::digest(content.as_bytes()))
}

fn chain_hash(prev: Option<&str>, content_hash: &str, evidence_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev.unwrap_or("genesis").as_bytes());
    h.update(content_hash.as_bytes());
    h.update(evidence_id.as_bytes());
    format!("{:x}", h.finalize())
}

pub fn epistemic_for_packet_type(packet_type: &str) -> EpistemicClass {
    match packet_type.to_ascii_lowercase().as_str() {
        "decision" | "instruction" | "input" => EpistemicClass::Authoritative,
        "extraction" | "action" | "feedback" => EpistemicClass::Observed,
        "contradiction" | "svf_derived" | "derived" => EpistemicClass::Derived,
        _ => EpistemicClass::Observed,
    }
}

/// Record evidence on successful MemWrite; returns chain tip hash.
pub fn append_on_write(
    state: &PlatformState,
    agent_vid: &str,
    source_id: &str,
    content: &str,
    raw_location: &str,
    packet_type: &str,
) -> Option<EvidenceRecord> {
    let Ok(mut es) = state.engine_store.lock() else {
        return None;
    };
    let tip_key = format!("{agent_vid}:tip");
    let prev = es
        .folder_get(EVIDENCE_CHAIN_FOLDER, &tip_key)
        .ok()
        .flatten()
        .and_then(|v| v.get("chain_hash").and_then(|x| x.as_str()).map(str::to_string));

    let evidence_id = format!("E{}", Uuid::new_v4().simple());
    let c_hash = content_hash(content);
    let record = EvidenceRecord {
        schema: EVIDENCE_RECORD_SCHEMA.into(),
        evidence_id: evidence_id.clone(),
        source_id: source_id.into(),
        agent_vid: agent_vid.into(),
        event_time_ms: now_ms(),
        ingest_time_ms: now_ms(),
        content_hash: c_hash.clone(),
        schema_hash: format!("{:x}", Sha256::digest(packet_type.as_bytes())),
        previous_event_hash: prev.clone(),
        raw_location: raw_location.into(),
        epistemic_class: epistemic_for_packet_type(packet_type),
        signature_status: "recorded".into(),
        fade_state: connector_trust::FadeState::F0Full,
        proof_level: connector_trust::ProofLevel::P0Full,
        bytes: content.len() as u64,
    };
    let chain = chain_hash(prev.as_deref(), &c_hash, &evidence_id);
    let idx_key = format!("{agent_vid}:{evidence_id}");
    let rec_json = serde_json::to_value(&record).unwrap_or_default();
    let _ = es.folder_put(EVIDENCE_INDEX_FOLDER, &idx_key, &rec_json);
    let _ = es.folder_put(
        EVIDENCE_CHAIN_FOLDER,
        &tip_key,
        &serde_json::json!({
            "chain_hash": chain,
            "evidence_id": evidence_id,
            "evidence_root": chain,
        }),
    );
    if crate::substrate::agent_memory::rollup::enabled() {
        crate::substrate::agent_memory::rollup::eligibility::init_meta_from_record(
            state,
            &record,
            content.len(),
        );
    }
    Some(record)
}

pub fn evidence_root(state: &PlatformState, agent_vid: &str) -> Option<String> {
    let es = state.engine_store.lock().ok()?;
    let tip_key = format!("{agent_vid}:tip");
    es.folder_get(EVIDENCE_CHAIN_FOLDER, &tip_key)
        .ok()
        .flatten()
        .and_then(|v| v.get("evidence_root").and_then(|x| x.as_str()).map(str::to_string))
}

pub fn verify_chain(state: &PlatformState, agent_vid: &str) -> bool {
    let Ok(es) = state.engine_store.lock() else {
        return false;
    };
    let prefix = format!("{agent_vid}:");
    let Ok(keys) = es.folder_keys(EVIDENCE_INDEX_FOLDER, Some(&prefix)) else {
        return true;
    };
    let mut prev: Option<String> = None;
    for k in keys {
        let Ok(Some(v)) = es.folder_get(EVIDENCE_INDEX_FOLDER, &k) else {
            continue;
        };
        let Ok(rec) = serde_json::from_value::<EvidenceRecord>(v) else {
            return false;
        };
        let expected = chain_hash(prev.as_deref(), &rec.content_hash, &rec.evidence_id);
        if rec.previous_event_hash.as_deref() != prev.as_deref() {
            return false;
        }
        prev = Some(expected);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_hash_deterministic() {
        let h1 = chain_hash(None, "abc", "E1");
        let h2 = chain_hash(Some(&h1), "def", "E2");
        assert_ne!(h1, h2);
    }
}
