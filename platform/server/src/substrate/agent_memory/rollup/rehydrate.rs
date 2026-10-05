//! Archive + rehydration (§17).
//!
//! F0 hot → F0 archive (payload retained off hot path) → F1 distilled.
//! Rehydrate restores available proof level only — never claims missing raw.

use connector_trust::{EvidenceRecord, FadeState, ProofLevel};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::state::PlatformState;

use super::eligibility::{load_meta, save_meta};
use super::metrics;

pub const ARCHIVE_FOLDER: &str = "agent_memory_evidence_archive";
pub const REHYDRATE_LOG: &str = "agent_memory_rehydrate_log";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Archive raw payload when fading F0→F1 (keeps bytes for later rehydrate).
pub fn archive_payload(
    state: &PlatformState,
    agent_vid: &str,
    evidence_id: &str,
    content_hash: &str,
    payload: &str,
) {
    let key = format!("{agent_vid}:{evidence_id}");
    let body = json!({
        "evidence_id": evidence_id,
        "agent_vid": agent_vid,
        "content_hash": content_hash,
        "payload": payload,
        "archived_at_ms": now_ms(),
        "bytes": payload.len(),
    });
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(ARCHIVE_FOLDER, &key, &body);
    }
}

pub fn get_archive(
    state: &PlatformState,
    agent_vid: &str,
    evidence_id: &str,
) -> Option<Value> {
    let es = state.engine_store.lock().ok()?;
    let key = format!("{agent_vid}:{evidence_id}");
    es.folder_get(ARCHIVE_FOLDER, &key).ok().flatten()
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RehydrateResult {
    pub ok: bool,
    pub evidence_id: String,
    pub restored_proof_level: ProofLevel,
    pub raw_available: bool,
    pub distilled_available: bool,
    pub honesty: String,
    pub payload_preview: Option<String>,
}

/// Rehydrate warm memory from archive if present; otherwise return remaining proof level.
pub fn rehydrate(
    state: &PlatformState,
    agent_vid: &str,
    evidence_id: &str,
) -> RehydrateResult {
    let meta = load_meta(state, agent_vid, evidence_id);
    let archive = get_archive(state, agent_vid, evidence_id);
    let raw_available = archive
        .as_ref()
        .and_then(|v| v.get("payload").and_then(|p| p.as_str()))
        .is_some();

    if raw_available {
        let mut m = meta;
        m.fade_state = FadeState::F0Full;
        // Restore byte estimate from archive
        if let Some(b) = archive
            .as_ref()
            .and_then(|v| v.get("bytes").and_then(|x| x.as_u64()))
        {
            m.bytes = b;
        }
        save_meta(state, agent_vid, evidence_id, &m);

        let mut metrics_m = metrics::load(state, agent_vid);
        metrics_m.rehydration_count += 1;
        metrics::save(state, &metrics_m);

        log_rehydrate(state, agent_vid, evidence_id, ProofLevel::P0Full, true);

        let preview = archive
            .as_ref()
            .and_then(|v| v.get("payload").and_then(|p| p.as_str()))
            .map(|s| s.chars().take(240).collect::<String>());

        return RehydrateResult {
            ok: true,
            evidence_id: evidence_id.into(),
            restored_proof_level: ProofLevel::P0Full,
            raw_available: true,
            distilled_available: true,
            honesty: "raw payload restored from archive store".into(),
            payload_preview: preview,
        };
    }

    // Distilled-only: bump meta excerpts into warm without claiming raw
    let distilled = !meta.distilled_excerpts.is_empty() || !meta.normalized_facts.is_empty();
    let level = ProofLevel::for_fade_state(meta.fade_state);
    log_rehydrate(state, agent_vid, evidence_id, level, false);

    RehydrateResult {
        ok: distilled || matches!(level, ProofLevel::P0Full | ProofLevel::P1Distilled),
        evidence_id: evidence_id.into(),
        restored_proof_level: level,
        raw_available: false,
        distilled_available: distilled || matches!(level, ProofLevel::P1Distilled),
        honesty: if matches!(level, ProofLevel::P3Commitment) {
            "raw evidence permanently faded — only commitment/tombstone available".into()
        } else {
            "archive miss — returning current proof level without claiming unavailable raw".into()
        },
        payload_preview: meta.distilled_excerpts.first().cloned(),
    }
}

fn log_rehydrate(
    state: &PlatformState,
    agent_vid: &str,
    evidence_id: &str,
    level: ProofLevel,
    from_archive: bool,
) {
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("{agent_vid}:{}:{}", evidence_id, now_ms());
        let _ = es.folder_put(
            REHYDRATE_LOG,
            &key,
            &json!({
                "agent_vid": agent_vid,
                "evidence_id": evidence_id,
                "level": level.as_str(),
                "from_archive": from_archive,
                "at_ms": now_ms(),
            }),
        );
    }
}

/// Distill excerpts from payload into meta (F0→F1 helper).
pub fn distill_into_meta(
    state: &PlatformState,
    agent_vid: &str,
    evidence_id: &str,
    payload: &str,
) {
    let mut meta = load_meta(state, agent_vid, evidence_id);
    let excerpt: String = payload.chars().take(512).collect();
    if !excerpt.is_empty() {
        meta.distilled_excerpts.push(excerpt);
    }
    // Simple fact: content hash prefix as normalized marker
    let fact = format!(
        "content_sha256_prefix={}",
        &format!("{:x}", Sha256::digest(payload.as_bytes()))[..16]
    );
    meta.normalized_facts.push(fact);
    save_meta(state, agent_vid, evidence_id, &meta);
}

pub fn verify_archive_hash(archive: &Value, expected_hash: &str) -> bool {
    let Some(payload) = archive.get("payload").and_then(|p| p.as_str()) else {
        return false;
    };
    let actual = format!("{:x}", Sha256::digest(payload.as_bytes()));
    actual == expected_hash
        || archive
            .get("content_hash")
            .and_then(|h| h.as_str())
            == Some(expected_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_hash_mismatch_detected() {
        let v = json!({ "payload": "hello", "content_hash": "deadbeef" });
        assert!(!verify_archive_hash(&v, "not-the-hash"));
    }
}
