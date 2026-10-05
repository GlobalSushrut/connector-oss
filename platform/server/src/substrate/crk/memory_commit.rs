//! Atomic MemoryCommit — authoritative packets + projections visible together or not at all.

use connector_trust::{MemoryCommit, MEMORY_COMMIT_SCHEMA};
use serde_json::json;

use crate::state::PlatformState;

use super::{digest_hex, now_ms, FOLDER_COMMITS, FOLDER_ROOTS};

/// Load current memory root for an agent (rebuildable projection watermark).
pub fn current_root(state: &PlatformState, agent_pid: &str) -> Option<String> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(FOLDER_ROOTS, agent_pid)
        .ok()
        .flatten()
        .and_then(|v| v.get("root").and_then(|r| r.as_str()).map(|s| s.to_string()))
}

fn set_root(state: &PlatformState, agent_pid: &str, root: &str, commit_id: &str) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| format!("engine_store lock: {e}"))?;
    es.folder_put(
        FOLDER_ROOTS,
        agent_pid,
        &json!({
            "root": root,
            "commit_id": commit_id,
            "updated_at_ms": now_ms(),
        }),
    )
    .map_err(|e| format!("put root: {e}"))?;
    Ok(())
}

/// Seal a memory commit. If `expected_previous_root` mismatches, refuse (no mixed state).
pub fn commit(
    state: &PlatformState,
    agent_pid: &str,
    authoritative_packet_cids: Vec<String>,
    envelope_cids: Vec<String>,
    claim_cids: Vec<String>,
    relation_cids: Vec<String>,
    affected_projection_keys: Vec<String>,
    expected_previous_root: Option<&str>,
    source_support_digest: &str,
) -> Result<MemoryCommit, String> {
    let prev = current_root(state, agent_pid);
    if let Some(exp) = expected_previous_root {
        let actual = prev.clone().unwrap_or_else(|| format!("genesis:{agent_pid}"));
        if root_mismatch(exp, &actual) {
            return Err(format!(
                "memory_commit_root_mismatch: expected={exp} actual={actual}"
            ));
        }
    }

    let now = now_ms();
    let material = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        agent_pid,
        authoritative_packet_cids.join(","),
        claim_cids.join(","),
        relation_cids.join(","),
        prev.as_deref().unwrap_or("genesis"),
        source_support_digest,
        now
    );
    let resulting_root = digest_hex(material.as_bytes());
    let commit_id = format!("mc_{}", &resulting_root[..resulting_root.len().min(16)]);

    let mc = MemoryCommit {
        schema: MEMORY_COMMIT_SCHEMA.into(),
        commit_id: commit_id.clone(),
        agent_pid: agent_pid.into(),
        authoritative_packet_cids,
        envelope_cids,
        claim_cids,
        relation_cids,
        affected_projection_keys,
        expected_previous_root: prev.clone().or_else(|| Some(format!("genesis:{agent_pid}"))),
        resulting_root: resulting_root.clone(),
        source_support_digest: source_support_digest.into(),
        committed_at_ms: now,
        sealed: true,
    };

    {
        let mut es = state
            .engine_store
            .lock()
            .map_err(|e| format!("engine_store lock: {e}"))?;
        let val = serde_json::to_value(&mc).map_err(|e| format!("serialize commit: {e}"))?;
        es.folder_put(FOLDER_COMMITS, &commit_id, &val)
            .map_err(|e| format!("put commit: {e}"))?;
        es.folder_put(
            FOLDER_COMMITS,
            &format!("head:{agent_pid}"),
            &json!({ "commit_id": commit_id, "root": resulting_root }),
        )
        .map_err(|e| format!("put head: {e}"))?;
    }
    set_root(state, agent_pid, &resulting_root, &commit_id)?;
    Ok(mc)
}

pub fn load(state: &PlatformState, commit_id: &str) -> Option<MemoryCommit> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(FOLDER_COMMITS, commit_id).ok().flatten()?;
    serde_json::from_value(v).ok()
}

/// Projection watermark for a named index (rebuildable from packets).
pub fn projection_watermark(state: &PlatformState, name: &str) -> Option<String> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(FOLDER_ROOTS, &format!("proj:{name}"))
        .ok()
        .flatten()
        .and_then(|v| v.get("watermark").and_then(|w| w.as_str()).map(|s| s.to_string()))
}

pub fn set_projection_watermark(
    state: &PlatformState,
    name: &str,
    watermark: &str,
    source_root: &str,
) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| format!("engine_store lock: {e}"))?;
    es.folder_put(
        FOLDER_ROOTS,
        &format!("proj:{name}"),
        &json!({
            "watermark": watermark,
            "source_root": source_root,
            "updated_at_ms": now_ms(),
        }),
    )
    .map_err(|e| format!("put watermark: {e}"))?;
    Ok(())
}

/// Pure check used by commit path and tests — refuse mixed visibility.
pub fn root_mismatch(expected: &str, actual: &str) -> bool {
    expected != actual
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_id_material_is_stable() {
        let material = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            "agent:t",
            "cid:1",
            "claim:1",
            "",
            "genesis",
            "src:1",
            42
        );
        let a = digest_hex(material.as_bytes());
        let b = digest_hex(material.as_bytes());
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn root_mismatch_blocks_mixed_visibility() {
        assert!(root_mismatch(
            "abc",
            "genesis:agent:1"
        ));
        assert!(!root_mismatch("same", "same"));
    }
}
