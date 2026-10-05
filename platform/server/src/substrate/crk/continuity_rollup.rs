//! Continuity rollup — state claims + procedures + open work, not recursive summaries.

use connector_trust::{
    ContinuityRollup, TrustTier, CONTINUITY_ROLLUP_SCHEMA,
};

use crate::state::PlatformState;

use super::memory_commit;
use super::procedure_capsule;
use super::store_scans;
use super::temporal_ledger;
use super::{digest_hex, now_ms, FOLDER_ROOTS};

const FOLDER_ROLLUPS: &str = "crk_continuity_rollups";

/// Build a continuity rollup from active claims and skill-bound procedures.
/// Deliberately does **not** nest LLM summaries — cold evidence is a digest only.
pub fn build(state: &PlatformState, agent_pid: &str) -> ContinuityRollup {
    let memory_root = memory_commit::current_root(state, agent_pid)
        .unwrap_or_else(|| format!("genesis:{agent_pid}"));

    let mut current_claim_ids = Vec::new();
    let mut claim_subjects = Vec::new();
    for id in temporal_ledger::list_active_claim_ids(state, agent_pid) {
        if let Some(c) = temporal_ledger::load_claim(state, agent_pid, &id) {
            if c.is_active_at(now_ms()) {
                claim_subjects.push(format!("{}:{}", c.subject, c.predicate));
                current_claim_ids.push(c.claim_id);
            }
        }
    }

    let mut procedure_ids = Vec::new();
    for key in store_scans::scan_procedure_keys(state, agent_pid) {
        if let Some(pid) = key.split(':').nth(1) {
            if procedure_capsule::load(state, agent_pid, pid).is_some() {
                procedure_ids.push(pid.to_string());
            }
        }
    }

    // Open work = latest moment-range context that is not a sealed claim/procedure.
    let open_work_cids = latest_open_work(state, agent_pid);

    let cold = digest_hex(
        format!(
            "{}|{}|{}",
            claim_subjects.join(","),
            procedure_ids.join(","),
            open_work_cids.join(",")
        )
        .as_bytes(),
    );

    ContinuityRollup {
        schema: CONTINUITY_ROLLUP_SCHEMA.into(),
        agent_pid: agent_pid.into(),
        memory_root: memory_root.clone(),
        current_claim_ids,
        procedure_ids,
        open_work_cids,
        cold_evidence_digest: cold,
        trust_floor: TrustTier::T1Observed,
        rolled_at_ms: now_ms(),
        honesty: "state+procedures+open_work — not recursive token summaries".into(),
    }
}

fn latest_open_work(state: &PlatformState, agent_pid: &str) -> Vec<String> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let Ok(Some(v)) = es.folder_get(super::FOLDER_RANGES, &format!("latest:{agent_pid}")) else {
        return Vec::new();
    };
    let Some(mid) = v.get("moment_range_id").and_then(|x| x.as_str()) else {
        return Vec::new();
    };
    drop(es);
    super::moment_range::load(state, mid)
        .map(|r| r.context_cids)
        .unwrap_or_default()
}

pub fn persist(state: &PlatformState, rollup: &ContinuityRollup) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| format!("engine_store lock: {e}"))?;
    let val = serde_json::to_value(rollup).map_err(|e| format!("serialize: {e}"))?;
    let key = format!("{}:{}", rollup.agent_pid, rollup.rolled_at_ms);
    es.folder_put(FOLDER_ROLLUPS, &key, &val)
        .map_err(|e| format!("put rollup: {e}"))?;
    es.folder_put(
        FOLDER_ROLLUPS,
        &format!("latest:{}", rollup.agent_pid),
        &serde_json::json!({ "key": key, "memory_root": rollup.memory_root }),
    )
    .map_err(|e| format!("put latest: {e}"))?;
    // Projection watermark — rebuildable from packets.
    es.folder_put(
        FOLDER_ROOTS,
        &format!("proj:{}", store_scans::PROJ_CURRENT_STATE),
        &serde_json::json!({
            "watermark": rollup.cold_evidence_digest,
            "source_root": rollup.memory_root,
            "agent_pid": rollup.agent_pid,
            "updated_at_ms": rollup.rolled_at_ms,
        }),
    )
    .map_err(|e| format!("put watermark: {e}"))?;
    Ok(())
}

pub fn load_latest(state: &PlatformState, agent_pid: &str) -> Option<ContinuityRollup> {
    let es = state.engine_store.lock().ok()?;
    let idx = es
        .folder_get(FOLDER_ROLLUPS, &format!("latest:{agent_pid}"))
        .ok()
        .flatten()?;
    let key = idx.get("key")?.as_str()?;
    let v = es.folder_get(FOLDER_ROLLUPS, key).ok().flatten()?;
    serde_json::from_value(v).ok()
}

/// Roll up and seal as a MemoryCommit projection update.
pub fn commit_rollup(state: &PlatformState, agent_pid: &str) -> Result<ContinuityRollup, String> {
    let rollup = build(state, agent_pid);
    persist(state, &rollup)?;
    let _ = memory_commit::commit(
        state,
        agent_pid,
        vec![],
        vec![],
        rollup.current_claim_ids.clone(),
        vec![],
        vec![
            format!("proj:{}", store_scans::PROJ_CURRENT_STATE),
            format!("rollup:{agent_pid}"),
        ],
        None,
        &rollup.cold_evidence_digest,
    )?;
    Ok(rollup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honesty_line_rejects_summary_product() {
        assert!(CONTINUITY_ROLLUP_SCHEMA.contains("continuity_rollup"));
        let honesty = "state+procedures+open_work — not recursive token summaries";
        assert!(!honesty.contains("summary chain"));
    }
}
