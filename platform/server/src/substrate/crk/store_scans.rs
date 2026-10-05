//! CRK projection scans over EngineStore folders — rebuildable indexes, not a new DB.
//!
//! Key layout (deterministic, prefix-scannable):
//! - claims: `{agent_pid}:{claim_id}` + `current:{agent_pid}:{subject}:{predicate}`
//! - procedures: `{agent_pid}:{procedure_id}` + `skill:{agent_pid}:{skill_id}`
//! - roots: `{agent_pid}` + `proj:{name}`
//!
//! When Prolly range scans land in KernelStore, these helpers stay the semantic
//! API; only the backend iteration changes.

use crate::state::PlatformState;

use super::{FOLDER_CLAIMS, FOLDER_PROCEDURES, FOLDER_ROOTS};

/// Structured CRK projection names (watermarks under `proj:{name}`).
pub const PROJ_CURRENT_STATE: &str = "current_state";
pub const PROJ_PROCEDURE_BY_SKILL: &str = "procedure_by_skill";
pub const PROJ_CAUSAL_RANGE: &str = "causal_range";

/// Prefix-scan claim keys for an agent (excludes `current:` pointers).
pub fn scan_claim_keys(state: &PlatformState, agent_pid: &str) -> Vec<String> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let prefix = format!("{agent_pid}:");
    let Ok(keys) = es.folder_keys(FOLDER_CLAIMS, Some(&prefix)) else {
        return Vec::new();
    };
    keys.into_iter()
        .filter(|k| !k.starts_with("current:"))
        .collect()
}

/// Prefix-scan procedure body keys for an agent (excludes skill index).
pub fn scan_procedure_keys(state: &PlatformState, agent_pid: &str) -> Vec<String> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let prefix = format!("{agent_pid}:");
    let Ok(keys) = es.folder_keys(FOLDER_PROCEDURES, Some(&prefix)) else {
        return Vec::new();
    };
    keys
}

/// Resolve skill → procedure_id pointer without loading the capsule body.
pub fn scan_skill_procedure_id(
    state: &PlatformState,
    agent_pid: &str,
    skill_id: &str,
) -> Option<String> {
    let es = state.engine_store.lock().ok()?;
    let key = format!("skill:{agent_pid}:{skill_id}");
    es.folder_get(FOLDER_PROCEDURES, &key)
        .ok()
        .flatten()
        .and_then(|v| v.get("procedure_id")?.as_str().map(|s| s.to_string()))
}

/// List known projection watermarks (`proj:*` under FOLDER_ROOTS).
pub fn list_projection_watermarks(state: &PlatformState) -> Vec<(String, String)> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let Ok(keys) = es.folder_keys(FOLDER_ROOTS, Some("proj:")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(FOLDER_ROOTS, &k) {
            if let Some(w) = v.get("watermark").and_then(|x| x.as_str()) {
                let name = k.strip_prefix("proj:").unwrap_or(&k).to_string();
                out.push((name, w.to_string()));
            }
        }
    }
    out
}

/// Deterministic projection key for current subject/predicate truth.
pub fn current_state_key(agent_pid: &str, subject: &str, predicate: &str) -> String {
    format!("current:{agent_pid}:{subject}:{predicate}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_state_key_is_prefix_scannable() {
        let k = current_state_key("agent:1", "door", "locked");
        assert!(k.starts_with("current:agent:1:"));
        assert!(k.contains("door"));
        assert!(k.ends_with("locked"));
    }

    #[test]
    fn projection_names_are_stable() {
        assert_eq!(PROJ_CURRENT_STATE, "current_state");
        assert_eq!(PROJ_PROCEDURE_BY_SKILL, "procedure_by_skill");
        assert_eq!(PROJ_CAUSAL_RANGE, "causal_range");
    }
}
