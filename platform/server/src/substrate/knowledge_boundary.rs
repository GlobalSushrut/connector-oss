//! Knowledge boundary — permitted / authoritative / prohibited sources (§5).
//! Does not admit effects; filters recall and labels unsupported knowledge under harden.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::PlatformState;
use crate::substrate::harden_posture;

pub const FOLDER: &str = "knowledge_boundaries";
pub const SCHEMA: &str = "connector.knowledge_boundary.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeBoundary {
    pub schema: String,
    pub agent_pid: String,
    /// Glob/prefix patterns for sources the agent may use.
    #[serde(default)]
    pub permitted: Vec<String>,
    /// Sources that may justify effects (harden: unsupported cannot justify).
    #[serde(default)]
    pub authoritative: Vec<String>,
    /// Hard deny — never surface in recall / never justify.
    #[serde(default)]
    pub prohibited: Vec<String>,
    /// When true, unknown sources require verification (tagged, not silent allow).
    #[serde(default)]
    pub unknown_requires_verification: bool,
    /// When true under harden, effects cannot cite only non-authoritative sources.
    #[serde(default)]
    pub effects_require_authoritative: bool,
    pub revision: u64,
    pub updated_at_ms: i64,
}

impl KnowledgeBoundary {
    pub fn open_default(agent_pid: &str) -> Self {
        Self {
            schema: SCHEMA.into(),
            agent_pid: agent_pid.into(),
            permitted: vec!["*".into()],
            authoritative: vec![],
            prohibited: vec![],
            unknown_requires_verification: false,
            effects_require_authoritative: false,
            revision: 1,
            updated_at_ms: chrono::Utc::now().timestamp_millis(),
        }
    }

    pub fn harden_default(agent_pid: &str) -> Self {
        Self {
            schema: SCHEMA.into(),
            agent_pid: agent_pid.into(),
            permitted: vec!["internal:*".into(), "vac:*".into(), "memory:*".into()],
            authoritative: vec!["internal:*".into(), "policy:*".into()],
            prohibited: vec!["open_internet:*".into(), "unknown:*".into()],
            unknown_requires_verification: true,
            effects_require_authoritative: true,
            revision: 1,
            updated_at_ms: chrono::Utc::now().timestamp_millis(),
        }
    }
}

fn glob_match(pat: &str, val: &str) -> bool {
    if pat == "*" || pat == val {
        return true;
    }
    if let Some(prefix) = pat.strip_suffix('*') {
        return val.starts_with(prefix);
    }
    if let Some(suffix) = pat.strip_prefix('*') {
        return val.ends_with(suffix);
    }
    false
}

fn any_match(pats: &[String], source: &str) -> bool {
    pats.iter().any(|p| glob_match(p, source))
}

pub fn load(state: &PlatformState, agent_pid: &str) -> KnowledgeBoundary {
    if let Ok(es) = state.engine_store.lock() {
        if let Ok(Some(v)) = es.folder_get(FOLDER, agent_pid) {
            if let Ok(b) = serde_json::from_value::<KnowledgeBoundary>(v) {
                return b;
            }
        }
    }
    if harden_posture::augmented_env_harden() {
        KnowledgeBoundary::harden_default(agent_pid)
    } else {
        KnowledgeBoundary::open_default(agent_pid)
    }
}

pub fn save(state: &PlatformState, boundary: &KnowledgeBoundary) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| e.to_string())?;
    es.folder_put(FOLDER, &boundary.agent_pid, &serde_json::to_value(boundary).unwrap_or(Value::Null))
        .map_err(|e| e.to_string())
}

/// Classify a source id against the boundary.
pub fn classify(boundary: &KnowledgeBoundary, source: &str) -> Value {
    let prohibited = any_match(&boundary.prohibited, source);
    let authoritative = any_match(&boundary.authoritative, source);
    let permitted = any_match(&boundary.permitted, source) || authoritative;
    let unknown = !prohibited && !permitted && !authoritative;
    let admit_to_recall = !prohibited && (permitted || authoritative || !boundary.unknown_requires_verification);
    let can_justify_effect = if boundary.effects_require_authoritative {
        authoritative && !prohibited
    } else {
        !prohibited && (permitted || authoritative)
    };
    json!({
        "source": source,
        "prohibited": prohibited,
        "permitted": permitted,
        "authoritative": authoritative,
        "unknown": unknown,
        "admit_to_recall": admit_to_recall && !prohibited,
        "can_justify_effect": can_justify_effect,
        "needs_verification": unknown && boundary.unknown_requires_verification,
    })
}

/// Filter retrieval candidates by source labels (cid/namespace/url-ish strings).
pub fn filter_sources(boundary: &KnowledgeBoundary, sources: &[String]) -> Value {
    let mut admitted = Vec::new();
    let mut denied = Vec::new();
    let mut needs_verify = Vec::new();
    for s in sources {
        let c = classify(boundary, s);
        if c.get("prohibited").and_then(|v| v.as_bool()) == Some(true)
            || c.get("admit_to_recall").and_then(|v| v.as_bool()) != Some(true)
        {
            denied.push(c);
        } else if c.get("needs_verification").and_then(|v| v.as_bool()) == Some(true) {
            needs_verify.push(c.clone());
            admitted.push(c);
        } else {
            admitted.push(c);
        }
    }
    json!({
        "schema": SCHEMA,
        "agent_pid": boundary.agent_pid,
        "admitted": admitted,
        "denied": denied,
        "needs_verification": needs_verify,
        "honesty": "Knowledge boundary filters belief/recall — ActionBinding still admits effects",
    })
}

/// Under harden + effects_require_authoritative: refuse citing only weak sources.
pub fn assert_sources_may_justify_effect(
    state: &PlatformState,
    agent_pid: &str,
    cited_sources: &[String],
) -> Result<(), Value> {
    let b = load(state, agent_pid);
    if !b.effects_require_authoritative {
        return Ok(());
    }
    if cited_sources.is_empty() {
        return Err(json!({
            "ok": false,
            "error": "knowledge_boundary_no_sources",
            "denial_reason": "effects_require_authoritative_sources",
            "schema": SCHEMA,
            "agent_pid": agent_pid,
            "honesty": "Unsupported knowledge cannot justify effect under harden boundary",
        }));
    }
    let any_auth = cited_sources.iter().any(|s| {
        classify(&b, s)
            .get("can_justify_effect")
            .and_then(|v| v.as_bool())
            == Some(true)
    });
    if !any_auth {
        return Err(json!({
            "ok": false,
            "error": "knowledge_boundary_not_authoritative",
            "denial_reason": "unsupported_knowledge_cannot_justify_effect",
            "schema": SCHEMA,
            "agent_pid": agent_pid,
            "cited": cited_sources,
        }));
    }
    for s in cited_sources {
        if classify(&b, s).get("prohibited").and_then(|v| v.as_bool()) == Some(true) {
            return Err(json!({
                "ok": false,
                "error": "knowledge_boundary_prohibited_source",
                "denial_reason": "prohibited_source",
                "schema": SCHEMA,
                "agent_pid": agent_pid,
                "source": s,
            }));
        }
    }
    Ok(())
}

pub fn posture_json(state: &PlatformState, agent_pid: &str) -> Value {
    let b = load(state, agent_pid);
    json!({
        "schema": SCHEMA,
        "agent_pid": agent_pid,
        "permitted": b.permitted,
        "authoritative": b.authoritative,
        "prohibited": b.prohibited,
        "unknown_requires_verification": b.unknown_requires_verification,
        "effects_require_authoritative": b.effects_require_authoritative,
        "revision": b.revision,
        "outcomes": ["§5"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prohibited_blocks_recall() {
        let mut b = KnowledgeBoundary::harden_default("a1");
        b.prohibited = vec!["open_internet:*".into()];
        let c = classify(&b, "open_internet:https://evil.example");
        assert_eq!(c.get("admit_to_recall").and_then(|v| v.as_bool()), Some(false));
    }

    #[test]
    fn authoritative_can_justify() {
        let b = KnowledgeBoundary::harden_default("a1");
        let c = classify(&b, "policy:credit-v1");
        assert_eq!(c.get("can_justify_effect").and_then(|v| v.as_bool()), Some(true));
    }
}
