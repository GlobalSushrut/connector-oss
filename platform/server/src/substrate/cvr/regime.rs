//! OS regime for CVR lifecycle (Phase F3).
//!
//! QUARANTINED and STOPPED_BY_OPERATOR never auto-revive via supervisor/watchdog.
//! Only an explicit operator (or HITL unquarantine) path may clear them.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::PlatformState;

pub const REGIME_FOLDER: &str = "cvr_os_regime";
pub const REGIME_SCHEMA: &str = "connector.cvr.os_regime.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OsRegime {
    Running,
    Paused,
    Quarantined,
    StoppedByOperator,
}

impl OsRegime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "RUNNING",
            Self::Paused => "PAUSED",
            Self::Quarantined => "QUARANTINED",
            Self::StoppedByOperator => "STOPPED_BY_OPERATOR",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "RUNNING" => Some(Self::Running),
            "PAUSED" => Some(Self::Paused),
            "QUARANTINED" => Some(Self::Quarantined),
            "STOPPED" | "STOPPED_BY_OPERATOR" => Some(Self::StoppedByOperator),
            _ => None,
        }
    }

    pub fn blocks_auto_revival(self) -> bool {
        matches!(self, Self::Quarantined | Self::StoppedByOperator)
    }

    pub fn blocks_effect(self) -> bool {
        !matches!(self, Self::Running)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegimeRecord {
    pub schema: String,
    pub agent_pid: String,
    pub regime: String,
    pub reason: String,
    pub set_by: String,
    pub updated_at_ms: i64,
    pub auto_revival_forbidden: bool,
}

impl RegimeRecord {
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(json!({}))
    }
}

pub fn get_regime(state: &PlatformState, agent_pid: &str) -> OsRegime {
    let Ok(es) = state.engine_store.lock() else {
        return OsRegime::Running;
    };
    es.folder_get(REGIME_FOLDER, agent_pid)
        .ok()
        .flatten()
        .and_then(|v| {
            v.get("regime")
                .and_then(|x| x.as_str())
                .and_then(OsRegime::parse)
        })
        .unwrap_or(OsRegime::Running)
}

pub fn set_regime(
    state: &PlatformState,
    agent_pid: &str,
    regime: OsRegime,
    reason: &str,
    set_by: &str,
) -> RegimeRecord {
    let rec = RegimeRecord {
        schema: REGIME_SCHEMA.into(),
        agent_pid: agent_pid.to_string(),
        regime: regime.as_str().into(),
        reason: reason.to_string(),
        set_by: set_by.to_string(),
        updated_at_ms: chrono::Utc::now().timestamp_millis(),
        auto_revival_forbidden: regime.blocks_auto_revival(),
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(REGIME_FOLDER, agent_pid, &rec.to_json());
        // Mirror onto agent_meta for operators / status.
        if let Ok(Some(mut meta)) = es.folder_get("agent_meta", agent_pid) {
            if let Some(obj) = meta.as_object_mut() {
                obj.insert("cvr_regime".into(), json!(regime.as_str()));
                obj.insert(
                    "cvr_auto_revival_forbidden".into(),
                    json!(regime.blocks_auto_revival()),
                );
            }
            let _ = es.folder_put("agent_meta", agent_pid, &meta);
        }
    }
    rec
}

/// Refuse supervisor/watchdog/start that would silently revive a sealed regime.
pub fn assert_may_auto_start(state: &PlatformState, agent_pid: &str) -> Result<(), Value> {
    let r = get_regime(state, agent_pid);
    if r.blocks_auto_revival() {
        return Err(json!({
            "ok": false,
            "status": 403,
            "error": "START_REFUSED",
            "denial_reason": "auto_revival_forbidden",
            "regime": r.as_str(),
            "honesty": "QUARANTINED / STOPPED_BY_OPERATOR never auto-revive — explicit operator or HITL unquarantine required",
            "hint": "POST /agents/:pid/unquarantine (HITL) or operator resume after regime clear",
        }));
    }
    Ok(())
}

/// Resume from PAUSED is fine; from QUARANTINED requires explicit unquarantine path.
pub fn assert_may_resume(
    state: &PlatformState,
    agent_pid: &str,
    via_unquarantine: bool,
) -> Result<(), Value> {
    let r = get_regime(state, agent_pid);
    match r {
        OsRegime::Quarantined if !via_unquarantine => Err(json!({
            "ok": false,
            "status": 403,
            "error": "RESUME_REFUSED",
            "denial_reason": "quarantine_requires_unquarantine",
            "regime": r.as_str(),
            "honesty": "No supervisor/watchdog/resume bypass of quarantine",
            "hint": "POST /agents/:pid/unquarantine",
        })),
        OsRegime::StoppedByOperator if !via_unquarantine => Err(json!({
            "ok": false,
            "status": 403,
            "error": "RESUME_REFUSED",
            "denial_reason": "stopped_by_operator",
            "regime": r.as_str(),
            "honesty": "STOPPED_BY_OPERATOR requires explicit operator start — not auto-resume",
        })),
        _ => Ok(()),
    }
}

pub fn clear_to_running(state: &PlatformState, agent_pid: &str, actor: &str) -> RegimeRecord {
    set_regime(state, agent_pid, OsRegime::Running, "operator_clear", actor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_regimes_block_auto() {
        assert!(OsRegime::Quarantined.blocks_auto_revival());
        assert!(OsRegime::StoppedByOperator.blocks_auto_revival());
        assert!(!OsRegime::Paused.blocks_auto_revival());
        assert!(!OsRegime::Running.blocks_auto_revival());
    }
}
