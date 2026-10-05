//! Scheduled hierarchical rollups (§31–§36, §47).
//!
//! continuous: decision/context (elsewhere)
//! daily: distill eligible F0
//! weekly-style aging: fade low-value via aging_pass
//! minute/session/daily skeleton indexes

use connector_trust::{DailyAgentRollup, SessionRollup, DAILY_ROLLUP_SCHEMA};
use serde_json::json;
use uuid::Uuid;

use crate::state::PlatformState;

use super::consolidate;
use super::execute::run_aging_pass;
use super::super::context_store;
use super::super::reducer;

pub const MINUTE_FOLDER: &str = "agent_memory_minute_rollups";
pub const DAILY_FOLDER: &str = "agent_memory_daily_rollups";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Minute rollup — event volume reduction, not DecisionMemory replacement.
pub fn minute_rollup(
    state: &PlatformState,
    agent_vid: &str,
    event_count: u64,
    state_change_count: u64,
    important_events: Vec<String>,
) -> serde_json::Value {
    let ctx = context_store::load_state(state, agent_vid);
    let body = json!({
        "schema": "connector.minute_rollup.v1",
        "rollup_id": format!("MIN-{}", Uuid::new_v4().simple()),
        "agent_vid": agent_vid,
        "event_count": event_count,
        "state_change_count": state_change_count,
        "context_change_count": ctx.delta_seq,
        "evidence_root": ctx.evidence_root,
        "important_events": important_events,
        "at_ms": now_ms(),
    });
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("{agent_vid}:{}", body["rollup_id"].as_str().unwrap_or("x"));
        let _ = es.folder_put(MINUTE_FOLDER, &key, &body);
    }
    body
}

pub fn session_rollup(
    state: &PlatformState,
    agent_vid: &str,
    session_id: &str,
) -> SessionRollup {
    let decisions = reducer::recent_decision_summaries(state, agent_vid, 32);
    consolidate::consolidate_session_end(
        state,
        agent_vid,
        session_id,
        decisions,
        vec![],
        vec![],
    )
}

pub fn daily_rollup(state: &PlatformState, agent_vid: &str, day: &str) -> DailyAgentRollup {
    let decisions = reducer::recent_decision_summaries(state, agent_vid, 64);
    let moments = list_recent_moment_ids(state, agent_vid, 32);
    let daily = DailyAgentRollup {
        schema: DAILY_ROLLUP_SCHEMA.into(),
        day: day.into(),
        agent_vid: agent_vid.into(),
        worked_on: decisions.iter().take(8).cloned().collect(),
        decisions: decisions.clone(),
        changes: vec![],
        commitments: vec![],
        external_actions: vec![],
        failures: vec![],
        unresolved: vec![],
        key_moments: moments,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("{agent_vid}:{day}");
        let _ = es.folder_put(
            DAILY_FOLDER,
            &key,
            &serde_json::to_value(&daily).unwrap_or_default(),
        );
    }
    daily
}

fn list_recent_moment_ids(state: &PlatformState, agent_vid: &str, limit: usize) -> Vec<String> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let Ok(keys) = es.folder_keys(super::super::moment::MOMENT_FOLDER, None) else {
        return vec![];
    };
    let mut out = Vec::new();
    for k in keys.into_iter().rev() {
        if let Ok(Some(v)) = es.folder_get(super::super::moment::MOMENT_FOLDER, &k) {
            if v.get("agent_vid").and_then(|x| x.as_str()) == Some(agent_vid) {
                if let Some(id) = v.get("moment_id").and_then(|x| x.as_str()) {
                    out.push(id.to_string());
                    if out.len() >= limit {
                        break;
                    }
                }
            }
        }
    }
    out
}

/// Full scheduled pass: minute snapshot + daily distill aging + metrics.
pub fn run_scheduled_pass(
    state: &PlatformState,
    agent_vid: &str,
    day: &str,
    aging_limit: usize,
) -> serde_json::Value {
    let minute = minute_rollup(state, agent_vid, 0, 0, vec![]);
    let daily = daily_rollup(state, agent_vid, day);
    let aging = run_aging_pass(state, agent_vid, aging_limit);
    let faded = aging.iter().filter(|r| r.ok).count();
    let denied = aging.iter().filter(|r| r.denied).count();
    json!({
        "schema": "connector.rollup.scheduled_pass.v1",
        "agent_vid": agent_vid,
        "day": day,
        "minute_rollup_id": minute.get("rollup_id"),
        "daily_key_moments": daily.key_moments.len(),
        "daily_decisions": daily.decisions.len(),
        "aging_faded": faded,
        "aging_denied": denied,
    })
}
