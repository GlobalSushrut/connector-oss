//! Rollup HTTP API (§65).

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::operator::honesty::operator_envelope;
use crate::state::SharedState;

use super::eligibility::{evaluate, put_fade_lock};
use super::execute::run_aging_pass;
use super::metrics;
use super::policy;
use super::rehydrate;
use super::schedule;
use super::tombstone;
use super::demo_c0c10;
use super::super::evidence;

#[derive(Debug, Deserialize)]
pub struct RollupAgentQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    50
}

#[derive(Debug, Deserialize)]
pub struct PolicyBody {
    pub policy: connector_trust::FadePolicy,
}

#[derive(Debug, Deserialize)]
pub struct ScheduledQuery {
    #[serde(default = "default_day")]
    pub day: String,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_day() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

/// GET /api/v1/rollup/posture
pub async fn get_posture(State(_state): State<SharedState>) -> Json<Value> {
    Json(operator_envelope(super::posture_json()))
}

/// GET /api/v1/rollup/:agent_vid/metrics
pub async fn get_metrics(
    State(state): State<SharedState>,
    Path(agent_vid): Path<String>,
) -> Json<Value> {
    Json(operator_envelope(json!({
        "schema": "connector.rollup.api.metrics.v1",
        "metrics": metrics::health_json(state.as_ref(), &agent_vid),
    })))
}

/// GET /api/v1/rollup/:agent_vid/policy
pub async fn get_policy(
    State(state): State<SharedState>,
    Path(agent_vid): Path<String>,
) -> Json<Value> {
    let p = policy::resolve(state.as_ref(), &agent_vid, None);
    Json(operator_envelope(json!({
        "schema": "connector.rollup.api.policy.v1",
        "agent_vid": agent_vid,
        "policy": p,
    })))
}

/// PUT /api/v1/rollup/:agent_vid/policy
pub async fn put_policy(
    State(state): State<SharedState>,
    Path(agent_vid): Path<String>,
    Json(body): Json<PolicyBody>,
) -> Json<Value> {
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_vid,
        "rollup",
        "put_rollup_policy",
        &json!({"agent_vid": agent_vid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let p = policy::put_agent_policy(state.as_ref(), &agent_vid, body.policy);
    open_proceed.finish_observed(true);
    Json(operator_envelope(json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "policy": p,
    })))
}

/// GET /api/v1/rollup/:agent_vid/explain/:evidence_id
pub async fn get_explain(
    State(state): State<SharedState>,
    Path((agent_vid, evidence_id)): Path<(String, String)>,
) -> Json<Value> {
    let key = format!("{agent_vid}:{evidence_id}");
    let es = state.engine_store.lock().unwrap();
    let v = es
        .folder_get(evidence::EVIDENCE_INDEX_FOLDER, &key)
        .ok()
        .flatten();
    drop(es);
    let Some(v) = v else {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "evidence_not_found",
        })));
    };
    let Ok(rec) = serde_json::from_value(v) else {
        return Json(operator_envelope(json!({ "ok": false, "error": "parse_error" })));
    };
    let pol = policy::resolve(state.as_ref(), &agent_vid, None);
    let explain = evaluate(state.as_ref(), &rec, &pol, 0.3);
    Json(operator_envelope(json!({
        "schema": "connector.rollup.api.explain.v1",
        "explain": explain,
    })))
}

/// POST /api/v1/rollup/:agent_vid/aging-pass
pub async fn post_aging_pass(
    State(state): State<SharedState>,
    Path(agent_vid): Path<String>,
    Query(q): Query<RollupAgentQuery>,
) -> Json<Value> {
    if !super::enabled() {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "rollup_disabled",
        })));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_vid,
        "rollup",
        "rollup_aging_pass",
        &json!({"agent_vid": agent_vid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let results = run_aging_pass(state.as_ref(), &agent_vid, q.limit.clamp(1, 500));
    let faded = results.iter().filter(|r| r.ok).count();
    let denied = results.iter().filter(|r| r.denied).count();
    open_proceed.finish_observed(true);
    Json(operator_envelope(json!({
        "schema": "connector.rollup.api.aging_pass.v1",
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "agent_vid": agent_vid,
        "processed": results.len(),
        "faded": faded,
        "denied": denied,
    })))
}

/// POST /api/v1/rollup/:agent_vid/scheduled-pass
pub async fn post_scheduled_pass(
    State(state): State<SharedState>,
    Path(agent_vid): Path<String>,
    Query(q): Query<ScheduledQuery>,
) -> Json<Value> {
    if !super::enabled() {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "rollup_disabled",
        })));
    }
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_vid,
        "rollup",
        "rollup_scheduled_pass",
        &json!({"agent_vid": agent_vid.as_str(), "day": q.day.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let v = schedule::run_scheduled_pass(
        state.as_ref(),
        &agent_vid,
        &q.day,
        q.limit.clamp(1, 500),
    );
    open_proceed.finish_observed(true);
    let mut body = v;
    if let Some(obj) = body.as_object_mut() {
        obj.insert("task_id".into(), json!(admitted.task_id));
        obj.insert("executed".into(), json!(true));
        obj.insert("admits".into(), json!(false));
    }
    Json(operator_envelope(body))
}

/// POST /api/v1/rollup/:agent_vid/rehydrate/:evidence_id
pub async fn post_rehydrate(
    State(state): State<SharedState>,
    Path((agent_vid, evidence_id)): Path<(String, String)>,
) -> Json<Value> {
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_vid,
        "rollup",
        "rollup_rehydrate",
        &json!({"agent_vid": agent_vid.as_str(), "evidence_id": evidence_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let r = rehydrate::rehydrate(state.as_ref(), &agent_vid, &evidence_id);
    open_proceed.finish_observed(true);
    Json(operator_envelope(json!({
        "schema": "connector.rollup.api.rehydrate.v1",
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "result": r,
    })))
}

/// POST /api/v1/rollup/:agent_vid/lock/:evidence_id
pub async fn post_lock(
    State(state): State<SharedState>,
    Path((agent_vid, evidence_id)): Path<(String, String)>,
) -> Json<Value> {
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_vid,
        "rollup",
        "rollup_fade_lock",
        &json!({"agent_vid": agent_vid.as_str(), "evidence_id": evidence_id.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    let lock = put_fade_lock(
        state.as_ref(),
        &agent_vid,
        &evidence_id,
        "operator_lock",
        None,
        None,
    );
    open_proceed.finish_observed(true);
    Json(operator_envelope(json!({
        "ok": true,
        "task_id": admitted.task_id,
        "executed": true,
        "admits": false,
        "lock": lock,
    })))
}

/// GET /api/v1/rollup/tombstone/:evidence_id
pub async fn get_tombstone(
    State(state): State<SharedState>,
    Path(evidence_id): Path<String>,
) -> Json<Value> {
    match tombstone::get(state.as_ref(), &evidence_id) {
        Some(t) => Json(operator_envelope(json!({ "tombstone": t }))),
        None => Json(operator_envelope(json!({
            "ok": false,
            "error": "tombstone_not_found",
        }))),
    }
}

/// POST /api/v1/rollup/demo/c0c10 — aging acceptance scenario
pub async fn post_c0c10_demo(State(state): State<SharedState>) -> Json<Value> {
    if !super::enabled() {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "rollup_disabled",
            "hint": "Set CONNECTOR_AGENT_MEMORY=1 or CONNECTOR_CONTEXT_ROLLUP=1",
        })));
    }
    let result = demo_c0c10::run_acceptance(state.as_ref());
    Json(operator_envelope(result))
}

/// GET /api/v1/forensics/moments/:agent_vid — TraceTramp moment index with proof symbols
pub async fn list_moments(
    State(state): State<SharedState>,
    Path(agent_vid): Path<String>,
) -> Json<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return Json(operator_envelope(json!({ "moments": [] })));
    };
    let Ok(keys) = es.folder_keys(super::super::moment::MOMENT_FOLDER, None) else {
        return Json(operator_envelope(json!({ "moments": [] })));
    };
    let mut moments = Vec::new();
    for k in keys.into_iter().rev().take(100) {
        if let Ok(Some(v)) = es.folder_get(super::super::moment::MOMENT_FOLDER, &k) {
            if v.get("agent_vid").and_then(|x| x.as_str()) != Some(agent_vid.as_str()) {
                continue;
            }
            let level = v
                .get("current_proof_level")
                .cloned()
                .unwrap_or(json!("p0_full"));
            let symbol = match level.as_str() {
                Some("p1_distilled") => "◉",
                Some("p2_contextual") => "○",
                Some("p3_commitment") => "·",
                _ => "●",
            };
            moments.push(json!({
                "moment_id": v.get("moment_id"),
                "trigger": v.get("trigger"),
                "connector_decision": v.get("connector_decision"),
                "actual_effect": v.get("actual_effect"),
                "timestamp_ms": v.get("timestamp_ms"),
                "proof_level": level,
                "proof_symbol": symbol,
                "proof_level_at_creation": v.get("proof_level_at_creation"),
            }));
        }
    }
    Json(operator_envelope(json!({
        "schema": "connector.forensics.moments.index.v1",
        "agent_vid": agent_vid,
        "moments": moments,
        "legend": {
            "P0_full": "●",
            "P1_distilled": "◉",
            "P2_contextual": "○",
            "P3_commitment": "·",
        },
    })))
}
