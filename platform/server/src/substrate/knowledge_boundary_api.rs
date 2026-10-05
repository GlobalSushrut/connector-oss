//! Knowledge boundary HTTP API (§5).

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::SharedState;
use crate::substrate::knowledge_boundary::{self, KnowledgeBoundary};

/// GET /api/v1/knowledge/:agent_pid/boundary
pub async fn get_boundary(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    Json(knowledge_boundary::posture_json(state.as_ref(), &agent_pid))
}

#[derive(Debug, Deserialize)]
pub struct PutBoundaryBody {
    #[serde(default)]
    pub permitted: Option<Vec<String>>,
    #[serde(default)]
    pub authoritative: Option<Vec<String>>,
    #[serde(default)]
    pub prohibited: Option<Vec<String>>,
    #[serde(default)]
    pub unknown_requires_verification: Option<bool>,
    #[serde(default)]
    pub effects_require_authoritative: Option<bool>,
}

/// PUT /api/v1/knowledge/:agent_pid/boundary
pub async fn put_boundary(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Json(body): Json<PutBoundaryBody>,
) -> Json<Value> {
    let mut b = knowledge_boundary::load(state.as_ref(), &agent_pid);
    if let Some(v) = body.permitted {
        b.permitted = v;
    }
    if let Some(v) = body.authoritative {
        b.authoritative = v;
    }
    if let Some(v) = body.prohibited {
        b.prohibited = v;
    }
    if let Some(v) = body.unknown_requires_verification {
        b.unknown_requires_verification = v;
    }
    if let Some(v) = body.effects_require_authoritative {
        b.effects_require_authoritative = v;
    }
    b.revision = b.revision.saturating_add(1);
    b.updated_at_ms = chrono::Utc::now().timestamp_millis();
    b.agent_pid = agent_pid.clone();
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_pid,
        "knowledge",
        "put_knowledge_boundary",
        &json!({"agent_pid": agent_pid.as_str(), "revision": b.revision}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match knowledge_boundary::save(state.as_ref(), &b) {
        Ok(()) => {
            open_proceed.finish_observed(true);
            Json(json!({
                "ok": true,
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
                "boundary": b,
            }))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({
                "ok": false,
                "error": e,
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ClassifyBody {
    pub sources: Vec<String>,
}

/// POST /api/v1/knowledge/:agent_pid/classify
pub async fn post_classify(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Json(body): Json<ClassifyBody>,
) -> Json<Value> {
    let b = knowledge_boundary::load(state.as_ref(), &agent_pid);
    Json(knowledge_boundary::filter_sources(&b, &body.sources))
}

/// POST /api/v1/knowledge/:agent_pid/assert-justify
pub async fn post_assert_justify(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Json(body): Json<ClassifyBody>,
) -> Json<Value> {
    match knowledge_boundary::assert_sources_may_justify_effect(
        state.as_ref(),
        &agent_pid,
        &body.sources,
    ) {
        Ok(()) => Json(json!({"ok": true})),
        Err(e) => Json(e),
    }
}

/// POST /api/v1/knowledge/:agent_pid/harden-default — apply harden template
pub async fn post_harden_default(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    let b = KnowledgeBoundary::harden_default(&agent_pid);
    let admitted = match crate::substrate::pate::require_proceed(
        &state,
        &agent_pid,
        "knowledge",
        "apply_knowledge_boundary",
        &json!({"agent_pid": agent_pid.as_str()}),
    ) {
        Ok(atu) => atu,
        Err(body) => return Json(body),
    };
    let mut open_proceed = crate::substrate::pate::OpenProceed::arm(&state, &admitted);
    match knowledge_boundary::save(state.as_ref(), &b) {
        Ok(()) => {
            open_proceed.finish_observed(true);
            Json(json!({
                "ok": true,
                "task_id": admitted.task_id,
                "executed": true,
                "admits": false,
                "boundary": b,
            }))
        }
        Err(e) => {
            open_proceed.finish_observed(false);
            Json(json!({
                "ok": false,
                "error": e,
                "task_id": admitted.task_id,
                "executed": false,
                "admits": false,
            }))
        }
    }
}
