//! HTTP API — posture, capsule, moment proof.

use axum::{
    extract::{Path, State},
    Json,
};
use serde_json::{json, Value};

use crate::operator::honesty::operator_envelope;
use crate::state::SharedState;

use super::{capsule, moment, posture_json, enabled};

/// GET /api/v1/agent-memory/posture
pub async fn get_posture(State(_state): State<SharedState>) -> Json<Value> {
    Json(operator_envelope(json!({
        "schema": "connector.agent_memory.api.posture.v1",
        "agent_memory": posture_json(),
        "docs": "platform/docs/arch/CONNECTOR_AGENT_MEMORY.md",
    })))
}

/// GET /api/v1/agent-memory/capsule/:agent_vid
pub async fn get_capsule(
    State(state): State<SharedState>,
    Path(agent_vid): Path<String>,
) -> Json<Value> {
    if !enabled() {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "agent_memory_disabled",
            "hint": "Set CONNECTOR_AGENT_MEMORY=1",
        })));
    }
    let amc = capsule::load_cached(state.as_ref(), &agent_vid).unwrap_or_else(|| {
        capsule::build(state.as_ref(), &agent_vid, 1, None, None)
    });
    Json(operator_envelope(json!({
        "schema": "connector.agent_memory.api.capsule.v1",
        "agent_vid": agent_vid,
        "capsule": amc,
        "bytes": serde_json::to_vec(&amc).map(|v| v.len()).unwrap_or(0),
    })))
}

/// GET /api/v1/forensics/moment/:moment_id/proof
pub async fn get_moment_proof(
    State(state): State<SharedState>,
    Path(moment_id): Path<String>,
) -> Json<Value> {
    if !enabled() {
        return Json(operator_envelope(json!({
            "ok": false,
            "error": "agent_memory_disabled",
        })));
    }
    match moment::proof_json(state.as_ref(), &moment_id) {
        Some(v) => Json(operator_envelope(v)),
        None => Json(operator_envelope(json!({
            "ok": false,
            "error": "moment_not_found",
            "moment_id": moment_id,
        }))),
    }
}
