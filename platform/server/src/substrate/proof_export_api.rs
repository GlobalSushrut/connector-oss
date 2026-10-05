//! E5 proof export HTTP API.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::SharedState;
use crate::substrate::proof_export;

#[derive(Debug, Deserialize)]
pub struct ProofQuery {
    #[serde(default)]
    pub mission_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// GET /api/v1/proof/export/:agent_pid
pub async fn get_proof_export(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Query(q): Query<ProofQuery>,
) -> Json<Value> {
    let body = proof_export::export_for_agent(
        state.as_ref(),
        &agent_pid,
        q.mission_id.as_deref(),
        q.limit.unwrap_or(50),
    );
    Json(body)
}

/// GET /api/v1/product/promise — short promise + posture (E1/E7).
pub async fn get_product_promise(State(_state): State<SharedState>) -> Json<Value> {
    Json(json!({
        "schema": "connector.product_promise.v1",
        "thesis": "tools + env + isolation + monitoring + proof — not absolute security",
        "guarantees": [
            "posture_honesty",
            "effect_exclusivity_when_gates_applied",
            "engineer_freedom",
            "reconstructible_worldline",
            "no_cognitive_self_authorization",
            "configurable_continuum",
        ],
        "does_not_guarantee": [
            "absolute_security",
            "equal_hardness_every_deploy",
            "model_correctness",
            "sil_from_lab_echo",
        ],
        "posture": proof_export::product_posture_json(),
        "docs": [
            "platform/docs/arch/CONNECTOR_CAPABILITY_STANDARD.md",
            "platform/docs/arch/CONNECTOR_PRODUCT_PROMISE.md",
            "platform/docs/arch/CONNECTOR_FINAL_OUTCOMES.md",
        ],
    }))
}
