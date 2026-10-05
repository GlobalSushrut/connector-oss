//! Memory / Knot belief-field HTTP surface.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::SharedState;
use crate::substrate::{knot_belief_field, memory_retrieval};

#[derive(Debug, Deserialize)]
pub struct RetrieveQuery {
    pub q: String,
    #[serde(default)]
    pub top_k: Option<usize>,
}

/// GET /api/v1/memory/retrieve/:agent_pid?q=...&top_k=8
pub async fn get_memory_retrieve(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
    Query(q): Query<RetrieveQuery>,
) -> Json<Value> {
    Json(memory_retrieval::retrieve(
        state.as_ref(),
        &agent_pid,
        &q.q,
        q.top_k.unwrap_or(8),
    ))
}

/// POST /api/v1/knot/:agent_pid/interference/scan
pub async fn post_interference_scan(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    Json(knot_belief_field::detect_and_persist_interference(
        state.as_ref(),
        &agent_pid,
    ))
}

/// GET /api/v1/knot/:agent_pid/interference
pub async fn get_interference(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    let events = knot_belief_field::list_interference(state.as_ref(), &agent_pid, 32);
    Json(json!({
        "ok": true,
        "agent_pid": agent_pid,
        "events": events,
        "belief_field": knot_belief_field::posture_json(),
    }))
}

/// GET /api/v1/knot/:agent_pid/foresight
pub async fn get_foresight(
    State(state): State<SharedState>,
    Path(agent_pid): Path<String>,
) -> Json<Value> {
    Json(knot_belief_field::selective_foresight(
        state.as_ref(),
        &agent_pid,
    ))
}
