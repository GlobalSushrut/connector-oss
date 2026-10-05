use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::{
    operator::{edge::merge_edge_plane, honesty::operator_envelope},
    services::plugin_matrix,
    state::SharedState,
};

/// `GET /api/v1/operator/setup/summary`
pub async fn get_operator_setup_summary(State(state): State<SharedState>) -> Json<Value> {
    let enabled: Vec<_> = plugin_matrix::enabled_plugin_ids().iter().cloned().collect();
    let edge = merge_edge_plane(&state);
    Json(operator_envelope(json!({
        "schema": "operator_setup_summary.v1",
        "plugins": {
            "enabled_plugin_ids": enabled,
            "status_path": "/api/v1/plugins/status",
        },
        "edge": {
            "record_count": edge.get("record_count"),
            "public_url": edge.get("public_url"),
            "cage_tld": edge.get("cage_tld"),
            "plane_path": "/api/v1/operator/edge/plane",
        },
        "license": {
            "status_path": "/api/v1/license/status",
        },
        "secrets_hint": "/api/v1/secrets",
    })))
}
