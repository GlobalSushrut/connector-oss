//! **`GET /api/v1/kernel/supervisor/inventory`** — Phase **5.10.6** supervisee pattern catalog.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::Value;

use crate::services::runtime_control;
use crate::state::SharedState;

fn require_auth_or_dev(headers: &HeaderMap) -> Result<(), Value> {
    if runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    if crate::auth::extract_claims(headers).is_some() {
        return Ok(());
    }
    Err(serde_json::json!({"ok": false, "error": "Unauthorized"}))
}

pub async fn get_supervisor_inventory(
    State(_state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_auth_or_dev(&headers) {
        return Err((StatusCode::UNAUTHORIZED, Json(e)));
    }
    Ok(Json(connector_supervisor::supervisee_inventory()))
}
