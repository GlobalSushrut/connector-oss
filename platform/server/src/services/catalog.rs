//! Product catalog endpoint (Phase 2.1).
//!
//! Serves `platform/products/catalog.json` verbatim from
//! `GET /api/v1/products`. The Leptos dashboard embeds the same file at
//! compile time; the endpoint is the canonical fetch path for any
//! out-of-process client (CLI, integrations, future plugin
//! marketplace).
//!
//! The JSON is `include_str!`'d at server build time so it ships inside
//! the platform binary — no filesystem dependency at runtime, no risk
//! of returning stale data from a missing file.

use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::Value;
use std::sync::OnceLock;

const CATALOG_JSON: &str = include_str!("../../../products/catalog.json");

fn parsed() -> &'static Result<Value, serde_json::Error> {
    static CELL: OnceLock<Result<Value, serde_json::Error>> = OnceLock::new();
    CELL.get_or_init(|| serde_json::from_str::<Value>(CATALOG_JSON))
}

/// `GET /api/v1/products` — returns the canonical product catalog.
///
/// 503 if the catalog failed to parse at boot. The boot probe ensures
/// every release notices a malformed catalog before serving any user
/// traffic; the handler here is just defensive.
pub async fn list_products() -> impl IntoResponse {
    match parsed() {
        Ok(value) => (StatusCode::OK, Json(value.clone())).into_response(),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "catalog_unavailable",
                "detail": err.to_string(),
                "source": "products/catalog.json",
            })),
        )
            .into_response(),
    }
}

/// Boot-time validity check. Call once from `main` before the router
/// starts serving traffic so a malformed catalog crashes the binary
/// rather than silently 503'ing.
pub fn validate_at_boot() -> Result<(), String> {
    match parsed() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("products/catalog.json failed to parse: {e}")),
    }
}
