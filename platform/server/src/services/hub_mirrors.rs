//! Phase 4.7 — prioritized Hub mirror URLs (enterprise / airgap).

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth;
use crate::services::runtime_control;
use crate::state::SharedState;

const STORE_FOLDER: &str = "hub_mirrors";
const STORE_KEY: &str = "config";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HubMirrorsConfig {
    /// Primary-first list of Hub base URLs (no trailing slash required).
    #[serde(default)]
    pub urls: Vec<String>,
}

fn normalize_base(s: &str) -> String {
    s.trim().trim_end_matches('/').to_string()
}

/// Effective mirror list: persisted config, then `CONNECTOR_HUB_URLS` (comma-separated), then `CONNECTOR_HUB_URL`, then local dev default.
pub fn hub_mirror_bases(state: &SharedState) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    let es = state.engine_store.lock().unwrap();
    if let Ok(Some(v)) = es.folder_get(STORE_FOLDER, STORE_KEY) {
        if let Ok(cfg) = serde_json::from_value::<HubMirrorsConfig>(v) {
            for u in cfg.urls {
                let n = normalize_base(&u);
                if !n.is_empty() && !out.iter().any(|x| x == &n) {
                    out.push(n);
                }
            }
        }
    }
    drop(es);

    if let Ok(raw) = std::env::var("CONNECTOR_HUB_URLS") {
        for part in raw.split(',') {
            let n = normalize_base(part);
            if !n.is_empty() && !out.iter().any(|x| x == &n) {
                out.push(n);
            }
        }
    }
    if let Ok(u) = std::env::var("CONNECTOR_HUB_URL") {
        let n = normalize_base(&u);
        if !n.is_empty() && !out.iter().any(|x| x == &n) {
            out.push(n);
        }
    }
    if out.is_empty() {
        out.push("http://127.0.0.1:19100".into());
    }
    out
}

fn require_admin_or_dev(headers: &axum::http::HeaderMap) -> Result<(), serde_json::Value> {
    if runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = auth::extract_claims(headers) else {
        return Err(json!({"ok": false, "error": "Unauthorized"}));
    };
    let role = auth::PlatformRole::from_str(&claims.role);
    if role.rank() < auth::PlatformRole::Admin.rank() {
        return Err(json!({"ok": false, "error": "Admin privileges required"}));
    }
    Ok(())
}

fn require_auth_or_dev(headers: &axum::http::HeaderMap) -> Result<(), serde_json::Value> {
    if runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    if auth::extract_claims(headers).is_some() {
        return Ok(());
    }
    Err(json!({"ok": false, "error": "Unauthorized"}))
}

pub async fn get_hub_mirrors(
    axum::extract::State(state): axum::extract::State<crate::state::SharedState>,
    headers: axum::http::HeaderMap,
) -> Result<axum::Json<serde_json::Value>, (axum::http::StatusCode, axum::Json<serde_json::Value>)>
{
    if let Err(e) = require_auth_or_dev(&headers) {
        return Err((axum::http::StatusCode::UNAUTHORIZED, axum::Json(e)));
    }
    let effective = hub_mirror_bases(&state);
    let es = state.engine_store.lock().unwrap();
    let persisted = es
        .folder_get(STORE_FOLDER, STORE_KEY)
        .ok()
        .flatten()
        .and_then(|v| serde_json::from_value::<HubMirrorsConfig>(v).ok())
        .unwrap_or_default();
    Ok(axum::Json(json!({
        "ok": true,
        "persisted": persisted,
        "effective_urls": effective,
        "hint": "Order is priority. UI/API writes persist; CONNECTOR_HUB_URLS / CONNECTOR_HUB_URL append or fill defaults."
    })))
}

pub async fn set_hub_mirrors(
    axum::extract::State(state): axum::extract::State<crate::state::SharedState>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<HubMirrorsConfig>,
) -> Result<axum::Json<serde_json::Value>, (axum::http::StatusCode, axum::Json<serde_json::Value>)>
{
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((axum::http::StatusCode::FORBIDDEN, axum::Json(e)));
    }
    let mut cfg = body;
    cfg.urls = cfg
        .urls
        .into_iter()
        .map(|u| normalize_base(&u))
        .filter(|u| !u.is_empty())
        .collect();
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        STORE_FOLDER,
        STORE_KEY,
        &serde_json::to_value(&cfg).unwrap_or_default(),
    );
    drop(es);
    Ok(axum::Json(json!({
        "ok": true,
        "persisted": cfg,
        "effective_urls": hub_mirror_bases(&state),
    })))
}
