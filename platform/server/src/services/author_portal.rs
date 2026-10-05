//! Phase 4.10 — author developer portal (tokens, namespace claims, publish stats).

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::auth;
use crate::services::runtime_control;
use crate::state::SharedState;

const TOKENS_FOLDER: &str = "author_tokens";
const NAMESPACES_FOLDER: &str = "author_namespaces";
const PUBLISH_EVENTS_FOLDER: &str = "author_publish_events";
const STATS_FOLDER: &str = "author_stats";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthorTokenRecord {
    pub token_id: String,
    pub label: String,
    pub vendor: String,
    pub created_at: String,
    #[serde(default)]
    pub revoked: bool,
    /// sha256 hex of secret (never store plaintext after mint).
    pub secret_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NamespaceClaim {
    pub vendor: String,
    #[serde(default)]
    pub proof_url: Option<String>,
    pub status: String,
    pub requested_at: String,
}

#[derive(Debug, Deserialize)]
pub struct MintTokenBody {
    pub label: String,
    pub vendor: String,
}

#[derive(Debug, Deserialize)]
pub struct ClaimNamespaceBody {
    pub vendor: String,
    #[serde(default)]
    pub proof_url: Option<String>,
}

fn require_admin_or_dev(headers: &HeaderMap) -> Result<(), serde_json::Value> {
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

fn random_token() -> String {
    let mut b = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut b);
    format!("cap_{}", hex::encode(b))
}

pub async fn list_author_tokens(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(TOKENS_FOLDER, None).unwrap_or_default();
    let mut rows = Vec::new();
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(TOKENS_FOLDER, &k) {
            if let Ok(r) = serde_json::from_value::<AuthorTokenRecord>(v) {
                rows.push(json!({
                    "token_id": r.token_id,
                    "label": r.label,
                    "vendor": r.vendor,
                    "created_at": r.created_at,
                    "revoked": r.revoked,
                    "secret_sha256_redacted": true,
                }));
            }
        }
    }
    Ok(Json(json!({ "ok": true, "tokens": rows })))
}

pub async fn mint_author_token(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<MintTokenBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let secret = random_token();
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    let secret_sha256 = hex::encode(h.finalize());
    let token_id = uuid::Uuid::new_v4().to_string();
    let rec = AuthorTokenRecord {
        token_id: token_id.clone(),
        label: body.label.clone(),
        vendor: body.vendor.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
        revoked: false,
        secret_sha256,
    };
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        TOKENS_FOLDER,
        &token_id,
        &serde_json::to_value(&rec).unwrap_or_default(),
    );
    Ok(Json(json!({
        "ok": true,
        "token": secret,
        "token_id": token_id,
        "warning": "Store this token now; it cannot be retrieved again.",
    })))
}

pub async fn revoke_author_token(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(token_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let mut es = state.engine_store.lock().unwrap();
    let Some(v) = es.folder_get(TOKENS_FOLDER, &token_id).ok().flatten() else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "token not found"})),
        ));
    };
    let mut r: AuthorTokenRecord = serde_json::from_value(v).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": "corrupt token record"})),
        )
    })?;
    r.revoked = true;
    let _ = es.folder_put(
        TOKENS_FOLDER,
        &token_id,
        &serde_json::to_value(&r).unwrap_or_default(),
    );
    Ok(Json(json!({"ok": true, "token_id": token_id})))
}

pub async fn claim_namespace(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<ClaimNamespaceBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let vendor = body.vendor.trim().to_ascii_lowercase();
    if vendor.is_empty()
        || vendor.contains('/')
        || !vendor
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid vendor label"})),
        ));
    }
    let claim = NamespaceClaim {
        vendor: vendor.clone(),
        proof_url: body.proof_url.clone(),
        status: "pending_review".into(),
        requested_at: chrono::Utc::now().to_rfc3339(),
    };
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        NAMESPACES_FOLDER,
        &vendor,
        &serde_json::to_value(&claim).unwrap_or_default(),
    );
    Ok(Json(json!({ "ok": true, "claim": claim })))
}

pub async fn list_namespace_claims(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let es = state.engine_store.lock().unwrap();
    let keys = es.folder_keys(NAMESPACES_FOLDER, None).unwrap_or_default();
    let mut claims = Vec::new();
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(NAMESPACES_FOLDER, &k) {
            claims.push(v);
        }
    }
    Ok(Json(json!({ "ok": true, "claims": claims })))
}

/// Append-only event for Hub/publish telemetry (kernel-side).
pub fn record_publish_event(state: &SharedState, vendor: &str, plugin_id: &str, version: &str) {
    let key = format!(
        "{}:{}",
        chrono::Utc::now().timestamp_millis(),
        uuid::Uuid::new_v4()
    );
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        PUBLISH_EVENTS_FOLDER,
        &key,
        &json!({
            "vendor": vendor,
            "plugin_id": plugin_id,
            "version": version,
            "at": chrono::Utc::now().to_rfc3339(),
        }),
    );
    let _ = es.folder_put(
        STATS_FOLDER,
        "totals",
        &json!({
            "last_publish_plugin_id": plugin_id,
            "last_publish_at": chrono::Utc::now().to_rfc3339(),
        }),
    );
}

pub async fn author_stats(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let es = state.engine_store.lock().unwrap();
    let ev_keys = es
        .folder_keys(PUBLISH_EVENTS_FOLDER, None)
        .unwrap_or_default();
    let tok_keys = es.folder_keys(TOKENS_FOLDER, None).unwrap_or_default();
    let ns_keys = es.folder_keys(NAMESPACES_FOLDER, None).unwrap_or_default();
    let totals = es
        .folder_get(STATS_FOLDER, "totals")
        .ok()
        .flatten()
        .unwrap_or(json!({}));
    Ok(Json(json!({
        "ok": true,
        "publish_events_count": ev_keys.len(),
        "author_tokens_count": tok_keys.len(),
        "namespace_claims_count": ns_keys.len(),
        "totals": totals,
    })))
}
