//! Mesh join-token lab mint (soak UX).
//!
//! Default: honesty surface with `join_token_api: false`.
//! Lab: `CONNECTOR_MESH_JOIN_LAB=1` mints random in-memory tokens for local soak.

use axum::{http::HeaderMap, Json};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

use crate::auth;

static LAB_TOKENS: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Lab mint enabled via `CONNECTOR_MESH_JOIN_LAB=1`.
pub fn join_lab_enabled() -> bool {
    env_flag("CONNECTOR_MESH_JOIN_LAB")
}

/// Whether the HTTP join-token API is active (lab only today).
pub fn join_token_api_enabled() -> bool {
    join_lab_enabled()
}

/// Validate a lab join token (optional inbox / peer bootstrap check).
pub fn validate_lab_token(token: &str) -> bool {
    if !join_lab_enabled() {
        return false;
    }
    let t = token.trim();
    if t.is_empty() {
        return false;
    }
    LAB_TOKENS.lock().map(|g| g.contains(t)).unwrap_or(false)
}

fn require_admin_or_dev(headers: &HeaderMap) -> Result<(), (axum::http::StatusCode, Json<Value>)> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = auth::extract_claims(headers) else {
        return Err((
            axum::http::StatusCode::UNAUTHORIZED,
            Json(
                json!({"ok": false, "error": "Unauthorized", "join_token_api": join_token_api_enabled()}),
            ),
        ));
    };
    let role = auth::PlatformRole::from_str(&claims.role);
    if role.rank() < auth::PlatformRole::Admin.rank() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            Json(
                json!({"ok": false, "error": "Admin privileges required", "join_token_api": join_token_api_enabled()}),
            ),
        ));
    }
    Ok(())
}

fn mint_token() -> String {
    format!("cjt_{}", uuid::Uuid::new_v4().simple())
}

/// GET /api/v1/runtime/mesh/join-token — status / honesty (or lab inventory).
pub async fn get_join_token(
    headers: HeaderMap,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_admin_or_dev(&headers)?;
    if !join_lab_enabled() {
        return Ok(Json(json!({
            "schema": "mesh_join_token.v1",
            "ok": true,
            "join_token_api": false,
            "lab": false,
            "env": "CONNECTOR_MESH_JOIN_LAB=1",
            "honesty": [
                "Join-token API is lab-only. Set CONNECTOR_MESH_JOIN_LAB=1 to mint in-memory soak tokens.",
                "Production bootstrap remains CONNECTOR_HA_PEER_URLS / federation peers (docs/architecture/ha-federation.md).",
            ],
        })));
    }
    let count = LAB_TOKENS.lock().map(|g| g.len()).unwrap_or(0);
    Ok(Json(json!({
        "schema": "mesh_join_token.v1",
        "ok": true,
        "join_token_api": true,
        "lab": true,
        "tokens_in_memory": count,
        "honesty": [
            "Lab mint only — tokens are process-local (not durable, not multi-node SoT).",
            "POST this route to mint; optional X-Connector-Join-Token on mesh channel inbox validates membership.",
        ],
    })))
}

/// POST /api/v1/runtime/mesh/join-token — mint a lab token when enabled.
pub async fn post_join_token(
    headers: HeaderMap,
) -> Result<Json<Value>, (axum::http::StatusCode, Json<Value>)> {
    require_admin_or_dev(&headers)?;
    if !join_lab_enabled() {
        return Ok(Json(json!({
            "schema": "mesh_join_token.v1",
            "ok": false,
            "join_token_api": false,
            "lab": false,
            "error": "join_token_api disabled",
            "env": "CONNECTOR_MESH_JOIN_LAB=1",
            "honesty": [
                "Join-token mint refused — lab flag off. Use CONNECTOR_HA_PEER_URLS for peer bootstrap.",
            ],
        })));
    }
    let token = mint_token();
    if let Ok(mut g) = LAB_TOKENS.lock() {
        g.insert(token.clone());
        if g.len() > 64 {
            // Drop arbitrary oldest-ish entries by rebuilding (set has no order — cap size).
            let keep: Vec<String> = g.iter().take(32).cloned().collect();
            g.clear();
            for k in keep {
                g.insert(k);
            }
            g.insert(token.clone());
        }
    }
    Ok(Json(json!({
        "schema": "mesh_join_token.v1",
        "ok": true,
        "join_token_api": true,
        "lab": true,
        "token": token,
        "ttl": "process_lifetime",
        "honesty": [
            "Lab join token — in-memory only; restart clears. Not a production bootstrap credential.",
        ],
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_off_rejects_validation() {
        std::env::remove_var("CONNECTOR_MESH_JOIN_LAB");
        assert!(!join_lab_enabled());
        assert!(!validate_lab_token("cjt_anything"));
    }

    #[test]
    fn lab_on_mints_and_validates() {
        std::env::set_var("CONNECTOR_MESH_JOIN_LAB", "1");
        assert!(join_lab_enabled());
        let token = mint_token();
        LAB_TOKENS.lock().unwrap().insert(token.clone());
        assert!(validate_lab_token(&token));
        assert!(!validate_lab_token("cjt_nope"));
        std::env::remove_var("CONNECTOR_MESH_JOIN_LAB");
        LAB_TOKENS.lock().unwrap().clear();
    }
}
