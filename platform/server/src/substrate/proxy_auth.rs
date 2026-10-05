//! Shared auth gate for plugin management plane proxies (TT/WC).

use axum::{
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Require authenticated platform caller for management proxy forwards (B-P0-4).
///
/// Intentionally **not** gated on general `CONNECTOR_DEV_MODE` — only explicit
/// `CONNECTOR_DEV_AUTH_BYPASS=1` may skip auth for lab break-glass.
pub fn require_management_proxy_auth(headers: &HeaderMap) -> Result<(), Response> {
    if matches!(
        std::env::var("CONNECTOR_DEV_AUTH_BYPASS")
            .ok()
            .as_deref(),
        Some("1") | Some("true") | Some("yes")
    ) {
        return Ok(());
    }
    let has_bearer = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .is_some_and(|t| !t.is_empty());
    let has_api_key = headers
        .get("x-api-key")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|k| !k.is_empty() && k.starts_with("cpk_"));
    if !has_bearer && !has_api_key {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "ok": false,
                "error": "authentication_required",
                "message": "Bearer token or x-api-key required for plugin management proxy",
            })),
        )
            .into_response());
    }
    let Some(claims) = crate::auth::extract_claims(headers) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "ok": false,
                "error": "authentication_required",
                "message": "Bearer token or x-api-key required for plugin management proxy",
            })),
        )
            .into_response());
    };
    let role = crate::auth::PlatformRole::from_str(&claims.role);
    if role.rank() < crate::auth::PlatformRole::Operator.rank() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "error": "forbidden",
                "message": "Operator role or higher required for plugin management proxy",
            })),
        )
            .into_response());
    }
    Ok(())
}

/// Cage hostname is routing only — caller must still authenticate (T2-4).
/// Principal must hold `plugin:cage:<slug>` or Operator+ role (T6 cage binding).
pub fn require_plugin_cage_auth(headers: &HeaderMap, method: &Method) -> Result<(), Response> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = crate::auth::extract_claims(headers) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "ok": false,
                "error": "authentication_required",
                "message": "Bearer token or x-api-key required for plugin cage proxy",
            })),
        )
            .into_response());
    };
    let role = crate::auth::PlatformRole::from_str(&claims.role);
    let min = if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        crate::auth::PlatformRole::Developer
    } else {
        crate::auth::PlatformRole::Operator
    };
    if role.rank() < min.rank() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "error": "forbidden",
                "message": format!(
                    "{} role or higher required for plugin cage {}",
                    min.to_str(),
                    method.as_str()
                ),
            })),
        )
            .into_response());
    }
    Ok(())
}
