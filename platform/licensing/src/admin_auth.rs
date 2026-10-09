//! Owner admin API authentication — validates X-API-Key against CONNECTOR_LICENSE_ADMIN_KEY.
//! Also provides email+password login endpoint (POST /api/v1/admin/auth).

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Paths requiring owner admin key (prefix match).
/// The /api/v1/admin/auth endpoint is EXEMPT — it IS the login endpoint.
pub fn requires_admin_auth(path: &str) -> bool {
    if path == "/api/v1/admin/auth" {
        return false; // login endpoint — no key required
    }
    path.starts_with("/api/v1/admin")
        || path.starts_with("/api/v1/surveillance")
        || path == "/api/v1/keys/issue"
        || path == "/api/v1/keys/revoke"
        || path.starts_with("/api/v1/issuances")
        || path.starts_with("/api/v1/payment/revenue")
        || path.starts_with("/api/v1/auth/users")
}

fn extract_api_key(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("X-API-Key").and_then(|v| v.to_str().ok()) {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    if let Some(v) = headers.get("Authorization").and_then(|v| v.to_str().ok()) {
        let t = v.trim();
        if let Some(key) = t.strip_prefix("Bearer ") {
            if !key.is_empty() {
                return Some(key.to_string());
            }
        }
        if t.starts_with("sk_admin_") {
            return Some(t.to_string());
        }
    }
    None
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub async fn admin_auth_middleware(request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path().to_string();
    if !requires_admin_auth(&path) {
        return next.run(request).await;
    }

    let expected = std::env::var("CONNECTOR_LICENSE_ADMIN_KEY").unwrap_or_default();
    if expected.is_empty() || expected == "change-me-to-a-long-random-secret" {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "Admin API not configured",
                "code": "ADMIN_KEY_MISSING",
            })),
        )
            .into_response();
    }

    let provided = match extract_api_key(request.headers()) {
        Some(k) => k,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Missing X-API-Key or Authorization",
                    "code": "ADMIN_AUTH_REQUIRED",
                })),
            )
                .into_response();
        }
    };

    if !constant_time_eq(&provided, &expected) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "Invalid admin API key",
                "code": "ADMIN_AUTH_FORBIDDEN",
            })),
        )
            .into_response();
    }

    next.run(request).await
}

// ─── Email + Password Admin Login ────────────────────────────────────────────
//
// Environment variables:
//   CONNECTOR_ADMIN_EMAIL          — owner email (e.g. umeshlamton@gmail.com)
//   CONNECTOR_ADMIN_PASSWORD_HASH  — SHA-256 hex of password
//   CONNECTOR_LICENSE_ADMIN_KEY    — the sk_admin_* key returned on success

#[derive(serde::Deserialize)]
pub struct AdminLoginRequest {
    pub email: String,
    pub password: String,
}

/// POST /api/v1/admin/auth — validate email + password, return admin key
pub async fn admin_login(
    Json(req): Json<AdminLoginRequest>,
) -> impl IntoResponse {
    let expected_email = std::env::var("CONNECTOR_ADMIN_EMAIL").unwrap_or_default();
    let expected_hash  = std::env::var("CONNECTOR_ADMIN_PASSWORD_HASH").unwrap_or_default();
    let admin_key      = std::env::var("CONNECTOR_LICENSE_ADMIN_KEY").unwrap_or_default();

    if expected_email.is_empty() || expected_hash.is_empty() || admin_key.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "Admin credentials not configured on server.",
                "code": "ADMIN_CREDS_MISSING",
            })),
        ).into_response();
    }

    // Constant-time email compare (case-insensitive)
    let email_match = constant_time_eq(
        &req.email.trim().to_lowercase(),
        &expected_email.trim().to_lowercase(),
    );

    // Hash the provided password and compare
    let provided_hash = sha256_hex(&req.password);
    let password_match = constant_time_eq(&provided_hash, &expected_hash.trim().to_lowercase());

    if !email_match || !password_match {
        // Rate-limit hint: log failed attempts
        eprintln!(
            "[ADMIN AUTH] Failed login attempt for email: {}",
            req.email.chars().take(3).collect::<String>() + "***"
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid email or password.",
                "code": "ADMIN_AUTH_FAILED",
            })),
        ).into_response();
    }

    eprintln!("[ADMIN AUTH] Successful admin login for: {}", req.email);

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "admin_key": admin_key,
            "email": req.email,
            "hint": "Store this key securely. It grants full admin access.",
        })),
    ).into_response()
}

fn sha256_hex(input: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
