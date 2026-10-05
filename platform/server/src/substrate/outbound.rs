//! Verified principal + CFNI stamping on outbound plugin proxy requests.

use axum::http::HeaderMap;
use base64::Engine;
use connector_trust::PrincipalContextV2;

/// Base64 JSON envelope for [`PrincipalContextV2`] on TT/WC/cage upstream hops.
pub const PRINCIPAL_CONTEXT_HEADER: &str = "x-connector-principal-context";

/// Build principal context from verified platform auth only (never from this header alone).
pub fn principal_from_inbound(headers: &HeaderMap) -> Option<PrincipalContextV2> {
    let claims = crate::auth::extract_claims(headers)?;
    Some(PrincipalContextV2::from(&claims))
}

/// Tenant for upstream isolation: JWT binding wins; header only in lab bypass.
pub fn verified_tenant_id(headers: &HeaderMap) -> Option<String> {
    if let Some(claims) = crate::auth::extract_claims(headers) {
        if let Some(tid) = claims
            .tenant_id
            .filter(|t| !t.trim().is_empty())
        {
            if let Some(hdr) = headers
                .get("x-tenant-id")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                if hdr != tid.as_str() {
                    return None;
                }
            }
            return Some(tid);
        }
    }
    if crate::services::runtime_control::dev_auth_bypass_allowed()
        && !crate::connector_profile::is_productionish_env()
    {
        return headers
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }
    None
}

/// Reject caller-supplied role/agent identity headers that disagree with verified claims.
/// Uses HMAC-verified JWT only (never open-auth synthetic claims).
pub fn spoofed_identity_headers(headers: &HeaderMap) -> Option<&'static str> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())?;
    if token.starts_with("cpk_") {
        return None;
    }
    let claims = crate::auth::verify_token(token).ok()?;
    for name in ["x-connector-role", "x-role", "x-platform-role"] {
        if let Some(hdr) = headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim) {
            if !hdr.is_empty() && !hdr.eq_ignore_ascii_case(&claims.role) {
                return Some("role_header_spoof");
            }
        }
    }
    for name in ["x-user-id", "x-connector-user", "x-subject"] {
        if let Some(hdr) = headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim) {
            if !hdr.is_empty() && hdr != claims.sub {
                return Some("subject_header_spoof");
            }
        }
    }
    None
}

/// Stamp reqwest builder with principal context + CFNI from verified caller.
pub fn stamp_reqwest(
    rb: reqwest::RequestBuilder,
    headers: &HeaderMap,
) -> reqwest::RequestBuilder {
    let mut rb = rb;
    if let Some(principal) = principal_from_inbound(headers) {
        if let Ok(json) = serde_json::to_string(&principal) {
            let enc = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
            rb = rb.header(PRINCIPAL_CONTEXT_HEADER, enc);
        }
        if let Some(id) =
            crate::substrate::cfni::mint_for_principal(&principal.subject, principal.tenant_id.as_deref())
        {
            if let Some((name, value)) = crate::substrate::cfni::header_from_identity(&id) {
                rb = rb.header(name, value);
            }
        }
    }
    if let Some(tid) = verified_tenant_id(headers) {
        rb = rb.header("X-Tenant-Id", tid);
    }
    rb.header("x-connector-mesh-hop", "1")
}
