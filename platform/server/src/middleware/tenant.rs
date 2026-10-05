//! Tenant Middleware — Multi-tenancy isolation for enterprise deployments.
//!
//! Extracts tenant context from requests and enforces isolation:
//! - `X-Tenant-ID` header (explicit)
//! - JWT `tenant_id` claim (implicit)
//! - API key tenant binding (implicit)
//!
//! Tenant namespace prefix is enforced in middleware for HTTP routes that use it.
//! Kernel **agent count** may still be globally capped unless `CONNECTOR_MULTI_TENANT` is set and
//! registration paths pass tenant context into `kernel_agent_limit_gate` (see BF2-B01/R01).
//! Cross-tenant access is blocked at the middleware layer.

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Tenant context extracted from the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantContext {
    /// Unique tenant identifier (e.g., "tenant_abc123")
    pub tenant_id: String,
    
    /// Tenant's namespace prefix (e.g., "/t/abc123/")
    pub namespace_prefix: String,
    
    /// Tenant display name (optional)
    pub name: Option<String>,
    
    /// Tenant tier (free, pro, enterprise)
    pub tier: TenantTier,
    
    /// Whether this tenant has HIPAA BAA signed
    pub hipaa_enabled: bool,
    
    /// Maximum agents allowed for this tenant
    pub agent_limit: u32,
    
    /// Maximum memory packets per agent
    pub memory_limit_per_agent: u64,
    
    /// Source of tenant context extraction
    pub source: TenantSource,
}

/// How the tenant was identified
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenantSource {
    /// Extracted from X-Tenant-ID header
    Header,
    /// Extracted from JWT tenant_id claim
    Jwt,
    /// Extracted from API key binding
    ApiKey,
    /// Default tenant (single-tenant mode)
    Default,
}

/// Tenant subscription tier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TenantTier {
    #[default]
    Free,
    Pro,
    Enterprise,
}

impl TenantTier {
    pub fn agent_limit(&self) -> u32 {
        match self {
            TenantTier::Free => 3,
            TenantTier::Pro => 25,
            TenantTier::Enterprise => 1000,
        }
    }
    
    pub fn memory_limit_per_agent(&self) -> u64 {
        match self {
            TenantTier::Free => 1000,        // 1K packets
            TenantTier::Pro => 100_000,      // 100K packets
            TenantTier::Enterprise => 10_000_000, // 10M packets
        }
    }
}

/// True if `ns` contains a `/t/<tenant>/` segment for a tenant other than `t` (BF2-V02).
pub fn references_other_tenant_namespace(ns: &str, t: &TenantContext) -> bool {
    if t.source == TenantSource::Default {
        return false;
    }
    for (idx, _) in ns.match_indices("/t/") {
        let rest = &ns[idx + 3..];
        let seg = rest.split('/').next().unwrap_or("");
        if !seg.is_empty() && seg != t.tenant_id {
            return true;
        }
    }
    false
}

impl TenantContext {
    /// Create a default tenant context for single-tenant deployments
    pub fn default_tenant() -> Self {
        Self {
            tenant_id: "default".to_string(),
            namespace_prefix: "/".to_string(),
            name: Some("Default Tenant".to_string()),
            tier: TenantTier::Enterprise,
            hipaa_enabled: false,
            agent_limit: 1000,
            memory_limit_per_agent: 10_000_000,
            source: TenantSource::Default,
        }
    }
    
    /// Create tenant context from a tenant ID
    pub fn from_id(tenant_id: &str, source: TenantSource) -> Self {
        // In production, this would look up tenant config from database
        let tier = TenantTier::Pro; // Default to Pro for now
        Self {
            tenant_id: tenant_id.to_string(),
            namespace_prefix: format!("/t/{}/", tenant_id),
            name: None,
            tier: tier.clone(),
            hipaa_enabled: false,
            agent_limit: tier.agent_limit(),
            memory_limit_per_agent: tier.memory_limit_per_agent(),
            source,
        }
    }
    
    /// Check if a namespace path is within this tenant's scope
    pub fn is_namespace_allowed(&self, namespace: &str) -> bool {
        if self.source == TenantSource::Default {
            return true; // Single-tenant mode allows all
        }
        namespace.starts_with(&self.namespace_prefix) || namespace.starts_with("/p/") // Public namespace
    }
    
    /// Prefix a namespace path with tenant prefix if not already prefixed
    pub fn prefix_namespace(&self, namespace: &str) -> String {
        if self.source == TenantSource::Default {
            return namespace.to_string();
        }
        if namespace.starts_with(&self.namespace_prefix) || namespace.starts_with("/p/") {
            namespace.to_string()
        } else {
            format!("{}{}", self.namespace_prefix, namespace.trim_start_matches('/'))
        }
    }
}

/// `X-Tenant-ID` header value when set (trimmed, non-empty).
pub fn header_tenant_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Extract tenant context from request headers.
///
/// AUTH-02: verified JWT / API-key binding is authoritative. `X-Tenant-ID` alone never
/// establishes tenancy here for production callers; middleware rejects header-only unless
/// `CONNECTOR_ALLOW_LEGACY_HEADER_TENANT=1`.
pub fn extract_tenant_from_headers(headers: &HeaderMap) -> Option<TenantContext> {
    if let Some(detail) = tenant_identification_mismatch(headers) {
        let _ = detail;
        return None;
    }

    if let Some(tenant_id) = jwt_or_key_tenant_id(headers) {
        let source = if headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|a| a.strip_prefix("Bearer "))
            .map(|t| t.starts_with("cpk_"))
            .unwrap_or(false)
            || headers.get("x-api-key").is_some()
        {
            TenantSource::ApiKey
        } else {
            TenantSource::Jwt
        };
        return Some(TenantContext::from_id(&tenant_id, source));
    }

    // Header-only — tagged so middleware can reject outside legacy migration mode.
    if let Some(tenant_id) = header_tenant_id(headers) {
        return Some(TenantContext::from_id(&tenant_id, TenantSource::Header));
    }

    None
}

/// Tenant id from verified Bearer JWT or API key registry — never from unsigned JWT payloads.
pub fn jwt_or_key_tenant_id(headers: &HeaderMap) -> Option<String> {
    if let Some(token) = bearer_token(headers) {
        if token.starts_with("cpk_") {
            if crate::auth::validate_api_key(&token).is_ok() {
                // cpk_* keys do not encode tenant in the raw string (prefix spoof closed).
                return std::env::var("CONNECTOR_DEFAULT_TENANT_ID").ok().filter(|s| !s.is_empty());
            }
            return None;
        }
        if let Ok(claims) = crate::auth::verify_token(&token) {
            if let Some(tid) = claims.tenant_id.filter(|s| !s.trim().is_empty()) {
                return Some(tid);
            }
        }
        return None;
    }
    if let Some(api_key) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        if crate::auth::validate_api_key(api_key).is_ok() {
            return std::env::var("CONNECTOR_DEFAULT_TENANT_ID").ok().filter(|s| !s.is_empty());
        }
        if !api_key.starts_with("cpk_") {
            return extract_tenant_from_api_key(api_key);
        }
    }
    None
}

/// When both `X-Tenant-ID` and a *verified* credential tenant are present they must match.
pub fn tenant_identification_mismatch(headers: &HeaderMap) -> Option<String> {
    let header_tid = header_tenant_id(headers)?;
    let verified_tid = jwt_or_key_tenant_id(headers)?;
    if header_tid != verified_tid {
        Some(format!(
            "X-Tenant-ID ({header_tid}) does not match verified tenant_id ({verified_tid})"
        ))
    } else {
        None
    }
}

/// Extract tenant from legacy `tenant_id:key` format only. Never for `cpk_*` keys
/// (prefix before colon would otherwise be attacker-controlled).
pub fn extract_tenant_from_api_key_public(api_key: &str) -> Option<String> {
    extract_tenant_from_api_key(api_key)
}

fn extract_tenant_from_api_key(api_key: &str) -> Option<String> {
    if api_key.starts_with("cpk_") || api_key.contains("cpk_") {
        return None;
    }
    if let Some((tenant_id, key)) = api_key.split_once(':') {
        if !tenant_id.is_empty() && !key.is_empty() && !tenant_id.contains('/') {
            return Some(tenant_id.to_string());
        }
    }
    None
}

fn allow_legacy_header_tenant() -> bool {
    if crate::services::playground::is_playground_mode() {
        return false;
    }
    std::env::var("CONNECTOR_ALLOW_LEGACY_HEADER_TENANT")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn reject_legacy_header_tenant() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "ok": false,
            "error": {
                "type": "https://connector.ai/docs/errors/tenant_legacy_header",
                "title": "Header-only tenant rejected",
                "status": 403,
                "detail": "X-Tenant-ID without a verified principal tenant binding is not accepted. \
                          Mint a JWT/API key with tenant_id, or set CONNECTOR_ALLOW_LEGACY_HEADER_TENANT=1 \
                          during migration.",
                "code": "tenant_legacy_header",
            }
        })),
    )
        .into_response()
}

/// Paths under `/api/v1` that may proceed without an explicit tenant when `CONNECTOR_MULTI_TENANT` is set.
pub fn is_tenant_exempt_path(path_bare: &str) -> bool {
    let p = path_bare.trim_start_matches('/').trim_end_matches('/');
    // Tenant-scoped settings paths (multi-tenant custom domains, etc.)
    if p == "settings/networking/custom-domains"
        || p.starts_with("settings/networking/custom-domains/")
    {
        return false;
    }
    // Prefix-based exemptions — entire subtrees that don't need tenant isolation
    if p == "apps" || p.starts_with("apps/")
        || p.starts_with("plugins/")
        || p.starts_with("surfaces/")
        || p.starts_with("kernel/")
        || p.starts_with("auth/")
        || p.starts_with("billing/")
        || p.starts_with("license/")
        || p.starts_with("runtime/")
        || p.starts_with("devguard/")
        || p.starts_with("playground/")
        || p.starts_with("workflows/")
        || p.starts_with("service-map/")
        || p.starts_with("settings/")
        || p.starts_with("notifications/")
        || p.starts_with("portal/")
        || p.starts_with("distribution/")
        || p.starts_with("monitor/")
        || p.starts_with("safety/")
        || p.starts_with("compliance/")
    {
        return true;
    }
    matches!(
        p,
        "health"
            | "metrics"
            | "boot/progress"
    )
}

/// Tenant middleware layer — inserts [`TenantContext`] into request extensions.
///
/// When multi-tenant mode is on and auth inserted a [`connector_trust::PrincipalContextV2`]
/// with a verified `tenant_id`, that binding wins. `X-Tenant-ID` may only equal the binding;
/// header-only tenancy without a verified principal binding is treated as legacy and logged.
pub async fn tenant_middleware(
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    // Ultimate-free self-host is single-operator. Hosted playground is the
    // opposite: each email/session is its own tenant even if ULTIMATE_FREE=1.
    let playground = crate::services::playground::is_playground_mode();
    let ultimate_free = std::env::var("CONNECTOR_ULTIMATE_FREE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let multi_tenant = playground
        || (!ultimate_free && std::env::var("CONNECTOR_MULTI_TENANT").is_ok());
    let path = request.uri().path();
    let path_bare = path.strip_prefix("/api/v1").unwrap_or(path);
    let exempt = is_tenant_exempt_path(path_bare);

    let principal = request
        .extensions()
        .get::<connector_trust::PrincipalContextV2>()
        .cloned();

    let tenant = if multi_tenant {
        if let Some(detail) = tenant_identification_mismatch(&headers) {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "ok": false,
                    "error": {
                        "type": "https://connector.ai/docs/errors/tenant_mismatch",
                        "title": "Tenant identification mismatch",
                        "status": 403,
                        "detail": detail,
                        "code": "tenant_mismatch",
                    }
                }))
            )
                .into_response();
        }

        // Verified principal tenant binding rejects spoofed X-Tenant-ID.
        if let Some(ref p) = principal {
            if let Some(bound) = p.tenant_id.as_deref().filter(|s| !s.is_empty()) {
                if let Some(hdr) = header_tenant_id(&headers) {
                    if p.tenant_header_mismatch(&hdr) {
                        return (
                            StatusCode::FORBIDDEN,
                            Json(serde_json::json!({
                                "ok": false,
                                "error": {
                                    "type": "https://connector.ai/docs/errors/tenant_mismatch",
                                    "title": "Tenant identification mismatch",
                                    "status": 403,
                                    "detail": format!(
                                        "X-Tenant-ID ({hdr}) does not match verified principal tenant_id ({bound})"
                                    ),
                                    "code": "tenant_mismatch",
                                }
                            }))
                        )
                            .into_response();
                    }
                }
                let source = match p.auth_source {
                    connector_trust::principal::AuthSourceV2::ApiKey => TenantSource::ApiKey,
                    connector_trust::principal::AuthSourceV2::Jwt
                    | connector_trust::principal::AuthSourceV2::Workload => TenantSource::Jwt,
                    connector_trust::principal::AuthSourceV2::Synthetic
                    | connector_trust::principal::AuthSourceV2::Legacy => {
                        if header_tenant_id(&headers).is_some() {
                            TenantSource::Header
                        } else {
                            TenantSource::Jwt
                        }
                    }
                };
                TenantContext::from_id(bound, source)
            } else {
                // No verified tenant on principal — reject header-only unless compatibility flag.
                match extract_tenant_from_headers(&headers) {
                    Some(t) if t.source == TenantSource::Header => {
                        if allow_legacy_header_tenant() {
                            tracing::warn!(
                                tenant_id = %t.tenant_id,
                                path = %path,
                                "legacy_header_only_tenant: allowed by CONNECTOR_ALLOW_LEGACY_HEADER_TENANT"
                            );
                            t
                        } else {
                            return reject_legacy_header_tenant();
                        }
                    }
                    Some(t) => t,
                    None if exempt => TenantContext::default_tenant(),
                    None => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({
                                "ok": false,
                                "error": {
                                    "type": "https://connector.ai/docs/errors/tenant_required",
                                    "title": "Tenant identification required",
                                    "status": 400,
                                    "detail": "Multi-tenant mode is enabled but no tenant was identified. \
                                              Provide a JWT/API key with tenant_id claim.",
                                    "code": "tenant_required",
                                    "hint": "Mint a tenant-bound credential. X-Tenant-ID alone is rejected.",
                                }
                            }))
                        )
                            .into_response();
                    }
                }
            }
        } else {
            match extract_tenant_from_headers(&headers) {
                Some(t) if t.source == TenantSource::Header => {
                    if allow_legacy_header_tenant() {
                        tracing::warn!(
                            tenant_id = %t.tenant_id,
                            path = %path,
                            "legacy_header_only_tenant: allowed by CONNECTOR_ALLOW_LEGACY_HEADER_TENANT (no PrincipalContextV2)"
                        );
                        t
                    } else {
                        return reject_legacy_header_tenant();
                    }
                }
                Some(t) => t,
                None if exempt => TenantContext::default_tenant(),
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "ok": false,
                            "error": {
                                "type": "https://connector.ai/docs/errors/tenant_required",
                                "title": "Tenant identification required",
                                "status": 400,
                                "detail": "Multi-tenant mode is enabled but no tenant was identified. \
                                          Use a JWT with tenant_id claim or a tenant-bound API key.",
                                "code": "tenant_required",
                                "hint": "Mint a tenant-bound credential. X-Tenant-ID alone is rejected.",
                            }
                        }))
                    )
                        .into_response();
                }
            }
        }
    } else {
        TenantContext::default_tenant()
    };

    request.extensions_mut().insert(tenant);
    next.run(request).await
}

/// Extension trait for extracting tenant from request
pub trait TenantExt {
    fn tenant(&self) -> Option<&TenantContext>;
}

impl TenantExt for axum::extract::Request {
    fn tenant(&self) -> Option<&TenantContext> {
        self.extensions().get::<TenantContext>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    
    #[test]
    fn auth_login_is_tenant_exempt() {
        assert!(is_tenant_exempt_path("auth/login"));
        assert!(!is_tenant_exempt_path("settings/networking/custom-domains"));
    }

    #[test]
    fn apps_catalog_is_tenant_exempt() {
        assert!(is_tenant_exempt_path("apps"));
        assert!(is_tenant_exempt_path("apps/tracetramp"));
    }

    #[test]
    fn plugin_cage_paths_require_tenant_when_multi_tenant() {
        assert!(!is_tenant_exempt_path("/plugin/tracetramp/admin/stats"));
        assert!(!is_tenant_exempt_path("plugin/tracetramp"));
    }

    #[test]
    fn test_tenant_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant-id", "acme_corp".parse().unwrap());
        
        let tenant = extract_tenant_from_headers(&headers).unwrap();
        assert_eq!(tenant.tenant_id, "acme_corp");
        assert_eq!(tenant.source, TenantSource::Header);
        assert_eq!(tenant.namespace_prefix, "/t/acme_corp/");
    }
    
    #[test]
    fn test_tenant_namespace_allowed() {
        let tenant = TenantContext::from_id("acme", TenantSource::Header);
        
        assert!(tenant.is_namespace_allowed("/t/acme/agents"));
        assert!(tenant.is_namespace_allowed("/t/acme/memory/data"));
        assert!(tenant.is_namespace_allowed("/p/public")); // Public namespace
        assert!(!tenant.is_namespace_allowed("/t/other/agents")); // Other tenant
        assert!(!tenant.is_namespace_allowed("/agents")); // No prefix
    }
    
    #[test]
    fn test_tenant_prefix_namespace() {
        let tenant = TenantContext::from_id("acme", TenantSource::Header);
        
        assert_eq!(tenant.prefix_namespace("agents"), "/t/acme/agents");
        assert_eq!(tenant.prefix_namespace("/agents"), "/t/acme/agents");
        assert_eq!(tenant.prefix_namespace("/t/acme/agents"), "/t/acme/agents"); // Already prefixed
        assert_eq!(tenant.prefix_namespace("/p/public"), "/p/public"); // Public stays
    }
    
    #[test]
    fn test_default_tenant_allows_all() {
        let tenant = TenantContext::default_tenant();
        
        assert!(tenant.is_namespace_allowed("/any/path"));
        assert!(tenant.is_namespace_allowed("/t/other/agents"));
        assert_eq!(tenant.prefix_namespace("/agents"), "/agents"); // No prefix added
    }
    
    #[test]
    fn test_tier_limits() {
        assert_eq!(TenantTier::Free.agent_limit(), 3);
        assert_eq!(TenantTier::Pro.agent_limit(), 25);
        assert_eq!(TenantTier::Enterprise.agent_limit(), 1000);
    }
    
    #[test]
    fn test_api_key_tenant_extraction() {
        assert_eq!(extract_tenant_from_api_key("acme:sk_live_abc123"), Some("acme".to_string()));
        assert_eq!(extract_tenant_from_api_key("sk_live_abc123"), None);
        assert_eq!(extract_tenant_from_api_key("evil:cpk_live_realkey"), None);
        assert_eq!(extract_tenant_from_api_key("cpk_live_realkey"), None);
    }

    #[test]
    fn unsigned_jwt_cannot_establish_or_mismatch_tenant() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant-id", "acme".parse().unwrap());
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"tenant_id":"other"}"#);
        let token = format!("aaa.{payload}.bbb");
        headers.insert(
            "authorization",
            format!("Bearer {token}").parse().unwrap(),
        );
        // Spoofed unsigned JWT is ignored — no verified binding → no mismatch signal.
        assert!(tenant_identification_mismatch(&headers).is_none());
        let ctx = extract_tenant_from_headers(&headers).unwrap();
        assert_eq!(ctx.tenant_id, "acme");
        assert_eq!(ctx.source, TenantSource::Header);
    }

    #[test]
    fn verified_jwt_tenant_beats_header_and_detects_mismatch() {
        let _lock = std::sync::Mutex::new(());
        let prev_env = std::env::var("CONNECTOR_ENV").ok();
        let prev_secret = std::env::var("CONNECTOR_JWT_SECRET").ok();
        std::env::set_var("CONNECTOR_ENV", "development");
        std::env::set_var("CONNECTOR_JWT_SECRET", "tenant-test-secret-must-be-long-enough-32b");
        let claims = crate::auth::Claims {
            sub: "u1".into(),
            email: "u1@example.com".into(),
            role: "viewer".into(),
            permissions: vec![],
            instance_id: None,
            tenant_id: Some("bound-tenant".into()),
            token_type: "access".into(),
            jti: uuid::Uuid::new_v4().to_string(),
            iat: chrono::Utc::now().timestamp() as usize,
            exp: (chrono::Utc::now().timestamp() + 3600) as usize,
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(
                std::env::var("CONNECTOR_JWT_SECRET").unwrap().as_bytes(),
            ),
        )
        .unwrap();

        let mut agree = HeaderMap::new();
        agree.insert("x-tenant-id", "bound-tenant".parse().unwrap());
        agree.insert("authorization", format!("Bearer {token}").parse().unwrap());
        assert!(tenant_identification_mismatch(&agree).is_none());
        let ctx = extract_tenant_from_headers(&agree).unwrap();
        assert_eq!(ctx.tenant_id, "bound-tenant");
        assert_eq!(ctx.source, TenantSource::Jwt);

        let mut bad = HeaderMap::new();
        bad.insert("x-tenant-id", "spoofed".parse().unwrap());
        bad.insert("authorization", format!("Bearer {token}").parse().unwrap());
        assert!(tenant_identification_mismatch(&bad).is_some());
        assert!(extract_tenant_from_headers(&bad).is_none());

        match prev_env {
            Some(v) => std::env::set_var("CONNECTOR_ENV", v),
            None => std::env::remove_var("CONNECTOR_ENV"),
        }
        match prev_secret {
            Some(v) => std::env::set_var("CONNECTOR_JWT_SECRET", v),
            None => std::env::remove_var("CONNECTOR_JWT_SECRET"),
        }
    }
}
