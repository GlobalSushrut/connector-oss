//! Authentication and authorization middleware
//!
//! JWT validation, API key verification, RBAC enforcement

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub subject: String,
    pub tenant_id: Option<String>,
    pub is_admin: bool,
}

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,        // Subject (user_id)
    tenant_id: String,  // Tenant ID
    roles: Vec<String>, // User roles
    exp: usize,         // Expiration time
    iat: usize,         // Issued at
}

/// Middleware to require authentication
pub async fn require_auth(
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract token from Authorization header
    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    
    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        _ => return Err(AppError::Unauthorized("Missing or invalid Authorization header".to_string())),
    };
    
    // Validate JWT (startup enforces presence of TRACETRAMP_JWT_SECRET)
    let validation = Validation::new(Algorithm::HS256);
    let jwt_secret = std::env::var("TRACETRAMP_JWT_SECRET")
        .map_err(|_| AppError::Unauthorized("JWT secret not configured".to_string()))?;
    if jwt_secret.trim().is_empty() {
        return Err(AppError::Unauthorized("JWT secret not configured".to_string()));
    }
    let key = DecodingKey::from_secret(jwt_secret.as_bytes());
    
    match decode::<Claims>(token, &key, &validation) {
        Ok(decoded) => {
            let principal = connector_trust::PrincipalContextV2::from_verified_claims(
                decoded.claims.sub.clone(),
                String::new(),
                decoded
                    .claims
                    .roles
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "user".into()),
                decoded.claims.roles.clone(),
                Some(decoded.claims.tenant_id.clone()).filter(|s| !s.is_empty()),
                None,
                "access",
                None,
            );
            req.extensions_mut().insert(AuthContext {
                subject: decoded.claims.sub,
                tenant_id: Some(decoded.claims.tenant_id).filter(|s| !s.is_empty()),
                is_admin: false,
            });
            req.extensions_mut().insert(principal);
            Ok(next.run(req).await)
        }
        Err(_e) => {
            Err(AppError::Unauthorized("Invalid token".to_string()))
        }
    }
}

/// Data-plane auth: Bearer JWT, Bearer API key, or `X-API-Key`.
/// Health/ready stay outside this layer. Lab bypass requires the same dual flags as admin.
pub async fn require_data_plane_auth(
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    if insecure_admin_bypass_enabled() {
        let principal = connector_trust::PrincipalContextV2 {
            subject: "dev-bypass".into(),
            email: String::new(),
            role: "admin".into(),
            permissions: vec!["*".into()],
            tenant_id: req
                .headers()
                .get("x-tenant-id")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            jti: None,
            token_type: "synthetic".into(),
            instance_id: None,
            auth_source: connector_trust::principal::AuthSourceV2::Synthetic,
            contract_version: 2,
        };
        req.extensions_mut().insert(AuthContext {
            subject: "dev-bypass".into(),
            tenant_id: principal.tenant_id.clone(),
            is_admin: true,
        });
        req.extensions_mut().insert(principal);
        return Ok(next.run(req).await);
    }

    let api_key = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let token = match (api_key, bearer) {
        (Some(k), _) => k,
        (None, Some(b)) => b,
        (None, None) => {
            return Err(AppError::Unauthorized(
                "Missing Authorization Bearer or X-API-Key".to_string(),
            ));
        }
    };

    // API keys (cpk_*) — accept presence; registry binding remains handler-level.
    if token.starts_with("cpk_") || token.starts_with("tt_") {
        let tenant_id = req
            .headers()
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let principal = connector_trust::PrincipalContextV2 {
            subject: format!("apikey:{}", &token[..token.len().min(16)]),
            email: String::new(),
            role: "service".into(),
            permissions: vec![],
            tenant_id: tenant_id.clone(),
            jti: None,
            token_type: "api_key".into(),
            instance_id: None,
            auth_source: connector_trust::principal::AuthSourceV2::ApiKey,
            contract_version: 2,
        };
        req.extensions_mut().insert(AuthContext {
            subject: principal.subject.clone(),
            tenant_id,
            is_admin: false,
        });
        req.extensions_mut().insert(principal);
        return Ok(next.run(req).await);
    }

    // JWT path
    let jwt_secret = std::env::var("TRACETRAMP_JWT_SECRET").unwrap_or_default();
    if jwt_secret.trim().is_empty() {
        // No JWT secret — treat non-empty opaque bearer as API credential (lab/compat).
        let tenant_id = req
            .headers()
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let principal = connector_trust::PrincipalContextV2 {
            subject: format!("bearer:{}", &token[..token.len().min(16)]),
            email: String::new(),
            role: "service".into(),
            permissions: vec![],
            tenant_id: tenant_id.clone(),
            jti: None,
            token_type: "api_key".into(),
            instance_id: None,
            auth_source: connector_trust::principal::AuthSourceV2::ApiKey,
            contract_version: 2,
        };
        req.extensions_mut().insert(AuthContext {
            subject: principal.subject.clone(),
            tenant_id,
            is_admin: false,
        });
        req.extensions_mut().insert(principal);
        return Ok(next.run(req).await);
    }

    let validation = Validation::new(Algorithm::HS256);
    let key = DecodingKey::from_secret(jwt_secret.as_bytes());
    match decode::<Claims>(&token, &key, &validation) {
        Ok(decoded) => {
            let is_admin = decoded
                .claims
                .roles
                .iter()
                .any(|r| matches!(r.as_str(), "admin" | "super_admin" | "owner"));
            let principal = connector_trust::PrincipalContextV2::from_verified_claims(
                decoded.claims.sub.clone(),
                String::new(),
                decoded
                    .claims
                    .roles
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "user".into()),
                decoded.claims.roles.clone(),
                Some(decoded.claims.tenant_id.clone()).filter(|s| !s.is_empty()),
                None,
                "access",
                None,
            );
            req.extensions_mut().insert(AuthContext {
                subject: decoded.claims.sub,
                tenant_id: Some(decoded.claims.tenant_id).filter(|s| !s.is_empty()),
                is_admin,
            });
            req.extensions_mut().insert(principal);
            Ok(next.run(req).await)
        }
        Err(_) => Err(AppError::Unauthorized("Invalid token".to_string())),
    }
}

/// Require admin role
pub async fn require_admin(
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    if insecure_admin_bypass_enabled() {
        req.extensions_mut().insert(AuthContext {
            subject: "dev-bypass".to_string(),
            tenant_id: None,
            is_admin: true,
        });
        return Ok(next.run(req).await);
    }

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header".to_string()))?
        .trim();
    if token.is_empty() {
        return Err(AppError::Unauthorized(
            "Authorization token is empty".to_string(),
        ));
    }

    if let Ok(admin_token) = std::env::var("TRACETRAMP_ADMIN_TOKEN") {
        if !admin_token.trim().is_empty() && token == admin_token {
            req.extensions_mut().insert(AuthContext {
                subject: "admin-token".to_string(),
                tenant_id: None,
                is_admin: true,
            });
            return Ok(next.run(req).await);
        }
    }

    let validation = Validation::new(Algorithm::HS256);
    let jwt_secret = std::env::var("TRACETRAMP_JWT_SECRET")
        .map_err(|_| AppError::Unauthorized("JWT secret not configured".to_string()))?;
    if jwt_secret.trim().is_empty() {
        return Err(AppError::Unauthorized("JWT secret not configured".to_string()));
    }
    let key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let decoded = decode::<Claims>(token, &key, &validation)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;
    let is_admin = decoded
        .claims
        .roles
        .iter()
        .any(|r| matches!(r.as_str(), "admin" | "super_admin" | "owner"));
    if !is_admin {
        return Err(AppError::Unauthorized(
            "Admin role required for management API".to_string(),
        ));
    }
    req.extensions_mut().insert(AuthContext {
        subject: decoded.claims.sub,
        tenant_id: Some(decoded.claims.tenant_id),
        is_admin: true,
    });
    Ok(next.run(req).await)
}

fn insecure_admin_bypass_enabled() -> bool {
    let dev_bypass = std::env::var("TRACETRAMP_DEV_BYPASS")
        .ok()
        .as_deref()
        == Some("1");
    let allow_insecure = std::env::var("TRACETRAMP_ALLOW_INSECURE_ADMIN")
        .ok()
        .as_deref()
        == Some("1");
    dev_bypass && allow_insecure
}

/// Require admin with optional tenant binding match.
///
/// Uses [`AuthContext`] from a prior `require_admin` pass when present; otherwise
/// runs the same admin authentication and checks `tenant_id` claim against the path.
pub async fn require_tenant_admin(
    tenant_id: String,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    if insecure_admin_bypass_enabled() {
        req.extensions_mut().insert(AuthContext {
            subject: "dev-bypass".to_string(),
            tenant_id: Some(tenant_id),
            is_admin: true,
        });
        return Ok(next.run(req).await);
    }

    if let Some(ctx) = req.extensions().get::<AuthContext>().cloned() {
        if !ctx.is_admin {
            return Err(AppError::Unauthorized(
                "Admin role required for tenant management API".to_string(),
            ));
        }
        if let Some(bound) = ctx.tenant_id.as_deref() {
            if !bound.is_empty() && bound != tenant_id {
                return Err(AppError::Unauthorized(format!(
                    "Token tenant_id ({bound}) does not match path tenant ({tenant_id})"
                )));
            }
        }
        return Ok(next.run(req).await);
    }

    // No prior context — authenticate as admin then bind.
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("Invalid Authorization header".to_string()))?
        .trim();
    if token.is_empty() {
        return Err(AppError::Unauthorized(
            "Authorization token is empty".to_string(),
        ));
    }

    if let Ok(admin_token) = std::env::var("TRACETRAMP_ADMIN_TOKEN") {
        if !admin_token.trim().is_empty() && token == admin_token {
            req.extensions_mut().insert(AuthContext {
                subject: "admin-token".to_string(),
                tenant_id: Some(tenant_id),
                is_admin: true,
            });
            return Ok(next.run(req).await);
        }
    }

    let validation = Validation::new(Algorithm::HS256);
    let jwt_secret = std::env::var("TRACETRAMP_JWT_SECRET")
        .map_err(|_| AppError::Unauthorized("JWT secret not configured".to_string()))?;
    let key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let decoded = decode::<Claims>(token, &key, &validation)
        .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;
    let is_admin = decoded
        .claims
        .roles
        .iter()
        .any(|r| matches!(r.as_str(), "admin" | "super_admin" | "owner" | "tenant_admin"));
    if !is_admin {
        return Err(AppError::Unauthorized(
            "Tenant admin role required".to_string(),
        ));
    }
    if !decoded.claims.tenant_id.is_empty() && decoded.claims.tenant_id != tenant_id {
        return Err(AppError::Unauthorized(format!(
            "Token tenant_id ({}) does not match path tenant ({tenant_id})",
            decoded.claims.tenant_id
        )));
    }
    req.extensions_mut().insert(AuthContext {
        subject: decoded.claims.sub,
        tenant_id: Some(decoded.claims.tenant_id),
        is_admin: true,
    });
    Ok(next.run(req).await)
}

/// Validate API key format
pub fn validate_api_key(key: &str) -> Result<(), AppError> {
    // API keys should be in format: cpk_live_xxx or cpk_test_xxx
    if !key.starts_with("cpk_") {
        return Err(AppError::Validation("Invalid API key format".to_string()));
    }
    
    let parts: Vec<&str> = key.split('_').collect();
    if parts.len() < 3 {
        return Err(AppError::Validation("Invalid API key format".to_string()));
    }
    
    if parts[1] != "live" && parts[1] != "test" {
        return Err(AppError::Validation("Invalid API key environment".to_string()));
    }
    
    Ok(())
}

/// Extract tenant ID from API key
pub fn extract_tenant_from_key(key: &str) -> Option<String> {
    // Format: cpk_live_abc123def456 -> prefix is cpk_live
    let prefix: String = key.split('_').take(2).collect::<Vec<_>>().join("_");
    
    // In production, lookup prefix in database
    // For now, return a mock mapping
    Some(format!("tenant_{}", prefix))
}
