//! Cage principal binding, scoped upstream caps, and isolation grade gates (T6 top-grade).

use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

use crate::{
    auth::{self, Claims, PlatformRole},
    services::{
        plugin_matrix,
        runtime_control::{self, IsolationRuntime},
    },
    state::PlatformState,
};

type HmacSha256 = Hmac<Sha256>;

pub const CAGE_CAP_HEADER: &str = "x-connector-cage-cap";
pub const CAGE_BINDING_HEADER: &str = "x-connector-cage-binding";

fn cage_hmac_secret() -> Vec<u8> {
    if let Ok(s) = std::env::var("CONNECTOR_CAGE_CAP_SECRET") {
        let t = s.trim();
        if !t.is_empty() {
            return t.as_bytes().to_vec();
        }
    }
    if prodish_isolation_enforced() {
        tracing::error!(
            "CONNECTOR_CAGE_CAP_SECRET missing under production/defense-strict — using reject marker"
        );
        return b"connector-cage-cap-MISSING-PROD-SECRET".to_vec();
    }
    std::env::var("CONNECTOR_CFNI_SECRET")
        .or_else(|_| std::env::var("CONNECTOR_JWT_SECRET"))
        .unwrap_or_else(|_| "connector-cage-cap-dev-only".into())
        .into_bytes()
}

fn cage_cap_ttl_secs() -> u64 {
    std::env::var("CONNECTOR_CAGE_CAP_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120)
}

/// Production / pilots / defense-strict isolation posture.
pub fn prodish_isolation_enforced() -> bool {
    matches!(
        std::env::var("CONNECTOR_ENV")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "production" | "prod" | "staging" | "pilots" | "pilot"
    ) || runtime_control::defense_strict_enabled()
}

/// Subprocess / internal isolation only when explicitly allowed outside prodish modes.
pub fn subprocess_isolation_allowed() -> bool {
    if !prodish_isolation_enforced() {
        return true;
    }
    runtime_control::env_flag_true("CONNECTOR_ALLOW_SUBPROCESS_ISOLATION")
}

/// Declared runtime must meet top-grade bar (microvm or docker_lab in prodish).
pub fn assert_isolation_runtime_grade(runtime: IsolationRuntime) -> Result<(), &'static str> {
    if !prodish_isolation_enforced() {
        return Ok(());
    }
    match runtime {
        IsolationRuntime::Microvm | IsolationRuntime::DockerLab | IsolationRuntime::Wasm => Ok(()),
        IsolationRuntime::Subprocess | IsolationRuntime::Internal => {
            if subprocess_isolation_allowed() {
                Ok(())
            } else {
                Err("subprocess_isolation_denied_in_production")
            }
        }
    }
}

/// Effective CONNECTOR_ISOLATION_RUNTIME env must match declared grade.
pub fn isolation_downgrade_active(declared: IsolationRuntime) -> bool {
    let effective = std::env::var("CONNECTOR_ISOLATION_RUNTIME").unwrap_or_default();
    let effective = effective.trim().to_ascii_lowercase();
    match declared {
        IsolationRuntime::Microvm => {
            !effective.contains("microvm") && !effective.contains("firecracker")
        }
        IsolationRuntime::DockerLab => !effective.contains("docker"),
        IsolationRuntime::Wasm => !effective.contains("wasm"),
        IsolationRuntime::Subprocess | IsolationRuntime::Internal => false,
    }
}

pub fn assert_cage_isolation_grade(state: &PlatformState) -> Result<(), &'static str> {
    let declared = *state.isolation_runtime.read().unwrap();
    assert_isolation_runtime_grade(declared)?;
    if prodish_isolation_enforced() && isolation_downgrade_active(declared) {
        return Err("isolation_downgrade_active");
    }
    if prodish_isolation_enforced()
        && runtime_control::env_flag_true("CONNECTOR_ALLOW_ISOLATION_DOWNGRADE")
    {
        return Err("isolation_downgrade_flag_set_in_production");
    }
    Ok(())
}

/// Principal may reach cage for `slug` — cryptographically bound, not hostname alone.
pub fn principal_may_access_cage(claims: &Claims, slug: &str, method: &Method) -> bool {
    let slug = slug.trim().to_ascii_lowercase();
    if !plugin_matrix::is_gated_plugin_segment(&slug) {
        return false;
    }
    if !plugin_matrix::is_plugin_enabled(&slug) {
        return false;
    }

    let role = PlatformRole::from_str(&claims.role);
    if role.rank() >= PlatformRole::Operator.rank() {
        return true;
    }

    let cap_wild = "plugin:cage:*";
    let cap_slug = format!("plugin:cage:{slug}");
    if claims
        .permissions
        .iter()
        .any(|p| p == cap_wild || p == &cap_slug)
    {
        return true;
    }

    if role.rank() >= PlatformRole::Developer.rank()
        && matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
    {
        return true;
    }

    false
}

/// Verify auth + plugin scope before cage forward.
pub fn assert_cage_principal_binding(
    headers: &HeaderMap,
    slug: &str,
    method: &Method,
) -> Result<Claims, Response> {
    if runtime_control::dev_auth_bypass_allowed() {
        return Ok(auth::Claims {
            sub: "dev".into(),
            email: "dev@local".into(),
            role: PlatformRole::SuperAdmin.to_str().into(),
            permissions: vec!["plugin:cage:*".into()],
            instance_id: None,
            tenant_id: None,
            token_type: "dev_bypass".into(),
            jti: "dev".into(),
            iat: 0,
            exp: usize::MAX,
        });
    }
    let Some(claims) = auth::extract_claims(headers) else {
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
    if !principal_may_access_cage(&claims, slug, method) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "error": "cage_principal_binding_denied",
                "message": format!(
                    "Principal '{}' is not authorized for plugin cage '{}'",
                    claims.sub, slug
                ),
                "required_capability": format!("plugin:cage:{slug}"),
                "cage_routing_key": crate::internal_dns::cage_routing_key(slug),
            })),
        )
            .into_response());
    }
    Ok(claims)
}

fn sign_payload(payload: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(&cage_hmac_secret()).expect("cage cap hmac key length");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Short-lived scoped cap proving platform authorized this upstream hop.
pub fn mint_cage_cap(
    principal_id: &str,
    tenant_id: Option<&str>,
    slug: &str,
    method: &str,
    path_tail: &str,
) -> String {
    let exp = chrono::Utc::now().timestamp() + cage_cap_ttl_secs() as i64;
    let routing_key = crate::internal_dns::cage_routing_key(slug);
    let payload = format!(
        "v1|{principal_id}|{}|{slug}|{routing_key}|{method}|{path_tail}|{exp}",
        tenant_id.unwrap_or("")
    );
    let sig = sign_payload(&payload);
    let enc = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
    format!("v1.{exp}.{enc}.{sig}")
}

fn cage_binding_digest(principal_id: &str, tenant_id: Option<&str>, slug: &str) -> String {
    let routing_key = crate::internal_dns::cage_routing_key(slug);
    let payload = format!(
        "bind|{principal_id}|{}|{slug}|{routing_key}",
        tenant_id.unwrap_or("")
    );
    sign_payload(&payload)
}

/// Stamp cage-cap + routing binding on upstream reqwest builder.
pub fn stamp_cage_upstream(
    rb: reqwest::RequestBuilder,
    claims: &Claims,
    slug: &str,
    method: &str,
    path_tail: &str,
) -> reqwest::RequestBuilder {
    let cap = mint_cage_cap(
        &claims.sub,
        claims.tenant_id.as_deref(),
        slug,
        method,
        path_tail,
    );
    let binding = cage_binding_digest(&claims.sub, claims.tenant_id.as_deref(), slug);
    rb.header(CAGE_CAP_HEADER, cap)
        .header(CAGE_BINDING_HEADER, binding)
}

pub fn cage_security_status(state: &PlatformState) -> serde_json::Value {
    let declared = *state.isolation_runtime.read().unwrap();
    let grade_ok = assert_cage_isolation_grade(state).is_ok()
        && assert_isolation_runtime_grade(declared).is_ok();
    json!({
        "schema": "cage_security_status.v1",
        "prodish_enforced": prodish_isolation_enforced(),
        "declared_isolation": declared.as_str(),
        "isolation_grade_ok": grade_ok,
        "downgrade_active": isolation_downgrade_active(declared),
        "subprocess_allowed": subprocess_isolation_allowed(),
        "cage_cap_ttl_secs": cage_cap_ttl_secs(),
        "principal_binding": "plugin:cage:<slug> capability or Operator+ role",
        "routing_key_bound": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operator_claims() -> Claims {
        Claims {
            sub: "u1".into(),
            email: "o@x.com".into(),
            role: PlatformRole::Operator.to_str().into(),
            permissions: vec![],
            instance_id: None,
            tenant_id: Some("t1".into()),
            token_type: "access".into(),
            jti: "j1".into(),
            iat: 0,
            exp: usize::MAX,
        }
    }

    #[test]
    fn operator_may_access_enabled_plugin() {
        std::env::remove_var("CONNECTOR_PLUGINS_ENABLED");
        let c = operator_claims();
        assert!(principal_may_access_cage(&c, "tracetramp", &Method::POST));
    }

    #[test]
    fn viewer_denied_mutating_cage() {
        let c = Claims {
            role: PlatformRole::Viewer.to_str().into(),
            ..operator_claims()
        };
        assert!(!principal_may_access_cage(&c, "tracetramp", &Method::POST));
    }

    #[test]
    fn scoped_cap_allows_viewer_with_plugin_cage_slug() {
        let c = Claims {
            role: PlatformRole::Viewer.to_str().into(),
            permissions: vec!["plugin:cage:tracetramp".into()],
            ..operator_claims()
        };
        assert!(principal_may_access_cage(&c, "tracetramp", &Method::GET));
        assert!(principal_may_access_cage(&c, "tracetramp", &Method::POST));
    }

    #[test]
    fn subprocess_denied_in_production_env() {
        std::env::set_var("CONNECTOR_ENV", "production");
        std::env::remove_var("CONNECTOR_ALLOW_SUBPROCESS_ISOLATION");
        assert!(assert_isolation_runtime_grade(IsolationRuntime::Subprocess).is_err());
        std::env::remove_var("CONNECTOR_ENV");
    }

    #[test]
    fn cage_cap_round_trip_format() {
        let cap = mint_cage_cap("u1", Some("t1"), "tracetramp", "GET", "/admin/stats");
        assert!(cap.starts_with("v1."));
        let parts: Vec<_> = cap.split('.').collect();
        assert_eq!(parts.len(), 4);
    }
}
