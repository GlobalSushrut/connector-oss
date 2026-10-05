//! Verified principal context produced by authentication.

use serde::{Deserialize, Serialize};

/// Verified identity and authority snapshot for a request.
///
/// Produced by authentication; consumed by tenant middleware, admission,
/// and workflow proxies. Never construct from unverified headers alone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrincipalContextV2 {
    /// Subject identifier (user id, service account id, workload id).
    pub subject: String,
    /// Email when available (humans); empty for machine principals.
    #[serde(default)]
    pub email: String,
    /// Platform role string (e.g. `admin`, `developer`, `service`).
    pub role: String,
    /// Effective permission strings.
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Registry-bound tenant when present. Absence means no verified tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Token / credential unique id (for revocation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Credential kind: `access` | `refresh` | `api_key` | `workload` | `synthetic`.
    #[serde(default = "default_token_type")]
    pub token_type: String,
    /// Optional instance / node binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    /// How this principal was established.
    pub auth_source: AuthSourceV2,
    /// Contract version (always 2 for this type).
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn default_token_type() -> String {
    "access".into()
}

fn trust_v2() -> u32 {
    2
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthSourceV2 {
    Jwt,
    ApiKey,
    Workload,
    /// Open-auth / lab synthetic principal — visibly non-production.
    Synthetic,
    /// Compatibility bridge while legacy paths migrate.
    Legacy,
}

impl PrincipalContextV2 {
    /// Build from JWT-like claim fields already verified by the platform.
    pub fn from_verified_claims(
        subject: impl Into<String>,
        email: impl Into<String>,
        role: impl Into<String>,
        permissions: Vec<String>,
        tenant_id: Option<String>,
        jti: Option<String>,
        token_type: impl Into<String>,
        instance_id: Option<String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            email: email.into(),
            role: role.into(),
            permissions,
            tenant_id,
            jti,
            token_type: token_type.into(),
            instance_id,
            auth_source: AuthSourceV2::Jwt,
            contract_version: 2,
        }
    }

    /// Whether this principal carries a non-empty verified tenant binding.
    pub fn has_verified_tenant(&self) -> bool {
        self.tenant_id
            .as_ref()
            .map(|t| !t.trim().is_empty())
            .unwrap_or(false)
    }

    /// Reject when a caller-supplied tenant header disagrees with the binding.
    pub fn tenant_header_mismatch(&self, header_tenant: &str) -> bool {
        match self.tenant_id.as_deref() {
            Some(bound) if !bound.is_empty() => bound != header_tenant,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mismatch_when_bound_tenant_differs() {
        let p = PrincipalContextV2::from_verified_claims(
            "u1",
            "a@b.c",
            "admin",
            vec![],
            Some("acme".into()),
            Some("jti".into()),
            "access",
            None,
        );
        assert!(p.tenant_header_mismatch("other"));
        assert!(!p.tenant_header_mismatch("acme"));
    }
}
