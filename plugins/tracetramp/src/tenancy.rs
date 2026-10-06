//! Tenancy isolation helpers — cache keys, validation, audit contracts.

use crate::error::AppError;

/// Redis key for per-tenant config (must include tenant id; no shared global config key).
pub fn tenant_redis_config_key(tenant_id: &str) -> String {
    format!("tenant:config:{}", tenant_id.trim())
}

/// Approval queue keys are global but items carry tenant_id in Postgres `approval_queue`.
pub fn tenant_scoped_label(tenant_id: &str) -> &str {
    if tenant_id.trim().is_empty() {
        "unknown-tenant"
    } else {
        tenant_id.trim()
    }
}

/// Reject empty or whitespace tenant identifiers on control-plane paths.
pub fn validate_tenant_id(tenant_id: &str) -> Result<(), AppError> {
    let t = tenant_id.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("unknown") {
        return Err(AppError::Validation(
            "tenant_id is required for tenancy isolation".to_string(),
        ));
    }
    if t.len() > 256 {
        return Err(AppError::Validation("tenant_id too long".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redis_keys_are_tenant_scoped() {
        let k1 = tenant_redis_config_key("tenant-a");
        let k2 = tenant_redis_config_key("tenant-b");
        assert!(k1.contains("tenant-a"));
        assert!(k2.contains("tenant-b"));
        assert_ne!(k1, k2);
    }

    #[test]
    fn rejects_empty_tenant() {
        assert!(validate_tenant_id("").is_err());
        assert!(validate_tenant_id("   ").is_err());
    }
}
