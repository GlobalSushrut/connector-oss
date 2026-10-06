//! Tenancy isolation static audit (production plan Phase 2).

const STORAGE: &str = include_str!("../src/storage.rs");
const TENANCY: &str = include_str!("../src/tenancy.rs");
const CONTROL: &str = include_str!("../src/control.rs");
const GATEWAY: &str = include_str!("../src/gateway.rs");
const ADMIN: &str = include_str!("../src/admin.rs");

#[test]
fn claim_tenant_redis_keys_scoped() {
    assert!(
        STORAGE.contains("tenancy::tenant_redis_config_key"),
        "storage must use tenancy helper for redis keys"
    );
    assert!(
        TENANCY.contains("tenant:config:"),
        "tenancy module documents tenant-scoped redis prefix"
    );
}

#[test]
fn claim_approval_queue_uses_postgres_tenant() {
    assert!(
        CONTROL.contains("INSERT INTO approval_queue") && CONTROL.contains("tenant_id"),
        "HITL approvals must persist tenant_id in postgres"
    );
}

#[test]
fn claim_cage_validates_tenant_address() {
    assert!(
        GATEWAY.contains("validate_cage_sha_address"),
        "cage route must validate tenant address before proxy"
    );
}

#[test]
fn claim_gateway_validates_tenant_after_resolve() {
    assert!(
        GATEWAY.contains("tenancy::validate_tenant_id"),
        "chat flow must validate tenant_id after resolver"
    );
}

#[test]
fn claim_admin_tenant_crud() {
    assert!(
        ADMIN.contains("/admin/tenants") && ADMIN.contains("INSERT INTO tenants"),
        "management plane must have explicit tenant records"
    );
}
