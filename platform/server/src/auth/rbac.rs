//! REST + UI-RPC RBAC helpers (T7). Used by `router::auth_middleware` and `ui_rpc::dispatch`.

use super::{Claims, PlatformRole};

/// Map `/api/v1/<service>/…` + HTTP method → permission string (`agents:read`, `memory:write`, …).
pub fn path_to_permission(path_bare: &str, method: &str) -> String {
    let path_bare = path_bare.trim_start_matches('/');
    let service = path_bare.split('/').next().unwrap_or("");
    let action = if method == "GET" || method == "HEAD" {
        "read"
    } else {
        "write"
    };
    if service.is_empty() {
        String::new()
    } else {
        format!("{service}:{action}")
    }
}

/// True when JWT `permissions` satisfy `required` (includes `system:admin` and `{service}:write` fallback).
pub fn claims_has_permission(claims: &Claims, required: &str) -> bool {
    if required.is_empty() {
        return true;
    }
    if claims.permissions.iter().any(|p| p == "system:admin") {
        return true;
    }
    if claims.permissions.iter().any(|p| p == required) {
        return true;
    }
    if let Some(service) = required.split(':').next() {
        let write = format!("{service}:write");
        if required.ends_with(":read") && claims.permissions.iter().any(|p| p == &write) {
            return true;
        }
    }
    false
}

/// Minimum role rank for sensitive REST paths (path without `/api/v1` prefix).
fn min_rank_for_sensitive_path(path_bare: &str, method: &str) -> Option<u8> {
    let p = path_bare.trim_start_matches('/');
    if p.starts_with("settings/secrets") {
        return Some(PlatformRole::Admin.rank());
    }
    if p.starts_with("settings/networking") {
        if method == "GET" || method == "HEAD" {
            return Some(PlatformRole::Operator.rank());
        }
        return Some(PlatformRole::Admin.rank());
    }
    if p.starts_with("plugins/cpkg") || p.contains("/cpkg/") {
        return Some(PlatformRole::Admin.rank());
    }
    if p == "devguard/connect" && (method == "POST") {
        return Some(PlatformRole::Operator.rank());
    }
    if p == "workflows/catalog/sync" || p.ends_with("/catalog/sync") {
        if method != "GET" && method != "HEAD" {
            return Some(PlatformRole::Admin.rank());
        }
    }
    if p.starts_with("auth/users") || p == "users" || p.starts_with("users/") {
        if method != "GET" && method != "HEAD" {
            return Some(PlatformRole::Admin.rank());
        }
        return Some(PlatformRole::Admin.rank());
    }
    if p.starts_with("runtime/") && method != "GET" && method != "HEAD" {
        return Some(PlatformRole::Admin.rank());
    }
    if p.starts_with("kernel/") && method != "GET" && method != "HEAD" {
        return Some(PlatformRole::Operator.rank());
    }
    if p.starts_with("agents") && method != "GET" && method != "HEAD" {
        return Some(PlatformRole::Operator.rank());
    }
    None
}

fn is_playground_token(claims: &Claims) -> bool {
    claims.token_type == "playground_key" || claims.sub.starts_with("pg_")
}

fn playground_path_denied(path_bare: &str, method: &str) -> Option<&'static str> {
    let p = path_bare.trim_start_matches('/');
    let write = method != "GET" && method != "HEAD";
    if p.starts_with("settings/secrets") {
        return Some("read or write the vault");
    }
    if p.starts_with("auth/users") || p == "users" || p.starts_with("users/") {
        return Some("manage users");
    }
    if write && p.starts_with("settings/networking") {
        return Some("change DNS / networking");
    }
    if p.starts_with("plugins/cpkg") || p.contains("/cpkg/") {
        return Some("install packages");
    }
    if write && p.starts_with("runtime/") {
        return Some("change runtime mode");
    }
    if write && p.starts_with("kernel/") {
        return Some("change kernel policy");
    }
    None
}

/// Dashboard self-service reads any authenticated JWT may call.
fn is_self_service_read(path_bare: &str, method: &str) -> bool {
    if method != "GET" && method != "HEAD" {
        return false;
    }
    let p = path_bare.trim_start_matches('/');
    matches!(
        p,
        "auth/me"
            | "apps"
            | "plugins/status"
            | "plugins/cage-proof"
            | "health"
            | "boot/progress"
    ) || p.starts_with("apps/")
        || p == "apps/parity"
        || p == "playground/status"
        || p == "playground/session"
        || p.starts_with("playground/session/")
        || p.starts_with("plugins/tracetramp/status")
        || p.starts_with("plugins/witnessctl/status")
        || p.starts_with("plugins/devguard/status")
        || p == "devguard/connect/info"
        || p == "workflows/reference-templates"
        || p.starts_with("billing/")
        || p.starts_with("runtime/")
        || p.starts_with("settings/llms")
}

/// Enforce RBAC for a verified JWT on REST. Returns denial reason when forbidden.
pub fn enforce_rest_access(claims: &Claims, path_bare: &str, method: &str) -> Option<String> {
    if is_self_service_read(path_bare, method) {
        return None;
    }
    // Hosted trial JWTs are role=developer with scopes `read`/`write` only.
    // Rank gates then block Talk (agents POST needs operator) and permission
    // checks block list/create (`agents:read`, `intelligence:write`). Allow
    // the trial surface; keep admin/vault/user paths denied.
    if is_playground_token(claims) {
        if let Some(why) = playground_path_denied(path_bare, method) {
            return Some(format!("playground cannot {why}"));
        }
        return None;
    }

    let role = PlatformRole::from_str(&claims.role);

    if let Some(min_rank) = min_rank_for_sensitive_path(path_bare, method) {
        if role.rank() < min_rank {
            return Some(format!(
                "role {} insufficient for {} {} (requires rank >= {min_rank})",
                role.to_str(),
                method,
                path_bare
            ));
        }
        return None;
    }

    let required = path_to_permission(path_bare, method);
    if !claims_has_permission(claims, &required) {
        return Some(format!(
            "missing permission {required} (role {})",
            role.to_str()
        ));
    }
    None
}

/// `cpk_*` API keys: scopes are permission strings (`agents:read`, `system:admin`, …).
pub fn api_key_scopes_allow(scopes: &[String], path_bare: &str, method: &str) -> bool {
    if scopes.iter().any(|s| s == "system:admin" || s == "*" || s == "admin") {
        return true;
    }
    let required = path_to_permission(path_bare, method);
    if scopes.iter().any(|p| p == &required) {
        return true;
    }
    if let Some(service) = required.split(':').next() {
        let write = format!("{service}:write");
        if required.ends_with(":read") && scopes.iter().any(|p| p == &write) {
            return true;
        }
    }
    false
}

/// UI-RPC method allow-list by role rank.
pub fn rpc_method_allowed(session_role: PlatformRole, method: &str, is_dev: bool) -> bool {
    if is_dev {
        return true;
    }
    let rank = session_role.rank();
    match method {
        "system.ping" | "system.boot_progress" | "health.status" | "metrics.summary" => true,
        "system.dns" | "audit.recent" => rank >= PlatformRole::Admin.rank(),
        "agents.list" | "agents.get" => rank >= PlatformRole::Operator.rank(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims_with(perms: Vec<&str>) -> Claims {
        Claims {
            sub: "u1".into(),
            email: "u@x.com".into(),
            role: "operator".into(),
            permissions: perms.into_iter().map(String::from).collect(),
            instance_id: None,
            tenant_id: None,
            token_type: "access".into(),
            jti: "j".into(),
            iat: 0,
            exp: 9_999_999,
        }
    }

    #[test]
    fn viewer_denied_agents_write() {
        let mut c = claims_with(vec!["agents:read", "health:read"]);
        c.role = "viewer".into();
        assert!(enforce_rest_access(&c, "agents", "POST").is_some());
    }

    #[test]
    fn admin_passes_secrets_path() {
        let mut c = claims_with(vec![]);
        c.role = PlatformRole::Admin.to_str().to_string();
        c.permissions = PlatformRole::Admin.permissions();
        assert!(enforce_rest_access(&c, "settings/secrets", "GET").is_none());
    }

    #[test]
    fn rpc_dns_requires_admin() {
        assert!(!rpc_method_allowed(PlatformRole::Operator, "system.dns", false));
        assert!(rpc_method_allowed(PlatformRole::Admin, "system.dns", false));
    }

    #[test]
    fn operator_reads_plugins_admin_proxy() {
        let mut c = claims_with(vec![]);
        c.role = PlatformRole::Operator.to_str().to_string();
        c.permissions = PlatformRole::Operator.permissions();
        assert!(enforce_rest_access(&c, "plugins/tracetramp/admin/stats", "GET").is_none());
    }

    #[test]
    fn viewer_cannot_post_agents() {
        let mut c = claims_with(vec![]);
        c.role = PlatformRole::Viewer.to_str().to_string();
        c.permissions = PlatformRole::Viewer.permissions();
        assert!(enforce_rest_access(&c, "agents", "POST").is_some());
    }

    #[test]
    fn api_key_admin_scope_allows_write() {
        assert!(api_key_scopes_allow(
            &["system:admin".to_string()],
            "agents",
            "POST"
        ));
    }

    #[test]
    fn api_key_read_scope_denies_post() {
        assert!(!api_key_scopes_allow(
            &["agents:read".to_string()],
            "agents",
            "POST"
        ));
    }

    #[test]
    fn playground_token_can_talk_and_create() {
        let mut c = claims_with(vec!["read", "write"]);
        c.role = "developer".into();
        c.token_type = "playground_key".into();
        c.sub = "pg_abc".into();
        assert!(enforce_rest_access(&c, "agents", "GET").is_none());
        assert!(enforce_rest_access(&c, "agents/agent_1/completions", "POST").is_none());
        assert!(enforce_rest_access(&c, "intelligence/apply", "POST").is_none());
        assert!(enforce_rest_access(&c, "settings/llms/link", "POST").is_none());
        assert!(enforce_rest_access(&c, "agents/agent_1", "DELETE").is_none());
        assert!(enforce_rest_access(&c, "settings/secrets", "GET").is_some());
    }

    #[test]
    fn operator_reads_custom_domains() {
        let mut c = claims_with(vec![]);
        c.role = PlatformRole::Operator.to_str().to_string();
        c.permissions = PlatformRole::Operator.permissions();
        assert!(
            enforce_rest_access(&c, "settings/networking/custom-domains", "GET").is_none()
        );
    }
}
