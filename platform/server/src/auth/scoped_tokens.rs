//! Scoped API Tokens — Fine-grained access control for API keys
//!
//! Supports:
//! - Resource scoping (agents, memory, tools, audit)
//! - Action scoping (read, write, delete, admin)
//! - Namespace scoping (limit to specific namespaces)
//! - Time-based expiration
//! - Rate limiting per token

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Scoped API token with fine-grained permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedToken {
    /// Unique token ID
    pub token_id: String,
    
    /// Human-readable name
    pub name: String,
    
    /// Token prefix (first 8 chars for identification)
    pub prefix: String,
    
    /// Hashed token value (never store plaintext)
    #[serde(skip_serializing)]
    pub token_hash: String,
    
    /// Tenant ID this token belongs to
    pub tenant_id: String,
    
    /// User/service that created this token
    pub created_by: String,
    
    /// Creation timestamp (ISO 8601)
    pub created_at: String,
    
    /// Expiration timestamp (ISO 8601), None = never expires
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    
    /// Last used timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    
    /// Token scopes
    pub scopes: TokenScopes,
    
    /// Rate limit (requests per minute), None = unlimited
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_rpm: Option<u32>,
    
    /// Whether this token is active
    pub active: bool,
}

/// Token permission scopes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenScopes {
    /// Resource permissions
    pub resources: ResourceScopes,
    
    /// Namespace restrictions (empty = all namespaces)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<String>,
    
    /// Agent restrictions (empty = all agents)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
}

/// Resource-level permissions
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceScopes {
    /// Agent permissions
    #[serde(default)]
    pub agents: ActionScope,
    
    /// Memory permissions
    #[serde(default)]
    pub memory: ActionScope,
    
    /// Session permissions
    #[serde(default)]
    pub sessions: ActionScope,
    
    /// Tool permissions
    #[serde(default)]
    pub tools: ActionScope,
    
    /// Audit permissions
    #[serde(default)]
    pub audit: ActionScope,
    
    /// Compliance permissions
    #[serde(default)]
    pub compliance: ActionScope,
    
    /// Admin permissions (settings, users, etc.)
    #[serde(default)]
    pub admin: ActionScope,
}

/// Action-level permissions for a resource
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActionScope {
    /// Can read/list resources
    #[serde(default)]
    pub read: bool,
    
    /// Can create/update resources
    #[serde(default)]
    pub write: bool,
    
    /// Can delete resources
    #[serde(default)]
    pub delete: bool,
}

impl ActionScope {
    pub fn none() -> Self {
        Self { read: false, write: false, delete: false }
    }
    
    pub fn read_only() -> Self {
        Self { read: true, write: false, delete: false }
    }
    
    pub fn read_write() -> Self {
        Self { read: true, write: true, delete: false }
    }
    
    pub fn full() -> Self {
        Self { read: true, write: true, delete: true }
    }
}

impl TokenScopes {
    /// Create a read-only scope for all resources
    pub fn read_only() -> Self {
        Self {
            resources: ResourceScopes {
                agents: ActionScope::read_only(),
                memory: ActionScope::read_only(),
                sessions: ActionScope::read_only(),
                tools: ActionScope::read_only(),
                audit: ActionScope::read_only(),
                compliance: ActionScope::read_only(),
                admin: ActionScope::none(),
            },
            namespaces: vec![],
            agents: vec![],
        }
    }
    
    /// Create a full-access scope (admin)
    pub fn admin() -> Self {
        Self {
            resources: ResourceScopes {
                agents: ActionScope::full(),
                memory: ActionScope::full(),
                sessions: ActionScope::full(),
                tools: ActionScope::full(),
                audit: ActionScope::full(),
                compliance: ActionScope::full(),
                admin: ActionScope::full(),
            },
            namespaces: vec![],
            agents: vec![],
        }
    }
    
    /// Create agent-only scope
    pub fn agent_only(agent_ids: Vec<String>) -> Self {
        Self {
            resources: ResourceScopes {
                agents: ActionScope::read_write(),
                memory: ActionScope::read_write(),
                sessions: ActionScope::read_write(),
                tools: ActionScope::read_only(),
                audit: ActionScope::read_only(),
                compliance: ActionScope::none(),
                admin: ActionScope::none(),
            },
            namespaces: vec![],
            agents: agent_ids,
        }
    }
}

/// Request to create a new scoped token
#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    #[serde(default)]
    pub scopes: Option<TokenScopes>,
    /// Expiration in seconds from now
    #[serde(default)]
    pub expires_in_seconds: Option<u64>,
    #[serde(default)]
    pub rate_limit_rpm: Option<u32>,
}

/// Response when creating a token (includes plaintext token once)
#[derive(Debug, Serialize)]
pub struct CreateTokenResponse {
    pub token_id: String,
    pub name: String,
    pub prefix: String,
    /// The actual token value - only shown once!
    pub token: String,
    pub scopes: TokenScopes,
    pub expires_at: Option<String>,
    pub created_at: String,
}

/// Check if a token has permission for an action
pub fn check_permission(
    scopes: &TokenScopes,
    resource: &str,
    action: &str,
    namespace: Option<&str>,
    agent_id: Option<&str>,
) -> bool {
    // Check namespace restriction
    if !scopes.namespaces.is_empty() {
        if let Some(ns) = namespace {
            if !scopes.namespaces.iter().any(|allowed| ns.starts_with(allowed)) {
                return false;
            }
        }
    }
    
    // Check agent restriction
    if !scopes.agents.is_empty() {
        if let Some(aid) = agent_id {
            if !scopes.agents.contains(&aid.to_string()) {
                return false;
            }
        }
    }
    
    // Check resource/action permission
    let action_scope = match resource {
        "agents" => &scopes.resources.agents,
        "memory" => &scopes.resources.memory,
        "sessions" => &scopes.resources.sessions,
        "tools" => &scopes.resources.tools,
        "audit" => &scopes.resources.audit,
        "compliance" => &scopes.resources.compliance,
        "admin" => &scopes.resources.admin,
        _ => return false,
    };
    
    match action {
        "read" | "list" | "get" => action_scope.read,
        "write" | "create" | "update" | "invoke" => action_scope.write,
        "delete" | "revoke" | "terminate" => action_scope.delete,
        _ => false,
    }
}

/// Generate a new API token
pub fn generate_token() -> (String, String) {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    
    // Generate a random-ish token (in production, use proper crypto)
    let random_part = format!("{:x}{:x}", now.as_nanos(), now.as_secs() ^ 0xDEADBEEF);
    let token = format!("cnt_{}", &random_part[..32.min(random_part.len())]);
    let prefix = token[..12.min(token.len())].to_string();
    
    (token, prefix)
}

/// Hash a token for storage
pub fn hash_token(token: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    token.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_read_only_scope() {
        let scopes = TokenScopes::read_only();
        
        assert!(check_permission(&scopes, "agents", "read", None, None));
        assert!(check_permission(&scopes, "memory", "list", None, None));
        assert!(!check_permission(&scopes, "agents", "write", None, None));
        assert!(!check_permission(&scopes, "memory", "delete", None, None));
        assert!(!check_permission(&scopes, "admin", "read", None, None));
    }
    
    #[test]
    fn test_admin_scope() {
        let scopes = TokenScopes::admin();
        
        assert!(check_permission(&scopes, "agents", "read", None, None));
        assert!(check_permission(&scopes, "agents", "write", None, None));
        assert!(check_permission(&scopes, "agents", "delete", None, None));
        assert!(check_permission(&scopes, "admin", "write", None, None));
    }
    
    #[test]
    fn test_namespace_restriction() {
        let mut scopes = TokenScopes::admin();
        scopes.namespaces = vec!["/m/allowed/".to_string()];
        
        assert!(check_permission(&scopes, "memory", "read", Some("/m/allowed/data"), None));
        assert!(!check_permission(&scopes, "memory", "read", Some("/m/other/data"), None));
    }
    
    #[test]
    fn test_agent_restriction() {
        let scopes = TokenScopes::agent_only(vec!["agent-001".to_string()]);
        
        assert!(check_permission(&scopes, "agents", "read", None, Some("agent-001")));
        assert!(!check_permission(&scopes, "agents", "read", None, Some("agent-002")));
    }
    
    #[test]
    fn test_token_generation() {
        let (token, prefix) = generate_token();
        
        assert!(token.starts_with("cnt_"));
        assert!(prefix.starts_with("cnt_"));
        assert!(token.len() > prefix.len());
    }
}
