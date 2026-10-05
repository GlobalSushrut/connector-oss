//! Scoped capability grants bound to principal, tenant, action, and resource.

use serde::{Deserialize, Serialize};

/// Short-lived, scoped capability grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityGrantV2 {
    pub grant_id: String,
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    /// Action identifier (e.g. `memory:write`, `plugin:invoke`).
    pub action: String,
    /// Resource locator / namespace / plugin id.
    pub resource: String,
    /// Intended audience (node id, service name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Unix epoch seconds expiry.
    pub expires_at: i64,
    /// Policy revision this grant was minted against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default = "trust_v2")]
    pub contract_version: u32,
}

fn trust_v2() -> u32 {
    2
}

impl CapabilityGrantV2 {
    pub fn is_active_at(&self, now_epoch_secs: i64) -> bool {
        !self.revoked && now_epoch_secs < self.expires_at
    }

    pub fn covers(&self, action: &str, resource: &str) -> bool {
        self.action == action && (self.resource == "*" || self.resource == resource)
    }
}
