//! Tenant authority lifecycle — roots, grant refs, revisions, tombstones.
//!
//! WorldGrant / CapabilityGrantV2 remain the legacy effect substrates.
//! These types add issuer lineage, monotonic revision, and revoke-before-delete
//! tombstones so native envelopes/receipts stop hardcoding `authority_revision: 1`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AUTHORITY_SCHEMA: &str = "connector.authority.v1";
pub const GRANT_REF_SCHEMA: &str = "connector.grant_ref.v1";
pub const TOMBSTONE_SCHEMA: &str = "connector.authority_tombstone.v1";
pub const REVISION_SCHEMA: &str = "connector.authority_revision.v1";

/// Signed-or-kernel authority root for a tenant partition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityRoot {
    pub schema: String,
    pub root_id: String,
    pub tenant_id: String,
    /// Issuer identity (`kernel`, DID, SPIFFE ID, …) — not a grant.
    pub issuer: String,
    pub created_at_ms: i64,
    /// Monotonic authority revision for this tenant.
    pub current_revision: u64,
}

/// Unforgeable-by-convention grant handle with optional parent attenuation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantRef {
    pub schema: String,
    pub grant_id: String,
    pub tenant_id: String,
    pub principal_id: String,
    /// Resource / world address / capability target.
    pub resource: String,
    /// Allowed actions / CNP capabilities (empty = inherit catalog).
    #[serde(default)]
    pub actions: Vec<String>,
    /// allow | ask | block
    pub effect: String,
    /// root | cone | app
    pub layer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_grant_id: Option<String>,
    /// Digest proving child ⊆ parent when attenuated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attenuation_digest: Option<String>,
    /// Dual-write key into legacy `iia_world_grants_v1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_world_grant_key: Option<String>,
    pub minted_at_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
    #[serde(default)]
    pub revoked: bool,
    pub minted_at_ms: i64,
}

/// Append-only revision event for a tenant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityRevisionRecord {
    pub schema: String,
    pub tenant_id: String,
    pub revision: u64,
    /// `root_create` | `mint` | `revoke` | `delegate`
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    pub at_ms: i64,
}

/// Revocation tombstone — must exist before legacy grant delete is acknowledged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationTombstone {
    pub schema: String,
    pub grant_id: String,
    pub tenant_id: String,
    pub revoked_at_revision: u64,
    pub reason: String,
    pub at_ms: i64,
}

impl AuthorityRoot {
    pub fn new(tenant_id: &str, issuer: &str, now_ms: i64) -> Self {
        let tenant = tenant_id.trim();
        let tenant = if tenant.is_empty() { "default" } else { tenant };
        Self {
            schema: AUTHORITY_SCHEMA.into(),
            root_id: format!("aroot_{tenant}"),
            tenant_id: tenant.into(),
            issuer: issuer.into(),
            created_at_ms: now_ms,
            current_revision: 0,
        }
    }
}

impl GrantRef {
    pub fn is_active_at(&self, now_ms: i64) -> bool {
        if self.revoked {
            return false;
        }
        match self.expires_at_ms {
            Some(exp) => now_ms < exp,
            None => true,
        }
    }

    /// Effect rank: block < ask < allow (higher = more permissive).
    pub fn effect_rank(effect: &str) -> u8 {
        match effect.trim().to_ascii_lowercase().as_str() {
            "allow" => 2,
            "ask" => 1,
            _ => 0,
        }
    }
}

/// True when `child` is a valid attenuation of `parent` (subset authority).
pub fn attenuates_ok(parent: &GrantRef, child: &GrantRef) -> bool {
    if parent.revoked {
        return false;
    }
    if parent.tenant_id != child.tenant_id {
        return false;
    }
    if child.parent_grant_id.as_deref() != Some(parent.grant_id.as_str()) {
        return false;
    }
    // Resource must match or be a path under parent (prefix with `/` or `::`).
    if child.resource != parent.resource
        && !child.resource.starts_with(&format!("{}/", parent.resource))
        && !child.resource.starts_with(&format!("{}::", parent.resource))
    {
        return false;
    }
    // Child actions ⊆ parent actions (empty parent actions = unrestricted catalog).
    if !parent.actions.is_empty() {
        for a in &child.actions {
            if !parent.actions.iter().any(|p| p == a) {
                return false;
            }
        }
    }
    // Child must not be more permissive than parent.
    if GrantRef::effect_rank(&child.effect) > GrantRef::effect_rank(&parent.effect) {
        return false;
    }
    true
}

/// Content digest for an attenuation edge (parent → child actions/resource/effect).
pub fn attenuation_digest(parent: &GrantRef, child: &GrantRef) -> String {
    let mut h = Sha256::new();
    h.update(parent.grant_id.as_bytes());
    h.update(b"|");
    h.update(child.resource.as_bytes());
    h.update(b"|");
    h.update(child.effect.as_bytes());
    h.update(b"|");
    let mut acts = child.actions.clone();
    acts.sort();
    for a in acts {
        h.update(a.as_bytes());
        h.update(b",");
    }
    format!("att1-sha256-{}", hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent() -> GrantRef {
        GrantRef {
            schema: GRANT_REF_SCHEMA.into(),
            grant_id: "g_parent".into(),
            tenant_id: "t1".into(),
            principal_id: "agent-1".into(),
            resource: "world/http".into(),
            actions: vec!["get".into(), "post".into()],
            effect: "ask".into(),
            layer: "cone".into(),
            parent_grant_id: None,
            attenuation_digest: None,
            legacy_world_grant_key: None,
            minted_at_revision: 1,
            expires_at_ms: None,
            revoked: false,
            minted_at_ms: 1,
        }
    }

    #[test]
    fn attenuation_subset_ok() {
        let p = parent();
        let mut c = p.clone();
        c.grant_id = "g_child".into();
        c.parent_grant_id = Some("g_parent".into());
        c.actions = vec!["get".into()];
        c.effect = "ask".into();
        assert!(attenuates_ok(&p, &c));
        let dig = attenuation_digest(&p, &c);
        assert!(dig.starts_with("att1-sha256-"));
    }

    #[test]
    fn attenuation_rejects_escalation() {
        let p = parent();
        let mut c = p.clone();
        c.grant_id = "g_child".into();
        c.parent_grant_id = Some("g_parent".into());
        c.effect = "allow".into(); // more permissive
        assert!(!attenuates_ok(&p, &c));
    }

    #[test]
    fn attenuation_rejects_extra_action() {
        let p = parent();
        let mut c = p.clone();
        c.grant_id = "g_child".into();
        c.parent_grant_id = Some("g_parent".into());
        c.actions = vec!["get".into(), "delete".into()];
        assert!(!attenuates_ok(&p, &c));
    }

    #[test]
    fn revoked_not_active() {
        let mut g = parent();
        g.revoked = true;
        assert!(!g.is_active_at(100));
    }
}
