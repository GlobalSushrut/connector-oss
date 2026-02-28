//! CapabilityToken — Zircon Handle equivalent for agent capabilities.
//!
//! Tokens are issued to agents, scoped to specific capabilities with constraints.
//! Tokens can be attenuated (narrowed) but never amplified.
//! Each token is Ed25519 signed and can form a proof chain for delegation.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{CapsError, CapsResult};

// ── Grant Constraints ───────────────────────────────────────────────

/// Constraints on a capability grant — narrows what the capability can do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantConstraints {
    /// Allowed filesystem paths (glob patterns)
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    /// Allowed network domains
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Max requests per minute (rate limit)
    pub rate_limit: Option<u32>,
    /// Max output size in bytes
    pub max_output_bytes: Option<u64>,
    /// Allowed argument values (key → allowed values)
    #[serde(default)]
    pub allowed_args: HashMap<String, Vec<String>>,
    /// Not valid before (millis since epoch)
    pub not_before: Option<i64>,
    /// Not valid after (millis since epoch)
    pub not_after: Option<i64>,
}

impl GrantConstraints {
    pub fn unrestricted() -> Self {
        Self {
            allowed_paths: vec![],
            allowed_domains: vec![],
            rate_limit: None,
            max_output_bytes: None,
            allowed_args: HashMap::new(),
            not_before: None,
            not_after: None,
        }
    }

    /// Check if `child` constraints are a strict subset of `self` (narrower or equal).
    pub fn is_subset_of(&self, parent: &GrantConstraints) -> bool {
        // Paths: child must be subset of parent (if parent has any)
        if !parent.allowed_paths.is_empty() {
            for path in &self.allowed_paths {
                if !parent.allowed_paths.contains(path) {
                    return false;
                }
            }
            if self.allowed_paths.is_empty() {
                return false; // parent restricts, child doesn't
            }
        }

        // Domains: child must be subset
        if !parent.allowed_domains.is_empty() {
            for domain in &self.allowed_domains {
                if !parent.allowed_domains.contains(domain) {
                    return false;
                }
            }
            if self.allowed_domains.is_empty() {
                return false;
            }
        }

        // Rate limit: child must be <= parent
        if let Some(parent_limit) = parent.rate_limit {
            match self.rate_limit {
                Some(child_limit) if child_limit <= parent_limit => {}
                None => return false, // parent limits, child doesn't
                _ => return false,
            }
        }

        // Max output: child must be <= parent
        if let Some(parent_max) = parent.max_output_bytes {
            match self.max_output_bytes {
                Some(child_max) if child_max <= parent_max => {}
                None => return false,
                _ => return false,
            }
        }

        // Time: child not_before >= parent, child not_after <= parent
        if let Some(pnb) = parent.not_before {
            match self.not_before {
                Some(cnb) if cnb >= pnb => {}
                None => return false,
                _ => return false,
            }
        }
        if let Some(pna) = parent.not_after {
            match self.not_after {
                Some(cna) if cna <= pna => {}
                None => return false,
                _ => return false,
            }
        }

        true
    }
}

/// A single capability grant within a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub capability_id: String,
    pub constraints: GrantConstraints,
}

// ── Capability Token ────────────────────────────────────────────────

/// A capability token — the authorization to perform specific operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Unique token ID
    pub token_id: String,
    /// Agent this token is issued to
    pub issued_to: String,
    /// Capabilities granted
    pub capabilities: Vec<CapabilityGrant>,
    /// Chain of parent token IDs (for delegation tracking)
    pub proof_chain: Vec<String>,
    /// Expiry timestamp (millis since epoch)
    pub expires_at: i64,
    /// Created timestamp
    pub created_at: i64,
    /// Ed25519 signature over canonical token bytes
    pub signature: Vec<u8>,
}

impl CapabilityToken {
    /// Canonical bytes for signing (excludes signature field).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "token_id": self.token_id,
            "issued_to": self.issued_to,
            "capabilities": self.capabilities,
            "proof_chain": self.proof_chain,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
        });
        serde_json::to_vec(&canonical).unwrap_or_default()
    }

    /// Sign this token.
    pub fn sign(&mut self, key: &SigningKey) {
        let bytes = self.signable_bytes();
        let sig = key.sign(&bytes);
        self.signature = sig.to_bytes().to_vec();
    }

    /// Verify this token's signature.
    pub fn verify_signature(&self, key: &VerifyingKey) -> CapsResult<()> {
        if self.signature.len() != 64 {
            return Err(CapsError::TokenSignatureInvalid("bad length".into()));
        }
        let sig_bytes: [u8; 64] = self.signature[..64]
            .try_into()
            .map_err(|_| CapsError::TokenSignatureInvalid("conversion".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        let bytes = self.signable_bytes();
        key.verify(&bytes, &sig)
            .map_err(|e| CapsError::TokenSignatureInvalid(e.to_string()))
    }

    /// Check if the token has expired.
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().timestamp_millis() > self.expires_at
    }

    /// Check if this token grants a specific capability.
    pub fn has_capability(&self, cap_id: &str) -> bool {
        self.capabilities.iter().any(|g| g.capability_id == cap_id)
    }

    /// Get the grant for a specific capability.
    pub fn get_grant(&self, cap_id: &str) -> Option<&CapabilityGrant> {
        self.capabilities.iter().find(|g| g.capability_id == cap_id)
    }
}

// ── Token Issuer ────────────────────────────────────────────────────

/// Issues and manages capability tokens.
pub struct TokenIssuer {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    /// Set of revoked token IDs.
    revoked: HashSet<String>,
}

impl TokenIssuer {
    pub fn new(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            revoked: HashSet::new(),
        }
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Issue a new capability token.
    pub fn issue_token(
        &self,
        agent_pid: &str,
        capabilities: Vec<CapabilityGrant>,
        expires_at: i64,
    ) -> CapabilityToken {
        let now = chrono::Utc::now().timestamp_millis();
        let token_id = uuid::Uuid::new_v4().to_string();

        let mut token = CapabilityToken {
            token_id,
            issued_to: agent_pid.to_string(),
            capabilities,
            proof_chain: vec![],
            expires_at,
            created_at: now,
            signature: vec![],
        };
        token.sign(&self.signing_key);
        token
    }

    /// Attenuate a token — derive a child token with narrower constraints.
    /// Returns error if child constraints are wider than parent.
    pub fn attenuate(
        &self,
        parent: &CapabilityToken,
        new_agent: &str,
        new_capabilities: Vec<CapabilityGrant>,
        new_expires_at: i64,
    ) -> CapsResult<CapabilityToken> {
        // Verify parent is valid
        self.verify_token(parent)?;

        // Expiry must be <= parent
        if new_expires_at > parent.expires_at {
            return Err(CapsError::AttenuationViolation(
                "Child expiry cannot exceed parent expiry".into(),
            ));
        }

        // Each child capability must exist in parent with narrower constraints
        for child_grant in &new_capabilities {
            let parent_grant = parent.get_grant(&child_grant.capability_id).ok_or_else(|| {
                CapsError::AttenuationViolation(format!(
                    "Capability '{}' not in parent token",
                    child_grant.capability_id
                ))
            })?;

            if !child_grant.constraints.is_subset_of(&parent_grant.constraints) {
                return Err(CapsError::AttenuationViolation(format!(
                    "Constraints for '{}' are wider than parent",
                    child_grant.capability_id
                )));
            }
        }

        let mut proof_chain = parent.proof_chain.clone();
        proof_chain.push(parent.token_id.clone());

        let mut token = CapabilityToken {
            token_id: uuid::Uuid::new_v4().to_string(),
            issued_to: new_agent.to_string(),
            capabilities: new_capabilities,
            proof_chain,
            expires_at: new_expires_at,
            created_at: chrono::Utc::now().timestamp_millis(),
            signature: vec![],
        };
        token.sign(&self.signing_key);
        Ok(token)
    }

    /// Verify a token: check signature, expiry, and revocation.
    pub fn verify_token(&self, token: &CapabilityToken) -> CapsResult<()> {
        // Check revocation
        if self.revoked.contains(&token.token_id) {
            return Err(CapsError::TokenRevoked(token.token_id.clone()));
        }

        // Check proof chain for revoked ancestors
        for ancestor_id in &token.proof_chain {
            if self.revoked.contains(ancestor_id) {
                return Err(CapsError::TokenRevoked(format!(
                    "ancestor {} revoked",
                    ancestor_id
                )));
            }
        }

        // Check expiry
        if token.is_expired() {
            return Err(CapsError::TokenExpired);
        }

        // Verify signature
        token.verify_signature(&self.verifying_key)
    }

    /// Revoke a token (and all its descendants).
    pub fn revoke(&mut self, token_id: &str) {
        self.revoked.insert(token_id.to_string());
    }

    /// Check if a token ID is revoked.
    pub fn is_revoked(&self, token_id: &str) -> bool {
        self.revoked.contains(token_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn future_ms(secs: i64) -> i64 {
        chrono::Utc::now().timestamp_millis() + secs * 1000
    }

    fn past_ms(secs: i64) -> i64 {
        chrono::Utc::now().timestamp_millis() - secs * 1000
    }

    fn make_issuer() -> TokenIssuer {
        TokenIssuer::new(SigningKey::generate(&mut OsRng))
    }

    fn make_fs_grant() -> CapabilityGrant {
        CapabilityGrant {
            capability_id: "fs.read".to_string(),
            constraints: GrantConstraints {
                allowed_paths: vec!["/tmp/*".to_string()],
                allowed_domains: vec![],
                rate_limit: Some(100),
                max_output_bytes: Some(1_000_000),
                allowed_args: HashMap::new(),
                not_before: None,
                not_after: None,
            },
        }
    }

    #[test]
    fn test_issue_token() {
        let issuer = make_issuer();
        let token = issuer.issue_token("agent-1", vec![make_fs_grant()], future_ms(3600));

        assert_eq!(token.issued_to, "agent-1");
        assert_eq!(token.capabilities.len(), 1);
        assert!(token.has_capability("fs.read"));
        assert!(!token.has_capability("fs.write"));
        assert!(!token.is_expired());
        assert!(issuer.verify_token(&token).is_ok());
    }

    #[test]
    fn test_token_expired() {
        let issuer = make_issuer();
        let token = issuer.issue_token("agent-1", vec![make_fs_grant()], past_ms(10));

        assert!(token.is_expired());
        assert!(issuer.verify_token(&token).is_err());
    }

    #[test]
    fn test_token_revoked() {
        let mut issuer = make_issuer();
        let token = issuer.issue_token("agent-1", vec![make_fs_grant()], future_ms(3600));

        assert!(issuer.verify_token(&token).is_ok());
        issuer.revoke(&token.token_id);
        assert!(issuer.verify_token(&token).is_err());
    }

    #[test]
    fn test_token_wrong_key_rejected() {
        let issuer = make_issuer();
        let token = issuer.issue_token("agent-1", vec![make_fs_grant()], future_ms(3600));

        let wrong_key = SigningKey::generate(&mut OsRng).verifying_key();
        assert!(token.verify_signature(&wrong_key).is_err());
    }

    #[test]
    fn test_attenuate_narrower_ok() {
        let issuer = make_issuer();
        let parent = issuer.issue_token("agent-1", vec![make_fs_grant()], future_ms(3600));

        let child_grant = CapabilityGrant {
            capability_id: "fs.read".to_string(),
            constraints: GrantConstraints {
                allowed_paths: vec!["/tmp/*".to_string()],
                allowed_domains: vec![],
                rate_limit: Some(50), // narrower
                max_output_bytes: Some(500_000), // narrower
                allowed_args: HashMap::new(),
                not_before: None,
                not_after: None,
            },
        };

        let child = issuer
            .attenuate(&parent, "agent-2", vec![child_grant], future_ms(1800))
            .unwrap();

        assert_eq!(child.issued_to, "agent-2");
        assert_eq!(child.proof_chain.len(), 1);
        assert_eq!(child.proof_chain[0], parent.token_id);
        assert!(issuer.verify_token(&child).is_ok());
    }

    #[test]
    fn test_attenuate_wider_rejected() {
        let issuer = make_issuer();
        let parent = issuer.issue_token("agent-1", vec![make_fs_grant()], future_ms(3600));

        let wider_grant = CapabilityGrant {
            capability_id: "fs.read".to_string(),
            constraints: GrantConstraints {
                allowed_paths: vec!["/tmp/*".to_string()],
                allowed_domains: vec![],
                rate_limit: Some(200), // WIDER than parent's 100
                max_output_bytes: Some(500_000),
                allowed_args: HashMap::new(),
                not_before: None,
                not_after: None,
            },
        };

        let result = issuer.attenuate(&parent, "agent-2", vec![wider_grant], future_ms(1800));
        assert!(result.is_err());
    }

    #[test]
    fn test_attenuate_new_capability_rejected() {
        let issuer = make_issuer();
        let parent = issuer.issue_token("agent-1", vec![make_fs_grant()], future_ms(3600));

        let new_cap = CapabilityGrant {
            capability_id: "fs.write".to_string(), // not in parent
            constraints: GrantConstraints::unrestricted(),
        };

        let result = issuer.attenuate(&parent, "agent-2", vec![new_cap], future_ms(1800));
        assert!(result.is_err());
    }

    #[test]
    fn test_attenuate_longer_expiry_rejected() {
        let issuer = make_issuer();
        let parent = issuer.issue_token("agent-1", vec![make_fs_grant()], future_ms(3600));

        let child_grant = CapabilityGrant {
            capability_id: "fs.read".to_string(),
            constraints: GrantConstraints {
                allowed_paths: vec!["/tmp/*".to_string()],
                allowed_domains: vec![],
                rate_limit: Some(50),
                max_output_bytes: Some(500_000),
                allowed_args: HashMap::new(),
                not_before: None,
                not_after: None,
            },
        };

        let result = issuer.attenuate(&parent, "agent-2", vec![child_grant], future_ms(7200)); // longer
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_ancestor_invalidates_child() {
        let mut issuer = make_issuer();
        let parent = issuer.issue_token("agent-1", vec![make_fs_grant()], future_ms(3600));

        let child_grant = CapabilityGrant {
            capability_id: "fs.read".to_string(),
            constraints: GrantConstraints {
                allowed_paths: vec!["/tmp/*".to_string()],
                allowed_domains: vec![],
                rate_limit: Some(50),
                max_output_bytes: Some(500_000),
                allowed_args: HashMap::new(),
                not_before: None,
                not_after: None,
            },
        };

        let child = issuer
            .attenuate(&parent, "agent-2", vec![child_grant], future_ms(1800))
            .unwrap();

        assert!(issuer.verify_token(&child).is_ok());

        // Revoke parent — child should become invalid
        issuer.revoke(&parent.token_id);
        assert!(issuer.verify_token(&child).is_err());
    }

    #[test]
    fn test_constraint_subset_check() {
        let parent = GrantConstraints {
            allowed_paths: vec!["/tmp/*".to_string(), "/var/*".to_string()],
            allowed_domains: vec!["api.example.com".to_string()],
            rate_limit: Some(100),
            max_output_bytes: Some(1_000_000),
            allowed_args: HashMap::new(),
            not_before: None,
            not_after: None,
        };

        // Narrower: subset of paths, lower rate
        let narrower = GrantConstraints {
            allowed_paths: vec!["/tmp/*".to_string()],
            allowed_domains: vec!["api.example.com".to_string()],
            rate_limit: Some(50),
            max_output_bytes: Some(500_000),
            allowed_args: HashMap::new(),
            not_before: None,
            not_after: None,
        };
        assert!(narrower.is_subset_of(&parent));

        // Wider domain
        let wider_domain = GrantConstraints {
            allowed_paths: vec!["/tmp/*".to_string()],
            allowed_domains: vec!["evil.com".to_string()],
            rate_limit: Some(50),
            max_output_bytes: Some(500_000),
            allowed_args: HashMap::new(),
            not_before: None,
            not_after: None,
        };
        assert!(!wider_domain.is_subset_of(&parent));
    }
}
