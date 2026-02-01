//! Capability tokens for AAPI authorization
//!
//! Implements Macaroon-style capability tokens with caveats for
//! fine-grained, attenuable authorization.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use uuid::Uuid;

use aapi_core::types::{Budget, PrincipalId, Timestamp};
use crate::error::{CryptoError, CryptoResult};
use crate::keys::{KeyId, KeyPair, KeyStore};
use crate::signing::sign_bytes;

/// Capability token for authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Unique token identifier
    pub token_id: String,
    /// Version of the token format
    pub version: u32,
    /// Issuer principal
    pub issuer: PrincipalId,
    /// Subject (who the token is for)
    pub subject: PrincipalId,
    /// Audience (intended verifier)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Allowed actions (glob patterns)
    pub actions: Vec<String>,
    /// Allowed resources (glob patterns)
    pub resources: Vec<String>,
    /// Allowed namespaces
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<String>,
    /// Token issuance time
    pub issued_at: DateTime<Utc>,
    /// Token activation time (not valid before)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    /// Token expiration time
    pub expires_at: DateTime<Utc>,
    /// Budget constraints
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub budgets: Vec<Budget>,
    /// Caveats (additional restrictions)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<Caveat>,
    /// Parent token ID (for delegation chain)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_token_id: Option<String>,
    /// Delegation depth (0 = root token)
    #[serde(default)]
    pub delegation_depth: u32,
    /// Maximum allowed delegation depth
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u32>,
    /// Key ID used for signing
    pub key_id: KeyId,
    /// Signature over the token
    pub signature: String,
}

impl CapabilityToken {
    /// Check if the token is currently valid (time-wise)
    pub fn is_valid_time(&self) -> bool {
        let now = Utc::now();
        
        if now >= self.expires_at {
            return false;
        }
        
        if let Some(nbf) = self.not_before {
            if now < nbf {
                return false;
            }
        }
        
        true
    }

    /// Check if an action is allowed by this token
    pub fn allows_action(&self, action: &str) -> bool {
        self.actions.iter().any(|pattern| glob_match(pattern, action))
    }

    /// Check if a resource is allowed by this token
    pub fn allows_resource(&self, resource: &str) -> bool {
        self.resources.iter().any(|pattern| glob_match(pattern, resource))
    }

    /// Check if a namespace is allowed by this token
    pub fn allows_namespace(&self, namespace: &str) -> bool {
        if self.namespaces.is_empty() {
            return true; // No namespace restrictions
        }
        self.namespaces.iter().any(|ns| namespace.starts_with(ns))
    }

    /// Check if delegation is allowed
    pub fn can_delegate(&self) -> bool {
        if let Some(max_depth) = self.max_delegation_depth {
            self.delegation_depth < max_depth
        } else {
            true // No limit
        }
    }

    /// Get the canonical bytes for signing
    pub fn canonical_bytes(&self) -> CryptoResult<Vec<u8>> {
        // Create a copy without the signature for canonicalization
        let mut token_for_signing = self.clone();
        token_for_signing.signature = String::new();
        
        let json = serde_json::to_vec(&token_for_signing)?;
        Ok(json)
    }

    /// Compute the token hash
    pub fn compute_hash(&self) -> CryptoResult<String> {
        let canonical = self.canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        Ok(hex::encode(hasher.finalize()))
    }
}

/// Caveat for capability attenuation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Caveat {
    /// Caveat type
    pub caveat_type: CaveatType,
    /// Caveat value (interpretation depends on type)
    pub value: serde_json::Value,
    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Types of caveats
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaveatType {
    /// Time-based restriction
    TimeWindow,
    /// IP address restriction
    IpAddress,
    /// Geographic restriction
    Geo,
    /// Rate limit
    RateLimit,
    /// Require specific header
    RequireHeader,
    /// Require specific claim
    RequireClaim,
    /// Custom caveat (third-party verifiable)
    ThirdParty,
    /// Custom caveat type
    Custom(String),
}

/// Builder for creating capability tokens
pub struct CapabilityTokenBuilder {
    issuer: Option<PrincipalId>,
    subject: Option<PrincipalId>,
    audience: Option<String>,
    actions: Vec<String>,
    resources: Vec<String>,
    namespaces: Vec<String>,
    ttl: Duration,
    not_before: Option<DateTime<Utc>>,
    budgets: Vec<Budget>,
    caveats: Vec<Caveat>,
    parent_token_id: Option<String>,
    delegation_depth: u32,
    max_delegation_depth: Option<u32>,
}

impl Default for CapabilityTokenBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityTokenBuilder {
    pub fn new() -> Self {
        Self {
            issuer: None,
            subject: None,
            audience: None,
            actions: vec![],
            resources: vec![],
            namespaces: vec![],
            ttl: Duration::hours(1),
            not_before: None,
            budgets: vec![],
            caveats: vec![],
            parent_token_id: None,
            delegation_depth: 0,
            max_delegation_depth: None,
        }
    }

    pub fn issuer(mut self, issuer: PrincipalId) -> Self {
        self.issuer = Some(issuer);
        self
    }

    pub fn subject(mut self, subject: PrincipalId) -> Self {
        self.subject = Some(subject);
        self
    }

    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.actions.push(action.into());
        self
    }

    pub fn actions(mut self, actions: Vec<String>) -> Self {
        self.actions = actions;
        self
    }

    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resources.push(resource.into());
        self
    }

    pub fn resources(mut self, resources: Vec<String>) -> Self {
        self.resources = resources;
        self
    }

    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespaces.push(namespace.into());
        self
    }

    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn ttl_seconds(mut self, seconds: i64) -> Self {
        self.ttl = Duration::seconds(seconds);
        self
    }

    pub fn not_before(mut self, not_before: DateTime<Utc>) -> Self {
        self.not_before = Some(not_before);
        self
    }

    pub fn budget(mut self, budget: Budget) -> Self {
        self.budgets.push(budget);
        self
    }

    pub fn caveat(mut self, caveat: Caveat) -> Self {
        self.caveats.push(caveat);
        self
    }

    pub fn parent_token(mut self, parent_id: impl Into<String>, depth: u32) -> Self {
        self.parent_token_id = Some(parent_id.into());
        self.delegation_depth = depth;
        self
    }

    pub fn max_delegation_depth(mut self, max_depth: u32) -> Self {
        self.max_delegation_depth = Some(max_depth);
        self
    }

    /// Build and sign the token
    pub fn build_and_sign(self, key_pair: &KeyPair) -> CryptoResult<CapabilityToken> {
        let issuer = self.issuer.ok_or_else(|| {
            CryptoError::CapabilityError("Issuer is required".to_string())
        })?;
        
        let subject = self.subject.ok_or_else(|| {
            CryptoError::CapabilityError("Subject is required".to_string())
        })?;

        if self.actions.is_empty() {
            return Err(CryptoError::CapabilityError("At least one action is required".to_string()));
        }

        if self.resources.is_empty() {
            return Err(CryptoError::CapabilityError("At least one resource is required".to_string()));
        }

        let now = Utc::now();
        
        let mut token = CapabilityToken {
            token_id: Uuid::new_v4().to_string(),
            version: 1,
            issuer,
            subject,
            audience: self.audience,
            actions: self.actions,
            resources: self.resources,
            namespaces: self.namespaces,
            issued_at: now,
            not_before: self.not_before,
            expires_at: now + self.ttl,
            budgets: self.budgets,
            caveats: self.caveats,
            parent_token_id: self.parent_token_id,
            delegation_depth: self.delegation_depth,
            max_delegation_depth: self.max_delegation_depth,
            key_id: key_pair.key_id.clone(),
            signature: String::new(),
        };

        // Sign the token
        let canonical = token.canonical_bytes()?;
        token.signature = sign_bytes(key_pair, &canonical)?;

        Ok(token)
    }
}

/// Capability token issuer
pub struct CapabilityIssuer {
    key_store: KeyStore,
    issuer_key_id: KeyId,
    issuer_principal: PrincipalId,
}

impl CapabilityIssuer {
    pub fn new(key_store: KeyStore, issuer_key_id: KeyId, issuer_principal: PrincipalId) -> Self {
        Self {
            key_store,
            issuer_key_id,
            issuer_principal,
        }
    }

    /// Issue a new capability token
    pub fn issue(&self, builder: CapabilityTokenBuilder) -> CryptoResult<CapabilityToken> {
        let key_pair = self.key_store.get_key(&self.issuer_key_id)?;
        
        builder
            .issuer(self.issuer_principal.clone())
            .build_and_sign(&key_pair)
    }

    /// Attenuate (derive a more restricted token from) an existing token
    pub fn attenuate(
        &self,
        parent: &CapabilityToken,
        new_subject: PrincipalId,
        attenuation: TokenAttenuation,
    ) -> CryptoResult<CapabilityToken> {
        // Verify parent token is valid
        if !parent.is_valid_time() {
            return Err(CryptoError::TokenExpired);
        }

        if !parent.can_delegate() {
            return Err(CryptoError::CapabilityError(
                "Token cannot be delegated further".to_string()
            ));
        }

        let key_pair = self.key_store.get_key(&self.issuer_key_id)?;

        // Compute attenuated values
        let actions = if attenuation.actions.is_empty() {
            parent.actions.clone()
        } else {
            // Intersection of parent actions and requested actions
            attenuation.actions.into_iter()
                .filter(|a| parent.allows_action(a))
                .collect()
        };

        let resources = if attenuation.resources.is_empty() {
            parent.resources.clone()
        } else {
            attenuation.resources.into_iter()
                .filter(|r| parent.allows_resource(r))
                .collect()
        };

        // TTL cannot exceed parent's remaining TTL
        let max_ttl = parent.expires_at.signed_duration_since(Utc::now());
        let ttl = if let Some(requested_ttl) = attenuation.ttl {
            std::cmp::min(requested_ttl, max_ttl)
        } else {
            max_ttl
        };

        // Merge caveats
        let mut caveats = parent.caveats.clone();
        caveats.extend(attenuation.additional_caveats);

        // Merge budgets (take minimum of each)
        let budgets = merge_budgets(&parent.budgets, &attenuation.budgets);

        let mut token = CapabilityToken {
            token_id: Uuid::new_v4().to_string(),
            version: 1,
            issuer: self.issuer_principal.clone(),
            subject: new_subject,
            audience: attenuation.audience.or_else(|| parent.audience.clone()),
            actions,
            resources,
            namespaces: if attenuation.namespaces.is_empty() {
                parent.namespaces.clone()
            } else {
                attenuation.namespaces
            },
            issued_at: Utc::now(),
            not_before: attenuation.not_before,
            expires_at: Utc::now() + ttl,
            budgets,
            caveats,
            parent_token_id: Some(parent.token_id.clone()),
            delegation_depth: parent.delegation_depth + 1,
            max_delegation_depth: parent.max_delegation_depth,
            key_id: key_pair.key_id.clone(),
            signature: String::new(),
        };

        // Sign the token
        let canonical = token.canonical_bytes()?;
        token.signature = sign_bytes(&key_pair, &canonical)?;

        Ok(token)
    }
}

/// Attenuation parameters for deriving a restricted token
#[derive(Debug, Clone, Default)]
pub struct TokenAttenuation {
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    pub namespaces: Vec<String>,
    pub ttl: Option<Duration>,
    pub not_before: Option<DateTime<Utc>>,
    pub budgets: Vec<Budget>,
    pub additional_caveats: Vec<Caveat>,
    pub audience: Option<String>,
}

/// Capability token verifier
pub struct CapabilityVerifier {
    key_store: KeyStore,
}

impl CapabilityVerifier {
    pub fn new(key_store: KeyStore) -> Self {
        Self { key_store }
    }

    /// Verify a capability token
    pub fn verify(&self, token: &CapabilityToken) -> CryptoResult<CapabilityVerification> {
        let mut verification = CapabilityVerification {
            valid: true,
            errors: vec![],
            warnings: vec![],
            verified_at: Utc::now(),
        };

        // Check time validity
        if !token.is_valid_time() {
            verification.valid = false;
            if Utc::now() >= token.expires_at {
                verification.errors.push("Token has expired".to_string());
            } else {
                verification.errors.push("Token is not yet valid".to_string());
            }
        }

        // Verify signature
        match self.verify_signature(token) {
            Ok(true) => {}
            Ok(false) => {
                verification.valid = false;
                verification.errors.push("Invalid signature".to_string());
            }
            Err(e) => {
                verification.valid = false;
                verification.errors.push(format!("Signature verification error: {}", e));
            }
        }

        // Check budgets
        for budget in &token.budgets {
            if budget.is_exhausted() {
                verification.valid = false;
                verification.errors.push(format!(
                    "Budget '{}' is exhausted ({}/{})",
                    budget.resource, budget.used, budget.limit
                ));
            } else if budget.remaining() < budget.limit / 10 {
                verification.warnings.push(format!(
                    "Budget '{}' is low ({} remaining)",
                    budget.resource, budget.remaining()
                ));
            }
        }

        Ok(verification)
    }

    /// Verify the token signature
    fn verify_signature(&self, token: &CapabilityToken) -> CryptoResult<bool> {
        let public_info = self.key_store.get_public_key(&token.key_id)?;
        let canonical = token.canonical_bytes()?;
        
        crate::signing::verify_bytes(&public_info, &canonical, &token.signature)
    }

    /// Verify token and check if it allows a specific action on a resource
    pub fn verify_access(
        &self,
        token: &CapabilityToken,
        action: &str,
        resource: &str,
    ) -> CryptoResult<AccessDecision> {
        let verification = self.verify(token)?;
        
        if !verification.valid {
            return Ok(AccessDecision {
                allowed: false,
                reason: verification.errors.join("; "),
            });
        }

        if !token.allows_action(action) {
            return Ok(AccessDecision {
                allowed: false,
                reason: format!("Action '{}' not allowed by token", action),
            });
        }

        if !token.allows_resource(resource) {
            return Ok(AccessDecision {
                allowed: false,
                reason: format!("Resource '{}' not allowed by token", resource),
            });
        }

        Ok(AccessDecision {
            allowed: true,
            reason: "Access granted".to_string(),
        })
    }
}

/// Result of capability verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityVerification {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub verified_at: DateTime<Utc>,
}

/// Access decision result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessDecision {
    pub allowed: bool,
    pub reason: String,
}

/// Simple glob matching for action/resource patterns
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == "**" {
        return true;
    }

    let pattern_parts: Vec<&str> = pattern.split('.').collect();
    let value_parts: Vec<&str> = value.split('.').collect();

    glob_match_parts(&pattern_parts, &value_parts)
}

fn glob_match_parts(pattern: &[&str], value: &[&str]) -> bool {
    if pattern.is_empty() {
        return value.is_empty();
    }

    if value.is_empty() {
        return pattern.iter().all(|p| *p == "*" || *p == "**");
    }

    match pattern[0] {
        "**" => {
            // Match zero or more segments
            for i in 0..=value.len() {
                if glob_match_parts(&pattern[1..], &value[i..]) {
                    return true;
                }
            }
            false
        }
        "*" => {
            // Match exactly one segment
            glob_match_parts(&pattern[1..], &value[1..])
        }
        p => {
            // Literal match
            if p == value[0] {
                glob_match_parts(&pattern[1..], &value[1..])
            } else {
                false
            }
        }
    }
}

/// Merge budgets, taking the minimum of each resource type
fn merge_budgets(parent: &[Budget], child: &[Budget]) -> Vec<Budget> {
    let mut result = parent.to_vec();
    
    for child_budget in child {
        if let Some(parent_budget) = result.iter_mut().find(|b| b.resource == child_budget.resource) {
            // Take minimum limit
            parent_budget.limit = std::cmp::min(parent_budget.limit, child_budget.limit);
        } else {
            result.push(child_budget.clone());
        }
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPurpose;

    #[test]
    fn test_capability_token_builder() {
        let key_store = KeyStore::new();
        let key_id = key_store.generate_key(KeyPurpose::CapabilitySigning).unwrap();
        let key_pair = key_store.get_key(&key_id).unwrap();

        let token = CapabilityTokenBuilder::new()
            .issuer(PrincipalId::new("issuer:test"))
            .subject(PrincipalId::new("subject:test"))
            .action("file.*")
            .resource("documents/**")
            .ttl_seconds(3600)
            .build_and_sign(&key_pair)
            .unwrap();

        assert!(token.is_valid_time());
        assert!(token.allows_action("file.read"));
        assert!(token.allows_action("file.write"));
        assert!(!token.allows_action("database.query"));
    }

    #[test]
    fn test_glob_matching() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("**", "a.b.c"));
        assert!(glob_match("file.*", "file.read"));
        assert!(glob_match("file.*", "file.write"));
        assert!(!glob_match("file.*", "database.read"));
        assert!(glob_match("**.read", "org.team.file.read"));
        assert!(glob_match("org.*.read", "org.team.read"));
    }

    #[test]
    fn test_token_verification() {
        let key_store = KeyStore::new();
        let key_id = key_store.generate_key(KeyPurpose::CapabilitySigning).unwrap();
        let key_pair = key_store.get_key(&key_id).unwrap();

        let token = CapabilityTokenBuilder::new()
            .issuer(PrincipalId::new("issuer:test"))
            .subject(PrincipalId::new("subject:test"))
            .action("file.*")
            .resource("**")
            .ttl_seconds(3600)
            .build_and_sign(&key_pair)
            .unwrap();

        let verifier = CapabilityVerifier::new(key_store);
        let result = verifier.verify(&token).unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_token_attenuation() {
        let key_store = KeyStore::new();
        let key_id = key_store.generate_key(KeyPurpose::CapabilitySigning).unwrap();
        let key_pair = key_store.get_key(&key_id).unwrap();

        let parent = CapabilityTokenBuilder::new()
            .issuer(PrincipalId::new("issuer:test"))
            .subject(PrincipalId::new("agent:parent"))
            .actions(vec!["file.read".to_string(), "file.write".to_string()])
            .resource("**")
            .ttl_seconds(3600)
            .max_delegation_depth(2)
            .build_and_sign(&key_pair)
            .unwrap();

        let issuer = CapabilityIssuer::new(
            key_store.clone(),
            key_id,
            PrincipalId::new("issuer:test"),
        );

        let child = issuer.attenuate(
            &parent,
            PrincipalId::new("agent:child"),
            TokenAttenuation {
                actions: vec!["file.read".to_string()], // Only read
                ttl: Some(Duration::minutes(30)),
                ..Default::default()
            },
        ).unwrap();

        assert_eq!(child.delegation_depth, 1);
        assert!(child.allows_action("file.read"));
        // Child should not have write permission (attenuated away)
        assert!(!child.actions.contains(&"file.write".to_string()));
    }
}
