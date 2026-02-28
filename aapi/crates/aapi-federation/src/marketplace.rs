//! Agent Marketplace — discover, publish, and verify agent service listings.
//!
//! Agents register their capabilities with pricing and health metrics.
//! Consumers discover agents by capability match, verify Ed25519 signatures,
//! and filter by health/pricing criteria.
//!
//! Analogous to a service registry (Consul/etcd) + app store.

use serde::{Deserialize, Serialize};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Pricing Model
// ═══════════════════════════════════════════════════════════════

/// How an agent charges for its services.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingModel {
    /// No charge
    Free,
    /// Charge per invocation
    PerCall { rate_micros: u64, currency: String },
    /// Charge per token processed
    PerToken { rate_micros: u64, currency: String },
    /// Fixed periodic subscription
    Subscription { period_days: u32, rate_micros: u64, currency: String },
}

impl std::fmt::Display for PricingModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PricingModel::Free => write!(f, "free"),
            PricingModel::PerCall { .. } => write!(f, "per_call"),
            PricingModel::PerToken { .. } => write!(f, "per_token"),
            PricingModel::Subscription { .. } => write!(f, "subscription"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Agent Health
// ═══════════════════════════════════════════════════════════════

/// Health metrics for a listed agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealthMetrics {
    /// Is the agent currently online
    pub online: bool,
    /// Uptime percentage (0.0–100.0)
    pub uptime_pct: f64,
    /// Average response latency in ms
    pub avg_latency_ms: f64,
    /// Error rate (0.0–1.0)
    pub error_rate: f64,
    /// Total requests served
    pub total_requests: u64,
    /// Last health check timestamp (ms epoch)
    pub last_check_ms: u64,
}

impl Default for AgentHealthMetrics {
    fn default() -> Self {
        Self {
            online: true,
            uptime_pct: 100.0,
            avg_latency_ms: 0.0,
            error_rate: 0.0,
            total_requests: 0,
            last_check_ms: 0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Agent Listing
// ═══════════════════════════════════════════════════════════════

/// A marketplace listing for an agent's services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentListing {
    /// Agent's DID
    pub did: String,
    /// Human-readable name
    pub name: String,
    /// Description of services
    pub description: String,
    /// Capabilities offered (domain:action format)
    pub capabilities: Vec<String>,
    /// Pricing model
    pub pricing: PricingModel,
    /// Current health metrics
    pub health: AgentHealthMetrics,
    /// Provider organization DID
    pub provider_org: String,
    /// Listing creation timestamp (ms epoch)
    pub created_at_ms: u64,
    /// Listing expiry timestamp (ms epoch, 0 = no expiry)
    pub expires_at_ms: u64,
    /// Ed25519 signature over canonical fields (hex)
    pub signature: String,
}

impl AgentListing {
    pub fn new(
        did: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        capabilities: Vec<String>,
        pricing: PricingModel,
        provider_org: impl Into<String>,
        created_at_ms: u64,
    ) -> Self {
        Self {
            did: did.into(),
            name: name.into(),
            description: description.into(),
            capabilities,
            pricing,
            health: AgentHealthMetrics::default(),
            provider_org: provider_org.into(),
            created_at_ms,
            expires_at_ms: 0,
            signature: String::new(),
        }
    }

    pub fn with_expiry(mut self, expires_at_ms: u64) -> Self {
        self.expires_at_ms = expires_at_ms;
        self
    }

    pub fn with_health(mut self, health: AgentHealthMetrics) -> Self {
        self.health = health;
        self
    }

    /// Canonical bytes for signing.
    fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            self.did,
            self.name,
            self.description,
            self.capabilities.join(","),
            self.pricing,
            self.provider_org,
            self.created_at_ms,
            self.expires_at_ms,
        );
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Sign the listing.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let digest = self.canonical_bytes();
        let sig = signing_key.sign(&digest);
        self.signature = hex::encode(sig.to_bytes());
    }

    /// Verify the listing's signature.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        let sig_bytes = match hex::decode(&self.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig_array: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&sig_array);
        let digest = self.canonical_bytes();
        verifying_key.verify(&digest, &signature).is_ok()
    }

    /// Check if the listing has expired.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expires_at_ms > 0 && now_ms > self.expires_at_ms
    }

    /// Check if this listing offers a given capability.
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }
}

// ═══════════════════════════════════════════════════════════════
// Agent Marketplace
// ═══════════════════════════════════════════════════════════════

/// Query for discovering agents.
#[derive(Debug, Clone, Default)]
pub struct DiscoverQuery {
    /// Required capability (empty = any)
    pub capability: Option<String>,
    /// Max acceptable latency (None = any)
    pub max_latency_ms: Option<f64>,
    /// Max acceptable error rate (None = any)
    pub max_error_rate: Option<f64>,
    /// Only free listings
    pub free_only: bool,
    /// Exclude expired listings
    pub exclude_expired: bool,
    /// Current time for expiry check
    pub now_ms: u64,
}

/// The marketplace: stores and queries agent listings.
pub struct AgentMarketplace {
    listings: HashMap<String, AgentListing>,
}

impl AgentMarketplace {
    pub fn new() -> Self {
        Self { listings: HashMap::new() }
    }

    /// Publish a listing. Overwrites if same DID exists.
    pub fn publish(&mut self, listing: AgentListing) {
        self.listings.insert(listing.did.clone(), listing);
    }

    /// Remove a listing by DID.
    pub fn unpublish(&mut self, did: &str) -> Option<AgentListing> {
        self.listings.remove(did)
    }

    /// Get a listing by DID.
    pub fn get(&self, did: &str) -> Option<&AgentListing> {
        self.listings.get(did)
    }

    /// Total listing count.
    pub fn count(&self) -> usize {
        self.listings.len()
    }

    /// Discover agents matching a query.
    pub fn discover(&self, query: &DiscoverQuery) -> Vec<&AgentListing> {
        self.listings.values()
            .filter(|l| {
                // Capability filter
                if let Some(ref cap) = query.capability {
                    if !l.has_capability(cap) { return false; }
                }
                // Expiry filter
                if query.exclude_expired && l.is_expired(query.now_ms) {
                    return false;
                }
                // Latency filter
                if let Some(max_lat) = query.max_latency_ms {
                    if l.health.avg_latency_ms > max_lat { return false; }
                }
                // Error rate filter
                if let Some(max_err) = query.max_error_rate {
                    if l.health.error_rate > max_err { return false; }
                }
                // Free only filter
                if query.free_only && l.pricing != PricingModel::Free {
                    return false;
                }
                true
            })
            .collect()
    }

    /// Verify a listing's signature with the given key.
    pub fn verify_listing(&self, did: &str, verifying_key: &VerifyingKey) -> Result<bool, String> {
        match self.listings.get(did) {
            Some(listing) => Ok(listing.verify(verifying_key)),
            None => Err(format!("Listing not found: {}", did)),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[77u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn base_listing(did: &str, caps: Vec<&str>) -> AgentListing {
        AgentListing::new(
            did, format!("Agent {}", did), "A test agent",
            caps.into_iter().map(String::from).collect(),
            PricingModel::Free, "did:org:test", 1000,
        )
    }

    #[test]
    fn test_publish_and_get() {
        let mut mp = AgentMarketplace::new();
        let listing = base_listing("did:agent:a", vec!["healthcare:diagnose"]);
        mp.publish(listing);
        assert_eq!(mp.count(), 1);
        assert!(mp.get("did:agent:a").is_some());
        assert_eq!(mp.get("did:agent:a").unwrap().name, "Agent did:agent:a");
    }

    #[test]
    fn test_discover_by_capability() {
        let mut mp = AgentMarketplace::new();
        mp.publish(base_listing("did:a", vec!["healthcare:diagnose", "healthcare:triage"]));
        mp.publish(base_listing("did:b", vec!["finance:audit"]));
        mp.publish(base_listing("did:c", vec!["healthcare:diagnose"]));

        let query = DiscoverQuery { capability: Some("healthcare:diagnose".into()), ..Default::default() };
        let results = mp.discover(&query);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_discover_returns_all_when_no_filter() {
        let mut mp = AgentMarketplace::new();
        mp.publish(base_listing("did:a", vec!["x"]));
        mp.publish(base_listing("did:b", vec!["y"]));
        mp.publish(base_listing("did:c", vec!["z"]));

        let query = DiscoverQuery::default();
        assert_eq!(mp.discover(&query).len(), 3);
    }

    #[test]
    fn test_verify_listing_passes() {
        let (sk, vk) = test_keypair();
        let mut mp = AgentMarketplace::new();
        let mut listing = base_listing("did:agent:signed", vec!["test:cap"]);
        listing.sign(&sk);
        mp.publish(listing);
        assert_eq!(mp.verify_listing("did:agent:signed", &vk).unwrap(), true);
    }

    #[test]
    fn test_tampered_listing_fails_verify() {
        let (sk, vk) = test_keypair();
        let mut listing = base_listing("did:agent:bad", vec!["test:cap"]);
        listing.sign(&sk);
        listing.name = "TAMPERED".into(); // Tamper after signing
        let mut mp = AgentMarketplace::new();
        mp.publish(listing);
        assert_eq!(mp.verify_listing("did:agent:bad", &vk).unwrap(), false);
    }

    #[test]
    fn test_pricing_model_serializes() {
        let per_call = PricingModel::PerCall { rate_micros: 100, currency: "USD".into() };
        let json = serde_json::to_string(&per_call).unwrap();
        assert!(json.contains("per_call"));
        let round: PricingModel = serde_json::from_str(&json).unwrap();
        assert_eq!(round, per_call);
    }

    #[test]
    fn test_health_populated() {
        let health = AgentHealthMetrics {
            online: true,
            uptime_pct: 99.5,
            avg_latency_ms: 45.0,
            error_rate: 0.02,
            total_requests: 10000,
            last_check_ms: 5000,
        };
        let listing = base_listing("did:h", vec!["test"]).with_health(health);
        assert_eq!(listing.health.uptime_pct, 99.5);
        assert_eq!(listing.health.total_requests, 10000);
    }

    #[test]
    fn test_expired_listing_excluded() {
        let mut mp = AgentMarketplace::new();
        mp.publish(base_listing("did:fresh", vec!["test"]).with_expiry(10000));
        mp.publish(base_listing("did:stale", vec!["test"]).with_expiry(3000));

        let query = DiscoverQuery {
            exclude_expired: true,
            now_ms: 5000,
            ..Default::default()
        };
        let results = mp.discover(&query);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].did, "did:fresh");
    }

    #[test]
    fn test_free_only_filter() {
        let mut mp = AgentMarketplace::new();
        mp.publish(base_listing("did:free", vec!["test"])); // Free by default
        let mut paid = base_listing("did:paid", vec!["test"]);
        paid.pricing = PricingModel::PerCall { rate_micros: 100, currency: "USD".into() };
        mp.publish(paid);

        let query = DiscoverQuery { free_only: true, ..Default::default() };
        let results = mp.discover(&query);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].did, "did:free");
    }

    #[test]
    fn test_unpublish() {
        let mut mp = AgentMarketplace::new();
        mp.publish(base_listing("did:temp", vec!["test"]));
        assert_eq!(mp.count(), 1);
        let removed = mp.unpublish("did:temp");
        assert!(removed.is_some());
        assert_eq!(mp.count(), 0);
    }
}
