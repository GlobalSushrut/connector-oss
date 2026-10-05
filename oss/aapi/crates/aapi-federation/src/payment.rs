//! Agent Payment Protocol (AP2) — cryptographic spending mandates.
//!
//! Ed25519-signed payment mandates with amount caps, merchant constraints,
//! and expiry. Inspired by Google AP2, UCAN delegation patterns.
//!
//! Every mandate is signed by the issuer's Ed25519 key. Verification checks:
//! 1. Signature validity
//! 2. Expiry (mandate_expires_at < now)
//! 3. Amount bounds (requested ≤ max_amount)
//! 4. Merchant constraints (merchant in allowed list, or list empty = any)

use serde::{Deserialize, Serialize};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use sha2::{Sha256, Digest};

// ═══════════════════════════════════════════════════════════════
// Mandate Types
// ═══════════════════════════════════════════════════════════════

/// Type of payment mandate — determines authorization scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateType {
    /// Pre-authorized cart: exact items, exact amount
    CartMandate,
    /// Intent-based: category + max amount, merchant chosen by agent
    IntentMandate,
    /// Open payment: max amount only, agent chooses merchant + items
    PaymentMandate,
}

impl std::fmt::Display for MandateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MandateType::CartMandate => write!(f, "cart"),
            MandateType::IntentMandate => write!(f, "intent"),
            MandateType::PaymentMandate => write!(f, "payment"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Payment Mandate
// ═══════════════════════════════════════════════════════════════

/// A signed spending authorization for an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMandate {
    /// Unique mandate ID
    pub mandate_id: String,
    /// DID of the issuer (human or org that grants spending authority)
    pub issuer_did: String,
    /// DID of the agent authorized to spend
    pub agent_did: String,
    /// Type of mandate
    pub mandate_type: MandateType,
    /// Maximum amount in smallest currency unit (e.g., cents)
    pub max_amount: u64,
    /// Currency code (e.g., "USD", "EUR")
    pub currency: String,
    /// Allowed merchant DIDs (empty = any merchant)
    pub merchant_constraints: Vec<String>,
    /// Allowed spending categories (empty = any category)
    pub category_constraints: Vec<String>,
    /// Expiry timestamp (ms epoch, 0 = no expiry)
    pub expires_at_ms: u64,
    /// Ed25519 signature over canonical fields (hex-encoded)
    pub signature: String,
    /// Amount already spent under this mandate
    pub spent_amount: u64,
}

impl PaymentMandate {
    /// Create a new unsigned mandate.
    pub fn new(
        mandate_id: impl Into<String>,
        issuer_did: impl Into<String>,
        agent_did: impl Into<String>,
        mandate_type: MandateType,
        max_amount: u64,
        currency: impl Into<String>,
    ) -> Self {
        Self {
            mandate_id: mandate_id.into(),
            issuer_did: issuer_did.into(),
            agent_did: agent_did.into(),
            mandate_type,
            max_amount,
            currency: currency.into(),
            merchant_constraints: Vec::new(),
            category_constraints: Vec::new(),
            expires_at_ms: 0,
            signature: String::new(),
            spent_amount: 0,
        }
    }

    /// Set merchant constraints.
    pub fn with_merchants(mut self, merchants: Vec<String>) -> Self {
        self.merchant_constraints = merchants;
        self
    }

    /// Set category constraints.
    pub fn with_categories(mut self, categories: Vec<String>) -> Self {
        self.category_constraints = categories;
        self
    }

    /// Set expiry.
    pub fn with_expiry(mut self, expires_at_ms: u64) -> Self {
        self.expires_at_ms = expires_at_ms;
        self
    }

    /// Canonical bytes for signing (excludes signature and spent_amount fields).
    fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.mandate_id,
            self.issuer_did,
            self.agent_did,
            self.mandate_type,
            self.max_amount,
            self.currency,
            self.merchant_constraints.join(","),
            self.category_constraints.join(","),
            self.expires_at_ms,
        );
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Sign the mandate with an Ed25519 signing key.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let digest = self.canonical_bytes();
        let sig = signing_key.sign(&digest);
        self.signature = hex::encode(sig.to_bytes());
    }

    /// Verify the mandate's Ed25519 signature.
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

    /// Check if the mandate has expired.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expires_at_ms > 0 && now_ms > self.expires_at_ms
    }

    /// Check if a payment of `amount` is within the remaining budget.
    pub fn is_within_budget(&self, amount: u64) -> bool {
        self.spent_amount + amount <= self.max_amount
    }

    /// Remaining budget.
    pub fn remaining(&self) -> u64 {
        self.max_amount.saturating_sub(self.spent_amount)
    }

    /// Check if a merchant is allowed by this mandate.
    pub fn is_merchant_allowed(&self, merchant_did: &str) -> bool {
        self.merchant_constraints.is_empty() || self.merchant_constraints.iter().any(|m| m == merchant_did)
    }

    /// Check if a category is allowed by this mandate.
    pub fn is_category_allowed(&self, category: &str) -> bool {
        self.category_constraints.is_empty() || self.category_constraints.iter().any(|c| c == category)
    }

    /// Record a spend. Returns Err if over budget.
    pub fn record_spend(&mut self, amount: u64) -> Result<(), String> {
        if !self.is_within_budget(amount) {
            return Err(format!(
                "Budget exceeded: {} + {} > {} (mandate {})",
                self.spent_amount, amount, self.max_amount, self.mandate_id
            ));
        }
        self.spent_amount += amount;
        Ok(())
    }

    /// Full validation: signature + expiry + amount + merchant + category.
    pub fn validate(
        &self,
        verifying_key: &VerifyingKey,
        now_ms: u64,
        amount: u64,
        merchant_did: &str,
        category: &str,
    ) -> Result<(), String> {
        if !self.verify(verifying_key) {
            return Err("Invalid signature".into());
        }
        if self.is_expired(now_ms) {
            return Err(format!("Mandate expired at {}", self.expires_at_ms));
        }
        if !self.is_within_budget(amount) {
            return Err(format!("Amount {} exceeds remaining budget {}", amount, self.remaining()));
        }
        if !self.is_merchant_allowed(merchant_did) {
            return Err(format!("Merchant {} not in allowed list", merchant_did));
        }
        if !self.is_category_allowed(category) {
            return Err(format!("Category {} not in allowed list", category));
        }
        Ok(())
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
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn base_mandate() -> PaymentMandate {
        PaymentMandate::new("m-001", "did:issuer:org", "did:agent:bot", MandateType::PaymentMandate, 10000, "USD")
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (sk, vk) = test_keypair();
        let mut mandate = base_mandate();
        mandate.sign(&sk);
        assert!(!mandate.signature.is_empty());
        assert!(mandate.verify(&vk));
    }

    #[test]
    fn test_tampered_mandate_fails_verify() {
        let (sk, vk) = test_keypair();
        let mut mandate = base_mandate();
        mandate.sign(&sk);
        // Tamper with max_amount
        mandate.max_amount = 99999;
        assert!(!mandate.verify(&vk));
    }

    #[test]
    fn test_expired_mandate_rejected() {
        let mandate = base_mandate().with_expiry(5000);
        assert!(!mandate.is_expired(3000)); // Not expired yet
        assert!(mandate.is_expired(6000));  // Expired
    }

    #[test]
    fn test_amount_over_max_rejected() {
        let mandate = base_mandate();
        assert!(mandate.is_within_budget(10000)); // Exact max
        assert!(!mandate.is_within_budget(10001)); // Over
    }

    #[test]
    fn test_merchant_constraint_enforced() {
        let mandate = base_mandate()
            .with_merchants(vec!["did:merchant:a".into(), "did:merchant:b".into()]);
        assert!(mandate.is_merchant_allowed("did:merchant:a"));
        assert!(mandate.is_merchant_allowed("did:merchant:b"));
        assert!(!mandate.is_merchant_allowed("did:merchant:c"));
    }

    #[test]
    fn test_empty_constraints_allow_any() {
        let mandate = base_mandate(); // No merchant/category constraints
        assert!(mandate.is_merchant_allowed("any:merchant"));
        assert!(mandate.is_category_allowed("any:category"));
    }

    #[test]
    fn test_cart_mandate_type() {
        let mandate = PaymentMandate::new("m-002", "did:issuer:org", "did:agent:bot", MandateType::CartMandate, 5000, "EUR");
        assert_eq!(mandate.mandate_type, MandateType::CartMandate);
        assert_eq!(format!("{}", mandate.mandate_type), "cart");
    }

    #[test]
    fn test_intent_mandate_type() {
        let mandate = PaymentMandate::new("m-003", "did:issuer:org", "did:agent:bot", MandateType::IntentMandate, 5000, "GBP");
        assert_eq!(mandate.mandate_type, MandateType::IntentMandate);
        assert_eq!(format!("{}", mandate.mandate_type), "intent");
    }

    #[test]
    fn test_record_spend_and_remaining() {
        let mut mandate = base_mandate(); // max 10000
        assert_eq!(mandate.remaining(), 10000);
        mandate.record_spend(3000).unwrap();
        assert_eq!(mandate.remaining(), 7000);
        assert_eq!(mandate.spent_amount, 3000);
        mandate.record_spend(7000).unwrap();
        assert_eq!(mandate.remaining(), 0);
        // Over budget
        assert!(mandate.record_spend(1).is_err());
    }

    #[test]
    fn test_full_validate_passes() {
        let (sk, vk) = test_keypair();
        let mut mandate = base_mandate()
            .with_merchants(vec!["did:merchant:shop".into()])
            .with_categories(vec!["groceries".into()])
            .with_expiry(100_000);
        mandate.sign(&sk);

        let result = mandate.validate(&vk, 50_000, 5000, "did:merchant:shop", "groceries");
        assert!(result.is_ok());
    }

    #[test]
    fn test_full_validate_rejects_bad_sig() {
        let (sk, _vk) = test_keypair();
        let wrong_sk = SigningKey::from_bytes(&[99u8; 32]);
        let wrong_vk = wrong_sk.verifying_key();

        let mut mandate = base_mandate();
        mandate.sign(&sk);
        // Verify with wrong key
        let result = mandate.validate(&wrong_vk, 1000, 100, "", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature"));
    }
}
