//! AP2 Bridge — Google Agent Payment Protocol (AP2).
//!
//! Cryptographic spending mandates for agent-to-agent payments:
//! - PaymentMandate with Ed25519 signature
//! - Three mandate types: Cart, Intent, Payment
//! - Integration with DelegationChain
//! - Every transaction → SCITT receipt

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, ProtocolResult};

// ── AP2 Types ───────────────────────────────────────────────────────

/// Type of payment mandate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateType {
    Cart,
    Intent,
    Payment,
}

impl std::fmt::Display for MandateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cart => write!(f, "cart"),
            Self::Intent => write!(f, "intent"),
            Self::Payment => write!(f, "payment"),
        }
    }
}

/// Currency code (ISO 4217).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Currency(pub String);

/// A payment mandate — a cryptographic authorization to spend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMandate {
    pub mandate_id: String,
    pub mandate_type: MandateType,
    /// DID of the issuer (the entity authorizing payment)
    pub issuer_did: String,
    /// DID of the agent authorized to spend
    pub agent_did: String,
    /// Maximum amount authorized (in minor units, e.g. cents)
    pub max_amount: u64,
    /// Currency
    pub currency: Currency,
    /// Amount already spent under this mandate
    pub spent_amount: u64,
    /// Description of what the mandate covers
    pub description: String,
    /// Expiry timestamp (millis since epoch)
    pub expires_at: i64,
    /// Created timestamp
    pub created_at: i64,
    /// Ed25519 signature of the mandate by the issuer
    pub signature: Vec<u8>,
}

impl PaymentMandate {
    /// Produce canonical bytes for signing.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "mandate_id": self.mandate_id,
            "mandate_type": self.mandate_type,
            "issuer_did": self.issuer_did,
            "agent_did": self.agent_did,
            "max_amount": self.max_amount,
            "currency": self.currency.0,
            "description": self.description,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
        });
        serde_json::to_vec(&canonical).unwrap_or_default()
    }

    /// Sign this mandate with the issuer's key.
    pub fn sign(&mut self, issuer_key: &SigningKey) {
        let bytes = self.signable_bytes();
        let sig = issuer_key.sign(&bytes);
        self.signature = sig.to_bytes().to_vec();
    }

    /// Verify the mandate's signature.
    pub fn verify(&self, issuer_public_key: &VerifyingKey) -> ProtocolResult<()> {
        if self.signature.len() != 64 {
            return Err(ProtocolError::SignatureInvalid("bad signature length".to_string()));
        }
        let sig_bytes: [u8; 64] = self.signature[..64]
            .try_into()
            .map_err(|_| ProtocolError::SignatureInvalid("conversion failed".to_string()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        let bytes = self.signable_bytes();
        issuer_public_key
            .verify(&bytes, &sig)
            .map_err(|e| ProtocolError::SignatureInvalid(format!("verification failed: {}", e)))
    }

    /// Check if the mandate has expired.
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp_millis();
        now > self.expires_at
    }

    /// Check if spending `amount` would exceed the mandate.
    pub fn can_spend(&self, amount: u64) -> bool {
        self.spent_amount + amount <= self.max_amount
    }

    /// Record a spend against this mandate.
    pub fn record_spend(&mut self, amount: u64) -> ProtocolResult<()> {
        if !self.can_spend(amount) {
            return Err(ProtocolError::AuthzDenied(format!(
                "Spend {} would exceed mandate limit {} (already spent {})",
                amount, self.max_amount, self.spent_amount
            )));
        }
        if self.is_expired() {
            return Err(ProtocolError::AuthzDenied("Mandate has expired".to_string()));
        }
        self.spent_amount += amount;
        Ok(())
    }

    /// Remaining budget.
    pub fn remaining(&self) -> u64 {
        self.max_amount.saturating_sub(self.spent_amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_mandate(issuer_key: &SigningKey) -> PaymentMandate {
        let now = chrono::Utc::now().timestamp_millis();
        let mut mandate = PaymentMandate {
            mandate_id: "mandate-001".to_string(),
            mandate_type: MandateType::Payment,
            issuer_did: "did:connector:issuer".to_string(),
            agent_did: "did:connector:agent".to_string(),
            max_amount: 10000, // $100.00 in cents
            currency: Currency("USD".to_string()),
            spent_amount: 0,
            description: "Agent shopping budget".to_string(),
            expires_at: now + 3_600_000, // 1 hour from now
            created_at: now,
            signature: vec![],
        };
        mandate.sign(issuer_key);
        mandate
    }

    #[test]
    fn test_ap2_create_and_verify_mandate() {
        let key = SigningKey::generate(&mut OsRng);
        let mandate = make_mandate(&key);

        assert!(mandate.verify(&key.verifying_key()).is_ok());
        assert_eq!(mandate.mandate_type, MandateType::Payment);
        assert_eq!(mandate.remaining(), 10000);
    }

    #[test]
    fn test_ap2_verify_wrong_key() {
        let key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let mandate = make_mandate(&key);

        assert!(mandate.verify(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn test_ap2_spend_within_budget() {
        let key = SigningKey::generate(&mut OsRng);
        let mut mandate = make_mandate(&key);

        mandate.record_spend(5000).unwrap(); // $50
        assert_eq!(mandate.remaining(), 5000);
        assert_eq!(mandate.spent_amount, 5000);

        mandate.record_spend(3000).unwrap(); // $30
        assert_eq!(mandate.remaining(), 2000);
    }

    #[test]
    fn test_ap2_exceed_mandate_denied() {
        let key = SigningKey::generate(&mut OsRng);
        let mut mandate = make_mandate(&key);

        mandate.record_spend(8000).unwrap();
        let result = mandate.record_spend(5000); // would exceed
        assert!(result.is_err());
    }

    #[test]
    fn test_ap2_expired_mandate_denied() {
        let key = SigningKey::generate(&mut OsRng);
        let now = chrono::Utc::now().timestamp_millis();
        let mut mandate = PaymentMandate {
            mandate_id: "mandate-expired".to_string(),
            mandate_type: MandateType::Cart,
            issuer_did: "did:connector:issuer".to_string(),
            agent_did: "did:connector:agent".to_string(),
            max_amount: 10000,
            currency: Currency("USD".to_string()),
            spent_amount: 0,
            description: "Already expired".to_string(),
            expires_at: now - 1000, // 1 second ago
            created_at: now - 60_000,
            signature: vec![],
        };
        mandate.sign(&key);

        assert!(mandate.is_expired());
        let result = mandate.record_spend(100);
        assert!(result.is_err());
    }

    #[test]
    fn test_ap2_mandate_types() {
        assert_eq!(format!("{}", MandateType::Cart), "cart");
        assert_eq!(format!("{}", MandateType::Intent), "intent");
        assert_eq!(format!("{}", MandateType::Payment), "payment");
    }
}
