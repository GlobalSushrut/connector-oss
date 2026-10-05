//! Execution Contract — 3-phase cryptographic agreement.
//!
//! Phase 1 (Offer): agent declares capability + params + postconditions + rollback
//! Phase 2 (Grant): kernel evaluates policy, issues token, selects runner
//! Phase 3 (Receipt): execution result + postcondition verification + seal
//!
//! Each contract has a deterministic CID, is Ed25519 signed, and forms a hash chain.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{CapsError, CapsResult};

// ── Contract Types ──────────────────────────────────────────────────

/// Rollback strategy if postconditions fail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStrategy {
    DeleteCreated,
    RestoreBackup,
    CompensatingOp { capability_id: String },
    None,
}

/// Resource usage during execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_us: u64,
    pub mem_peak_bytes: u64,
    pub io_bytes: u64,
}

/// Side effect recorded during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideEffect {
    pub description: String,
    pub reversible: bool,
}

/// Phase 1: Offer — agent declares what it wants to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractOffer {
    pub agent_pid: String,
    pub capability_id: String,
    pub params: serde_json::Value,
    pub params_hash: String,
    pub postconditions: Vec<String>,
    pub rollback_strategy: RollbackStrategy,
    pub timeout_ms: u64,
    pub created_at: i64,
}

impl ContractOffer {
    /// Compute deterministic contract ID from offer fields.
    pub fn contract_id(&self) -> String {
        let canonical = serde_json::json!({
            "agent_pid": self.agent_pid,
            "capability_id": self.capability_id,
            "params_hash": self.params_hash,
            "postconditions": self.postconditions,
            "rollback_strategy": self.rollback_strategy,
            "timeout_ms": self.timeout_ms,
            "created_at": self.created_at,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        let hash = Sha256::digest(&bytes);
        format!("cid:{}", hex::encode(hash))
    }

    /// Compute SHA-256 hash of params.
    pub fn compute_params_hash(params: &serde_json::Value) -> String {
        let bytes = serde_json::to_vec(params).unwrap_or_default();
        let hash = Sha256::digest(&bytes);
        hex::encode(hash)
    }
}

/// Phase 2: Grant — kernel authorizes execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractGrant {
    pub policy_decision: String,
    pub token_id: String,
    pub runner_id: String,
    pub runner_digest: String,
    pub granted_at: i64,
}

/// Phase 3: Receipt — actual execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractReceipt {
    pub inputs_hash: String,
    pub outputs_hash: String,
    pub output_cid: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub resource_usage: ResourceUsage,
    pub postconditions_verified: bool,
    pub side_effects: Vec<SideEffect>,
    pub sealed_at: i64,
}

// ── Execution Contract ──────────────────────────────────────────────

/// The complete execution contract — all 3 phases + chain link + signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContract {
    /// Deterministic ID from offer
    pub contract_id: String,
    /// Phase 1
    pub offer: ContractOffer,
    /// Phase 2 (filled after policy evaluation)
    pub grant: Option<ContractGrant>,
    /// Phase 3 (filled after execution)
    pub receipt: Option<ContractReceipt>,
    /// Link to previous contract (hash chain)
    pub prev_contract_id: Option<String>,
    /// Ed25519 signature over the sealed contract
    pub signature: Vec<u8>,
}

impl ExecutionContract {
    /// Create a new contract from an offer.
    pub fn from_offer(offer: ContractOffer, prev_contract_id: Option<String>) -> Self {
        let contract_id = offer.contract_id();
        Self {
            contract_id,
            offer,
            grant: None,
            receipt: None,
            prev_contract_id,
            signature: vec![],
        }
    }

    /// Apply the grant phase.
    pub fn apply_grant(&mut self, grant: ContractGrant) -> CapsResult<()> {
        if self.grant.is_some() {
            return Err(CapsError::ContractError("Already granted".into()));
        }
        self.grant = Some(grant);
        Ok(())
    }

    /// Seal the contract with the receipt and sign it.
    pub fn seal(&mut self, receipt: ContractReceipt, signing_key: &SigningKey) -> CapsResult<()> {
        if self.grant.is_none() {
            return Err(CapsError::ContractError("Cannot seal without grant".into()));
        }
        if self.receipt.is_some() {
            return Err(CapsError::ContractError("Already sealed".into()));
        }
        self.receipt = Some(receipt);

        let bytes = self.signable_bytes();
        let sig = signing_key.sign(&bytes);
        self.signature = sig.to_bytes().to_vec();
        Ok(())
    }

    /// Check if the contract is fully sealed (all 3 phases complete + signed).
    pub fn is_sealed(&self) -> bool {
        self.grant.is_some() && self.receipt.is_some() && self.signature.len() == 64
    }

    /// Canonical bytes for signing.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "contract_id": self.contract_id,
            "offer": self.offer,
            "grant": self.grant,
            "receipt": self.receipt,
            "prev_contract_id": self.prev_contract_id,
        });
        serde_json::to_vec(&canonical).unwrap_or_default()
    }

    /// Verify the contract's signature.
    pub fn verify_signature(&self, key: &VerifyingKey) -> CapsResult<()> {
        if self.signature.len() != 64 {
            return Err(CapsError::SignatureError("bad length".into()));
        }
        let sig_bytes: [u8; 64] = self.signature[..64]
            .try_into()
            .map_err(|_| CapsError::SignatureError("conversion".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        let bytes = self.signable_bytes();
        key.verify(&bytes, &sig)
            .map_err(|e| CapsError::SignatureError(e.to_string()))
    }
}

// hex encoding helper (inline, no dep needed beyond sha2)
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_offer() -> ContractOffer {
        let params = serde_json::json!({"path": "/tmp/test.txt"});
        ContractOffer {
            agent_pid: "agent-1".to_string(),
            capability_id: "fs.read".to_string(),
            params: params.clone(),
            params_hash: ContractOffer::compute_params_hash(&params),
            postconditions: vec!["exit_code_zero".to_string()],
            rollback_strategy: RollbackStrategy::None,
            timeout_ms: 5000,
            created_at: chrono::Utc::now().timestamp_millis(),
        }
    }

    fn make_grant() -> ContractGrant {
        ContractGrant {
            policy_decision: "allow".to_string(),
            token_id: "token-001".to_string(),
            runner_id: "noop".to_string(),
            runner_digest: "sha256:abc".to_string(),
            granted_at: chrono::Utc::now().timestamp_millis(),
        }
    }

    fn make_receipt() -> ContractReceipt {
        ContractReceipt {
            inputs_hash: "sha256:inputs".to_string(),
            outputs_hash: "sha256:outputs".to_string(),
            output_cid: "cid:output".to_string(),
            exit_code: 0,
            duration_ms: 42,
            resource_usage: ResourceUsage {
                cpu_us: 1000,
                mem_peak_bytes: 4096,
                io_bytes: 256,
            },
            postconditions_verified: true,
            side_effects: vec![],
            sealed_at: chrono::Utc::now().timestamp_millis(),
        }
    }

    #[test]
    fn test_contract_deterministic_id() {
        let offer = make_offer();
        let id1 = offer.contract_id();
        let id2 = offer.contract_id();
        assert_eq!(id1, id2, "Same offer should produce same contract ID");
        assert!(id1.starts_with("cid:"));
    }

    #[test]
    fn test_contract_lifecycle() {
        let key = SigningKey::generate(&mut OsRng);
        let mut contract = ExecutionContract::from_offer(make_offer(), None);

        assert!(!contract.is_sealed());
        assert!(contract.grant.is_none());
        assert!(contract.receipt.is_none());

        contract.apply_grant(make_grant()).unwrap();
        assert!(!contract.is_sealed());

        contract.seal(make_receipt(), &key).unwrap();
        assert!(contract.is_sealed());
    }

    #[test]
    fn test_contract_signature_verify() {
        let key = SigningKey::generate(&mut OsRng);
        let mut contract = ExecutionContract::from_offer(make_offer(), None);
        contract.apply_grant(make_grant()).unwrap();
        contract.seal(make_receipt(), &key).unwrap();

        assert!(contract.verify_signature(&key.verifying_key()).is_ok());

        let wrong_key = SigningKey::generate(&mut OsRng);
        assert!(contract.verify_signature(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn test_contract_chain_link() {
        let key = SigningKey::generate(&mut OsRng);

        let mut c1 = ExecutionContract::from_offer(make_offer(), None);
        c1.apply_grant(make_grant()).unwrap();
        c1.seal(make_receipt(), &key).unwrap();

        let mut c2 = ExecutionContract::from_offer(make_offer(), Some(c1.contract_id.clone()));
        assert_eq!(c2.prev_contract_id, Some(c1.contract_id.clone()));
        c2.apply_grant(make_grant()).unwrap();
        c2.seal(make_receipt(), &key).unwrap();

        assert!(c2.is_sealed());
    }

    #[test]
    fn test_contract_seal_without_grant_fails() {
        let key = SigningKey::generate(&mut OsRng);
        let mut contract = ExecutionContract::from_offer(make_offer(), None);
        assert!(contract.seal(make_receipt(), &key).is_err());
    }

    #[test]
    fn test_contract_double_grant_fails() {
        let mut contract = ExecutionContract::from_offer(make_offer(), None);
        contract.apply_grant(make_grant()).unwrap();
        assert!(contract.apply_grant(make_grant()).is_err());
    }

    #[test]
    fn test_contract_double_seal_fails() {
        let key = SigningKey::generate(&mut OsRng);
        let mut contract = ExecutionContract::from_offer(make_offer(), None);
        contract.apply_grant(make_grant()).unwrap();
        contract.seal(make_receipt(), &key).unwrap();
        assert!(contract.seal(make_receipt(), &key).is_err());
    }

    #[test]
    fn test_rollback_strategy_serde() {
        let s = RollbackStrategy::CompensatingOp { capability_id: "fs.delete".to_string() };
        let json = serde_json::to_string(&s).unwrap();
        let deserialized: RollbackStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, s);
    }
}
