//! Execution Journal — append-only, hash-chained ledger of all execution contracts.
//!
//! Provides tamper-evident storage with Merkle root for SCITT publishability.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::contract::ExecutionContract;
use crate::error::{CapsError, CapsResult};

/// Trait for execution journal storage.
pub trait ExecutionStore: Send + Sync {
    /// Append a sealed contract. Verifies chain link.
    fn append(&mut self, contract: ExecutionContract) -> CapsResult<()>;

    /// Get contract by ID.
    fn get(&self, contract_id: &str) -> CapsResult<&ExecutionContract>;

    /// Get all contracts since a given contract ID (inclusive).
    fn chain_since(&self, contract_id: &str) -> CapsResult<Vec<&ExecutionContract>>;

    /// Verify the entire chain integrity.
    fn verify_chain(&self) -> CapsResult<()>;

    /// Compute Merkle root over all contract IDs.
    fn merkle_root(&self) -> String;

    /// Query contracts by agent.
    fn query_by_agent(&self, agent_pid: &str) -> Vec<&ExecutionContract>;

    /// Query contracts by capability.
    fn query_by_capability(&self, capability_id: &str) -> Vec<&ExecutionContract>;

    /// Total number of contracts in the journal.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// ID of the most recent contract (tip of the chain).
    fn tip(&self) -> Option<String>;
}

/// In-memory implementation of ExecutionStore.
pub struct InMemoryExecutionStore {
    contracts: HashMap<String, ExecutionContract>,
    /// Ordered list of contract IDs (append order).
    chain: Vec<String>,
}

impl InMemoryExecutionStore {
    pub fn new() -> Self {
        Self {
            contracts: HashMap::new(),
            chain: Vec::new(),
        }
    }
}

impl Default for InMemoryExecutionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionStore for InMemoryExecutionStore {
    fn append(&mut self, contract: ExecutionContract) -> CapsResult<()> {
        if !contract.is_sealed() {
            return Err(CapsError::ContractError("Cannot append unsealed contract".into()));
        }

        // Verify chain link
        let expected_prev = self.chain.last().cloned();
        if contract.prev_contract_id != expected_prev {
            return Err(CapsError::ChainIntegrity(format!(
                "Expected prev_contract_id {:?}, got {:?}",
                expected_prev, contract.prev_contract_id
            )));
        }

        // Check for duplicate
        if self.contracts.contains_key(&contract.contract_id) {
            return Err(CapsError::ContractError(format!(
                "Duplicate contract ID: {}",
                contract.contract_id
            )));
        }

        self.chain.push(contract.contract_id.clone());
        self.contracts.insert(contract.contract_id.clone(), contract);
        Ok(())
    }

    fn get(&self, contract_id: &str) -> CapsResult<&ExecutionContract> {
        self.contracts
            .get(contract_id)
            .ok_or_else(|| CapsError::ContractError(format!("Contract not found: {}", contract_id)))
    }

    fn chain_since(&self, contract_id: &str) -> CapsResult<Vec<&ExecutionContract>> {
        let start_idx = self.chain.iter().position(|id| id == contract_id)
            .ok_or_else(|| CapsError::ContractError(format!("Contract not in chain: {}", contract_id)))?;

        Ok(self.chain[start_idx..]
            .iter()
            .filter_map(|id| self.contracts.get(id))
            .collect())
    }

    fn verify_chain(&self) -> CapsResult<()> {
        let mut expected_prev: Option<String> = None;

        for cid in &self.chain {
            let contract = self.contracts.get(cid).ok_or_else(|| {
                CapsError::ChainIntegrity(format!("Missing contract in chain: {}", cid))
            })?;

            if contract.prev_contract_id != expected_prev {
                return Err(CapsError::ChainIntegrity(format!(
                    "Chain broken at {}: expected prev {:?}, got {:?}",
                    cid, expected_prev, contract.prev_contract_id
                )));
            }

            if !contract.is_sealed() {
                return Err(CapsError::ChainIntegrity(format!(
                    "Unsealed contract in chain: {}",
                    cid
                )));
            }

            expected_prev = Some(cid.clone());
        }

        Ok(())
    }

    fn merkle_root(&self) -> String {
        if self.chain.is_empty() {
            return "0".repeat(64);
        }

        // Simple binary Merkle tree over contract IDs
        let mut hashes: Vec<[u8; 32]> = self.chain.iter().map(|cid| {
            let mut hasher = Sha256::new();
            hasher.update(cid.as_bytes());
            hasher.finalize().into()
        }).collect();

        while hashes.len() > 1 {
            let mut next = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(chunk[1]);
                } else {
                    hasher.update(chunk[0]); // duplicate odd leaf
                }
                next.push(hasher.finalize().into());
            }
            hashes = next;
        }

        hashes[0].iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn query_by_agent(&self, agent_pid: &str) -> Vec<&ExecutionContract> {
        self.chain
            .iter()
            .filter_map(|id| self.contracts.get(id))
            .filter(|c| c.offer.agent_pid == agent_pid)
            .collect()
    }

    fn query_by_capability(&self, capability_id: &str) -> Vec<&ExecutionContract> {
        self.chain
            .iter()
            .filter_map(|id| self.contracts.get(id))
            .filter(|c| c.offer.capability_id == capability_id)
            .collect()
    }

    fn len(&self) -> usize {
        self.chain.len()
    }

    fn tip(&self) -> Option<String> {
        self.chain.last().cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_sealed_contract(
        key: &SigningKey,
        agent: &str,
        cap: &str,
        prev: Option<String>,
    ) -> ExecutionContract {
        let params = serde_json::json!({"path": "/tmp/test"});
        let offer = ContractOffer {
            agent_pid: agent.to_string(),
            capability_id: cap.to_string(),
            params: params.clone(),
            params_hash: ContractOffer::compute_params_hash(&params),
            postconditions: vec![],
            rollback_strategy: RollbackStrategy::None,
            timeout_ms: 5000,
            created_at: chrono::Utc::now().timestamp_millis(),
        };
        let mut c = ExecutionContract::from_offer(offer, prev);
        c.apply_grant(ContractGrant {
            policy_decision: "allow".into(),
            token_id: "tok".into(),
            runner_id: "noop".into(),
            runner_digest: "sha256:noop".into(),
            granted_at: chrono::Utc::now().timestamp_millis(),
        }).unwrap();
        c.seal(ContractReceipt {
            inputs_hash: "h1".into(),
            outputs_hash: "h2".into(),
            output_cid: "cid:out".into(),
            exit_code: 0,
            duration_ms: 10,
            resource_usage: ResourceUsage::default(),
            postconditions_verified: true,
            side_effects: vec![],
            sealed_at: chrono::Utc::now().timestamp_millis(),
        }, key).unwrap();
        c
    }

    #[test]
    fn test_journal_append_and_get() {
        let key = SigningKey::generate(&mut OsRng);
        let mut store = InMemoryExecutionStore::new();

        let c1 = make_sealed_contract(&key, "agent-1", "fs.read", None);
        let c1_id = c1.contract_id.clone();
        store.append(c1).unwrap();

        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&c1_id).unwrap().offer.agent_pid, "agent-1");
    }

    #[test]
    fn test_journal_chain() {
        let key = SigningKey::generate(&mut OsRng);
        let mut store = InMemoryExecutionStore::new();

        let c1 = make_sealed_contract(&key, "agent-1", "fs.read", None);
        let c1_id = c1.contract_id.clone();
        store.append(c1).unwrap();

        let c2 = make_sealed_contract(&key, "agent-1", "fs.write", Some(c1_id.clone()));
        store.append(c2).unwrap();

        let c3 = make_sealed_contract(&key, "agent-2", "net.http_get", store.tip());
        store.append(c3).unwrap();

        assert_eq!(store.len(), 3);
        assert!(store.verify_chain().is_ok());
    }

    #[test]
    fn test_journal_broken_chain_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let mut store = InMemoryExecutionStore::new();

        let c1 = make_sealed_contract(&key, "agent-1", "fs.read", None);
        store.append(c1).unwrap();

        // Try to append with wrong prev
        let bad = make_sealed_contract(&key, "agent-1", "fs.write", Some("wrong-id".into()));
        assert!(store.append(bad).is_err());
    }

    #[test]
    fn test_journal_merkle_root_changes() {
        let key = SigningKey::generate(&mut OsRng);
        let mut store = InMemoryExecutionStore::new();

        let root0 = store.merkle_root();

        let c1 = make_sealed_contract(&key, "agent-1", "fs.read", None);
        store.append(c1).unwrap();
        let root1 = store.merkle_root();

        let c2 = make_sealed_contract(&key, "agent-1", "fs.write", store.tip());
        store.append(c2).unwrap();
        let root2 = store.merkle_root();

        assert_ne!(root0, root1);
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_journal_query_by_agent() {
        let key = SigningKey::generate(&mut OsRng);
        let mut store = InMemoryExecutionStore::new();

        let c1 = make_sealed_contract(&key, "agent-1", "fs.read", None);
        store.append(c1).unwrap();

        let c2 = make_sealed_contract(&key, "agent-2", "fs.write", store.tip());
        store.append(c2).unwrap();

        let c3 = make_sealed_contract(&key, "agent-1", "net.http_get", store.tip());
        store.append(c3).unwrap();

        assert_eq!(store.query_by_agent("agent-1").len(), 2);
        assert_eq!(store.query_by_agent("agent-2").len(), 1);
        assert_eq!(store.query_by_agent("agent-3").len(), 0);
    }

    #[test]
    fn test_journal_query_by_capability() {
        let key = SigningKey::generate(&mut OsRng);
        let mut store = InMemoryExecutionStore::new();

        let c1 = make_sealed_contract(&key, "agent-1", "fs.read", None);
        store.append(c1).unwrap();

        let c2 = make_sealed_contract(&key, "agent-1", "fs.read", store.tip());
        store.append(c2).unwrap();

        assert_eq!(store.query_by_capability("fs.read").len(), 2);
        assert_eq!(store.query_by_capability("fs.write").len(), 0);
    }

    #[test]
    fn test_journal_chain_since() {
        let key = SigningKey::generate(&mut OsRng);
        let mut store = InMemoryExecutionStore::new();

        let c1 = make_sealed_contract(&key, "agent-1", "fs.read", None);
        let c1_id = c1.contract_id.clone();
        store.append(c1).unwrap();

        let c2 = make_sealed_contract(&key, "agent-1", "fs.write", store.tip());
        store.append(c2).unwrap();

        let c3 = make_sealed_contract(&key, "agent-1", "net.http_get", store.tip());
        store.append(c3).unwrap();

        let since = store.chain_since(&c1_id).unwrap();
        assert_eq!(since.len(), 3); // includes c1
    }

    #[test]
    fn test_journal_unsealed_rejected() {
        let mut store = InMemoryExecutionStore::new();
        let offer = ContractOffer {
            agent_pid: "a".into(),
            capability_id: "fs.read".into(),
            params: serde_json::json!({}),
            params_hash: "h".into(),
            postconditions: vec![],
            rollback_strategy: RollbackStrategy::None,
            timeout_ms: 5000,
            created_at: 0,
        };
        let c = ExecutionContract::from_offer(offer, None);
        assert!(store.append(c).is_err()); // not sealed
    }
}
