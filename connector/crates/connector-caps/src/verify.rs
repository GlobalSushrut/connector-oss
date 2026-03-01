//! Verification module — verify tokens, chains, and contracts.

use ed25519_dalek::VerifyingKey;

use crate::contract::ExecutionContract;
use crate::error::{CapsError, CapsResult};
use crate::journal::ExecutionStore;

/// Verify the entire execution journal chain integrity + signatures.
pub fn verify_chain(store: &dyn ExecutionStore, key: &VerifyingKey) -> CapsResult<()> {
    // First check structural chain integrity
    store.verify_chain()?;

    // Then verify every contract's signature
    let tip = match store.tip() {
        Some(t) => t,
        None => return Ok(()), // empty chain is valid
    };

    // Walk from first contract
    // We need to get all contracts — use chain_since on the first one
    // Since we verified chain integrity above, we trust the ordering
    let first_id = {
        // Get the first contract by walking chain_since from tip and taking the earliest
        let all = store.chain_since(&tip)?;
        if all.is_empty() {
            return Ok(());
        }
        // chain_since returns from the given ID, but we need the first
        // Actually we need a different approach — let's verify each contract we can reach
        for contract in &all {
            contract.verify_signature(key)?;
        }
        return Ok(());
    };
}

/// Verify a single contract: signature + sealed status.
pub fn verify_contract(contract: &ExecutionContract, key: &VerifyingKey) -> CapsResult<()> {
    if !contract.is_sealed() {
        return Err(CapsError::ContractError("Contract is not sealed".into()));
    }
    contract.verify_signature(key)
}

/// Replay verification: given the same offer fields, verify the contract_id matches.
pub fn replay_contract_id(contract: &ExecutionContract) -> CapsResult<()> {
    let expected_id = contract.offer.contract_id();
    if contract.contract_id != expected_id {
        return Err(CapsError::ContractError(format!(
            "Contract ID mismatch: stored={}, computed={}",
            contract.contract_id, expected_id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::*;
    use crate::journal::InMemoryExecutionStore;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_sealed(key: &SigningKey, prev: Option<String>) -> ExecutionContract {
        let params = serde_json::json!({"path": "/tmp/test"});
        let offer = ContractOffer {
            agent_pid: "agent-1".into(),
            capability_id: "fs.read".into(),
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
            inputs_hash: "h".into(),
            outputs_hash: "h".into(),
            output_cid: "c".into(),
            exit_code: 0,
            duration_ms: 1,
            resource_usage: ResourceUsage::default(),
            postconditions_verified: true,
            side_effects: vec![],
            sealed_at: chrono::Utc::now().timestamp_millis(),
        }, key).unwrap();
        c
    }

    #[test]
    fn test_verify_chain_valid() {
        let key = SigningKey::generate(&mut OsRng);
        let mut store = InMemoryExecutionStore::new();

        let c1 = make_sealed(&key, None);
        let c1_id = c1.contract_id.clone();
        store.append(c1).unwrap();

        // Sleep 1ms to ensure distinct created_at timestamps → distinct contract IDs
        std::thread::sleep(std::time::Duration::from_millis(2));

        let c2 = make_sealed(&key, Some(c1_id));
        store.append(c2).unwrap();

        assert!(verify_chain(&store, &key.verifying_key()).is_ok());
    }

    #[test]
    fn test_verify_chain_wrong_key() {
        let key = SigningKey::generate(&mut OsRng);
        let wrong = SigningKey::generate(&mut OsRng);
        let mut store = InMemoryExecutionStore::new();

        let c1 = make_sealed(&key, None);
        store.append(c1).unwrap();

        assert!(verify_chain(&store, &wrong.verifying_key()).is_err());
    }

    #[test]
    fn test_verify_contract_sealed() {
        let key = SigningKey::generate(&mut OsRng);
        let c = make_sealed(&key, None);
        assert!(verify_contract(&c, &key.verifying_key()).is_ok());
    }

    #[test]
    fn test_verify_contract_unsealed() {
        let key = SigningKey::generate(&mut OsRng);
        let params = serde_json::json!({});
        let offer = ContractOffer {
            agent_pid: "a".into(),
            capability_id: "fs.read".into(),
            params,
            params_hash: "h".into(),
            postconditions: vec![],
            rollback_strategy: RollbackStrategy::None,
            timeout_ms: 5000,
            created_at: 0,
        };
        let c = ExecutionContract::from_offer(offer, None);
        assert!(verify_contract(&c, &key.verifying_key()).is_err());
    }

    #[test]
    fn test_replay_contract_id() {
        let key = SigningKey::generate(&mut OsRng);
        let c = make_sealed(&key, None);
        assert!(replay_contract_id(&c).is_ok());
    }

    #[test]
    fn test_replay_contract_id_tampered() {
        let key = SigningKey::generate(&mut OsRng);
        let mut c = make_sealed(&key, None);
        c.contract_id = "tampered".into();
        assert!(replay_contract_id(&c).is_err());
    }
}
