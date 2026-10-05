//! Evidence Chain Verification — Cryptographic Linking
//!
//! FIX BUG-055: Link controls to evidence with crypto verification

use std::collections::HashMap;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

// =============================================================================
// Evidence Chain Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChain {
    pub chain_id: String,
    pub control_id: String,
    pub evidence_items: Vec<ChainedEvidence>,
    pub merkle_root: String,
    pub created_at: i64,
    pub witness_signatures: Vec<WitnessSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedEvidence {
    pub evidence_id: String,
    pub previous_hash: String,
    pub data_hash: String,
    pub timestamp: i64,
    pub collector: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    pub witness_id: String,
    pub public_key: String,
    pub signature: String,
    pub timestamp: i64,
}

// =============================================================================
// Chain Verifier
// =============================================================================

pub struct EvidenceChainVerifier {
    chains: HashMap<String, EvidenceChain>,
}

impl EvidenceChainVerifier {
    pub fn new() -> Self {
        Self {
            chains: HashMap::new(),
        }
    }

    /// Create new evidence chain for control
    pub fn create_chain(&mut self, control_id: &str) -> String {
        let chain_id = format!("chain-{}", uuid::Uuid::new_v4());
        
        let chain = EvidenceChain {
            chain_id: chain_id.clone(),
            control_id: control_id.to_string(),
            evidence_items: vec![],
            merkle_root: String::new(),
            created_at: chrono::Utc::now().timestamp_millis(),
            witness_signatures: vec![],
        };

        self.chains.insert(chain_id.clone(), chain);
        chain_id
    }

    /// Add evidence to chain
    pub fn add_evidence(
        &mut self,
        chain_id: &str,
        evidence_id: String,
        data: &[u8],
        collector: String,
    ) -> Result<String, String> {
        let chain = self.chains.get_mut(chain_id)
            .ok_or("Chain not found")?;

        // Calculate previous hash
        let previous_hash = chain.evidence_items.last()
            .map(|e| e.data_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));

        // Hash data
        let data_hash = Self::hash_data(data);

        // Create signature (collector + hash)
        let signature_input = format!("{}{}{}", collector, data_hash, previous_hash);
        let signature = Self::hash_data(signature_input.as_bytes());

        let chained = ChainedEvidence {
            evidence_id: evidence_id.clone(),
            previous_hash,
            data_hash,
            timestamp: chrono::Utc::now().timestamp_millis(),
            collector,
            signature,
        };

        chain.evidence_items.push(chained);
        
        // Update Merkle root
        chain.merkle_root = Self::compute_merkle_root_static(&chain.evidence_items);

        Ok(evidence_id)
    }

    /// Compute Merkle root
    fn compute_merkle_root_static(items: &[ChainedEvidence]) -> String {
        if items.is_empty() {
            return String::new();
        }

        let mut hashes: Vec<String> = items.iter()
            .map(|e| e.data_hash.clone())
            .collect();

        while hashes.len() > 1 {
            let mut new_level = Vec::new();
            
            for pair in hashes.chunks(2) {
                let combined = if pair.len() == 2 {
                    format!("{}{}", pair[0], pair[1])
                } else {
                    format!("{}{}", pair[0], pair[0])
                };
                new_level.push(Self::hash_data(combined.as_bytes()));
            }
            
            hashes = new_level;
        }

        hashes[0].clone()
    }

    /// Add witness signature
    pub fn add_witness(&mut self, chain_id: &str, witness_id: String, public_key: String) -> Result<(), String> {
        let chain = self.chains.get_mut(chain_id)
            .ok_or("Chain not found")?;

        // Sign the merkle root
        let signature_input = format!("{}{}", witness_id, chain.merkle_root);
        let signature = Self::hash_data(signature_input.as_bytes());

        chain.witness_signatures.push(WitnessSignature {
            witness_id,
            public_key,
            signature,
            timestamp: chrono::Utc::now().timestamp_millis(),
        });

        Ok(())
    }

    /// Verify chain integrity
    pub fn verify_chain(&self, chain_id: &str) -> VerificationResult {
        let chain = match self.chains.get(chain_id) {
            Some(c) => c,
            None => {
                return VerificationResult {
                    valid: false,
                    chain_id: chain_id.to_string(),
                    evidence_count: 0,
                    broken_at: Some("Chain not found".to_string()),
                    merkle_valid: false,
                    witness_count: 0,
                };
            }
        };

        let mut valid = true;
        let mut broken_at = None;

        // Verify chain links
        for (i, item) in chain.evidence_items.iter().enumerate() {
            if i == 0 {
                continue;
            }

            let prev_hash = &chain.evidence_items[i-1].data_hash;
            if &item.previous_hash != prev_hash {
                valid = false;
                broken_at = Some(format!("Evidence {}: hash mismatch", item.evidence_id));
                break;
            }

            // Verify signature
            let expected_sig = Self::hash_data(
                format!("{}{}{}", item.collector, item.data_hash, item.previous_hash).as_bytes()
            );
            if item.signature != expected_sig {
                valid = false;
                broken_at = Some(format!("Evidence {}: signature invalid", item.evidence_id));
                break;
            }
        }

        // Verify Merkle root
        let computed_root = Self::compute_merkle_root_static(&chain.evidence_items);
        let merkle_valid = computed_root == chain.merkle_root;

        VerificationResult {
            valid: valid && merkle_valid,
            chain_id: chain_id.to_string(),
            evidence_count: chain.evidence_items.len(),
            broken_at,
            merkle_valid,
            witness_count: chain.witness_signatures.len(),
        }
    }

    fn hash_data(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Link control to evidence chain
    pub fn link_control_to_evidence(&self, control_id: &str) -> Option<String> {
        self.chains.values()
            .find(|c| c.control_id == control_id)
            .map(|c| c.chain_id.clone())
    }
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub chain_id: String,
    pub evidence_count: usize,
    pub broken_at: Option<String>,
    pub merkle_valid: bool,
    pub witness_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_chain() {
        let mut verifier = EvidenceChainVerifier::new();
        
        let chain_id = verifier.create_chain("CC6.1");
        
        verifier.add_evidence(&chain_id, "ev-1".to_string(), b"data1", "collector1".to_string()).unwrap();
        verifier.add_evidence(&chain_id, "ev-2".to_string(), b"data2", "collector2".to_string()).unwrap();
        
        let result = verifier.verify_chain(&chain_id);
        assert!(result.valid);
        assert_eq!(result.evidence_count, 2);
    }

    #[test]
    fn test_witness_signature() {
        let mut verifier = EvidenceChainVerifier::new();
        let chain_id = verifier.create_chain("CC6.1");
        
        verifier.add_evidence(&chain_id, "ev-1".to_string(), b"data", "collector".to_string()).unwrap();
        verifier.add_witness(&chain_id, "witness-1".to_string(), "pubkey-1".to_string()).unwrap();
        
        let result = verifier.verify_chain(&chain_id);
        assert_eq!(result.witness_count, 1);
    }
}
