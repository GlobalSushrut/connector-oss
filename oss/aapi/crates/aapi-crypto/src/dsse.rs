//! DSSE (Dead Simple Signing Envelope) implementation
//!
//! DSSE provides a simple, secure envelope format for signing arbitrary payloads.
//! It binds the payload type to the signature, preventing type confusion attacks.
//!
//! Reference: https://github.com/secure-systems-lab/dsse

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{KeyId, KeyPair, KeyStore};
use crate::signing::sign_bytes;

/// DSSE Envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseEnvelope {
    /// Payload type URI (e.g., "application/vnd.aapi.vakya+json")
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64-encoded payload
    pub payload: String,
    /// Signatures over the PAE (Pre-Authentication Encoding)
    pub signatures: Vec<DsseSignature>,
}

/// DSSE Signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    /// Key ID used for signing
    #[serde(rename = "keyid")]
    pub key_id: String,
    /// Base64-encoded signature
    pub sig: String,
}

impl DsseEnvelope {
    /// Create a new DSSE envelope with a single signature
    pub fn sign(
        payload_type: impl Into<String>,
        payload: &[u8],
        key_pair: &KeyPair,
    ) -> CryptoResult<Self> {
        let payload_type = payload_type.into();
        
        // Compute PAE
        let pae = compute_pae(&payload_type, payload);
        
        // Sign the PAE
        let signature = sign_bytes(key_pair, &pae)?;
        
        use base64::Engine;
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        
        Ok(Self {
            payload_type,
            payload: payload_b64,
            signatures: vec![DsseSignature {
                key_id: key_pair.key_id.0.clone(),
                sig: signature,
            }],
        })
    }

    /// Add an additional signature to the envelope
    pub fn add_signature(&mut self, key_pair: &KeyPair) -> CryptoResult<()> {
        use base64::Engine;
        let payload = base64::engine::general_purpose::STANDARD
            .decode(&self.payload)?;
        
        let pae = compute_pae(&self.payload_type, &payload);
        let signature = sign_bytes(key_pair, &pae)?;
        
        self.signatures.push(DsseSignature {
            key_id: key_pair.key_id.0.clone(),
            sig: signature,
        });
        
        Ok(())
    }

    /// Get the decoded payload
    pub fn decode_payload(&self) -> CryptoResult<Vec<u8>> {
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.decode(&self.payload)?)
    }

    /// Verify all signatures in the envelope
    pub fn verify(&self, key_store: &KeyStore) -> CryptoResult<DsseVerification> {
        use base64::Engine;
        let payload = base64::engine::general_purpose::STANDARD
            .decode(&self.payload)?;
        
        let pae = compute_pae(&self.payload_type, &payload);
        
        let mut results = Vec::with_capacity(self.signatures.len());
        
        for sig in &self.signatures {
            let key_id = KeyId::new(&sig.key_id);
            
            match key_store.get_public_key(&key_id) {
                Ok(public_info) => {
                    match crate::signing::verify_bytes(&public_info, &pae, &sig.sig) {
                        Ok(valid) => {
                            results.push(SignatureVerification {
                                key_id: sig.key_id.clone(),
                                valid,
                                error: None,
                            });
                        }
                        Err(e) => {
                            results.push(SignatureVerification {
                                key_id: sig.key_id.clone(),
                                valid: false,
                                error: Some(e.to_string()),
                            });
                        }
                    }
                }
                Err(e) => {
                    results.push(SignatureVerification {
                        key_id: sig.key_id.clone(),
                        valid: false,
                        error: Some(e.to_string()),
                    });
                }
            }
        }
        
        let all_valid = results.iter().all(|r| r.valid);
        let valid_count = results.iter().filter(|r| r.valid).count();
        
        Ok(DsseVerification {
            all_valid,
            valid_count,
            total_count: results.len(),
            results,
        })
    }

    /// Verify with a minimum number of valid signatures (threshold)
    pub fn verify_threshold(&self, key_store: &KeyStore, threshold: usize) -> CryptoResult<bool> {
        let verification = self.verify(key_store)?;
        Ok(verification.valid_count >= threshold)
    }
}

/// Result of DSSE verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseVerification {
    pub all_valid: bool,
    pub valid_count: usize,
    pub total_count: usize,
    pub results: Vec<SignatureVerification>,
}

/// Individual signature verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureVerification {
    pub key_id: String,
    pub valid: bool,
    pub error: Option<String>,
}

/// Compute Pre-Authentication Encoding (PAE)
/// 
/// PAE format: "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(payload) + SP + payload
/// where SP is a space character and LEN is the decimal length
fn compute_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = Vec::new();
    
    // "DSSEv1 "
    pae.extend_from_slice(b"DSSEv1 ");
    
    // Length of payload type
    pae.extend_from_slice(payload_type.len().to_string().as_bytes());
    pae.push(b' ');
    
    // Payload type
    pae.extend_from_slice(payload_type.as_bytes());
    pae.push(b' ');
    
    // Length of payload
    pae.extend_from_slice(payload.len().to_string().as_bytes());
    pae.push(b' ');
    
    // Payload
    pae.extend_from_slice(payload);
    
    pae
}

/// AAPI-specific payload types
pub mod payload_types {
    pub const VAKYA: &str = "application/vnd.aapi.vakya+json";
    pub const PRAMANA: &str = "application/vnd.aapi.pramana+json";
    pub const CAPABILITY: &str = "application/vnd.aapi.capability+json";
    pub const EFFECT: &str = "application/vnd.aapi.effect+json";
}

/// Helper to create a signed VĀKYA envelope
pub fn sign_vakya_envelope(
    vakya_json: &[u8],
    key_pair: &KeyPair,
) -> CryptoResult<DsseEnvelope> {
    DsseEnvelope::sign(payload_types::VAKYA, vakya_json, key_pair)
}

/// Helper to create a signed PRAMĀṆA envelope
pub fn sign_pramana_envelope(
    pramana_json: &[u8],
    key_pair: &KeyPair,
) -> CryptoResult<DsseEnvelope> {
    DsseEnvelope::sign(payload_types::PRAMANA, pramana_json, key_pair)
}

/// Statement for in-toto style attestations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    /// Statement type (always "https://in-toto.io/Statement/v1")
    #[serde(rename = "_type")]
    pub statement_type: String,
    /// Subject of the statement
    pub subject: Vec<Subject>,
    /// Predicate type URI
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// Predicate content
    pub predicate: serde_json::Value,
}

/// Subject of a statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    /// Subject name/identifier
    pub name: String,
    /// Content digest
    pub digest: std::collections::HashMap<String, String>,
}

impl Statement {
    /// Create a new statement
    pub fn new(
        subject_name: impl Into<String>,
        subject_digest: impl Into<String>,
        predicate_type: impl Into<String>,
        predicate: serde_json::Value,
    ) -> Self {
        let mut digest = std::collections::HashMap::new();
        digest.insert("sha256".to_string(), subject_digest.into());
        
        Self {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![Subject {
                name: subject_name.into(),
                digest,
            }],
            predicate_type: predicate_type.into(),
            predicate,
        }
    }

    /// Sign the statement as a DSSE envelope
    pub fn sign(&self, key_pair: &KeyPair) -> CryptoResult<DsseEnvelope> {
        let json = serde_json::to_vec(self)?;
        DsseEnvelope::sign("application/vnd.in-toto+json", &json, key_pair)
    }
}

/// AAPI predicate types for in-toto statements
pub mod predicate_types {
    pub const VAKYA_EXECUTION: &str = "https://aapi.dev/predicate/vakya-execution/v1";
    pub const EFFECT_CAPTURE: &str = "https://aapi.dev/predicate/effect-capture/v1";
    pub const CAPABILITY_GRANT: &str = "https://aapi.dev/predicate/capability-grant/v1";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPurpose;

    #[test]
    fn test_dsse_sign_and_verify() {
        let key_store = KeyStore::new();
        let key_id = key_store.generate_key(KeyPurpose::General).unwrap();
        let key_pair = key_store.get_key(&key_id).unwrap();

        let payload = b"test payload data";
        let envelope = DsseEnvelope::sign("application/json", payload, &key_pair).unwrap();

        let verification = envelope.verify(&key_store).unwrap();
        assert!(verification.all_valid);
        assert_eq!(verification.valid_count, 1);
    }

    #[test]
    fn test_dsse_multi_signature() {
        let key_store = KeyStore::new();
        let key_id1 = key_store.generate_key(KeyPurpose::General).unwrap();
        let key_id2 = key_store.generate_key(KeyPurpose::General).unwrap();
        let key_pair1 = key_store.get_key(&key_id1).unwrap();
        let key_pair2 = key_store.get_key(&key_id2).unwrap();

        let payload = b"test payload";
        let mut envelope = DsseEnvelope::sign("application/json", payload, &key_pair1).unwrap();
        envelope.add_signature(&key_pair2).unwrap();

        assert_eq!(envelope.signatures.len(), 2);

        let verification = envelope.verify(&key_store).unwrap();
        assert!(verification.all_valid);
        assert_eq!(verification.valid_count, 2);
    }

    #[test]
    fn test_dsse_threshold_verification() {
        let key_store = KeyStore::new();
        let key_id = key_store.generate_key(KeyPurpose::General).unwrap();
        let key_pair = key_store.get_key(&key_id).unwrap();

        let payload = b"test";
        let envelope = DsseEnvelope::sign("application/json", payload, &key_pair).unwrap();

        assert!(envelope.verify_threshold(&key_store, 1).unwrap());
        assert!(!envelope.verify_threshold(&key_store, 2).unwrap());
    }

    #[test]
    fn test_pae_computation() {
        let pae = compute_pae("application/json", b"{}");
        let expected = b"DSSEv1 16 application/json 2 {}";
        assert_eq!(pae, expected);
    }

    #[test]
    fn test_statement_creation() {
        let key_store = KeyStore::new();
        let key_id = key_store.generate_key(KeyPurpose::General).unwrap();
        let key_pair = key_store.get_key(&key_id).unwrap();

        let statement = Statement::new(
            "vakya:12345",
            "abc123def456",
            predicate_types::VAKYA_EXECUTION,
            serde_json::json!({
                "action": "file.read",
                "result": "success"
            }),
        );

        let envelope = statement.sign(&key_pair).unwrap();
        let verification = envelope.verify(&key_store).unwrap();
        assert!(verification.all_valid);
    }
}
