//! Signing and verification for AAPI
//!
//! Implements Ed25519 signing for VĀKYA requests and PRAMĀṆA receipts.

use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};

use aapi_core::{Vakya, SandhiOutput, canonicalize};
use crate::error::{CryptoError, CryptoResult};
use crate::keys::{KeyId, KeyPair, KeyStore, PublicKeyInfo};

/// Signed VĀKYA with signature metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedVakya {
    /// The original VĀKYA
    pub vakya: Vakya,
    /// Signature over the canonical form
    pub signature: VakyaSignature,
    /// Canonical hash (for verification)
    pub vakya_hash: String,
}

/// Signature metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VakyaSignature {
    /// Key ID used for signing
    pub key_id: KeyId,
    /// Signature algorithm
    pub algorithm: SignatureAlgorithm,
    /// Signature bytes (base64 encoded)
    pub value: String,
    /// Timestamp of signing
    pub signed_at: chrono::DateTime<chrono::Utc>,
}

/// Supported signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureAlgorithm {
    Ed25519,
}

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        Self::Ed25519
    }
}

/// Signer for VĀKYA requests
pub struct VakyaSigner {
    key_store: KeyStore,
}

impl VakyaSigner {
    pub fn new(key_store: KeyStore) -> Self {
        Self { key_store }
    }

    /// Sign a VĀKYA with the specified key
    pub fn sign(&self, vakya: &Vakya, key_id: &KeyId) -> CryptoResult<SignedVakya> {
        // Get the key pair
        let key_pair = self.key_store.get_key(key_id)?;
        
        if key_pair.is_expired() {
            return Err(CryptoError::TokenExpired);
        }

        // Canonicalize the VĀKYA
        let sandhi = canonicalize(vakya)
            .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;

        // Sign the canonical bytes
        let signature = sign_bytes(&key_pair, &sandhi.canonical_bytes)?;

        Ok(SignedVakya {
            vakya: vakya.clone(),
            signature: VakyaSignature {
                key_id: key_id.clone(),
                algorithm: SignatureAlgorithm::Ed25519,
                value: signature,
                signed_at: chrono::Utc::now(),
            },
            vakya_hash: sandhi.vakya_hash.value,
        })
    }

    /// Sign with automatic key selection based on principal
    pub fn sign_auto(&self, vakya: &Vakya) -> CryptoResult<SignedVakya> {
        // Try to find a key for this principal
        let principal = &vakya.v1_karta.pid.0;
        
        let keys = self.key_store.list_public_keys()?;
        let key = keys.iter()
            .find(|k| k.principal.as_deref() == Some(principal))
            .or_else(|| keys.first())
            .ok_or_else(|| CryptoError::KeyNotFound("No signing keys available".to_string()))?;

        self.sign(vakya, &key.key_id)
    }
}

/// Verifier for signed VĀKYA requests
pub struct VakyaVerifier {
    key_store: KeyStore,
}

impl VakyaVerifier {
    pub fn new(key_store: KeyStore) -> Self {
        Self { key_store }
    }

    /// Verify a signed VĀKYA
    pub fn verify(&self, signed: &SignedVakya) -> CryptoResult<VerificationResult> {
        // Get the public key
        let public_info = self.key_store.get_public_key(&signed.signature.key_id)?;
        let verifying_key = public_info.verifying_key()?;

        // Re-canonicalize the VĀKYA
        let sandhi = canonicalize(&signed.vakya)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;

        // Verify hash matches
        if sandhi.vakya_hash.value != signed.vakya_hash {
            return Ok(VerificationResult {
                valid: false,
                reason: Some("Hash mismatch".to_string()),
                key_id: signed.signature.key_id.clone(),
                verified_at: chrono::Utc::now(),
            });
        }

        // Decode signature
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&signed.signature.value)?;
        
        if sig_bytes.len() != 64 {
            return Err(CryptoError::InvalidSignature);
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_array);

        // Verify signature
        match verifying_key.verify(&sandhi.canonical_bytes, &signature) {
            Ok(_) => Ok(VerificationResult {
                valid: true,
                reason: None,
                key_id: signed.signature.key_id.clone(),
                verified_at: chrono::Utc::now(),
            }),
            Err(e) => Ok(VerificationResult {
                valid: false,
                reason: Some(e.to_string()),
                key_id: signed.signature.key_id.clone(),
                verified_at: chrono::Utc::now(),
            }),
        }
    }

    /// Verify with a specific public key (without key store lookup)
    pub fn verify_with_key(&self, signed: &SignedVakya, public_info: &PublicKeyInfo) -> CryptoResult<VerificationResult> {
        let verifying_key = public_info.verifying_key()?;

        // Re-canonicalize the VĀKYA
        let sandhi = canonicalize(&signed.vakya)
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;

        // Decode signature
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&signed.signature.value)?;
        
        if sig_bytes.len() != 64 {
            return Err(CryptoError::InvalidSignature);
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_array);

        // Verify signature
        match verifying_key.verify(&sandhi.canonical_bytes, &signature) {
            Ok(_) => Ok(VerificationResult {
                valid: true,
                reason: None,
                key_id: signed.signature.key_id.clone(),
                verified_at: chrono::Utc::now(),
            }),
            Err(e) => Ok(VerificationResult {
                valid: false,
                reason: Some(e.to_string()),
                key_id: signed.signature.key_id.clone(),
                verified_at: chrono::Utc::now(),
            }),
        }
    }
}

/// Result of signature verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub reason: Option<String>,
    pub key_id: KeyId,
    pub verified_at: chrono::DateTime<chrono::Utc>,
}

/// Sign arbitrary bytes with a key pair
pub fn sign_bytes(key_pair: &KeyPair, data: &[u8]) -> CryptoResult<String> {
    let signature = key_pair.signing_key().sign(data);
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
}

/// Verify a signature over arbitrary bytes
pub fn verify_bytes(public_info: &PublicKeyInfo, data: &[u8], signature_b64: &str) -> CryptoResult<bool> {
    let verifying_key = public_info.verifying_key()?;
    
    use base64::Engine;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)?;
    
    if sig_bytes.len() != 64 {
        return Err(CryptoError::InvalidSignature);
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_array);

    Ok(verifying_key.verify(data, &signature).is_ok())
}

/// Batch signature for multiple VĀKYA requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSignature {
    /// Individual signatures
    pub signatures: Vec<SignedVakya>,
    /// Aggregate hash of all VĀKYA hashes
    pub batch_hash: String,
    /// Signature over the batch hash
    pub batch_signature: VakyaSignature,
}

impl VakyaSigner {
    /// Sign multiple VĀKYA requests as a batch
    pub fn sign_batch(&self, vakyas: &[Vakya], key_id: &KeyId) -> CryptoResult<BatchSignature> {
        let key_pair = self.key_store.get_key(key_id)?;
        
        if key_pair.is_expired() {
            return Err(CryptoError::TokenExpired);
        }

        // Sign each VĀKYA individually
        let mut signatures = Vec::with_capacity(vakyas.len());
        let mut hashes = Vec::with_capacity(vakyas.len());
        
        for vakya in vakyas {
            let signed = self.sign(vakya, key_id)?;
            hashes.push(signed.vakya_hash.clone());
            signatures.push(signed);
        }

        // Compute batch hash
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        for hash in &hashes {
            hasher.update(hash.as_bytes());
        }
        let batch_hash = hex::encode(hasher.finalize());

        // Sign the batch hash
        let batch_sig = sign_bytes(&key_pair, batch_hash.as_bytes())?;

        Ok(BatchSignature {
            signatures,
            batch_hash,
            batch_signature: VakyaSignature {
                key_id: key_id.clone(),
                algorithm: SignatureAlgorithm::Ed25519,
                value: batch_sig,
                signed_at: chrono::Utc::now(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aapi_core::*;
    use crate::keys::KeyPurpose;

    fn create_test_vakya() -> Vakya {
        Vakya::builder()
            .karta(Karta {
                pid: PrincipalId::new("user:test"),
                role: None,
                realm: None,
                key_id: None,
                actor_type: ActorType::Human,
                delegation_chain: vec![],
            })
            .karma(Karma {
                rid: ResourceId::new("test:resource"),
                kind: None,
                ns: None,
                version: None,
                labels: std::collections::HashMap::new(),
            })
            .kriya(Kriya::new("test", "action"))
            .adhikarana(Adhikarana {
                cap: CapabilityRef::Reference { cap_ref: "cap:test".to_string() },
                policy_ref: None,
                ttl: Some(TtlConstraint {
                    expires_at: Timestamp(chrono::Utc::now() + chrono::Duration::hours(1)),
                    max_duration_ms: None,
                }),
                budgets: vec![],
                approval_lane: ApprovalLane::None,
                scopes: vec![],
                context: None,
            })
            .build()
            .unwrap()
    }

    #[test]
    fn test_sign_and_verify() {
        let key_store = KeyStore::new();
        let key_id = key_store.generate_key(KeyPurpose::VakyaSigning).unwrap();
        
        let signer = VakyaSigner::new(key_store.clone());
        let verifier = VakyaVerifier::new(key_store);
        
        let vakya = create_test_vakya();
        let signed = signer.sign(&vakya, &key_id).unwrap();
        
        let result = verifier.verify(&signed).unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_tampered_vakya_fails() {
        let key_store = KeyStore::new();
        let key_id = key_store.generate_key(KeyPurpose::VakyaSigning).unwrap();
        
        let signer = VakyaSigner::new(key_store.clone());
        let verifier = VakyaVerifier::new(key_store);
        
        let vakya = create_test_vakya();
        let mut signed = signer.sign(&vakya, &key_id).unwrap();
        
        // Tamper with the VĀKYA
        signed.vakya.v3_kriya.action = "tampered.action".to_string();
        
        let result = verifier.verify(&signed).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_batch_signing() {
        let key_store = KeyStore::new();
        let key_id = key_store.generate_key(KeyPurpose::VakyaSigning).unwrap();
        
        let signer = VakyaSigner::new(key_store);
        
        let vakyas: Vec<Vakya> = (0..3).map(|_| create_test_vakya()).collect();
        let batch = signer.sign_batch(&vakyas, &key_id).unwrap();
        
        assert_eq!(batch.signatures.len(), 3);
        assert!(!batch.batch_hash.is_empty());
    }
}
