//! Key generation and management

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use vac_core::{VacError, VacResult};

/// A keypair for signing
#[derive(Clone)]
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }
    
    /// Create from secret key bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }
    
    /// Get the signing key
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
    
    /// Get the verifying (public) key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    
    /// Get the secret key bytes
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
    
    /// Get the public key bytes
    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }
    
    /// Get the DID key identifier
    pub fn did_key(&self) -> String {
        let public_bytes = self.public_bytes();
        // Multicodec prefix for Ed25519 public key: 0xed01
        let mut prefixed = vec![0xed, 0x01];
        prefixed.extend_from_slice(&public_bytes);
        
        // Base58btc encode with 'z' prefix
        let encoded = bs58::encode(&prefixed).into_string();
        format!("did:key:z{}", encoded)
    }
}

/// Parse a DID key to extract the public key bytes
pub fn parse_did_key(did: &str) -> VacResult<[u8; 32]> {
    if !did.starts_with("did:key:z") {
        return Err(VacError::InvalidState("Invalid DID key format".into()));
    }
    
    let encoded = &did[9..]; // Skip "did:key:z"
    let decoded = bs58::decode(encoded)
        .into_vec()
        .map_err(|e| VacError::InvalidState(format!("Invalid base58: {}", e)))?;
    
    // Check multicodec prefix (0xed01 for Ed25519)
    if decoded.len() < 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(VacError::InvalidState("Invalid Ed25519 multicodec prefix".into()));
    }
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded[2..34]);
    Ok(bytes)
}

/// Create a VerifyingKey from DID
pub fn verifying_key_from_did(did: &str) -> VacResult<VerifyingKey> {
    let bytes = parse_did_key(did)?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| VacError::InvalidState(format!("Invalid public key: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_keypair_generation() {
        let kp = KeyPair::generate();
        assert_eq!(kp.secret_bytes().len(), 32);
        assert_eq!(kp.public_bytes().len(), 32);
    }
    
    #[test]
    fn test_did_key_format() {
        let kp = KeyPair::generate();
        let did = kp.did_key();
        
        assert!(did.starts_with("did:key:z"));
    }
    
    #[test]
    fn test_did_key_roundtrip() {
        let kp = KeyPair::generate();
        let did = kp.did_key();
        
        let parsed_bytes = parse_did_key(&did).unwrap();
        assert_eq!(parsed_bytes, kp.public_bytes());
    }
    
    #[test]
    fn test_verifying_key_from_did() {
        let kp = KeyPair::generate();
        let did = kp.did_key();
        
        let vk = verifying_key_from_did(&did).unwrap();
        assert_eq!(vk.to_bytes(), kp.public_bytes());
    }
}
