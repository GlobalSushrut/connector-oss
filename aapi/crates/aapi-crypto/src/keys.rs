//! Key management for AAPI
//!
//! Provides Ed25519 key generation, storage, and retrieval.

use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::{CryptoError, CryptoResult};

/// Key identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub String);

impl KeyId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Key pair with metadata
#[derive(Clone)]
pub struct KeyPair {
    /// Unique key identifier
    pub key_id: KeyId,
    /// Ed25519 signing key (private)
    signing_key: SigningKey,
    /// Key creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Key expiration (optional)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Key purpose/usage
    pub purpose: KeyPurpose,
    /// Associated principal
    pub principal: Option<String>,
}

impl KeyPair {
    /// Generate a new key pair
    pub fn generate(purpose: KeyPurpose) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            key_id: KeyId::generate(),
            signing_key,
            created_at: chrono::Utc::now(),
            expires_at: None,
            purpose,
            principal: None,
        }
    }

    /// Generate with a specific key ID
    pub fn generate_with_id(key_id: KeyId, purpose: KeyPurpose) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            key_id,
            signing_key,
            created_at: chrono::Utc::now(),
            expires_at: None,
            purpose,
            principal: None,
        }
    }

    /// Create from existing secret key bytes
    pub fn from_secret_bytes(key_id: KeyId, bytes: &[u8], purpose: KeyPurpose) -> CryptoResult<Self> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(CryptoError::InvalidKeyFormat(format!(
                "Expected {} bytes, got {}",
                SECRET_KEY_LENGTH,
                bytes.len()
            )));
        }
        let mut key_bytes = [0u8; SECRET_KEY_LENGTH];
        key_bytes.copy_from_slice(bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        
        Ok(Self {
            key_id,
            signing_key,
            created_at: chrono::Utc::now(),
            expires_at: None,
            purpose,
            principal: None,
        })
    }

    /// Get the signing key
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get the verifying (public) key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Export public key as bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }

    /// Export public key as hex
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    /// Export public key as base64
    pub fn public_key_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.public_key_bytes())
    }

    /// Check if key is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            expires < chrono::Utc::now()
        } else {
            false
        }
    }

    /// Set expiration
    pub fn with_expiration(mut self, expires_at: chrono::DateTime<chrono::Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set principal
    pub fn with_principal(mut self, principal: impl Into<String>) -> Self {
        self.principal = Some(principal.into());
        self
    }

    /// Export as PublicKeyInfo for sharing
    pub fn to_public_info(&self) -> PublicKeyInfo {
        PublicKeyInfo {
            key_id: self.key_id.clone(),
            public_key: self.public_key_hex(),
            algorithm: "Ed25519".to_string(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            purpose: self.purpose,
            principal: self.principal.clone(),
        }
    }
}

/// Key purpose/usage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    /// Signing VĀKYA requests
    VakyaSigning,
    /// Signing capability tokens
    CapabilitySigning,
    /// Signing PRAMĀṆA receipts
    ReceiptSigning,
    /// General purpose signing
    General,
}

/// Public key information for sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    pub key_id: KeyId,
    pub public_key: String,
    pub algorithm: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub purpose: KeyPurpose,
    pub principal: Option<String>,
}

impl PublicKeyInfo {
    /// Parse public key bytes
    pub fn public_key_bytes(&self) -> CryptoResult<[u8; 32]> {
        let bytes = hex::decode(&self.public_key)?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyFormat(
                "Public key must be 32 bytes".to_string(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Get verifying key
    pub fn verifying_key(&self) -> CryptoResult<VerifyingKey> {
        let bytes = self.public_key_bytes()?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))
    }
}

/// In-memory key store
pub struct KeyStore {
    keys: Arc<RwLock<HashMap<KeyId, KeyPair>>>,
    public_keys: Arc<RwLock<HashMap<KeyId, PublicKeyInfo>>>,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            public_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate and store a new key pair
    pub fn generate_key(&self, purpose: KeyPurpose) -> CryptoResult<KeyId> {
        let key_pair = KeyPair::generate(purpose);
        let key_id = key_pair.key_id.clone();
        
        let mut keys = self.keys.write().map_err(|_| {
            CryptoError::KeyGeneration("Failed to acquire lock".to_string())
        })?;
        
        keys.insert(key_id.clone(), key_pair);
        Ok(key_id)
    }

    /// Store an existing key pair
    pub fn store_key(&self, key_pair: KeyPair) -> CryptoResult<()> {
        let key_id = key_pair.key_id.clone();
        let public_info = key_pair.to_public_info();
        
        let mut keys = self.keys.write().map_err(|_| {
            CryptoError::KeyGeneration("Failed to acquire lock".to_string())
        })?;
        
        keys.insert(key_id.clone(), key_pair);
        
        let mut public_keys = self.public_keys.write().map_err(|_| {
            CryptoError::KeyGeneration("Failed to acquire lock".to_string())
        })?;
        
        public_keys.insert(key_id, public_info);
        Ok(())
    }

    /// Store a public key (for verification only)
    pub fn store_public_key(&self, info: PublicKeyInfo) -> CryptoResult<()> {
        let mut public_keys = self.public_keys.write().map_err(|_| {
            CryptoError::KeyGeneration("Failed to acquire lock".to_string())
        })?;
        
        public_keys.insert(info.key_id.clone(), info);
        Ok(())
    }

    /// Get a key pair by ID
    pub fn get_key(&self, key_id: &KeyId) -> CryptoResult<KeyPair> {
        let keys = self.keys.read().map_err(|_| {
            CryptoError::KeyNotFound("Failed to acquire lock".to_string())
        })?;
        
        keys.get(key_id)
            .cloned()
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))
    }

    /// Get public key info by ID
    pub fn get_public_key(&self, key_id: &KeyId) -> CryptoResult<PublicKeyInfo> {
        // First check if we have the full key pair
        if let Ok(key_pair) = self.get_key(key_id) {
            return Ok(key_pair.to_public_info());
        }
        
        // Otherwise check public keys only
        let public_keys = self.public_keys.read().map_err(|_| {
            CryptoError::KeyNotFound("Failed to acquire lock".to_string())
        })?;
        
        public_keys.get(key_id)
            .cloned()
            .ok_or_else(|| CryptoError::KeyNotFound(key_id.to_string()))
    }

    /// Get verifying key by ID
    pub fn get_verifying_key(&self, key_id: &KeyId) -> CryptoResult<VerifyingKey> {
        self.get_public_key(key_id)?.verifying_key()
    }

    /// Remove a key
    pub fn remove_key(&self, key_id: &KeyId) -> CryptoResult<()> {
        let mut keys = self.keys.write().map_err(|_| {
            CryptoError::KeyNotFound("Failed to acquire lock".to_string())
        })?;
        
        keys.remove(key_id);
        
        let mut public_keys = self.public_keys.write().map_err(|_| {
            CryptoError::KeyNotFound("Failed to acquire lock".to_string())
        })?;
        
        public_keys.remove(key_id);
        Ok(())
    }

    /// List all key IDs
    pub fn list_keys(&self) -> CryptoResult<Vec<KeyId>> {
        let keys = self.keys.read().map_err(|_| {
            CryptoError::KeyNotFound("Failed to acquire lock".to_string())
        })?;
        
        Ok(keys.keys().cloned().collect())
    }

    /// List all public key infos
    pub fn list_public_keys(&self) -> CryptoResult<Vec<PublicKeyInfo>> {
        let keys = self.keys.read().map_err(|_| {
            CryptoError::KeyNotFound("Failed to acquire lock".to_string())
        })?;
        
        let public_keys = self.public_keys.read().map_err(|_| {
            CryptoError::KeyNotFound("Failed to acquire lock".to_string())
        })?;
        
        let mut result: Vec<PublicKeyInfo> = keys.values()
            .map(|kp| kp.to_public_info())
            .collect();
        
        for (key_id, info) in public_keys.iter() {
            if !keys.contains_key(key_id) {
                result.push(info.clone());
            }
        }
        
        Ok(result)
    }
}

impl Clone for KeyStore {
    fn clone(&self) -> Self {
        Self {
            keys: Arc::clone(&self.keys),
            public_keys: Arc::clone(&self.public_keys),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_pair_generation() {
        let key_pair = KeyPair::generate(KeyPurpose::VakyaSigning);
        assert!(!key_pair.key_id.0.is_empty());
        assert!(!key_pair.is_expired());
    }

    #[test]
    fn test_key_pair_with_expiration() {
        let expires = chrono::Utc::now() - chrono::Duration::hours(1);
        let key_pair = KeyPair::generate(KeyPurpose::General)
            .with_expiration(expires);
        assert!(key_pair.is_expired());
    }

    #[test]
    fn test_key_store_operations() {
        let store = KeyStore::new();
        
        // Generate key
        let key_id = store.generate_key(KeyPurpose::VakyaSigning).unwrap();
        
        // Retrieve key
        let key_pair = store.get_key(&key_id).unwrap();
        assert_eq!(key_pair.key_id, key_id);
        
        // Get public key
        let public_info = store.get_public_key(&key_id).unwrap();
        assert_eq!(public_info.key_id, key_id);
        
        // List keys
        let keys = store.list_keys().unwrap();
        assert!(keys.contains(&key_id));
        
        // Remove key
        store.remove_key(&key_id).unwrap();
        assert!(store.get_key(&key_id).is_err());
    }

    #[test]
    fn test_public_key_export() {
        let key_pair = KeyPair::generate(KeyPurpose::General);
        let hex = key_pair.public_key_hex();
        let base64 = key_pair.public_key_base64();
        
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
        assert!(!base64.is_empty());
    }
}
