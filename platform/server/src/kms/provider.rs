//! KMS Provider Trait
//!
//! Defines the interface that all KMS providers must implement.

use async_trait::async_trait;
use super::{
    EncryptedEnvelope, SignatureEnvelope, KeyMetadata, KmsResult,
};

/// Trait for KMS providers
#[async_trait]
pub trait KmsProvider: Send + Sync {
    /// Get provider name
    fn name(&self) -> &'static str;
    
    /// Encrypt data with a key
    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> KmsResult<EncryptedEnvelope>;
    
    /// Decrypt data
    async fn decrypt(&self, envelope: &EncryptedEnvelope) -> KmsResult<Vec<u8>>;
    
    /// Sign data with a key
    async fn sign(&self, key_id: &str, data: &[u8]) -> KmsResult<SignatureEnvelope>;
    
    /// Verify a signature
    async fn verify(&self, data: &[u8], signature: &SignatureEnvelope) -> KmsResult<bool>;
    
    /// Generate a data encryption key (for envelope encryption)
    async fn generate_data_key(&self, key_id: &str) -> KmsResult<(Vec<u8>, Vec<u8>)>;
    
    /// Get key metadata
    async fn get_key_metadata(&self, key_id: &str) -> KmsResult<KeyMetadata>;
    
    /// List all keys
    async fn list_keys(&self) -> KmsResult<Vec<KeyMetadata>>;
    
    /// Create a new key
    async fn create_key(
        &self,
        alias: &str,
        algorithm: super::KeyAlgorithm,
        usage: super::KeyUsage,
    ) -> KmsResult<KeyMetadata>;
    
    /// Rotate a key
    async fn rotate_key(&self, key_id: &str) -> KmsResult<KeyMetadata>;
    
    /// Disable a key
    async fn disable_key(&self, key_id: &str) -> KmsResult<()>;
    
    /// Enable a key
    async fn enable_key(&self, key_id: &str) -> KmsResult<()>;
    
    /// Schedule key deletion
    async fn schedule_key_deletion(&self, key_id: &str, days: u32) -> KmsResult<()>;
    
    /// Cancel key deletion
    async fn cancel_key_deletion(&self, key_id: &str) -> KmsResult<()>;
}
