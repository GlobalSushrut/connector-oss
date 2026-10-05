//! External KMS Integration Module
//!
//! Provides a unified interface for external Key Management Systems:
//! - AWS KMS
//! - HashiCorp Vault
//! - Azure Key Vault
//! - Google Cloud KMS
//! - Local (file-based, for development)
//!
//! All encryption keys used by Connector can be managed externally,
//! enabling enterprise security requirements and compliance (HIPAA, SOC2).

pub mod provider;
pub mod aws;
pub mod vault;
pub mod azure;
pub mod gcp;
pub mod local;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

pub use provider::KmsProvider;

/// KMS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsConfig {
    /// Provider type
    pub provider: KmsProviderType,
    
    /// Provider-specific configuration
    #[serde(flatten)]
    pub settings: HashMap<String, String>,
    
    /// Key ID for data encryption
    pub data_key_id: Option<String>,
    
    /// Key ID for audit log signing
    pub audit_key_id: Option<String>,
    
    /// Key ID for token encryption
    pub token_key_id: Option<String>,
    
    /// Cache TTL for decrypted keys (seconds)
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
    
    /// Enable key rotation
    #[serde(default)]
    pub auto_rotate: bool,
    
    /// Rotation interval (days)
    #[serde(default = "default_rotation_days")]
    pub rotation_days: u32,
}

fn default_cache_ttl() -> u64 { 300 } // 5 minutes
fn default_rotation_days() -> u32 { 90 }

impl Default for KmsConfig {
    fn default() -> Self {
        Self {
            provider: KmsProviderType::Local,
            settings: HashMap::new(),
            data_key_id: None,
            audit_key_id: None,
            token_key_id: None,
            cache_ttl_secs: default_cache_ttl(),
            auto_rotate: false,
            rotation_days: default_rotation_days(),
        }
    }
}

/// Supported KMS providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KmsProviderType {
    /// Local file-based keys (development only)
    Local,
    /// AWS Key Management Service
    Aws,
    /// HashiCorp Vault
    Vault,
    /// Azure Key Vault
    Azure,
    /// Google Cloud KMS
    Gcp,
}

impl std::fmt::Display for KmsProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KmsProviderType::Local => write!(f, "local"),
            KmsProviderType::Aws => write!(f, "aws"),
            KmsProviderType::Vault => write!(f, "vault"),
            KmsProviderType::Azure => write!(f, "azure"),
            KmsProviderType::Gcp => write!(f, "gcp"),
        }
    }
}

/// Key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key ID
    pub key_id: String,
    
    /// Key alias (human-readable name)
    pub alias: Option<String>,
    
    /// Key algorithm
    pub algorithm: KeyAlgorithm,
    
    /// Key usage
    pub usage: KeyUsage,
    
    /// Creation timestamp
    pub created_at: String,
    
    /// Last rotation timestamp
    pub rotated_at: Option<String>,
    
    /// Expiration timestamp
    pub expires_at: Option<String>,
    
    /// Key state
    pub state: KeyState,
    
    /// Provider-specific metadata
    #[serde(default)]
    pub provider_metadata: HashMap<String, String>,
}

/// Key algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyAlgorithm {
    /// AES-256-GCM (symmetric encryption)
    Aes256Gcm,
    /// RSA-2048 (asymmetric)
    Rsa2048,
    /// RSA-4096 (asymmetric)
    Rsa4096,
    /// ECDSA P-256 (signing)
    EcdsaP256,
    /// ECDSA P-384 (signing)
    EcdsaP384,
    /// Ed25519 (signing)
    Ed25519,
}

/// Key usage types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyUsage {
    /// Encrypt/decrypt data
    EncryptDecrypt,
    /// Sign/verify
    SignVerify,
    /// Generate data keys
    GenerateDataKey,
}

/// Key state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyState {
    /// Key is active and can be used
    Active,
    /// Key is disabled
    Disabled,
    /// Key is pending deletion
    PendingDeletion,
    /// Key is scheduled for rotation
    PendingRotation,
}

/// Encrypted data envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Key ID used for encryption
    pub key_id: String,
    
    /// Encrypted data key (for envelope encryption)
    pub encrypted_data_key: Option<Vec<u8>>,
    
    /// Ciphertext
    pub ciphertext: Vec<u8>,
    
    /// Initialization vector / nonce
    pub iv: Vec<u8>,
    
    /// Authentication tag (for AEAD)
    pub tag: Option<Vec<u8>>,
    
    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,
    
    /// Algorithm used
    pub algorithm: KeyAlgorithm,
    
    /// Provider type
    pub provider: KmsProviderType,
}

/// Signature envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEnvelope {
    /// Key ID used for signing
    pub key_id: String,
    
    /// Signature bytes
    pub signature: Vec<u8>,
    
    /// Algorithm used
    pub algorithm: KeyAlgorithm,
    
    /// Provider type
    pub provider: KmsProviderType,
    
    /// Timestamp
    pub signed_at: String,
}

/// KMS error types
#[derive(Debug, Clone)]
pub enum KmsError {
    /// Key not found
    KeyNotFound(String),
    /// Access denied
    AccessDenied(String),
    /// Invalid key state
    InvalidKeyState(String),
    /// Encryption failed
    EncryptionFailed(String),
    /// Decryption failed
    DecryptionFailed(String),
    /// Signing failed
    SigningFailed(String),
    /// Verification failed
    VerificationFailed(String),
    /// Provider error
    ProviderError(String),
    /// Configuration error
    ConfigError(String),
    /// Network error
    NetworkError(String),
    /// Rate limited
    RateLimited(String),
}

impl std::fmt::Display for KmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KmsError::KeyNotFound(k) => write!(f, "Key not found: {}", k),
            KmsError::AccessDenied(m) => write!(f, "Access denied: {}", m),
            KmsError::InvalidKeyState(s) => write!(f, "Invalid key state: {}", s),
            KmsError::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            KmsError::DecryptionFailed(e) => write!(f, "Decryption failed: {}", e),
            KmsError::SigningFailed(e) => write!(f, "Signing failed: {}", e),
            KmsError::VerificationFailed(e) => write!(f, "Verification failed: {}", e),
            KmsError::ProviderError(e) => write!(f, "Provider error: {}", e),
            KmsError::ConfigError(e) => write!(f, "Configuration error: {}", e),
            KmsError::NetworkError(e) => write!(f, "Network error: {}", e),
            KmsError::RateLimited(m) => write!(f, "Rate limited: {}", m),
        }
    }
}

impl std::error::Error for KmsError {}

/// Result type for KMS operations
pub type KmsResult<T> = Result<T, KmsError>;

/// Create a KMS provider from configuration
pub fn create_provider(config: &KmsConfig) -> KmsResult<Arc<dyn KmsProvider>> {
    match config.provider {
        KmsProviderType::Local => {
            let provider = local::LocalKmsProvider::new(config)?;
            Ok(Arc::new(provider))
        }
        KmsProviderType::Aws => {
            let provider = aws::AwsKmsProvider::new(config)?;
            Ok(Arc::new(provider))
        }
        KmsProviderType::Vault => {
            let provider = vault::VaultKmsProvider::new(config)?;
            Ok(Arc::new(provider))
        }
        KmsProviderType::Azure => {
            let provider = azure::AzureKmsProvider::new(config)?;
            Ok(Arc::new(provider))
        }
        KmsProviderType::Gcp => {
            let provider = gcp::GcpKmsProvider::new(config)?;
            Ok(Arc::new(provider))
        }
    }
}

/// KMS manager for handling multiple keys and caching
pub struct KmsManager {
    provider: Arc<dyn KmsProvider>,
    config: KmsConfig,
    // Key cache: key_id -> (decrypted_key, cached_at)
    key_cache: std::sync::RwLock<HashMap<String, (Vec<u8>, std::time::Instant)>>,
}

impl KmsManager {
    pub fn new(config: KmsConfig) -> KmsResult<Self> {
        let provider = create_provider(&config)?;
        Ok(Self {
            provider,
            config,
            key_cache: std::sync::RwLock::new(HashMap::new()),
        })
    }
    
    /// Encrypt data using the configured data key
    pub async fn encrypt_data(&self, plaintext: &[u8]) -> KmsResult<EncryptedEnvelope> {
        let key_id = self.config.data_key_id.as_ref()
            .ok_or_else(|| KmsError::ConfigError("No data key configured".to_string()))?;
        
        self.provider.encrypt(key_id, plaintext, None).await
    }
    
    /// Decrypt data
    pub async fn decrypt_data(&self, envelope: &EncryptedEnvelope) -> KmsResult<Vec<u8>> {
        self.provider.decrypt(envelope).await
    }
    
    /// Sign data using the configured audit key
    pub async fn sign_audit(&self, data: &[u8]) -> KmsResult<SignatureEnvelope> {
        let key_id = self.config.audit_key_id.as_ref()
            .ok_or_else(|| KmsError::ConfigError("No audit key configured".to_string()))?;
        
        self.provider.sign(key_id, data).await
    }
    
    /// Verify signature
    pub async fn verify_signature(&self, data: &[u8], signature: &SignatureEnvelope) -> KmsResult<bool> {
        self.provider.verify(data, signature).await
    }
    
    /// Get key metadata
    pub async fn get_key_metadata(&self, key_id: &str) -> KmsResult<KeyMetadata> {
        self.provider.get_key_metadata(key_id).await
    }
    
    /// List all keys
    pub async fn list_keys(&self) -> KmsResult<Vec<KeyMetadata>> {
        self.provider.list_keys().await
    }
    
    /// Rotate a key
    pub async fn rotate_key(&self, key_id: &str) -> KmsResult<KeyMetadata> {
        self.provider.rotate_key(key_id).await
    }
    
    /// Check if key rotation is needed
    pub async fn check_rotation_needed(&self) -> KmsResult<Vec<String>> {
        if !self.config.auto_rotate {
            return Ok(vec![]);
        }
        
        let keys = self.provider.list_keys().await?;
        let rotation_threshold = chrono::Duration::days(self.config.rotation_days as i64);
        let now = chrono::Utc::now();
        
        let mut needs_rotation = vec![];
        for key in keys {
            if key.state != KeyState::Active {
                continue;
            }
            
            let last_rotation = key.rotated_at.as_ref()
                .or(Some(&key.created_at))
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));
            
            if let Some(last) = last_rotation {
                if now - last > rotation_threshold {
                    needs_rotation.push(key.key_id);
                }
            }
        }
        
        Ok(needs_rotation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = KmsConfig::default();
        assert_eq!(config.provider, KmsProviderType::Local);
        assert_eq!(config.cache_ttl_secs, 300);
        assert!(!config.auto_rotate);
    }
    
    #[test]
    fn test_provider_type_display() {
        assert_eq!(KmsProviderType::Aws.to_string(), "aws");
        assert_eq!(KmsProviderType::Vault.to_string(), "vault");
        assert_eq!(KmsProviderType::Azure.to_string(), "azure");
        assert_eq!(KmsProviderType::Gcp.to_string(), "gcp");
        assert_eq!(KmsProviderType::Local.to_string(), "local");
    }
    
    #[test]
    fn test_kms_error_display() {
        let err = KmsError::KeyNotFound("test-key".to_string());
        assert!(err.to_string().contains("test-key"));
    }
}
