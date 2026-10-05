//! Local KMS Provider
//!
//! File-based key management for development and testing.
//! NOT recommended for production use.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;

use super::{
    provider::KmsProvider,
    EncryptedEnvelope, SignatureEnvelope, KeyMetadata, KmsResult, KmsError,
    KmsConfig, KmsProviderType, KeyAlgorithm, KeyUsage, KeyState,
};

/// Local file-based KMS provider
pub struct LocalKmsProvider {
    keys: RwLock<HashMap<String, LocalKey>>,
    data_dir: String,
}

struct LocalKey {
    metadata: KeyMetadata,
    key_material: Vec<u8>,
}

impl LocalKmsProvider {
    pub fn new(config: &KmsConfig) -> KmsResult<Self> {
        let data_dir = config.settings.get("data_dir")
            .cloned()
            .unwrap_or_else(|| "/tmp/connector-kms".to_string());
        
        // Create data directory
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| KmsError::ConfigError(format!("Failed to create KMS dir: {}", e)))?;
        
        let provider = Self {
            keys: RwLock::new(HashMap::new()),
            data_dir,
        };
        
        // Load existing keys
        provider.load_keys()?;
        
        Ok(provider)
    }
    
    fn load_keys(&self) -> KmsResult<()> {
        let keys_file = format!("{}/keys.json", self.data_dir);
        if std::path::Path::new(&keys_file).exists() {
            let content = std::fs::read_to_string(&keys_file)
                .map_err(|e| KmsError::ConfigError(format!("Failed to read keys: {}", e)))?;
            
            let stored: HashMap<String, StoredKey> = serde_json::from_str(&content)
                .map_err(|e| KmsError::ConfigError(format!("Failed to parse keys: {}", e)))?;
            
            let mut keys = self.keys.write().unwrap();
            for (id, stored) in stored {
                keys.insert(id, LocalKey {
                    metadata: stored.metadata,
                    key_material: stored.key_material,
                });
            }
        }
        Ok(())
    }
    
    fn save_keys(&self) -> KmsResult<()> {
        let keys = self.keys.read().unwrap();
        let stored: HashMap<String, StoredKey> = keys.iter()
            .map(|(id, k)| (id.clone(), StoredKey {
                metadata: k.metadata.clone(),
                key_material: k.key_material.clone(),
            }))
            .collect();
        
        let content = serde_json::to_string_pretty(&stored)
            .map_err(|e| KmsError::ConfigError(format!("Failed to serialize keys: {}", e)))?;
        
        let keys_file = format!("{}/keys.json", self.data_dir);
        std::fs::write(&keys_file, content)
            .map_err(|e| KmsError::ConfigError(format!("Failed to write keys: {}", e)))?;
        
        Ok(())
    }
    
    fn generate_key_material(algorithm: KeyAlgorithm) -> Vec<u8> {
        use rand::Rng;
        let size = match algorithm {
            KeyAlgorithm::Aes256Gcm => 32,
            KeyAlgorithm::Ed25519 => 32,
            KeyAlgorithm::EcdsaP256 => 32,
            KeyAlgorithm::EcdsaP384 => 48,
            KeyAlgorithm::Rsa2048 => 256,
            KeyAlgorithm::Rsa4096 => 512,
        };
        
        let mut rng = rand::thread_rng();
        (0..size).map(|_| rng.gen()).collect()
    }
    
    fn generate_nonce() -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..12).map(|_| rng.gen()).collect()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredKey {
    metadata: KeyMetadata,
    key_material: Vec<u8>,
}

#[async_trait]
impl KmsProvider for LocalKmsProvider {
    fn name(&self) -> &'static str {
        "local"
    }
    
    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> KmsResult<EncryptedEnvelope> {
        let keys = self.keys.read().unwrap();
        let key = keys.get(key_id)
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;
        
        if key.metadata.state != KeyState::Active {
            return Err(KmsError::InvalidKeyState(format!("{:?}", key.metadata.state)));
        }
        
        // Simple XOR encryption for demo (use proper crypto in production)
        let iv = Self::generate_nonce();
        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= key.key_material[i % key.key_material.len()];
            *byte ^= iv[i % iv.len()];
        }
        
        Ok(EncryptedEnvelope {
            key_id: key_id.to_string(),
            encrypted_data_key: None,
            ciphertext,
            iv,
            tag: None,
            aad: aad.map(|a| a.to_vec()),
            algorithm: key.metadata.algorithm,
            provider: KmsProviderType::Local,
        })
    }
    
    async fn decrypt(&self, envelope: &EncryptedEnvelope) -> KmsResult<Vec<u8>> {
        let keys = self.keys.read().unwrap();
        let key = keys.get(&envelope.key_id)
            .ok_or_else(|| KmsError::KeyNotFound(envelope.key_id.clone()))?;
        
        // Reverse XOR
        let mut plaintext = envelope.ciphertext.clone();
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= envelope.iv[i % envelope.iv.len()];
            *byte ^= key.key_material[i % key.key_material.len()];
        }
        
        Ok(plaintext)
    }
    
    async fn sign(&self, key_id: &str, data: &[u8]) -> KmsResult<SignatureEnvelope> {
        let keys = self.keys.read().unwrap();
        let key = keys.get(key_id)
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;
        
        if key.metadata.state != KeyState::Active {
            return Err(KmsError::InvalidKeyState(format!("{:?}", key.metadata.state)));
        }
        
        // Simple HMAC-like signature for demo
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        key.key_material.hash(&mut hasher);
        let hash = hasher.finish();
        
        Ok(SignatureEnvelope {
            key_id: key_id.to_string(),
            signature: hash.to_le_bytes().to_vec(),
            algorithm: key.metadata.algorithm,
            provider: KmsProviderType::Local,
            signed_at: chrono::Utc::now().to_rfc3339(),
        })
    }
    
    async fn verify(&self, data: &[u8], signature: &SignatureEnvelope) -> KmsResult<bool> {
        let expected = self.sign(&signature.key_id, data).await?;
        Ok(expected.signature == signature.signature)
    }
    
    async fn generate_data_key(&self, key_id: &str) -> KmsResult<(Vec<u8>, Vec<u8>)> {
        // Validate key exists and generate plaintext key
        let plaintext_key = {
            let keys = self.keys.read().unwrap();
            let _key = keys.get(key_id)
                .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;
            Self::generate_key_material(KeyAlgorithm::Aes256Gcm)
        }; // RwLockReadGuard dropped here
        
        // Encrypt it with the master key
        let envelope = self.encrypt(key_id, &plaintext_key, None).await?;
        
        Ok((plaintext_key, envelope.ciphertext))
    }
    
    async fn get_key_metadata(&self, key_id: &str) -> KmsResult<KeyMetadata> {
        let keys = self.keys.read().unwrap();
        keys.get(key_id)
            .map(|k| k.metadata.clone())
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))
    }
    
    async fn list_keys(&self) -> KmsResult<Vec<KeyMetadata>> {
        let keys = self.keys.read().unwrap();
        Ok(keys.values().map(|k| k.metadata.clone()).collect())
    }
    
    async fn create_key(
        &self,
        alias: &str,
        algorithm: KeyAlgorithm,
        usage: KeyUsage,
    ) -> KmsResult<KeyMetadata> {
        let key_id = format!("local-{}", uuid::Uuid::new_v4());
        let now = chrono::Utc::now().to_rfc3339();
        
        let metadata = KeyMetadata {
            key_id: key_id.clone(),
            alias: Some(alias.to_string()),
            algorithm,
            usage,
            created_at: now.clone(),
            rotated_at: None,
            expires_at: None,
            state: KeyState::Active,
            provider_metadata: HashMap::new(),
        };
        
        let key_material = Self::generate_key_material(algorithm);
        
        {
            let mut keys = self.keys.write().unwrap();
            keys.insert(key_id, LocalKey {
                metadata: metadata.clone(),
                key_material,
            });
        }
        
        self.save_keys()?;
        
        Ok(metadata)
    }
    
    async fn rotate_key(&self, key_id: &str) -> KmsResult<KeyMetadata> {
        let mut keys = self.keys.write().unwrap();
        let key = keys.get_mut(key_id)
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;
        
        // Generate new key material
        key.key_material = Self::generate_key_material(key.metadata.algorithm);
        key.metadata.rotated_at = Some(chrono::Utc::now().to_rfc3339());
        
        let metadata = key.metadata.clone();
        drop(keys);
        
        self.save_keys()?;
        
        Ok(metadata)
    }
    
    async fn disable_key(&self, key_id: &str) -> KmsResult<()> {
        let mut keys = self.keys.write().unwrap();
        let key = keys.get_mut(key_id)
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;
        
        key.metadata.state = KeyState::Disabled;
        drop(keys);
        
        self.save_keys()
    }
    
    async fn enable_key(&self, key_id: &str) -> KmsResult<()> {
        let mut keys = self.keys.write().unwrap();
        let key = keys.get_mut(key_id)
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;
        
        key.metadata.state = KeyState::Active;
        drop(keys);
        
        self.save_keys()
    }
    
    async fn schedule_key_deletion(&self, key_id: &str, _days: u32) -> KmsResult<()> {
        let mut keys = self.keys.write().unwrap();
        let key = keys.get_mut(key_id)
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;
        
        key.metadata.state = KeyState::PendingDeletion;
        drop(keys);
        
        self.save_keys()
    }
    
    async fn cancel_key_deletion(&self, key_id: &str) -> KmsResult<()> {
        let mut keys = self.keys.write().unwrap();
        let key = keys.get_mut(key_id)
            .ok_or_else(|| KmsError::KeyNotFound(key_id.to_string()))?;
        
        if key.metadata.state == KeyState::PendingDeletion {
            key.metadata.state = KeyState::Disabled;
        }
        drop(keys);
        
        self.save_keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_local_kms_create_key() {
        let config = KmsConfig {
            provider: KmsProviderType::Local,
            settings: [("data_dir".to_string(), "/tmp/test-kms".to_string())].into(),
            ..Default::default()
        };
        
        let provider = LocalKmsProvider::new(&config).unwrap();
        
        let metadata = provider.create_key(
            "test-key",
            KeyAlgorithm::Aes256Gcm,
            KeyUsage::EncryptDecrypt,
        ).await.unwrap();
        
        assert!(metadata.key_id.starts_with("local-"));
        assert_eq!(metadata.alias, Some("test-key".to_string()));
        assert_eq!(metadata.state, KeyState::Active);
    }
    
    #[tokio::test]
    async fn test_local_kms_encrypt_decrypt() {
        let config = KmsConfig {
            provider: KmsProviderType::Local,
            settings: [("data_dir".to_string(), "/tmp/test-kms-enc".to_string())].into(),
            ..Default::default()
        };
        
        let provider = LocalKmsProvider::new(&config).unwrap();
        
        let metadata = provider.create_key(
            "enc-key",
            KeyAlgorithm::Aes256Gcm,
            KeyUsage::EncryptDecrypt,
        ).await.unwrap();
        
        let plaintext = b"Hello, World!";
        let envelope = provider.encrypt(&metadata.key_id, plaintext, None).await.unwrap();
        let decrypted = provider.decrypt(&envelope).await.unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
    
    #[tokio::test]
    async fn test_local_kms_sign_verify() {
        let config = KmsConfig {
            provider: KmsProviderType::Local,
            settings: [("data_dir".to_string(), "/tmp/test-kms-sign".to_string())].into(),
            ..Default::default()
        };
        
        let provider = LocalKmsProvider::new(&config).unwrap();
        
        let metadata = provider.create_key(
            "sign-key",
            KeyAlgorithm::Ed25519,
            KeyUsage::SignVerify,
        ).await.unwrap();
        
        let data = b"Sign this data";
        let signature = provider.sign(&metadata.key_id, data).await.unwrap();
        let valid = provider.verify(data, &signature).await.unwrap();
        
        assert!(valid);
    }
}
