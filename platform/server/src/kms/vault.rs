//! HashiCorp Vault KMS Provider
//!
//! Integration with HashiCorp Vault Transit secrets engine.
//! Supports encryption, signing, and key management.

use async_trait::async_trait;
use std::collections::HashMap;

use super::{
    provider::KmsProvider,
    EncryptedEnvelope, SignatureEnvelope, KeyMetadata, KmsResult, KmsError,
    KmsConfig, KmsProviderType, KeyAlgorithm, KeyUsage, KeyState,
};

/// HashiCorp Vault KMS provider
pub struct VaultKmsProvider {
    address: String,
    token: Option<String>,
    namespace: Option<String>,
    mount_path: String,
}

impl VaultKmsProvider {
    pub fn new(config: &KmsConfig) -> KmsResult<Self> {
        let address = config.settings.get("address")
            .cloned()
            .or_else(|| std::env::var("VAULT_ADDR").ok())
            .unwrap_or_else(|| "http://127.0.0.1:8200".to_string());
        
        let token = config.settings.get("token")
            .cloned()
            .or_else(|| std::env::var("VAULT_TOKEN").ok());
        
        let namespace = config.settings.get("namespace")
            .cloned()
            .or_else(|| std::env::var("VAULT_NAMESPACE").ok());
        
        let mount_path = config.settings.get("mount_path")
            .cloned()
            .unwrap_or_else(|| "transit".to_string());
        
        Ok(Self {
            address,
            token,
            namespace,
            mount_path,
        })
    }
    
    fn map_algorithm(algorithm: KeyAlgorithm) -> &'static str {
        match algorithm {
            KeyAlgorithm::Aes256Gcm => "aes256-gcm96",
            KeyAlgorithm::Rsa2048 => "rsa-2048",
            KeyAlgorithm::Rsa4096 => "rsa-4096",
            KeyAlgorithm::EcdsaP256 => "ecdsa-p256",
            KeyAlgorithm::EcdsaP384 => "ecdsa-p384",
            KeyAlgorithm::Ed25519 => "ed25519",
        }
    }
    
    async fn vault_request(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> KmsResult<serde_json::Value> {
        let url = format!("{}/v1/{}", self.address, path);
        
        let client = reqwest::Client::new();
        let mut request = match method {
            "GET" => client.get(&url),
            "POST" => client.post(&url),
            "DELETE" => client.delete(&url),
            _ => return Err(KmsError::ProviderError(format!("Unknown method: {}", method))),
        };
        
        if let Some(ref token) = self.token {
            request = request.header("X-Vault-Token", token);
        }
        
        if let Some(ref ns) = self.namespace {
            request = request.header("X-Vault-Namespace", ns);
        }
        
        if let Some(body) = body {
            request = request.json(&body);
        }
        
        let response = request.send().await
            .map_err(|e| KmsError::NetworkError(e.to_string()))?;
        
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(KmsError::ProviderError(format!("Vault error {}: {}", status, text)));
        }
        
        response.json().await
            .map_err(|e| KmsError::ProviderError(e.to_string()))
    }
}

#[async_trait]
impl KmsProvider for VaultKmsProvider {
    fn name(&self) -> &'static str {
        "vault"
    }
    
    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        _aad: Option<&[u8]>,
    ) -> KmsResult<EncryptedEnvelope> {
        let path = format!("{}/encrypt/{}", self.mount_path, key_id);
        let plaintext_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            plaintext,
        );
        
        let body = serde_json::json!({
            "plaintext": plaintext_b64
        });
        
        let response = self.vault_request("POST", &path, Some(body)).await?;
        
        let ciphertext = response["data"]["ciphertext"]
            .as_str()
            .ok_or_else(|| KmsError::ProviderError("No ciphertext in response".to_string()))?;
        
        Ok(EncryptedEnvelope {
            key_id: key_id.to_string(),
            encrypted_data_key: None,
            ciphertext: ciphertext.as_bytes().to_vec(),
            iv: vec![],
            tag: None,
            aad: None,
            algorithm: KeyAlgorithm::Aes256Gcm,
            provider: KmsProviderType::Vault,
        })
    }
    
    async fn decrypt(&self, envelope: &EncryptedEnvelope) -> KmsResult<Vec<u8>> {
        let path = format!("{}/decrypt/{}", self.mount_path, envelope.key_id);
        let ciphertext = String::from_utf8(envelope.ciphertext.clone())
            .map_err(|e| KmsError::DecryptionFailed(e.to_string()))?;
        
        let body = serde_json::json!({
            "ciphertext": ciphertext
        });
        
        let response = self.vault_request("POST", &path, Some(body)).await?;
        
        let plaintext_b64 = response["data"]["plaintext"]
            .as_str()
            .ok_or_else(|| KmsError::ProviderError("No plaintext in response".to_string()))?;
        
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, plaintext_b64)
            .map_err(|e| KmsError::DecryptionFailed(e.to_string()))
    }
    
    async fn sign(&self, key_id: &str, data: &[u8]) -> KmsResult<SignatureEnvelope> {
        let path = format!("{}/sign/{}", self.mount_path, key_id);
        let input_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            data,
        );
        
        let body = serde_json::json!({
            "input": input_b64
        });
        
        let response = self.vault_request("POST", &path, Some(body)).await?;
        
        let signature = response["data"]["signature"]
            .as_str()
            .ok_or_else(|| KmsError::ProviderError("No signature in response".to_string()))?;
        
        Ok(SignatureEnvelope {
            key_id: key_id.to_string(),
            signature: signature.as_bytes().to_vec(),
            algorithm: KeyAlgorithm::Ed25519,
            provider: KmsProviderType::Vault,
            signed_at: chrono::Utc::now().to_rfc3339(),
        })
    }
    
    async fn verify(&self, data: &[u8], signature: &SignatureEnvelope) -> KmsResult<bool> {
        let path = format!("{}/verify/{}", self.mount_path, signature.key_id);
        let input_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            data,
        );
        let sig = String::from_utf8(signature.signature.clone())
            .map_err(|e| KmsError::VerificationFailed(e.to_string()))?;
        
        let body = serde_json::json!({
            "input": input_b64,
            "signature": sig
        });
        
        let response = self.vault_request("POST", &path, Some(body)).await?;
        
        Ok(response["data"]["valid"].as_bool().unwrap_or(false))
    }
    
    async fn generate_data_key(&self, key_id: &str) -> KmsResult<(Vec<u8>, Vec<u8>)> {
        let path = format!("{}/datakey/plaintext/{}", self.mount_path, key_id);
        
        let response = self.vault_request("POST", &path, Some(serde_json::json!({}))).await?;
        
        let plaintext_b64 = response["data"]["plaintext"]
            .as_str()
            .ok_or_else(|| KmsError::ProviderError("No plaintext in response".to_string()))?;
        
        let ciphertext = response["data"]["ciphertext"]
            .as_str()
            .ok_or_else(|| KmsError::ProviderError("No ciphertext in response".to_string()))?;
        
        let plaintext = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, plaintext_b64)
            .map_err(|e| KmsError::ProviderError(e.to_string()))?;
        
        Ok((plaintext, ciphertext.as_bytes().to_vec()))
    }
    
    async fn get_key_metadata(&self, key_id: &str) -> KmsResult<KeyMetadata> {
        let path = format!("{}/keys/{}", self.mount_path, key_id);
        let response = self.vault_request("GET", &path, None).await?;
        
        let data = &response["data"];
        
        Ok(KeyMetadata {
            key_id: key_id.to_string(),
            alias: data["name"].as_str().map(|s| s.to_string()),
            algorithm: KeyAlgorithm::Aes256Gcm,
            usage: KeyUsage::EncryptDecrypt,
            created_at: chrono::Utc::now().to_rfc3339(),
            rotated_at: None,
            expires_at: None,
            state: if data["deletion_allowed"].as_bool().unwrap_or(true) {
                KeyState::Active
            } else {
                KeyState::Disabled
            },
            provider_metadata: HashMap::new(),
        })
    }
    
    async fn list_keys(&self) -> KmsResult<Vec<KeyMetadata>> {
        let path = format!("{}/keys", self.mount_path);
        let response = self.vault_request("GET", &path, None).await?;
        
        let keys = response["data"]["keys"]
            .as_array()
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str())
                .map(|name| KeyMetadata {
                    key_id: name.to_string(),
                    alias: Some(name.to_string()),
                    algorithm: KeyAlgorithm::Aes256Gcm,
                    usage: KeyUsage::EncryptDecrypt,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    rotated_at: None,
                    expires_at: None,
                    state: KeyState::Active,
                    provider_metadata: HashMap::new(),
                })
                .collect())
            .unwrap_or_default();
        
        Ok(keys)
    }
    
    async fn create_key(
        &self,
        alias: &str,
        algorithm: KeyAlgorithm,
        _usage: KeyUsage,
    ) -> KmsResult<KeyMetadata> {
        let path = format!("{}/keys/{}", self.mount_path, alias);
        let body = serde_json::json!({
            "type": Self::map_algorithm(algorithm)
        });
        
        self.vault_request("POST", &path, Some(body)).await?;
        
        Ok(KeyMetadata {
            key_id: alias.to_string(),
            alias: Some(alias.to_string()),
            algorithm,
            usage: _usage,
            created_at: chrono::Utc::now().to_rfc3339(),
            rotated_at: None,
            expires_at: None,
            state: KeyState::Active,
            provider_metadata: HashMap::new(),
        })
    }
    
    async fn rotate_key(&self, key_id: &str) -> KmsResult<KeyMetadata> {
        let path = format!("{}/keys/{}/rotate", self.mount_path, key_id);
        self.vault_request("POST", &path, Some(serde_json::json!({}))).await?;
        
        self.get_key_metadata(key_id).await
    }
    
    async fn disable_key(&self, key_id: &str) -> KmsResult<()> {
        let path = format!("{}/keys/{}/config", self.mount_path, key_id);
        let body = serde_json::json!({
            "deletion_allowed": false
        });
        
        self.vault_request("POST", &path, Some(body)).await?;
        Ok(())
    }
    
    async fn enable_key(&self, key_id: &str) -> KmsResult<()> {
        let path = format!("{}/keys/{}/config", self.mount_path, key_id);
        let body = serde_json::json!({
            "deletion_allowed": true
        });
        
        self.vault_request("POST", &path, Some(body)).await?;
        Ok(())
    }
    
    async fn schedule_key_deletion(&self, key_id: &str, _days: u32) -> KmsResult<()> {
        let path = format!("{}/keys/{}", self.mount_path, key_id);
        self.vault_request("DELETE", &path, None).await?;
        Ok(())
    }
    
    async fn cancel_key_deletion(&self, _key_id: &str) -> KmsResult<()> {
        Err(KmsError::ProviderError("Vault does not support canceling deletion".to_string()))
    }
}
