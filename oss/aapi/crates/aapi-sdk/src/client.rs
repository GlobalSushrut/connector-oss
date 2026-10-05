//! AAPI Client for interacting with the Gateway

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info};

use aapi_core::Vakya;
use aapi_crypto::{KeyStore, KeyId, VakyaSigner, SignedVakya};

use crate::error::{SdkError, SdkResult};

/// Configuration for the AAPI client
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Gateway base URL
    pub gateway_url: String,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Whether to sign requests
    pub sign_requests: bool,
    /// Key ID for signing
    pub signing_key_id: Option<KeyId>,
    /// User agent string
    pub user_agent: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            gateway_url: "http://localhost:8080".to_string(),
            timeout_secs: 30,
            sign_requests: false,
            signing_key_id: None,
            user_agent: format!("aapi-sdk/{}", env!("CARGO_PKG_VERSION")),
        }
    }
}

impl ClientConfig {
    pub fn new(gateway_url: impl Into<String>) -> Self {
        Self {
            gateway_url: gateway_url.into(),
            ..Default::default()
        }
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    pub fn with_signing(mut self, key_id: KeyId) -> Self {
        self.sign_requests = true;
        self.signing_key_id = Some(key_id);
        self
    }
}

/// AAPI Client for submitting requests to the Gateway
pub struct AapiClient {
    config: ClientConfig,
    http_client: Client,
    key_store: Option<KeyStore>,
    signer: Option<VakyaSigner>,
}

impl AapiClient {
    /// Create a new client with the given configuration
    pub fn new(config: ClientConfig) -> SdkResult<Self> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent(&config.user_agent)
            .build()?;

        Ok(Self {
            config,
            http_client,
            key_store: None,
            signer: None,
        })
    }

    /// Create a client with signing capabilities
    pub fn with_key_store(mut self, key_store: KeyStore) -> Self {
        let signer = VakyaSigner::new(key_store.clone());
        self.key_store = Some(key_store);
        self.signer = Some(signer);
        self
    }

    /// Submit a VĀKYA request
    pub async fn submit(&self, vakya: Vakya) -> SdkResult<SubmitResponse> {
        let url = format!("{}/v1/vakya", self.config.gateway_url);
        
        debug!(vakya_id = %vakya.vakya_id, action = %vakya.v3_kriya.action, "Submitting VĀKYA");

        let request_body = if self.config.sign_requests {
            if let (Some(ref signer), Some(ref key_id)) = (&self.signer, &self.config.signing_key_id) {
                let signed = signer.sign(&vakya, key_id)
                    .map_err(|e| SdkError::Signing(e.to_string()))?;
                
                SubmitRequest {
                    vakya,
                    signature: Some(signed.signature.value),
                    key_id: Some(signed.signature.key_id.0),
                }
            } else {
                return Err(SdkError::Configuration(
                    "Signing enabled but no key store or key ID configured".to_string()
                ));
            }
        } else {
            SubmitRequest {
                vakya,
                signature: None,
                key_id: None,
            }
        };

        let response = self.http_client
            .post(&url)
            .json(&request_body)
            .send()
            .await?;

        self.handle_response(response).await
    }

    /// Get a VĀKYA by ID
    pub async fn get_vakya(&self, vakya_id: &str) -> SdkResult<VakyaResponse> {
        let url = format!("{}/v1/vakya/{}", self.config.gateway_url, vakya_id);
        
        let response = self.http_client.get(&url).send().await?;
        self.handle_response(response).await
    }

    /// Get receipt for a VĀKYA
    pub async fn get_receipt(&self, vakya_id: &str) -> SdkResult<ReceiptResponse> {
        let url = format!("{}/v1/vakya/{}/receipt", self.config.gateway_url, vakya_id);
        
        let response = self.http_client.get(&url).send().await?;
        self.handle_response(response).await
    }

    /// Get effects for a VĀKYA
    pub async fn get_effects(&self, vakya_id: &str) -> SdkResult<Vec<EffectResponse>> {
        let url = format!("{}/v1/vakya/{}/effects", self.config.gateway_url, vakya_id);
        
        let response = self.http_client.get(&url).send().await?;
        self.handle_response(response).await
    }

    /// Get Merkle root for a tree type
    pub async fn get_merkle_root(&self, tree_type: &str) -> SdkResult<MerkleRootResponse> {
        let url = format!("{}/v1/merkle/root?tree_type={}", self.config.gateway_url, tree_type);
        
        let response = self.http_client.get(&url).send().await?;
        self.handle_response(response).await
    }

    /// Get inclusion proof
    pub async fn get_inclusion_proof(&self, tree_type: &str, leaf_index: i64) -> SdkResult<InclusionProofResponse> {
        let url = format!(
            "{}/v1/merkle/proof?tree_type={}&leaf_index={}",
            self.config.gateway_url, tree_type, leaf_index
        );
        
        let response = self.http_client.get(&url).send().await?;
        self.handle_response(response).await
    }

    /// Health check
    pub async fn health(&self) -> SdkResult<HealthResponse> {
        let url = format!("{}/health", self.config.gateway_url);
        
        let response = self.http_client.get(&url).send().await?;
        self.handle_response(response).await
    }

    /// Handle HTTP response
    async fn handle_response<T: for<'de> Deserialize<'de>>(&self, response: reqwest::Response) -> SdkResult<T> {
        let status = response.status();
        
        if status.is_success() {
            Ok(response.json().await?)
        } else {
            let error_body: ErrorResponse = response.json().await
                .unwrap_or_else(|_| ErrorResponse {
                    error: "UNKNOWN".to_string(),
                    message: "Unknown error".to_string(),
                });

            match status {
                StatusCode::NOT_FOUND => Err(SdkError::NotFound(error_body.message)),
                StatusCode::FORBIDDEN => Err(SdkError::Authorization(error_body.message)),
                StatusCode::BAD_REQUEST => Err(SdkError::Validation(error_body.message)),
                _ => Err(SdkError::Gateway {
                    code: error_body.error,
                    message: error_body.message,
                }),
            }
        }
    }
}

/// Request to submit a VĀKYA
#[derive(Debug, Serialize)]
struct SubmitRequest {
    vakya: Vakya,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
}

/// Response from submitting a VĀKYA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitResponse {
    pub vakya_id: String,
    pub vakya_hash: String,
    pub status: String,
    pub receipt: Option<ReceiptResponse>,
    pub merkle_root: Option<String>,
    pub leaf_index: Option<i64>,
}

/// VĀKYA record response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VakyaResponse {
    pub id: String,
    pub vakya_id: String,
    pub vakya_hash: String,
    pub karta_pid: String,
    pub karma_rid: String,
    pub kriya_action: String,
    pub created_at: String,
    pub leaf_index: Option<i64>,
    pub merkle_root: Option<String>,
}

/// Receipt response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptResponse {
    pub vakya_id: String,
    pub vakya_hash: String,
    pub reason_code: String,
    pub message: Option<String>,
    pub duration_ms: Option<i64>,
    pub effect_ids: Vec<String>,
    pub executor_id: String,
    pub created_at: String,
}

/// Effect response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectResponse {
    pub id: String,
    pub vakya_id: String,
    pub effect_bucket: String,
    pub target_rid: String,
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
    pub reversible: bool,
    pub created_at: String,
}

/// Merkle root response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleRootResponse {
    pub tree_type: String,
    pub root_hash: Option<String>,
    pub timestamp: String,
}

/// Inclusion proof response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofResponse {
    pub leaf_hash: String,
    pub leaf_index: i64,
    pub tree_size: i64,
    pub proof_hashes: Vec<ProofNode>,
    pub root_hash: String,
}

/// Proof node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofNode {
    pub hash: String,
    pub position: String,
}

/// Health response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub gateway_id: String,
    pub version: String,
    pub timestamp: String,
}

/// Error response from gateway
#[derive(Debug, Clone, Deserialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config() {
        let config = ClientConfig::new("http://localhost:8080")
            .with_timeout(60);

        assert_eq!(config.gateway_url, "http://localhost:8080");
        assert_eq!(config.timeout_secs, 60);
    }

    #[test]
    fn test_client_creation() {
        let config = ClientConfig::default();
        let client = AapiClient::new(config);
        assert!(client.is_ok());
    }
}
