//! Azure OpenAI provider implementation

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::{Provider, UnifiedRequest, UnifiedResponse, StreamChunk, TokenUsage};
use crate::error::AppError;

pub struct AzureProvider {
    client: Client,
    api_key: String,
    endpoint: String,
    api_version: String,
}

impl AzureProvider {
    pub fn new(api_key: String, endpoint: String, api_version: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_key,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            api_version,
        }
    }
}

#[async_trait]
impl Provider for AzureProvider {
    fn name(&self) -> &str {
        "azure"
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        true
    }

    async fn list_models(&self) -> Result<Vec<String>, AppError> {
        // Azure requires deployment names, so list deployments
        Ok(vec![
            "gpt-4o".to_string(),
            "gpt-4o-mini".to_string(),
            "gpt-4".to_string(),
            "gpt-35-turbo".to_string(),
            "text-embedding-3-large".to_string(),
            "text-embedding-3-small".to_string(),
        ])
    }

    async fn complete(&self, request: UnifiedRequest) -> Result<UnifiedResponse, AppError> {
        // Azure uses deployment name as the model
        let url = format!(
            "{}/openai/deployments/{}/chat/completions?api-version={}",
            self.endpoint, request.model, self.api_version
        );

        let azure_request = AzureRequest {
            messages: request.messages.into_iter().map(|m| AzureMessage {
                role: m.role,
                content: m.content,
            }).collect(),
            temperature: request.temperature,
            max_tokens: request.max_tokens.map(|t| t as i32),
            stream: Some(false),
        };

        let response = self.client
            .post(&url)
            .header("api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&azure_request)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Azure request failed: {}", e)))?;

        let data: AzureResponse = response.json().await
            .map_err(|e| AppError::Serialization(e.to_string()))?;

        let choice = data.choices.first()
            .ok_or_else(|| AppError::Internal("No choices in Azure response".to_string()))?;

        let token_usage = data.usage.map(|u| TokenUsage {
            input_tokens: u.prompt_tokens as u64,
            output_tokens: u.completion_tokens as u64,
            total_tokens: u.total_tokens as u64,
            estimated_cost_usd: calculate_azure_cost(&request.model, u.prompt_tokens as u64, u.completion_tokens as u64),
        }).unwrap_or(TokenUsage {
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            estimated_cost_usd: 0.0,
        });

        Ok(UnifiedResponse {
            id: data.id,
            model: data.model,
            content: choice.message.content.clone(),
            tool_calls: vec![],
            usage: token_usage,
            finish_reason: choice.finish_reason.clone().unwrap_or_default(),
            metadata: std::collections::HashMap::new(),
        })
    }

    async fn complete_stream(
        &self,
        _request: UnifiedRequest,
    ) -> Result<tokio::sync::mpsc::Receiver<Result<StreamChunk, AppError>>, AppError> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx.send(Err(AppError::Internal("Streaming not yet implemented".to_string()))).await;
        Ok(rx)
    }

    async fn embed(&self, texts: Vec<String>, model: &str) -> Result<Vec<Vec<f32>>, AppError> {
        let url = format!(
            "{}/openai/deployments/{}/embeddings?api-version={}",
            self.endpoint, model, self.api_version
        );

        let request = AzureEmbedRequest {
            input: texts,
            model: model.to_string(),
        };

        let response = self.client
            .post(&url)
            .header("api-key", &self.api_key)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Azure embedding request failed: {}", e)))?;

        if response.status().is_success() {
            let data: AzureEmbedResponse = response.json().await
                .map_err(|e| AppError::Serialization(e.to_string()))?;
            
            Ok(data.data.into_iter().map(|d| d.embedding).collect())
        } else {
            Err(AppError::ConnectorProxy("Azure embedding request failed".to_string()))
        }
    }
}

#[derive(Debug, Serialize)]
struct AzureRequest {
    messages: Vec<AzureMessage>,
    temperature: Option<f32>,
    max_tokens: Option<i32>,
    stream: Option<bool>,
}

#[derive(Debug, Serialize)]
struct AzureMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct AzureResponse {
    id: String,
    model: String,
    choices: Vec<AzureChoice>,
    usage: Option<AzureUsage>,
}

#[derive(Debug, Deserialize)]
struct AzureChoice {
    message: AzureMessageResponse,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AzureMessageResponse {
    content: String,
}

#[derive(Debug, Deserialize)]
struct AzureUsage {
    prompt_tokens: i32,
    completion_tokens: i32,
    total_tokens: i32,
}

#[derive(Debug, Serialize)]
struct AzureEmbedRequest {
    input: Vec<String>,
    model: String,
}

#[derive(Debug, Deserialize)]
struct AzureEmbedResponse {
    data: Vec<AzureEmbedData>,
}

#[derive(Debug, Deserialize)]
struct AzureEmbedData {
    embedding: Vec<f32>,
}

fn calculate_azure_cost(model: &str, input_tokens: u64, output_tokens: u64) -> f64 {
    // Azure pricing (similar to OpenAI)
    let (input_price, output_price) = match model {
        m if m.contains("gpt-4o") => (0.005, 0.015), // Global pricing
        m if m.contains("gpt-4") => (0.03, 0.06),
        m if m.contains("gpt-35-turbo") => (0.0005, 0.0015),
        _ => (0.001, 0.002),
    };
    
    (input_tokens as f64 / 1000.0) * input_price + (output_tokens as f64 / 1000.0) * output_price
}
