//! Anthropic Claude provider implementation

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::{Provider, UnifiedRequest, UnifiedResponse, StreamChunk, TokenUsage};
use crate::error::AppError;

pub struct AnthropicProvider {
    client: Client,
    api_key: String,
    api_base: String,
}

impl AnthropicProvider {
    pub fn new(api_key: String, api_base: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_key,
            api_base: api_base.unwrap_or_else(|| "https://api.anthropic.com".to_string()),
        }
    }
}

#[async_trait]
impl Provider for AnthropicProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        true
    }

    async fn list_models(&self) -> Result<Vec<String>, AppError> {
        Ok(vec![
            "claude-3-5-sonnet-20241022".to_string(),
            "claude-3-5-haiku-20241022".to_string(),
            "claude-3-opus-20240229".to_string(),
            "claude-3-sonnet-20240229".to_string(),
            "claude-3-haiku-20240307".to_string(),
        ])
    }

    async fn complete(&self, request: UnifiedRequest) -> Result<UnifiedResponse, AppError> {
        // Convert unified request to Anthropic format
        let url = format!("{}/v1/messages", self.api_base);
        
        let anthropic_request = AnthropicRequest {
            model: request.model,
            max_tokens: request.max_tokens.map(|t| t as i32).unwrap_or(4096),
            messages: request.messages.into_iter().map(|m| AnthropicMessage {
                role: if m.role == "user" { "user" } else { "assistant" },
                content: m.content,
            }).collect(),
            temperature: request.temperature,
        };

        let response = self.client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&anthropic_request)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Anthropic request failed: {}", e)))?;

        let data: AnthropicResponse = response.json().await
            .map_err(|e| AppError::Serialization(e.to_string()))?;

        let model_name = data.model.clone();
        let content = data.content.iter()
            .filter(|c| c.content_type == "text")
            .map(|c| c.text.clone())
            .collect::<Vec<_>>()
            .join("");

        Ok(UnifiedResponse {
            id: data.id,
            model: data.model,
            content,
            tool_calls: vec![],
            usage: TokenUsage {
                input_tokens: data.usage.input_tokens as u64,
                output_tokens: data.usage.output_tokens as u64,
                total_tokens: (data.usage.input_tokens + data.usage.output_tokens) as u64,
                estimated_cost_usd: calculate_anthropic_cost(&model_name, data.usage.input_tokens as u64, data.usage.output_tokens as u64),
            },
            finish_reason: data.stop_reason.unwrap_or_default(),
            metadata: std::collections::HashMap::new(),
        })
    }

    async fn complete_stream(
        &self,
        _request: UnifiedRequest,
    ) -> Result<tokio::sync::mpsc::Receiver<Result<StreamChunk, AppError>>, AppError> {
        // Streaming implementation placeholder
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let _ = tx.send(Err(AppError::Internal("Streaming not yet implemented".to_string()))).await;
        Ok(rx)
    }

    async fn embed(&self, _texts: Vec<String>, _model: &str) -> Result<Vec<Vec<f32>>, AppError> {
        Err(AppError::Internal("Embeddings not supported by Anthropic".to_string()))
    }
}

#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: i32,
    messages: Vec<AnthropicMessage>,
    temperature: Option<f32>,
}

#[derive(Debug, Serialize)]
struct AnthropicMessage {
    role: &'static str,
    content: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    id: String,
    model: String,
    content: Vec<AnthropicContent>,
    stop_reason: Option<String>,
    usage: AnthropicUsage,
}

#[derive(Debug, Deserialize)]
struct AnthropicContent {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicUsage {
    input_tokens: i32,
    output_tokens: i32,
}

fn calculate_anthropic_cost(model: &str, input_tokens: u64, output_tokens: u64) -> f64 {
    let (input_price, output_price) = match model {
        m if m.contains("claude-3-5-sonnet") => (0.003, 0.015),
        m if m.contains("claude-3-5-haiku") => (0.0008, 0.004),
        m if m.contains("claude-3-opus") => (0.015, 0.075),
        m if m.contains("claude-3-haiku") => (0.00025, 0.00125),
        _ => (0.008, 0.024),
    };
    
    (input_tokens as f64 / 1000.0) * input_price + (output_tokens as f64 / 1000.0) * output_price
}
