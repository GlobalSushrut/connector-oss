//! Ollama provider implementation
//!
//! Supports local LLMs via Ollama API (llama, mistral, qwen, etc.)

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use super::{Provider, UnifiedRequest, UnifiedResponse, StreamChunk, TokenUsage};
use crate::error::AppError;

pub struct OllamaProvider {
    client: Client,
    base_url: String,
}

impl OllamaProvider {
    pub fn new(base_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(600)) // Longer timeout for local models
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }
}

#[async_trait]
impl Provider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        // Tool support depends on the model
        true
    }

    async fn list_models(&self) -> Result<Vec<String>, AppError> {
        let url = format!("{}/api/tags", self.base_url);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Ollama list models failed: {}", e)))?;

        if response.status().is_success() {
            let data: OllamaTagsResponse = response.json().await
                .map_err(|e| AppError::Serialization(e.to_string()))?;
            
            Ok(data.models.into_iter().map(|m| m.name).collect())
        } else {
            Err(AppError::ConnectorProxy("Failed to list Ollama models".to_string()))
        }
    }

    async fn complete(&self, request: UnifiedRequest) -> Result<UnifiedResponse, AppError> {
        let url = format!("{}/api/generate", self.base_url);
        
        // Convert messages to prompt
        let prompt = messages_to_prompt(&request.messages);
        
        let ollama_request = OllamaGenerateRequest {
            model: request.model,
            prompt,
            stream: false,
            options: OllamaOptions {
                temperature: request.temperature,
                num_predict: request.max_tokens.map(|t| t as i32),
            },
        };

        let start = Instant::now();
        
        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&ollama_request)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Ollama request failed: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            warn!("Ollama error: {} - {}", status, body);
            return Err(AppError::ConnectorProxy(format!("Ollama error: {}", status)));
        }

        let data: OllamaGenerateResponse = response.json().await
            .map_err(|e| AppError::Serialization(e.to_string()))?;

        let execution_time = start.elapsed().as_millis() as u64;
        
        // Estimate tokens (Ollama doesn't always return counts)
        let input_tokens = data.prompt_eval_count.unwrap_or(0) as u64;
        let output_tokens = data.eval_count.unwrap_or(0) as u64;
        let total_tokens = input_tokens + output_tokens;

        info!("Ollama completion: {} tokens in {}ms", total_tokens, execution_time);

        Ok(UnifiedResponse {
            id: format!("ollama-{}", uuid::Uuid::new_v4()),
            model: data.model,
            content: data.response,
            tool_calls: vec![],
            usage: TokenUsage {
                input_tokens,
                output_tokens,
                total_tokens,
                estimated_cost_usd: 0.0, // Local = free
            },
            finish_reason: if data.done { "stop".to_string() } else { "length".to_string() },
            metadata: std::collections::HashMap::new(),
        })
    }

    async fn complete_stream(
        &self,
        request: UnifiedRequest,
    ) -> Result<tokio::sync::mpsc::Receiver<Result<StreamChunk, AppError>>, AppError> {
        let url = format!("{}/api/generate", self.base_url);
        
        let prompt = messages_to_prompt(&request.messages);
        
        let ollama_request = OllamaGenerateRequest {
            model: request.model,
            prompt,
            stream: true,
            options: OllamaOptions {
                temperature: request.temperature,
                num_predict: request.max_tokens.map(|t| t as i32),
            },
        };

        let (tx, rx) = tokio::sync::mpsc::channel(100);
        
        let client = self.client.clone();
        
        tokio::spawn(async move {
            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&ollama_request)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    let mut stream = resp.bytes_stream();
                    let mut index = 0;
                    
                    while let Some(chunk_result) = stream.next().await {
                        match chunk_result {
                            Ok(chunk) => {
                                let text = String::from_utf8_lossy(&chunk);
                                if let Ok(stream_resp) = serde_json::from_str::<OllamaStreamResponse>(&text) {
                                    let _ = tx.send(Ok(StreamChunk {
                                        id: format!("ollama-{}", index),
                                        index,
                                        content: stream_resp.response,
                                        tool_calls: vec![],
                                        finish_reason: if stream_resp.done { Some("stop".to_string()) } else { None },
                                        usage: stream_resp.eval_count.map(|c| TokenUsage {
                                            input_tokens: stream_resp.prompt_eval_count.unwrap_or(0) as u64,
                                            output_tokens: c as u64,
                                            total_tokens: (stream_resp.prompt_eval_count.unwrap_or(0) + c) as u64,
                                            estimated_cost_usd: 0.0,
                                        }),
                                    })).await;
                                    index += 1;
                                    
                                    if stream_resp.done { break; }
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Err(AppError::ConnectorProxy(e.to_string()))).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(AppError::ConnectorProxy(e.to_string()))).await;
                }
            }
        });

        Ok(rx)
    }

    async fn embed(&self, texts: Vec<String>, model: &str) -> Result<Vec<Vec<f32>>, AppError> {
        let url = format!("{}/api/embeddings", self.base_url);
        
        let mut embeddings = Vec::new();
        
        for text in texts {
            let request = OllamaEmbedRequest {
                model: model.to_string(),
                prompt: text,
            };

            let response = self.client
                .post(&url)
                .json(&request)
                .send()
                .await
                .map_err(|e| AppError::ConnectorProxy(format!("Embedding request failed: {}", e)))?;

            if response.status().is_success() {
                let data: OllamaEmbedResponse = response.json().await
                    .map_err(|e| AppError::Serialization(e.to_string()))?;
                embeddings.push(data.embedding);
            }
        }
        
        Ok(embeddings)
    }
}

// Ollama API types
#[derive(Debug, Serialize)]
struct OllamaGenerateRequest {
    model: String,
    prompt: String,
    stream: bool,
    options: OllamaOptions,
}

#[derive(Debug, Serialize)]
struct OllamaOptions {
    temperature: Option<f32>,
    num_predict: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct OllamaGenerateResponse {
    model: String,
    response: String,
    done: bool,
    prompt_eval_count: Option<i32>,
    eval_count: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct OllamaStreamResponse {
    response: String,
    done: bool,
    prompt_eval_count: Option<i32>,
    eval_count: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModel>,
}

#[derive(Debug, Deserialize)]
struct OllamaModel {
    name: String,
}

#[derive(Debug, Serialize)]
struct OllamaEmbedRequest {
    model: String,
    prompt: String,
}

#[derive(Debug, Deserialize)]
struct OllamaEmbedResponse {
    embedding: Vec<f32>,
}

fn messages_to_prompt(messages: &[super::Message]) -> String {
    messages.iter()
        .map(|m| format!("{}: {}", m.role, m.content))
        .collect::<Vec<_>>()
        .join("\n\n")
}

use futures_util::StreamExt;
