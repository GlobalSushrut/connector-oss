//! OpenAI provider implementation
//!
//! Supports chat completions, embeddings, and streaming

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tracing::{debug, error, info};

use super::{Provider, UnifiedRequest, UnifiedResponse, StreamChunk, TokenUsage};
use crate::error::AppError;

pub struct OpenAiProvider {
    client: Client,
    api_key: String,
    api_base: String,
    organization: Option<String>,
}

impl OpenAiProvider {
    pub fn new(api_key: String, api_base: String, organization: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_key,
            api_base,
            organization,
        }
    }
}

#[async_trait]
impl Provider for OpenAiProvider {
    fn name(&self) -> &str {
        "openai"
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn supports_tools(&self) -> bool {
        true
    }

    async fn list_models(&self) -> Result<Vec<String>, AppError> {
        let url = format!("{}/models", self.api_base);
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Failed to list models: {}", e)))?;

        if response.status().is_success() {
            let data: OpenAiModelsResponse = response.json().await
                .map_err(|e| AppError::Serialization(e.to_string()))?;
            
            Ok(data.data.into_iter().map(|m| m.id).collect())
        } else {
            Err(AppError::ConnectorProxy("Failed to list models".to_string()))
        }
    }

    async fn complete(&self, request: UnifiedRequest) -> Result<UnifiedResponse, AppError> {
        let url = format!("{}/chat/completions", self.api_base);
        
        let model_name = request.model.clone();
        
        let openai_request = OpenAiRequest {
            model: request.model,
            messages: request.messages.into_iter().map(|m| OpenAiMessage {
                role: m.role,
                content: m.content,
            }).collect(),
            temperature: request.temperature,
            max_tokens: request.max_tokens.map(|t| t as u32),
            stream: Some(false),
            tools: request.tools.map(|tools| tools.into_iter().map(|t| OpenAiTool {
                tool_type: "function".to_string(),
                function: OpenAiFunction {
                    name: t.name,
                    description: t.description,
                    parameters: t.parameters,
                },
            }).collect()),
        };

        let start = Instant::now();
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&openai_request)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("OpenAI request failed: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            error!("OpenAI error: {} - {}", status, body);
            return Err(AppError::ConnectorProxy(format!("OpenAI error: {}", status)));
        }

        let data: OpenAiResponse = response.json().await
            .map_err(|e| AppError::Serialization(e.to_string()))?;

        let execution_time = start.elapsed().as_millis() as u64;
        
        let choice = data.choices.first()
            .ok_or_else(|| AppError::Internal("No choices in OpenAI response".to_string()))?;

        let token_usage = data.usage.map(|u| TokenUsage {
            input_tokens: u.prompt_tokens as u64,
            output_tokens: u.completion_tokens as u64,
            total_tokens: u.total_tokens as u64,
            estimated_cost_usd: calculate_openai_cost(&model_name, u.prompt_tokens as u64, u.completion_tokens as u64),
        }).unwrap_or(TokenUsage {
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            estimated_cost_usd: 0.0,
        });

        info!("OpenAI completion: {} tokens in {}ms", token_usage.total_tokens, execution_time);

        Ok(UnifiedResponse {
            id: data.id,
            model: data.model,
            content: choice.message.content.clone(),
            tool_calls: choice.message.tool_calls.clone().unwrap_or_default()
                .into_iter().map(|tc| super::ToolCall {
                    id: tc.id,
                    function: super::FunctionCall {
                        name: tc.function.name,
                        arguments: tc.function.arguments,
                    },
                }).collect(),
            usage: token_usage,
            finish_reason: choice.finish_reason.clone().unwrap_or_default(),
            metadata: std::collections::HashMap::new(),
        })
    }

    async fn complete_stream(
        &self,
        request: UnifiedRequest,
    ) -> Result<tokio::sync::mpsc::Receiver<Result<StreamChunk, AppError>>, AppError> {
        let url = format!("{}/chat/completions", self.api_base);
        
        let openai_request = OpenAiRequest {
            model: request.model,
            messages: request.messages.into_iter().map(|m| OpenAiMessage {
                role: m.role,
                content: m.content,
            }).collect(),
            temperature: request.temperature,
            max_tokens: request.max_tokens.map(|t| t as u32),
            stream: Some(true),
            tools: None,
        };

        let (tx, rx) = tokio::sync::mpsc::channel(100);
        
        let client = self.client.clone();
        let api_key = self.api_key.clone();
        
        tokio::spawn(async move {
            let response = client
                .post(&url)
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&openai_request)
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
                                for line in text.lines() {
                                    if line.starts_with("data: ") {
                                        let data = &line[6..];
                                        if data == "[DONE]" { break; }
                                        
                                        if let Ok(stream_resp) = serde_json::from_str::<OpenAiStreamResponse>(data) {
                                            let content = stream_resp.choices.first()
                                                .and_then(|c| c.delta.content.clone())
                                                .unwrap_or_default();
                                            
                                            let _ = tx.send(Ok(StreamChunk {
                                                id: stream_resp.id,
                                                index,
                                                content,
                                                tool_calls: vec![],
                                                finish_reason: stream_resp.choices.first()
                                                    .and_then(|c| c.finish_reason.clone()),
                                                usage: None,
                                            })).await;
                                            index += 1;
                                        }
                                    }
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
        let url = format!("{}/embeddings", self.api_base);
        
        let request = OpenAiEmbeddingRequest {
            model: model.to_string(),
            input: texts,
        };

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Embedding request failed: {}", e)))?;

        if response.status().is_success() {
            let data: OpenAiEmbeddingResponse = response.json().await
                .map_err(|e| AppError::Serialization(e.to_string()))?;
            
            Ok(data.data.into_iter().map(|d| d.embedding).collect())
        } else {
            Err(AppError::ConnectorProxy("Embedding request failed".to_string()))
        }
    }
}

// OpenAI API types
#[derive(Debug, Serialize)]
struct OpenAiRequest {
    model: String,
    messages: Vec<OpenAiMessage>,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
    stream: Option<bool>,
    tools: Option<Vec<OpenAiTool>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OpenAiMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct OpenAiTool {
    #[serde(rename = "type")]
    tool_type: String,
    function: OpenAiFunction,
}

#[derive(Debug, Serialize)]
struct OpenAiFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    id: String,
    model: String,
    choices: Vec<OpenAiChoice>,
    usage: Option<OpenAiUsage>,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    message: OpenAiResponseMessage,
    finish_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenAiResponseMessage {
    content: String,
    tool_calls: Option<Vec<OpenAiToolCall>>,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenAiToolCall {
    id: String,
    function: OpenAiFunctionCall,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenAiFunctionCall {
    name: String,
    arguments: String,
}

#[derive(Debug, Deserialize)]
struct OpenAiUsage {
    prompt_tokens: i32,
    completion_tokens: i32,
    total_tokens: i32,
}

#[derive(Debug, Deserialize)]
struct OpenAiStreamResponse {
    id: String,
    choices: Vec<OpenAiStreamChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenAiStreamChoice {
    delta: OpenAiDelta,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiDelta {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiModelsResponse {
    data: Vec<OpenAiModel>,
}

#[derive(Debug, Deserialize)]
struct OpenAiModel {
    id: String,
}

#[derive(Debug, Serialize)]
struct OpenAiEmbeddingRequest {
    model: String,
    input: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiEmbeddingResponse {
    data: Vec<OpenAiEmbeddingData>,
}

#[derive(Debug, Deserialize)]
struct OpenAiEmbeddingData {
    embedding: Vec<f32>,
}

fn calculate_openai_cost(model: &str, input_tokens: u64, output_tokens: u64) -> f64 {
    let (input_price, output_price) = match model {
        m if m.contains("gpt-4o-mini") => (0.00015, 0.0006),
        m if m.contains("gpt-4o") => (0.0025, 0.01),
        m if m.contains("gpt-4") => (0.03, 0.06),
        m if m.contains("o1") => (0.015, 0.06),
        _ => (0.001, 0.002),
    };
    
    (input_tokens as f64 / 1000.0) * input_price + (output_tokens as f64 / 1000.0) * output_price
}

use futures_util::StreamExt;
