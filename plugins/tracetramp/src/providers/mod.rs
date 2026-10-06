//! Provider abstractions for different LLM services
//!
//! Supports: OpenAI, Anthropic, Azure, Ollama, Mistral, Cohere, 
//! and custom/local providers

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod openai;
pub mod anthropic;
pub mod azure;
pub mod ollama;
pub mod unified;

/// Unified request format (normalized across providers)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u64>,
    pub stream: bool,
    pub tools: Option<Vec<ToolDefinition>>,
    pub tool_choice: Option<String>,
    pub response_format: Option<ResponseFormat>,
    pub extra_params: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value, // JSON Schema
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub function: FunctionCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFormat {
    #[serde(rename = "type")]
    pub format_type: String,
    pub schema: Option<serde_json::Value>,
}

/// Unified response format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedResponse {
    pub id: String,
    pub model: String,
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: TokenUsage,
    pub finish_reason: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub estimated_cost_usd: f64,
}

/// Provider trait for pluggable LLM backends
#[async_trait]
pub trait Provider: Send + Sync {
    /// Provider name
    fn name(&self) -> &str;
    
    /// Check if provider supports streaming
    fn supports_streaming(&self) -> bool;
    
    /// Check if provider supports tools/function calling
    fn supports_tools(&self) -> bool;
    
    /// List available models
    async fn list_models(&self) -> Result<Vec<String>, crate::error::AppError>;
    
    /// Complete a chat request
    async fn complete(&self, request: UnifiedRequest) -> Result<UnifiedResponse, crate::error::AppError>;
    
    /// Stream a chat request
    async fn complete_stream(
        &self, 
        request: UnifiedRequest
    ) -> Result<tokio::sync::mpsc::Receiver<Result<StreamChunk, crate::error::AppError>>, crate::error::AppError>;
    
    /// Get embeddings
    async fn embed(&self, texts: Vec<String>, model: &str) -> Result<Vec<Vec<f32>>, crate::error::AppError>;
}

/// Streaming chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    pub id: String,
    pub index: u32,
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub finish_reason: Option<String>,
    pub usage: Option<TokenUsage>,
}

/// Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    pub provider_type: ProviderType,
    pub api_base: String,
    pub api_key: String,
    pub default_model: String,
    pub timeout_secs: u64,
    pub rate_limit_rps: f64,
    pub supports_streaming: bool,
    pub supports_tools: bool,
    pub custom_headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    OpenAi,
    Anthropic,
    Azure,
    Ollama,
    Mistral,
    Cohere,
    Vertex,
    Bedrock,
    Custom,
}

/// Provider registry
pub struct ProviderRegistry {
    providers: HashMap<String, Box<dyn Provider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }
    
    pub fn register(&mut self, name: String, provider: Box<dyn Provider>) {
        self.providers.insert(name, provider);
    }
    
    pub fn get(&self, name: &str) -> Option<&dyn Provider> {
        self.providers.get(name).map(|p| p.as_ref())
    }
}
