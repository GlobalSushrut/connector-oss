//! Tool Execution Engine
//!
//! Executes tools from various sources (OpenAI functions, MCP, REST APIs, etc.)

use super::{Tool, ToolCall, ToolResult, ToolOutput};
use crate::error::AppError;
use reqwest::Client;
use std::time::{Duration, Instant};
use tracing::{info, debug, error};

pub struct ToolExecutor {
    http_client: Client,
}

impl ToolExecutor {
    pub fn new() -> Self {
        Self {
            http_client: Client::builder()
                .timeout(Duration::from_secs(300))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }
    
    /// Execute a tool call
    pub async fn execute(&self, tool: &Tool, call: &ToolCall) -> Result<ToolResult, AppError> {
        let start = Instant::now();
        
        debug!("Executing tool: {} with args: {:?}", tool.name, call.arguments);
        
        let result = match &tool.execution {
            super::ExecutionConfig { endpoint: Some(url), method, .. } => {
                self.execute_rest(tool, call, url, method.as_deref().unwrap_or("POST")).await
            }
            super::ExecutionConfig { function_name: Some(name), gateway_url, .. } => {
                self.execute_openfaas(tool, call, gateway_url.as_deref().unwrap_or("http://localhost:8080"), name).await
            }
            super::ExecutionConfig { code: Some(code), .. } => {
                self.execute_code(tool, call, code).await
            }
            super::ExecutionConfig { mcp_server: Some(server), .. } => {
                self.execute_mcp(tool, call, server).await
            }
            _ => Err(AppError::Internal("Tool execution not configured".to_string())),
        };
        
        let execution_time = start.elapsed().as_millis() as u64;
        
        match result {
            Ok(output) => {
                info!("Tool {} executed successfully in {}ms", tool.name, execution_time);
                Ok(ToolResult {
                    tool_name: tool.name.clone(),
                    success: true,
                    output,
                    execution_time_ms: execution_time,
                    tokens_consumed: None,
                    metadata: std::collections::HashMap::new(),
                })
            }
            Err(e) => {
                error!("Tool {} failed: {}", tool.name, e);
                Ok(ToolResult {
                    tool_name: tool.name.clone(),
                    success: false,
                    output: ToolOutput::Error {
                        code: "EXECUTION_FAILED".to_string(),
                        message: e.to_string(),
                    },
                    execution_time_ms: execution_time,
                    tokens_consumed: None,
                    metadata: std::collections::HashMap::new(),
                })
            }
        }
    }
    
    /// Execute REST API tool
    async fn execute_rest(
        &self,
        _tool: &Tool,
        call: &ToolCall,
        url: &str,
        method: &str,
    ) -> Result<ToolOutput, AppError> {
        let request_builder = match method {
            "GET" => self.http_client.get(url),
            "POST" => self.http_client.post(url).json(&call.arguments),
            "PUT" => self.http_client.put(url).json(&call.arguments),
            "PATCH" => self.http_client.patch(url).json(&call.arguments),
            "DELETE" => self.http_client.delete(url),
            _ => self.http_client.post(url).json(&call.arguments),
        };
        
        let response = request_builder
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("HTTP request failed: {}", e)))?;
        
        let body = response.text().await?;
        
        // Try to parse as JSON, fall back to text
        let output = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            ToolOutput::Json(json)
        } else {
            ToolOutput::Text(body)
        };
        
        Ok(output)
    }
    
    /// Execute OpenFaaS function
    async fn execute_openfaas(
        &self,
        _tool: &Tool,
        call: &ToolCall,
        gateway_url: &str,
        function_name: &str,
    ) -> Result<ToolOutput, AppError> {
        let url = format!("{}/function/{}", gateway_url, function_name);
        
        let response = self.http_client
            .post(&url)
            .json(&call.arguments)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("OpenFaaS call failed: {}", e)))?;
        
        let body = response.text().await?;
        
        let output = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            ToolOutput::Json(json)
        } else {
            ToolOutput::Text(body)
        };
        
        Ok(output)
    }
    
    /// Execute inline code (Python/JavaScript)
    async fn execute_code(
        &self,
        _tool: &Tool,
        call: &ToolCall,
        code: &str,
    ) -> Result<ToolOutput, AppError> {
        // In production, this would use a sandboxed environment
        // For now, return a placeholder
        debug!("Would execute code: {} with args: {:?}", code, call.arguments);
        
        Ok(ToolOutput::Json(serde_json::json!({
            "executed": true,
            "code_snippet": &code[..code.len().min(100)],
            "args": call.arguments,
        })))
    }
    
    /// Execute MCP (Model Context Protocol) tool
    async fn execute_mcp(
        &self,
        tool: &Tool,
        call: &ToolCall,
        server_url: &str,
    ) -> Result<ToolOutput, AppError> {
        let url = format!("{}/tools/{}/execute", server_url, tool.name);
        
        let response = self.http_client
            .post(&url)
            .json(&call.arguments)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("MCP call failed: {}", e)))?;
        
        let body = response.text().await?;
        
        let output = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            ToolOutput::Json(json)
        } else {
            ToolOutput::Text(body)
        };
        
        Ok(output)
    }
    
    /// Execute batch of tools
    pub async fn execute_batch(
        &self,
        calls: &[(Tool, ToolCall)],
    ) -> Vec<Result<ToolResult, AppError>> {
        let futures: Vec<_> = calls
            .iter()
            .map(|(tool, call)| self.execute(tool, call))
            .collect();
        
        futures::future::join_all(futures).await
    }
}

impl Default for ToolExecutor {
    fn default() -> Self {
        Self::new()
    }
}
