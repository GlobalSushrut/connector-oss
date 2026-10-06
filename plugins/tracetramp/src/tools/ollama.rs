//! Ollama tool integration
//!
//! Tools for local LLM execution via Ollama

use super::{Tool, ToolType, ExecutionConfig};

/// Create a tool that calls an Ollama model
pub fn create_ollama_tool(name: &str, model: &str, ollama_url: &str) -> Tool {
    Tool {
        name: name.to_string(),
        description: format!("Ollama model: {}", model),
        tool_type: ToolType::AgenticWorkflow,
        parameters: super::ToolParameters {
            required: vec!["prompt".to_string()],
            properties: serde_json::json!({
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "The prompt to send to the model"
                    }
                }
            }),
            additional_properties: false,
        },
        execution: ExecutionConfig {
            endpoint: Some(format!("{}/api/generate", ollama_url)),
            function_name: None,
            gateway_url: None,
            code: None,
            container_image: None,
            workflow_id: None,
            mcp_server: None,
            method: Some("POST".to_string()),
            timeout_secs: 300,
            retry: None,
        },
        auth: None,
        rate_limit: None,
    }
}
