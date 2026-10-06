//! Tool Builder DSL
//!
//! Fluent API for constructing tools

use super::{Tool, ToolType, ToolParameters, ExecutionConfig, ToolAuth, RateLimit};

pub struct ToolBuilder {
    tool: Tool,
}

impl ToolBuilder {
    pub fn new(name: &str) -> Self {
        Self {
            tool: Tool {
                name: name.to_string(),
                description: String::new(),
                tool_type: ToolType::RestApi,
                parameters: ToolParameters {
                    required: vec![],
                    properties: serde_json::json!({}),
                    additional_properties: true,
                },
                execution: ExecutionConfig {
                    endpoint: None,
                    function_name: None,
                    gateway_url: None,
                    code: None,
                    container_image: None,
                    workflow_id: None,
                    mcp_server: None,
                    method: Some("GET".to_string()),
                    timeout_secs: 30,
                    retry: None,
                },
                auth: None,
                rate_limit: None,
            },
        }
    }
    
    pub fn description(mut self, desc: &str) -> Self {
        self.tool.description = desc.to_string();
        self
    }
    
    pub fn endpoint(mut self, url: &str) -> Self {
        self.tool.execution.endpoint = Some(url.to_string());
        self
    }
    
    pub fn build(self) -> Tool {
        self.tool
    }
}
