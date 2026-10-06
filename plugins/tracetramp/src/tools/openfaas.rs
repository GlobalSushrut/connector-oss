//! OpenFaaS tool integration
//!
//! Tools that wrap OpenFaaS functions

use super::{Tool, ToolType, ExecutionConfig};

/// Create a tool from an OpenFaaS function
pub fn create_openfaas_tool(name: &str, function_name: &str, gateway_url: &str) -> Tool {
    Tool {
        name: name.to_string(),
        description: format!("OpenFaaS function: {}", function_name),
        tool_type: ToolType::OpenFaasFunction,
        parameters: super::ToolParameters {
            required: vec![],
            properties: serde_json::json!({}),
            additional_properties: true,
        },
        execution: ExecutionConfig {
            endpoint: None,
            function_name: Some(function_name.to_string()),
            gateway_url: Some(gateway_url.to_string()),
            code: None,
            container_image: None,
            workflow_id: None,
            mcp_server: None,
            method: Some("POST".to_string()),
            timeout_secs: 30,
            retry: None,
        },
        auth: None,
        rate_limit: None,
    }
}
