//! AWS Lambda function execution backend
//!
//! Invokes Lambda via HTTP (Lambda Function URL) or API Gateway endpoint
//! For full IAM-signed invocation, use aws-sdk-lambda

use super::{FunctionCall, FunctionResult};
use crate::error::AppError;
use reqwest::Client;
use std::time::{Duration, Instant};
use tracing::{info, debug, error};

pub struct LambdaClient {
    client: Client,
    region: String,
    role_arn: Option<String>,
    function_url_template: Option<String>,
}

impl LambdaClient {
    pub fn new(region: String, role_arn: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(900)) // Lambda max 15 min
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            client,
            region,
            role_arn,
            function_url_template: std::env::var("LAMBDA_FUNCTION_URL_TEMPLATE").ok(),
        }
    }
    
    /// Invoke a Lambda function
    /// Supports: Lambda Function URLs (simplest), API Gateway endpoints
    pub async fn invoke(&self, call: &FunctionCall) -> Result<FunctionResult, AppError> {
        let start = Instant::now();
        
        // Build URL from template or use function name
        let url = if let Some(template) = &self.function_url_template {
            template.replace("{function}", &call.function_name)
                .replace("{region}", &self.region)
        } else {
            // Lambda Function URL format: https://<url-id>.lambda-url.<region>.on.aws/
            format!("https://{}.lambda-url.{}.on.aws/", call.function_name, self.region)
        };
        
        debug!("Invoking Lambda: {} via {}", call.function_name, url);
        
        let mut req_builder = self.client.post(&url);
        
        // Add IAM auth if role_arn provided (in production: sigv4 signing)
        if let Some(ref arn) = self.role_arn {
            req_builder = req_builder.header("X-IAM-Role", arn);
        }
        
        // Add function-specific headers
        req_builder = req_builder.header("X-Amz-Invocation-Type", 
            if call.async_execution { "Event" } else { "RequestResponse" });
        
        let response = req_builder
            .json(&call.parameters)
            .timeout(Duration::from_secs(call.timeout_seconds))
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Lambda invoke failed: {}", e)))?;
        
        let status = response.status();
        let execution_time_ms = start.elapsed().as_millis() as u64;
        
        // Check for cold start indicator
        let cold_start = response.headers()
            .get("X-Amz-Cold-Start")
            .and_then(|v| v.to_str().ok())
            .map(|s| s == "true")
            .unwrap_or(false);
        
        let body_text = response.text().await.unwrap_or_default();
        let output: serde_json::Value = serde_json::from_str(&body_text)
            .unwrap_or_else(|_| serde_json::json!({ "raw": body_text }));
        
        let success = status.is_success();
        if !success {
            error!("Lambda {} returned {}: {}", call.function_name, status, 
                serde_json::to_string(&output).unwrap_or_default());
        } else {
            info!("Lambda {} invoked: {}ms{}", call.function_name, execution_time_ms,
                if cold_start { " (cold start)" } else { "" });
        }
        
        Ok(FunctionResult {
            success,
            output,
            logs: vec![],
            execution_time_ms,
            cold_start,
        })
    }
    
    /// List available functions (requires AWS SDK - stub for now)
    pub async fn list_functions(&self) -> Result<Vec<String>, AppError> {
        debug!("list_functions requires aws-sdk-lambda for full implementation");
        Ok(vec![])
    }
}
