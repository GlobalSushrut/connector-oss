//! OpenFaaS integration for serverless function execution
//!
//! Calls functions deployed on OpenFaaS gateway

use super::{FunctionCall, FunctionResult};
use crate::error::AppError;
use reqwest::Client;
use std::time::{Duration, Instant};
use tracing::{debug, info, error};

pub struct OpenFaasClient {
    client: Client,
    gateway_url: String,
}

impl OpenFaasClient {
    pub fn new(gateway_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .expect("Failed to create HTTP client");
            
        Self {
            client,
            gateway_url: gateway_url.trim_end_matches('/').to_string(),
        }
    }
    
    /// Call an OpenFaaS function
    pub async fn call(&self, call: &FunctionCall) -> Result<FunctionResult, AppError> {
        let url = format!("{}/function/{}", self.gateway_url, call.function_name);
        
        debug!("Calling OpenFaaS function: {} (timeout: {}s)", 
            call.function_name, call.timeout_seconds);
        
        let start = Instant::now();
        
        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&call.parameters)
            .timeout(Duration::from_secs(call.timeout_seconds))
            .send()
            .await
            .map_err(|e| {
                error!("OpenFaaS call failed: {}", e);
                AppError::Internal(format!("Function call failed: {}", e))
            })?;
        
        let status = response.status();
        let body = response.text().await?;
        
        let execution_time = start.elapsed().as_millis() as u64;
        
        if status.is_success() {
            let output = serde_json::from_str(&body)
                .unwrap_or_else(|_| serde_json::json!({ "raw": body }));
            
            info!("OpenFaaS function {} completed in {}ms", 
                call.function_name, execution_time);
            
            Ok(FunctionResult {
                success: true,
                output,
                logs: vec![],
                execution_time_ms: execution_time,
                cold_start: execution_time > 1000,
            })
        } else {
            error!("OpenFaaS function {} failed: {} - {}", 
                call.function_name, status, body);
            
            Ok(FunctionResult {
                success: false,
                output: serde_json::json!({ "error": body }),
                logs: vec![format!("HTTP {}", status)],
                execution_time_ms: execution_time,
                cold_start: false,
            })
        }
    }
    
    /// List available functions
    pub async fn list_functions(&self) -> Result<Vec<String>, AppError> {
        let url = format!("{}/system/functions", self.gateway_url);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to list functions: {}", e)))?;
        
        if response.status().is_success() {
            let functions: Vec<OpenFaasFunction> = response.json().await
                .map_err(|e| AppError::Serialization(e.to_string()))?;
            
            Ok(functions.into_iter().map(|f| f.name).collect())
        } else {
            Err(AppError::Internal("Failed to list OpenFaaS functions".to_string()))
        }
    }
    
    /// Deploy a function
    pub async fn deploy(&self, config: &super::FunctionConfig) -> Result<(), AppError> {
        let url = format!("{}/system/functions", self.gateway_url);
        
        let deploy_req = OpenFaasDeployRequest {
            service: config.name.clone(),
            image: match &config.backend {
                super::FunctionBackend::Docker { image, .. } => image.clone(),
                _ => return Err(AppError::Validation("Only Docker backend supported for OpenFaaS".to_string())),
            },
            env_vars: config.env_vars.clone(),
            limits: Limits {
                memory: format!("{}Mi", config.memory_mb),
            },
        };
        
        let response = self.client
            .post(&url)
            .json(&deploy_req)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Deploy failed: {}", e)))?;
        
        if response.status().is_success() {
            info!("Deployed OpenFaaS function: {}", config.name);
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(AppError::Internal(format!("Deploy failed: {}", body)))
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct OpenFaasFunction {
    name: String,
}

#[derive(Debug, serde::Serialize)]
struct OpenFaasDeployRequest {
    service: String,
    image: String,
    #[serde(rename = "envVars")]
    env_vars: std::collections::HashMap<String, String>,
    limits: Limits,
}

#[derive(Debug, serde::Serialize)]
struct Limits {
    memory: String,
}
