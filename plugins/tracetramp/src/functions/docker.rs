//! Docker container execution backend
//!
//! Runs functions as one-shot Docker containers via Docker Engine API

use super::{FunctionCall, FunctionResult};
use crate::error::AppError;
use reqwest::Client;
use serde_json::json;
use std::time::{Duration, Instant};
use tracing::{info, debug, warn, error};

pub struct DockerExecutor {
    client: Client,
    network: String,
    docker_host: String,
}

impl DockerExecutor {
    pub fn new(network: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(900))
            .build()
            .expect("Failed to create HTTP client");
        
        // Support both TCP (http://...) and Unix socket (unix:///var/run/docker.sock via DOCKER_HOST)
        let docker_host = std::env::var("DOCKER_HOST")
            .unwrap_or_else(|_| "http://localhost:2375".to_string());
        
        Self { client, network, docker_host }
    }
    
    /// Run function as a one-shot Docker container
    pub async fn run(&self, image: &str, call: &FunctionCall) -> Result<FunctionResult, AppError> {
        let start = Instant::now();
        
        debug!("Running Docker container: {} on network {}", image, self.network);
        
        // 1. Create container
        let create_url = format!("{}/v1.41/containers/create", self.docker_host);
        let create_body = json!({
            "Image": image,
            "Env": [
                format!("FUNCTION_NAME={}", call.function_name),
                format!("FUNCTION_INPUT={}", serde_json::to_string(&call.parameters).unwrap_or_default()),
            ],
            "HostConfig": {
                "NetworkMode": self.network,
                "AutoRemove": true,
                "Memory": 268435456_i64, // 256MB default
            },
            "AttachStdout": true,
            "AttachStderr": true,
            "Tty": false,
        });
        
        let create_resp = self.client
            .post(&create_url)
            .json(&create_body)
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Docker create failed: {}", e)))?;
        
        if !create_resp.status().is_success() {
            let err_body = create_resp.text().await.unwrap_or_default();
            return Err(AppError::Internal(format!("Docker create failed: {}", err_body)));
        }
        
        let create_data: serde_json::Value = create_resp.json().await
            .map_err(|e| AppError::Serialization(e.to_string()))?;
        let container_id = create_data["Id"].as_str().unwrap_or_default().to_string();
        
        if container_id.is_empty() {
            return Err(AppError::Internal("Docker didn't return container ID".to_string()));
        }
        
        // 2. Start container
        let start_url = format!("{}/v1.41/containers/{}/start", self.docker_host, container_id);
        let _ = self.client.post(&start_url).send().await
            .map_err(|e| AppError::ConnectorProxy(format!("Docker start failed: {}", e)))?;
        
        // 3. Wait for container to finish
        let wait_url = format!("{}/v1.41/containers/{}/wait", self.docker_host, container_id);
        let wait_resp = self.client
            .post(&wait_url)
            .timeout(Duration::from_secs(call.timeout_seconds))
            .send()
            .await
            .map_err(|e| AppError::ConnectorProxy(format!("Docker wait failed: {}", e)))?;
        
        let wait_data: serde_json::Value = wait_resp.json().await
            .unwrap_or_else(|_| json!({ "StatusCode": -1 }));
        let exit_code = wait_data["StatusCode"].as_i64().unwrap_or(-1);
        
        // 4. Get container logs
        let logs_url = format!("{}/v1.41/containers/{}/logs?stdout=true&stderr=true", 
            self.docker_host, container_id);
        let logs_resp = self.client.get(&logs_url).send().await;
        let logs_text = match logs_resp {
            Ok(r) => r.text().await.unwrap_or_default(),
            Err(_) => String::new(),
        };
        
        let execution_time_ms = start.elapsed().as_millis() as u64;
        let success = exit_code == 0;
        
        if success {
            info!("Docker {} completed in {}ms", image, execution_time_ms);
        } else {
            warn!("Docker {} exited with code {}", image, exit_code);
        }
        
        // Try to parse stdout as JSON
        let output: serde_json::Value = serde_json::from_str(&logs_text)
            .unwrap_or_else(|_| json!({ "exit_code": exit_code, "logs": logs_text.clone() }));
        
        Ok(FunctionResult {
            success,
            output,
            logs: logs_text.lines().map(String::from).collect(),
            execution_time_ms,
            cold_start: true, // Each Docker run is a cold start
        })
    }
    
    /// Check Docker daemon connectivity
    pub async fn health_check(&self) -> bool {
        let url = format!("{}/v1.41/version", self.docker_host);
        self.client.get(&url).timeout(Duration::from_secs(3)).send().await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}
