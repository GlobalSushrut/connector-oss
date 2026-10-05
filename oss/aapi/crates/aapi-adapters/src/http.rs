//! HTTP adapter for external API calls

use async_trait::async_trait;
use reqwest::{Client, Method, Response};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

use aapi_core::types::EffectBucket;
use aapi_core::Vakya;

use crate::effect::{CapturedEffect, EffectBuilder, StateSnapshot};
use crate::error::{AdapterError, AdapterResult};
use crate::traits::{Adapter, ActionDescriptor, ExecutionContext, ExecutionResult, HealthStatus};

/// HTTP adapter for making external API calls
pub struct HttpAdapter {
    client: Client,
    /// Allowed hosts (empty = all allowed)
    allowed_hosts: Vec<String>,
    /// Denied hosts
    denied_hosts: Vec<String>,
    /// Default timeout in seconds
    default_timeout_secs: u64,
    /// Maximum response size
    max_response_size: usize,
}

impl Default for HttpAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpAdapter {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("AAPI-HttpAdapter/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            allowed_hosts: vec![],
            denied_hosts: vec![],
            default_timeout_secs: 30,
            max_response_size: 10 * 1024 * 1024, // 10MB
        }
    }

    pub fn with_allowed_hosts(mut self, hosts: Vec<String>) -> Self {
        self.allowed_hosts = hosts;
        self
    }

    pub fn with_denied_hosts(mut self, hosts: Vec<String>) -> Self {
        self.denied_hosts = hosts;
        self
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.default_timeout_secs = timeout_secs;
        self
    }

    /// Check if a URL is allowed
    fn is_url_allowed(&self, url: &str) -> AdapterResult<()> {
        let parsed = url::Url::parse(url)
            .map_err(|e| AdapterError::InvalidInput(format!("Invalid URL: {}", e)))?;

        let host = parsed.host_str()
            .ok_or_else(|| AdapterError::InvalidInput("URL has no host".to_string()))?;

        // Check denied hosts first
        for denied in &self.denied_hosts {
            if host == denied || host.ends_with(&format!(".{}", denied)) {
                return Err(AdapterError::PermissionDenied(format!(
                    "Host {} is denied",
                    host
                )));
            }
        }

        // Check allowed hosts if specified
        if !self.allowed_hosts.is_empty() {
            let allowed = self.allowed_hosts.iter().any(|allowed| {
                host == allowed || host.ends_with(&format!(".{}", allowed))
            });
            if !allowed {
                return Err(AdapterError::PermissionDenied(format!(
                    "Host {} is not in allowed list",
                    host
                )));
            }
        }

        Ok(())
    }

    /// Parse method from action or body
    fn parse_method(&self, action: &str, body: &serde_json::Value) -> Method {
        // Check body for explicit method
        if let Some(method_str) = body.get("method").and_then(|v| v.as_str()) {
            return match method_str.to_uppercase().as_str() {
                "GET" => Method::GET,
                "POST" => Method::POST,
                "PUT" => Method::PUT,
                "DELETE" => Method::DELETE,
                "PATCH" => Method::PATCH,
                "HEAD" => Method::HEAD,
                "OPTIONS" => Method::OPTIONS,
                _ => Method::GET,
            };
        }

        // Infer from action
        match action {
            "http.get" => Method::GET,
            "http.post" => Method::POST,
            "http.put" => Method::PUT,
            "http.delete" => Method::DELETE,
            "http.patch" => Method::PATCH,
            "http.head" => Method::HEAD,
            _ => Method::GET,
        }
    }

    /// Execute an HTTP request
    async fn execute_request(
        &self,
        vakya: &Vakya,
        context: &ExecutionContext,
    ) -> AdapterResult<ExecutionResult> {
        let start = std::time::Instant::now();

        // Get URL from resource ID
        let url = vakya.v2_karma.rid.0
            .strip_prefix("http://")
            .or_else(|| vakya.v2_karma.rid.0.strip_prefix("https://"))
            .map(|s| {
                if vakya.v2_karma.rid.0.starts_with("https://") {
                    format!("https://{}", s)
                } else {
                    format!("http://{}", s)
                }
            })
            .unwrap_or_else(|| vakya.v2_karma.rid.0.clone());

        // Validate URL
        self.is_url_allowed(&url)?;

        let method = self.parse_method(&vakya.v3_kriya.action, &vakya.body);
        let body = &vakya.body;

        debug!(url = %url, method = %method, "Executing HTTP request");

        if context.dry_run {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ExecutionResult::success(
                serde_json::json!({
                    "dry_run": true,
                    "url": url,
                    "method": method.as_str(),
                }),
                vec![],
                duration_ms,
            ));
        }

        // Build request
        let mut request = self.client.request(method.clone(), &url);

        // Add headers
        if let Some(headers) = body.get("headers").and_then(|v| v.as_object()) {
            for (key, value) in headers {
                if let Some(v) = value.as_str() {
                    request = request.header(key.as_str(), v);
                }
            }
        }

        // Add query parameters
        if let Some(query) = body.get("query").and_then(|v| v.as_object()) {
            let params: Vec<(String, String)> = query.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect();
            request = request.query(&params);
        }

        // Add body for POST/PUT/PATCH
        if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
            if let Some(json_body) = body.get("body") {
                request = request.json(json_body);
            } else if let Some(form) = body.get("form").and_then(|v| v.as_object()) {
                let form_data: HashMap<String, String> = form.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect();
                request = request.form(&form_data);
            }
        }

        // Set timeout
        let timeout = context.timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(self.default_timeout_secs));
        request = request.timeout(timeout);

        // Execute request
        let response = request.send().await
            .map_err(|e| AdapterError::Http(e.to_string()))?;

        // Capture response
        let status = response.status();
        let headers: HashMap<String, String> = response.headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.to_string(), s.to_string())))
            .collect();

        // Read response body
        let response_body = response.bytes().await
            .map_err(|e| AdapterError::Http(e.to_string()))?;

        if response_body.len() > self.max_response_size {
            return Err(AdapterError::Http(format!(
                "Response too large: {} bytes",
                response_body.len()
            )));
        }

        // Parse response as JSON if possible
        let response_data = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&response_body) {
            json
        } else {
            serde_json::json!({
                "content_type": headers.get("content-type").cloned(),
                "size": response_body.len(),
                "content": String::from_utf8_lossy(&response_body),
            })
        };

        // Determine effect bucket based on method
        let effect_bucket = match method {
            Method::GET | Method::HEAD | Method::OPTIONS => EffectBucket::Read,
            Method::POST => EffectBucket::Create,
            Method::PUT | Method::PATCH => EffectBucket::Update,
            Method::DELETE => EffectBucket::Delete,
            _ => EffectBucket::External,
        };

        // Build effect
        let effect = EffectBuilder::new(
            vakya.vakya_id.0.clone(),
            effect_bucket,
            vakya.v2_karma.rid.0.clone(),
        )
        .target_type("http")
        .after(StateSnapshot::from_json(&serde_json::json!({
            "status": status.as_u16(),
            "headers": headers,
        })))
        .metadata("url", serde_json::json!(url))
        .metadata("method", serde_json::json!(method.as_str()))
        .metadata("status", serde_json::json!(status.as_u16()))
        .build();

        let duration_ms = start.elapsed().as_millis() as u64;

        let result = serde_json::json!({
            "status": status.as_u16(),
            "status_text": status.canonical_reason().unwrap_or("Unknown"),
            "headers": headers,
            "body": response_data,
            "url": url,
            "method": method.as_str(),
        });

        if status.is_success() {
            Ok(ExecutionResult::success(result, vec![effect], duration_ms))
        } else {
            Ok(ExecutionResult::failure(
                format!("HTTP {} {}", status.as_u16(), status.canonical_reason().unwrap_or("Error")),
                duration_ms,
            ).with_metadata("response", result))
        }
    }
}

#[async_trait]
impl Adapter for HttpAdapter {
    fn domain(&self) -> &str {
        "http"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn supported_actions(&self) -> Vec<&str> {
        vec![
            "http.get",
            "http.post",
            "http.put",
            "http.delete",
            "http.patch",
            "http.head",
            "http.request",
        ]
    }

    async fn execute(&self, vakya: &Vakya, context: &ExecutionContext) -> AdapterResult<ExecutionResult> {
        self.execute_request(vakya, context).await
    }

    fn can_rollback(&self, _action: &str) -> bool {
        false // HTTP requests are generally not reversible
    }

    async fn rollback(&self, _effect: &CapturedEffect) -> AdapterResult<()> {
        Err(AdapterError::RollbackFailed(
            "HTTP requests cannot be automatically rolled back".to_string()
        ))
    }

    async fn health_check(&self) -> AdapterResult<HealthStatus> {
        Ok(HealthStatus::healthy())
    }
}

/// Get action descriptors for the HTTP adapter
pub fn http_action_descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new("http.get", "Make HTTP GET request")
            .with_effect(EffectBucket::Read)
            .idempotent(),
        ActionDescriptor::new("http.post", "Make HTTP POST request")
            .with_effect(EffectBucket::Create),
        ActionDescriptor::new("http.put", "Make HTTP PUT request")
            .with_effect(EffectBucket::Update)
            .idempotent(),
        ActionDescriptor::new("http.delete", "Make HTTP DELETE request")
            .with_effect(EffectBucket::Delete),
        ActionDescriptor::new("http.patch", "Make HTTP PATCH request")
            .with_effect(EffectBucket::Update),
        ActionDescriptor::new("http.head", "Make HTTP HEAD request")
            .with_effect(EffectBucket::Read)
            .idempotent(),
        ActionDescriptor::new("http.request", "Make generic HTTP request")
            .with_effect(EffectBucket::External),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_validation_allowed() {
        let adapter = HttpAdapter::new()
            .with_allowed_hosts(vec!["api.example.com".to_string()]);

        assert!(adapter.is_url_allowed("https://api.example.com/v1/users").is_ok());
        assert!(adapter.is_url_allowed("https://sub.api.example.com/v1").is_ok());
        assert!(adapter.is_url_allowed("https://other.com/api").is_err());
    }

    #[test]
    fn test_url_validation_denied() {
        let adapter = HttpAdapter::new()
            .with_denied_hosts(vec!["internal.local".to_string(), "localhost".to_string()]);

        assert!(adapter.is_url_allowed("https://api.example.com/v1").is_ok());
        assert!(adapter.is_url_allowed("http://localhost:8080/api").is_err());
        assert!(adapter.is_url_allowed("http://internal.local/secret").is_err());
    }

    #[test]
    fn test_method_parsing() {
        let adapter = HttpAdapter::new();

        assert_eq!(adapter.parse_method("http.get", &serde_json::json!({})), Method::GET);
        assert_eq!(adapter.parse_method("http.post", &serde_json::json!({})), Method::POST);
        assert_eq!(
            adapter.parse_method("http.request", &serde_json::json!({"method": "DELETE"})),
            Method::DELETE
        );
    }
}
