//! Middleware for the Gateway

use axum::{
    body::Body,
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use std::time::Instant;
use tracing::{debug, info, span, Level};
use uuid::Uuid;

/// Request ID middleware - adds unique request ID to each request
pub async fn request_id(mut request: Request, next: Next) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    request.headers_mut().insert(
        "x-request-id",
        request_id.parse().unwrap(),
    );

    let mut response = next.run(request).await;
    
    response.headers_mut().insert(
        "x-request-id",
        request_id.parse().unwrap(),
    );

    response
}

/// Logging middleware - logs request/response details
pub async fn logging(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let span = span!(Level::INFO, "request", %method, %uri, %request_id);
    let _enter = span.enter();

    let start = Instant::now();
    
    debug!("Request started");
    
    let response = next.run(request).await;
    
    let duration = start.elapsed();
    let status = response.status();
    
    info!(
        status = %status.as_u16(),
        duration_ms = %duration.as_millis(),
        "Request completed"
    );

    response
}

/// CORS middleware configuration
pub fn cors_layer() -> tower_http::cors::CorsLayer {
    tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            header::HeaderName::from_static("x-request-id"),
            header::HeaderName::from_static("x-trace-id"),
            header::HeaderName::from_static("x-span-id"),
        ])
        .max_age(std::time::Duration::from_secs(3600))
}

/// Rate limiting state
pub struct RateLimiter {
    requests: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, RateLimitEntry>>>,
    max_requests: u32,
    window_secs: u64,
}

struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            requests: std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            max_requests,
            window_secs,
        }
    }

    pub async fn check(&self, key: &str) -> bool {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        
        let entry = requests.entry(key.to_string()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start).as_secs() >= self.window_secs {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= self.max_requests {
            return false;
        }

        entry.count += 1;
        true
    }

    pub async fn cleanup(&self) {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        
        requests.retain(|_, entry| {
            now.duration_since(entry.window_start).as_secs() < self.window_secs * 2
        });
    }
}

/// Compression middleware
pub fn compression_layer() -> tower_http::compression::CompressionLayer {
    tower_http::compression::CompressionLayer::new()
}

/// Request timeout configuration
pub fn timeout_layer(timeout_secs: u64) -> tower::timeout::TimeoutLayer {
    tower::timeout::TimeoutLayer::new(std::time::Duration::from_secs(timeout_secs))
}
