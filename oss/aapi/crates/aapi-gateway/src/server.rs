//! Gateway server implementation

use axum::middleware;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, error};

use crate::middleware::{cors_layer, compression_layer, logging, request_id};
use crate::routes::create_router_with_docs;
use crate::state::{AppState, GatewayConfig};

/// AAPI Gateway Server
pub struct GatewayServer {
    state: Arc<AppState>,
}

impl GatewayServer {
    /// Create a new gateway server with the given configuration
    pub async fn new(config: GatewayConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let state = Arc::new(AppState::new(config).await?);
        Ok(Self { state })
    }

    /// Create a gateway server with in-memory storage (for testing)
    pub async fn in_memory(config: GatewayConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let state = Arc::new(AppState::in_memory(config).await?);
        Ok(Self { state })
    }

    /// Get the application state
    pub fn state(&self) -> Arc<AppState> {
        Arc::clone(&self.state)
    }

    /// Build the router with all middleware
    pub fn router(&self) -> axum::Router {
        create_router_with_docs(Arc::clone(&self.state))
            .layer(middleware::from_fn(logging))
            .layer(middleware::from_fn(request_id))
            .layer(compression_layer())
            .layer(cors_layer())
    }

    /// Run the server
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = self.state.config.bind_address();
        let router = self.router();

        info!(address = %addr, "Starting AAPI Gateway");

        let listener = TcpListener::bind(&addr).await?;
        
        axum::serve(listener, router)
            .await
            .map_err(|e| {
                error!(error = %e, "Server error");
                Box::new(e) as Box<dyn std::error::Error>
            })
    }

    /// Run the server with graceful shutdown
    pub async fn run_with_shutdown(
        &self,
        shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let addr = self.state.config.bind_address();
        let router = self.router();

        info!(address = %addr, "Starting AAPI Gateway with graceful shutdown");

        let listener = TcpListener::bind(&addr).await?;
        
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal)
            .await
            .map_err(|e| {
                error!(error = %e, "Server error");
                Box::new(e) as Box<dyn std::error::Error>
            })
    }
}

/// Builder for GatewayServer
pub struct GatewayServerBuilder {
    config: GatewayConfig,
}

impl Default for GatewayServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayServerBuilder {
    pub fn new() -> Self {
        Self {
            config: GatewayConfig::default(),
        }
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.config.host = host.into();
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    pub fn database_url(mut self, url: impl Into<String>) -> Self {
        self.config.database_url = url.into();
        self
    }

    pub fn gateway_id(mut self, id: impl Into<String>) -> Self {
        self.config.gateway_id = id.into();
        self
    }

    pub fn require_signatures(mut self, require: bool) -> Self {
        self.config.require_signatures = require;
        self
    }

    pub fn require_capabilities(mut self, require: bool) -> Self {
        self.config.require_capabilities = require;
        self
    }

    pub fn production_mode(mut self, enabled: bool) -> Self {
        self.config.production_mode = enabled;
        self
    }

    pub fn max_body_size(mut self, size: usize) -> Self {
        self.config.max_body_size = size;
        self
    }

    pub fn request_timeout_secs(mut self, secs: u64) -> Self {
        self.config.request_timeout_secs = secs;
        self
    }

    pub async fn build(self) -> Result<GatewayServer, Box<dyn std::error::Error>> {
        GatewayServer::new(self.config).await
    }

    pub async fn build_in_memory(self) -> Result<GatewayServer, Box<dyn std::error::Error>> {
        GatewayServer::in_memory(self.config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_builder() {
        let server = GatewayServerBuilder::new()
            .host("127.0.0.1")
            .port(8081)
            .build_in_memory()
            .await
            .unwrap();

        assert_eq!(server.state.config.port, 8081);
    }

    #[tokio::test]
    async fn test_router_creation() {
        let server = GatewayServerBuilder::new()
            .build_in_memory()
            .await
            .unwrap();

        let _router = server.router();
        // Router created successfully
    }
}
