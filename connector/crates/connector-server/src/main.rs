//! # connector-server — Lightweight REST API + Prometheus Metrics
//!
//! A ~5MB static binary that serves the Connector API over HTTP.
//! Designed for `FROM scratch` containers with 0 CVEs.
//!
//! ## Endpoints
//!
//! - `POST /run`           — Run an agent with input
//! - `POST /pipeline`      — Run a multi-agent pipeline
//! - `POST /config/parse`  — Parse a connector.yaml and return config summary
//! - `GET  /health`        — Health check
//! - `GET  /metrics`       — Prometheus scrape endpoint
//!
//! ## Usage
//!
//! ```bash
//! CONNECTOR_LLM_PROVIDER=openai CONNECTOR_LLM_MODEL=gpt-4o \
//!   CONNECTOR_LLM_API_KEY=sk-... connector-server
//! ```

mod routes;
mod metrics;

use axum::{Router, routing::{get, post}};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

pub struct AppState {
    pub connector: connector_api::Connector,
    pub metrics: metrics::Metrics,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let connector = connector_api::Connector::new()
        .llm_from_env()
        .build();

    let metrics = metrics::Metrics::new();

    let state = Arc::new(AppState { connector, metrics });

    let app = Router::new()
        .route("/run", post(routes::run_agent))
        .route("/pipeline", post(routes::run_pipeline))
        .route("/config/parse", post(routes::parse_config))
        .route("/health", get(routes::health))
        .route("/metrics", get(routes::metrics_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = std::env::var("CONNECTOR_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    tracing::info!("connector-server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
