//! # connector-server — Full REST API + Prometheus Metrics
//!
//! A ~5MB static binary that serves the Connector API over HTTP.
//! Designed for `FROM scratch` containers with 0 CVEs.
//!
//! ## Endpoints
//!
//! ### Core
//! - `POST /run`              — Run an agent with input
//! - `POST /pipeline`         — Run a multi-agent pipeline
//! - `POST /config/parse`     — Parse a connector.yaml and return config summary
//!
//! ### Memory & Knowledge
//! - `POST /remember`         — Write a memory packet to the kernel
//! - `GET  /memories/:ns`     — List packets in a namespace
//! - `POST /knowledge/ingest` — Ingest namespace into knowledge graph
//! - `POST /knowledge/query`  — RAG retrieval with entities/keywords
//!
//! ### Agents & Audit
//! - `GET  /agents`           — List registered agents
//! - `GET  /audit`            — Tail audit log
//!
//! ### Tools
//! - `POST /tools/register`   — Register a tool definition
//! - `POST /tools/call`       — Authorize + execute a tool call
//!
//! ### Custom Folders (Dynamic Storage)
//! - `POST /folders/create`   — Create a namespaced storage folder
//! - `POST /folders/put`      — Write key-value to a folder
//! - `POST /folders/get`      — Read key-value from a folder
//! - `GET  /folders/list`     — List all folders
//!
//! ### Infrastructure
//! - `GET  /db/stats`         — Engine store statistics
//! - `GET  /health`           — Health check
//! - `GET  /metrics`          — Prometheus scrape endpoint
//!
//! ## Usage
//!
//! ```bash
//! CONNECTOR_LLM_PROVIDER=openai CONNECTOR_LLM_MODEL=gpt-4o \
//!   CONNECTOR_LLM_API_KEY=sk-... \
//!   CONNECTOR_ENGINE_STORAGE=sqlite:engine.db \
//!   CONNECTOR_CELL_ID=cell_main \
//!   connector-server
//! ```

mod routes;
mod metrics;

use axum::{Router, routing::{get, post}};
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;
use vac_core::kernel::MemoryKernel;
use vac_core::knot::KnotEngine;
use connector_engine::engine_store::{EngineStore, InMemoryEngineStore};
use connector_engine::storage_zone::StorageLayout;

pub struct AppState {
    pub connector: connector_api::Connector,
    pub kernel: Mutex<MemoryKernel>,
    pub knot: Mutex<KnotEngine>,
    pub engine_store: Mutex<Box<dyn EngineStore + Send>>,
    pub storage_layout: StorageLayout,
    pub metrics: metrics::Metrics,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // Build connector with env config
    let mut builder = connector_api::Connector::new().llm_from_env();

    // Engine storage from env
    if let Ok(uri) = std::env::var("CONNECTOR_ENGINE_STORAGE") {
        builder = builder.engine_storage(&uri);
    }
    let cell_id = std::env::var("CONNECTOR_CELL_ID")
        .unwrap_or_else(|_| "cell_local".to_string());
    builder = builder.cell(&cell_id);

    let connector = builder.build();

    // Create engine store (SQLite if configured, else InMemory)
    let engine_store: Box<dyn EngineStore + Send> = match std::env::var("CONNECTOR_ENGINE_STORAGE") {
        Ok(uri) if uri.starts_with("sqlite:") => {
            let path = uri.trim_start_matches("sqlite:");
            match connector_engine::sqlite_store::SqliteEngineStore::open(path) {
                Ok(s) => {
                    tracing::info!("engine store: SQLite at {}", path);
                    Box::new(s)
                }
                Err(e) => {
                    tracing::warn!("SQLite open failed ({}), falling back to InMemory", e);
                    Box::new(InMemoryEngineStore::new())
                }
            }
        }
        _ => {
            tracing::info!("engine store: InMemory");
            Box::new(InMemoryEngineStore::new())
        }
    };

    let storage_layout = StorageLayout::default_for_cell(&cell_id);
    let metrics = metrics::Metrics::new();

    // Log Tier 3 feature flags before moving connector into state
    tracing::info!("cell_id: {}", cell_id);
    tracing::info!("storage zones:\n{}", storage_layout.to_tree());
    if connector.cluster_config().is_some()       { tracing::info!("feature ON: cluster"); }
    if connector.swarm_config().is_some()         { tracing::info!("feature ON: swarm"); }
    if connector.streaming_config().is_some()     { tracing::info!("feature ON: streaming"); }
    if connector.perception_config().is_some()    { tracing::info!("feature ON: perception"); }
    if connector.cognitive_config().is_some()      { tracing::info!("feature ON: cognitive"); }
    if connector.watchdog_config().is_some()      { tracing::info!("feature ON: watchdog"); }
    if connector.observability_config().is_some()  { tracing::info!("feature ON: observability"); }
    if connector.tracing_config().is_some()       { tracing::info!("feature ON: tracing"); }
    if connector.negotiation_config().is_some()   { tracing::info!("feature ON: negotiation"); }

    // Read server config for addr before moving connector
    let server_addr = connector.server_config().map(|sc| {
        let host = sc.host.as_deref().unwrap_or("0.0.0.0");
        let port = sc.port.unwrap_or(8080);
        format!("{}:{}", host, port)
    });

    let state = Arc::new(AppState {
        connector,
        kernel: Mutex::new(MemoryKernel::new()),
        knot: Mutex::new(KnotEngine::new()),
        engine_store: Mutex::new(engine_store),
        storage_layout,
        metrics,
    });

    let app = Router::new()
        // Core
        .route("/run", post(routes::run_agent))
        .route("/pipeline", post(routes::run_pipeline))
        .route("/config/parse", post(routes::parse_config))
        // Memory & Knowledge
        .route("/remember", post(routes::remember))
        .route("/memories/{namespace}", get(routes::memories))
        .route("/knowledge/ingest", post(routes::knowledge_ingest))
        .route("/knowledge/query", post(routes::knowledge_query))
        // Agents & Audit
        .route("/agents", get(routes::list_agents))
        .route("/audit", get(routes::audit_tail))
        // Tools
        .route("/tools/register", post(routes::tools_register))
        .route("/tools/call", post(routes::tools_call))
        // Custom Folders
        .route("/folders/create", post(routes::folder_create))
        .route("/folders/put", post(routes::folder_put))
        .route("/folders/get", post(routes::folder_get))
        .route("/folders/list", get(routes::folder_list))
        // Trust, Perception, Cognitive, Logic
        .route("/trust", get(routes::trust_breakdown))
        .route("/perceive", post(routes::perceive))
        .route("/cognitive/cycle", post(routes::cognitive_cycle))
        .route("/logic/plan", post(routes::logic_plan))
        // Sessions
        .route("/sessions/create", post(routes::session_create))
        .route("/sessions/close", post(routes::session_close))
        // Search, Policies, Grounding, Secrets
        .route("/search", post(routes::search_packets))
        .route("/policies/evaluate", post(routes::policy_evaluate))
        .route("/grounding/{category}/{term}", get(routes::grounding_lookup))
        .route("/secrets/store", post(routes::secret_store))
        // Connector Protocol (CP/1.0) — 7-layer protocol surface
        .route("/protocol/info", get(routes::protocol_info))
        .route("/protocol/identity/register", post(routes::protocol_identity_register))
        .route("/protocol/capabilities", get(routes::protocol_capabilities))
        .route("/protocol/capability/check", post(routes::protocol_capability_check))
        .route("/protocol/safety/estop", post(routes::protocol_estop))
        .route("/protocol/intent", post(routes::protocol_intent))
        .route("/protocol/consensus/propose", post(routes::protocol_consensus_propose))
        .route("/protocol/attestation/verify", post(routes::protocol_attestation_verify))
        .route("/protocol/telemetry/streams", get(routes::protocol_telemetry_streams))
        .route("/protocol/routing/info", get(routes::protocol_routing_info))
        // Infrastructure
        .route("/db/stats", get(routes::db_stats))
        .route("/health", get(routes::health))
        .route("/metrics", get(routes::metrics_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Server address: env var > server_config > default
    let addr = std::env::var("CONNECTOR_ADDR").unwrap_or_else(|_| {
        server_addr.unwrap_or_else(|| "0.0.0.0:8080".to_string())
    });

    tracing::info!("connector-server listening on {} (38 routes)", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
