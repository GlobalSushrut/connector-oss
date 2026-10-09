//! Engram — The SQL of Agent Memory
//!
//! Startup sequence:
//!   1. Load env (.env), init structured JSON logging, set panic hook
//!   2. Parse ENGRAM_URL (one-URI model — auth + host + namespace all in one)
//!   3. Connect PgPool, run SQLx migrations
//!   4. Build ConnectorOS client, verify connectivity
//!   5. Install Prometheus metrics recorder
//!   6. Build Axum router with full middleware stack
//!   7. Spawn background tasks:
//!        a. Entropy sweep (every ENTROPY_SWEEP_SECS, default 300)
//!   8. Serve API on PORT (default 9092)
//!   9. Graceful drain on Ctrl-C

mod connector;
mod cot_anchor;
mod dehallucination;
mod entropy;
mod error;
mod knowledge_gate;
mod knot;
mod metrics;
mod routes;
mod state;
mod types;
mod url;

use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    routing::{get, post, put},
    Router,
};
use metrics_exporter_prometheus::PrometheusBuilder;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    timeout::TimeoutLayer,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::connector::{ConnectorClient, ConnectorConfig};
use crate::state::AppState;
use crate::url::EngramUrl;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── 1. Environment + logging ───────────────────────────────────────────────
    dotenvy::dotenv().ok();

    let log_format = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "json".into());
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,engram=debug"));

    if log_format == "pretty" {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().pretty())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json())
            .init();
    }

    std::panic::set_hook(Box::new(|info| {
        tracing::error!(panic = %info, "PANIC — thread panicked");
    }));

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "Engram starting");

    // ── 2. Parse ENGRAM_URL ────────────────────────────────────────────────────
    let engram_url = EngramUrl::from_env().unwrap_or_else(|e| {
        // Self-hosted operators may omit ENGRAM_URL and set DATABASE_URL + namespace directly
        tracing::warn!(error = %e, "ENGRAM_URL not set — using DATABASE_URL + ENGRAM_NAMESPACE");
        let ns = std::env::var("ENGRAM_NAMESPACE").unwrap_or_else(|_| "default/agent".into());
        let key = std::env::var("ENGRAM_API_KEY").unwrap_or_default();
        let host = std::env::var("ENGRAM_HOST").unwrap_or_else(|_| "localhost:9092".into());
        EngramUrl::parse(&format!("engram://{}@{}/{}", key, host, ns))
            .expect("Could not construct fallback EngramUrl")
    });

    tracing::info!(
        namespace = %engram_url.namespace,
        host      = %engram_url.host,
        "ENGRAM_URL parsed"
    );

    // ── 3. Database ────────────────────────────────────────────────────────────
    let db_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set (self-hosted) or injected by Connector Cloud");

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(1800))
        .test_before_acquire(true)
        .connect(&db_url).await
        .expect("Failed to connect to Postgres");

    sqlx::migrate!("./migrations").run(&pool).await
        .expect("Failed to run Engram migrations");

    tracing::info!("Postgres connected and migrations applied");

    // Auto-provision the namespace from ENGRAM_URL if it doesn't exist yet
    let ns_path = engram_url.namespace.clone();
    let _ = sqlx::query!(
        r#"
        INSERT INTO engram_namespaces (path, retention_days, entropy_alert, entropy_halt, hipaa)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (path) DO NOTHING
        "#,
        ns_path,
        engram_url.retention_days.unwrap_or(90),
        engram_url.entropy_alert.unwrap_or(0.7),
        engram_url.entropy_halt.unwrap_or(0.95),
        engram_url.hipaa.unwrap_or(false),
    )
    .execute(&pool)
    .await;

    tracing::info!(namespace = %ns_path, "Default namespace provisioned");

    // ── 4. ConnectorOS client ──────────────────────────────────────────────────
    let connector = ConnectorClient::new(ConnectorConfig::from_env())
        .expect("Failed to build ConnectorOS client");

    match connector.health().await {
        Ok(h)  => tracing::info!(status = %h.status, "ConnectorOS kernel reachable"),
        Err(e) => tracing::warn!(error = %e, "ConnectorOS unreachable — continuing in standalone mode"),
    }

    // ── 5. Prometheus ──────────────────────────────────────────────────────────
    let metrics_port: u16 = std::env::var("METRICS_PORT")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(9093);
    let metrics_addr = SocketAddr::from(([0, 0, 0, 0], metrics_port));

    PrometheusBuilder::new()
        .with_http_listener(metrics_addr)
        .install()
        .expect("Failed to install Prometheus recorder");

    tracing::info!(port = metrics_port, "Prometheus metrics listening");

    // ── 6. App state ──────────────────────────────────────────────────────────
    let app_state = AppState {
        pool:       pool.clone(),
        connector:  connector.clone(),
        engram_url: engram_url.clone(),
    };

    // ── 7. Router ──────────────────────────────────────────────────────────────
    let timeout_secs: u64 = std::env::var("REQUEST_TIMEOUT_SECS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(30);

    let api_router = Router::new()
        // ── Namespaces
        .route("/api/v1/namespaces",                        post(routes::create_namespace))
        .route("/api/v1/namespaces",                        get(routes::list_namespaces))
        .route("/api/v1/namespaces/:path",                  get(routes::get_namespace))
        .route("/api/v1/namespaces/:path",                  put(routes::update_namespace))
        // ── Memory
        .route("/api/v1/memory",                            post(routes::write_memory))
        .route("/api/v1/memory/recall",                     post(routes::recall_memory))
        .route("/api/v1/memory/search",                     post(routes::search_memory))
        .route("/api/v1/memory/ground",                     post(routes::ground_memory))
        .route("/api/v1/memory/health/:path",               get(routes::memory_health))
        .route("/api/v1/memory/consolidate",                post(routes::consolidate_memory))
        // ── CoT Anchor
        .route("/api/v1/cot/session",                       post(routes::create_cot_session))
        .route("/api/v1/cot/session/:id/step",              post(routes::cot_step))
        .route("/api/v1/cot/session/:id/conclude",          post(routes::cot_conclude))
        .route("/api/v1/cot/session/:id",                   get(routes::get_cot_session))
        // ── Knowledge sharing
        .route("/api/v1/knowledge/share",                   post(routes::create_knowledge_share))
        // ── Health
        .route("/health",                                   get(routes::health));

    let app = api_router
        .with_state(app_state.clone())
        .layer(
            ServiceBuilder::new()
                .layer(TimeoutLayer::new(Duration::from_secs(timeout_secs)))
                .layer(CompressionLayer::new())
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                ),
        );

    // ── 7. Background tasks ────────────────────────────────────────────────────
    {
        let pool_bg      = pool.clone();
        let connector_bg = connector.clone();
        let sweep_secs: u64 = std::env::var("ENTROPY_SWEEP_SECS")
            .ok().and_then(|s| s.parse().ok()).unwrap_or(300);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(sweep_secs));
            loop {
                ticker.tick().await;
                entropy::background_sweep(pool_bg.clone(), connector_bg.clone()).await;
            }
        });
    }

    // ── 8. Serve ───────────────────────────────────────────────────────────────
    let port: u16 = std::env::var("PORT")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(9092);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!(
        port         = port,
        metrics_port = metrics_port,
        namespace    = %engram_url.namespace,
        "Engram listening — ready"
    );

    // ── 9. Graceful shutdown ───────────────────────────────────────────────────
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Shutdown signal received — draining connections");
    })
    .await?;

    Ok(())
}
