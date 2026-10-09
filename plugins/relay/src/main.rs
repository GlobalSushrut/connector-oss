use std::time::Duration;

use axum::{
    routing::{delete, get, post, put},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use tokio::time;
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod connector;
mod error;
mod instructions;
mod metrics;
mod policy;
mod proxy;
mod registry;
mod routes;
mod state;
mod types;

use connector::{ConnectorClient, ConnectorConfig};
use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Environment ────────────────────────────────────────────────────────────
    dotenvy::dotenv().ok();

    // ── Tracing ────────────────────────────────────────────────────────────────
    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::from_default_env()
            .add_directive("relay=info".parse()?)
            .add_directive("tower_http=warn".parse()?))
        .init();

    tracing::info!("Relay v{} starting", env!("CARGO_PKG_VERSION"));

    // ── Database ───────────────────────────────────────────────────────────────
    let db_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db_url)
        .await
        .expect("Failed to connect to Postgres");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    tracing::info!("Database connected and migrations applied");

    // ── Connector client ───────────────────────────────────────────────────────
    let connector_cfg = ConnectorConfig::from_env();
    let connector = ConnectorClient::new(connector_cfg)
        .expect("Failed to build Connector client");

    // ── Prometheus metrics ─────────────────────────────────────────────────────
    let metrics_port: u16 = std::env::var("METRICS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(9091);

    let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let handle = builder
        .with_http_listener(([0, 0, 0, 0], metrics_port))
        .install_recorder()
        .expect("Failed to install Prometheus recorder");

    metrics::register_all();
    tracing::info!(port = metrics_port, "Prometheus metrics listening");

    // ── HTTP client (shared for proxy forwarding) ──────────────────────────────
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(format!("relay-proxy/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("Failed to build proxy HTTP client");

    // ── App state ──────────────────────────────────────────────────────────────
    let state = AppState { pool: pool.clone(), connector, http };

    // ── Router ─────────────────────────────────────────────────────────────────
    let app = Router::new()
        // Function CRUD
        .route("/api/v1/functions",                  post(routes::register_function))
        .route("/api/v1/functions",                  get(routes::list_functions))
        .route("/api/v1/functions/:name",            get(routes::get_function))
        .route("/api/v1/functions/:name",            put(routes::update_function))
        .route("/api/v1/functions/:name",            delete(routes::deregister_function))
        // Invocation
        .route("/api/v1/functions/:name/invoke",     post(routes::invoke_function))
        .route("/api/v1/invoke",                     post(routes::invoke_raw))
        // Observability
        .route("/api/v1/functions/:name/logs",       get(routes::get_logs))
        .route("/api/v1/functions/:name/stats",      get(routes::get_stats))
        // Lifecycle
        .route("/api/v1/functions/:name/suspend",    post(routes::suspend_function))
        .route("/api/v1/functions/:name/resume",     post(routes::resume_function))
        // Health
        .route("/health",                            get(routes::health))
        // Prometheus scrape
        .route("/metrics", get(move || {
            let h = handle.clone();
            async move { h.render() }
        }))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(60)))
        .layer(CorsLayer::permissive())
        .with_state(state.clone());

    // ── Background tasks ───────────────────────────────────────────────────────
    let health_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            registry::health_check_loop(health_pool.clone()).await;
        }
    });

    let async_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            registry::async_job_worker(async_pool.clone()).await;
        }
    });

    // ── Listen ─────────────────────────────────────────────────────────────────
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8087);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!(addr = %addr, "Relay API listening");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c    => { tracing::info!("Relay shutting down (SIGINT)") }
        _ = terminate => { tracing::info!("Relay shutting down (SIGTERM)") }
    }
}
