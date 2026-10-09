//! Conductor — governed multi-agent orchestration platform.
//! Enterprise-grade Axum server: connection pooling, graceful shutdown,
//! auth middleware, request-ID propagation, CORS, compression, body limit.

mod cage;
mod connector;
mod error;
mod gate;
mod hitl;
mod middleware;
mod pipeline;
mod proxy;
mod routes;
mod runner;
mod scheduler;
mod types;

use anyhow::Result;
use axum::{
    http::HeaderValue,
    middleware as axum_middleware,
    routing::{delete, get, post},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use std::time::Duration;
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowHeaders, AllowMethods, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use connector::{ConnectorClient, ConnectorConfig};

#[derive(Clone)]
pub struct AppState {
    pub pool:      sqlx::PgPool,
    pub connector: ConnectorClient,
}

#[tokio::main]
async fn main() -> Result<()> {
    // ── Logging ───────────────────────────────────────────────────────────────
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "conductor=info,tower_http=warn".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    dotenvy::dotenv().ok();

    // ── Config from environment ───────────────────────────────────────────────
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8083".into())
        .parse()
        .expect("PORT must be a valid number");
    let db_max_connections: u32 = std::env::var("DB_MAX_CONNECTIONS")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(20);
    let db_min_connections: u32 = std::env::var("DB_MIN_CONNECTIONS")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    let body_limit_mb: usize = std::env::var("BODY_LIMIT_MB")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(4);

    // ── Database pool ─────────────────────────────────────────────────────────
    let pool = PgPoolOptions::new()
        .max_connections(db_max_connections)
        .min_connections(db_min_connections)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    sqlx::migrate!("./migrations").run(&pool).await
        .expect("Failed to run database migrations");

    tracing::info!(
        max_connections = db_max_connections,
        min_connections = db_min_connections,
        "Database connected and migrations applied"
    );

    // ── Connector client ──────────────────────────────────────────────────────
    let connector = ConnectorClient::with_config(ConnectorConfig::from_env());

    match connector.health().await {
        Ok(_) => tracing::info!(url = %connector.base_url(), "Connector reachable"),
        Err(e) => tracing::warn!(err = %e, "Connector not reachable — continuing in degraded mode"),
    }

    let state = AppState { pool: pool.clone(), connector: connector.clone() };

    // ── Scheduler ─────────────────────────────────────────────────────────────
    scheduler::spawn_scheduler(pool.clone(), connector.clone());
    tracing::info!("Scheduler started (cron tick + HITL expiry)");

    // ── CORS ──────────────────────────────────────────────────────────────────
    let allowed_origin = std::env::var("CORS_ALLOW_ORIGIN")
        .unwrap_or_else(|_| "".into());
    let cors = if allowed_origin.is_empty() || allowed_origin == "*" {
        CorsLayer::permissive()
    } else {
        let origin_hv = allowed_origin.parse::<HeaderValue>()
            .unwrap_or_else(|_| HeaderValue::from_static("*"));
        CorsLayer::new()
            .allow_origin(origin_hv)
            .allow_methods(AllowMethods::any())
            .allow_headers(AllowHeaders::any())
    };

    // ── Router ────────────────────────────────────────────────────────────────
    //
    // Middleware stack (bottom → top = outer → inner):
    //   1. CompressionLayer    — gzip/br response compression
    //   2. RequestBodyLimit    — reject oversized payloads early
    //   3. TraceLayer          — tower-http access log
    //   4. CorsLayer           — CORS headers
    //   5. request_id          — inject/echo X-Request-ID
    //   6. trace_request       — structured per-request tracing
    //   7. require_api_key     — auth on /api/* routes only

    let api_routes = Router::new()
        // Pipelines
        .route("/v1/pipelines",          post(routes::create_pipeline).get(routes::list_pipelines))
        .route("/v1/pipelines/:id",      get(routes::get_pipeline).delete(routes::archive_pipeline))
        .route("/v1/pipelines/:id/run",  post(routes::start_run))
        // Runs
        .route("/v1/runs",                        get(routes::list_runs))
        .route("/v1/runs/:id",                    get(routes::get_run))
        .route("/v1/runs/:id/pause",              post(routes::pause_run))
        .route("/v1/runs/:id/resume",             post(routes::resume_run))
        .route("/v1/runs/:id/abort",              post(routes::abort_run))
        .route("/v1/runs/:id/replay/:step",       post(routes::replay_run))
        .route("/v1/runs/:id/receipt-chain",      get(routes::receipt_chain))
        .route("/v1/runs/:id/gate",               get(routes::evaluate_gate))
        // Approvals
        .route("/v1/approvals",       get(routes::list_approvals))
        .route("/v1/approvals/:id",   post(routes::resolve_approval))
        // Schedules
        .route("/v1/schedules",       post(routes::create_schedule).get(routes::list_schedules))
        .route("/v1/schedules/:id",   delete(routes::delete_schedule))
        // Webhook trigger (token-authenticated, no API key required)
        .route("/v1/webhooks/trigger/:token", post(routes::webhook_trigger))
        // Cage management
        .route("/v1/cages",             post(routes::upsert_cage))
        .route("/v1/cages/:pipeline_id", get(routes::get_cage).delete(routes::delete_cage))
        // Cage proxy — agent action calls
        .route("/v1/proxy/action",                    post(proxy::proxy_action))
        .route("/v1/proxy/intercepts/:run_id",        get(proxy::list_intercepts))
        .route("/v1/proxy/intercepts/:run_id/verify", get(proxy::verify_chain))
        // Apply API key auth to all /api/* routes
        .layer(axum_middleware::from_fn(middleware::require_api_key))
        .with_state(state.clone());

    let app = Router::new()
        .route("/health", get(routes::health))
        .route("/healthz", get(routes::health))
        .nest("/api", api_routes)
        .layer(axum_middleware::from_fn(middleware::request_id))
        .layer(axum_middleware::from_fn(middleware::trace_request))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(RequestBodyLimitLayer::new(body_limit_mb * 1024 * 1024))
        .with_state(state);

    // ── Graceful shutdown ─────────────────────────────────────────────────────
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, version = env!("CARGO_PKG_VERSION"), "Conductor listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Conductor shut down cleanly");
    Ok(())
}

// ── Graceful shutdown signal ──────────────────────────────────────────────────

async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to install CTRL+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c    => tracing::info!("Received CTRL+C — shutting down"),
        _ = terminate => tracing::info!("Received SIGTERM — shutting down"),
    }
}
