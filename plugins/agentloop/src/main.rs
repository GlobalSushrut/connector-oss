//! AgentLoop — Cloudflare for the agentic web.
//! DNS · Mesh · Workers · Observability — powered by ConnectorOS.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    http::{HeaderValue, Method},
    response::IntoResponse,
    routing::{delete, get, post},
    Router,
};
use metrics_exporter_prometheus::PrometheusBuilder;
use sqlx::postgres::PgPoolOptions;
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowHeaders, AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod agent_dns;
mod app_middleware;
mod connector;
mod debug;
mod design;
mod error;
mod mesh;
mod optimize;
mod routes;
mod ship;
mod types;
mod worker;

use connector::{ConnectorClient, ConnectorConfig};
use mesh::MeshProxy;

// ── App state ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub pool:      sqlx::PgPool,
    pub connector: ConnectorClient,
    pub mesh:      Arc<MeshProxy>,
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    // ── Panic hook: log panics as structured errors ──────────────────────────
    std::panic::set_hook(Box::new(|info| {
        let msg = info.to_string();
        tracing::error!(panic = %msg, "Thread panicked");
    }));

    // ── Logging ───────────────────────────────────────────────────────────────
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "agentloop=info,tower_http=warn,sqlx=warn".parse().unwrap()))
        .with(fmt::layer().json().with_current_span(true))
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "AgentLoop starting"
    );

    // ── Prometheus metrics ────────────────────────────────────────────────────
    let prometheus_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("install prometheus recorder");

    // ── Database pool ─────────────────────────────────────────────────────────
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_max: u32 = env_u32("DB_MAX_CONNECTIONS", 20);
    let db_min: u32 = env_u32("DB_MIN_CONNECTIONS", 2);
    let pool = PgPoolOptions::new()
        .max_connections(db_max)
        .min_connections(db_min)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(1800))
        .test_before_acquire(true)
        .connect(&database_url)
        .await
        .expect("connect to database");

    // ── Migrations ────────────────────────────────────────────────────────────
    sqlx::migrate!("./migrations").run(&pool).await
        .expect("run database migrations");
    tracing::info!("Migrations applied");

    // ── Connector client ──────────────────────────────────────────────────────
    let connector = ConnectorClient::new(ConnectorConfig::from_env())
        .expect("build connector client");

    // ── Mesh proxy ────────────────────────────────────────────────────────────
    let mesh = Arc::new(MeshProxy::new(pool.clone(), Arc::new(connector.clone())));

    // ── Background: DNS health sweeper ────────────────────────────────────────
    {
        let sweep_pool = pool.clone();
        tokio::spawn(async move {
            agent_dns::health_sweeper(sweep_pool).await;
        });
    }

    let state = AppState { pool: pool.clone(), connector, mesh };

    // ── CORS ──────────────────────────────────────────────────────────────────
    let cors_origin = std::env::var("CORS_ALLOW_ORIGIN").unwrap_or_else(|_| "*".into());
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers(AllowHeaders::any())
        .allow_origin(if cors_origin == "*" {
            AllowOrigin::any()
        } else {
            AllowOrigin::exact(cors_origin.parse::<HeaderValue>()?)
        });

    let body_limit_mb: usize = env_u32("BODY_LIMIT_MB", 4) as usize;
    let request_timeout_secs: u64 = env_u32("REQUEST_TIMEOUT_SECS", 60) as u64;

    // ── Prometheus /metrics handler ────────────────────────────────────────────
    let metrics_app = Router::new().route("/metrics", get(move || {
        let h = prometheus_handle.clone();
        async move { h.render().into_response() }
    }));

    // ── Main API router ───────────────────────────────────────────────────────
    let api = Router::new()
        // Health & readiness
        .route("/health",   get(routes::health))
        .route("/healthz",  get(routes::health))
        .route("/readyz",   get(routes::readyz))

        // Agent DNS
        .route("/api/v1/dns/register",          post(routes::dns_register))
        .route("/api/v1/dns/resolve/:fqan",     get(routes::dns_resolve))
        .route("/api/v1/dns/records",           get(routes::dns_list))
        .route("/api/v1/dns/records/:fqan",     delete(routes::dns_deregister))

        // Mesh
        .route("/api/v1/mesh/call",             post(routes::mesh_call))
        .route("/api/v1/mesh/hops",             get(routes::mesh_hops))
        .route("/api/v1/mesh/hops/:id/verify",  get(routes::mesh_verify_chain))
        .route("/api/v1/mesh/circuit-breakers", get(routes::mesh_circuit_breakers))

        // Workers
        .route("/api/v1/workers",               get(routes::list_workers).post(routes::create_worker))
        .route("/api/v1/workers/:id",           get(routes::get_worker))
        .route("/api/v1/workers/:id/invoke",    post(routes::invoke_worker))
        .route("/api/v1/workers/:id/mcp",       get(routes::worker_mcp_manifest))
        .route("/api/v1/workers/:id/invocations", get(routes::worker_invocations))

        // Agents
        .route("/api/v1/agents",                get(routes::list_agents).post(routes::create_agent))
        .route("/api/v1/agents/:id",            get(routes::get_agent))
        .route("/api/v1/agents/:id/timeline",   get(routes::agent_timeline))
        .route("/api/v1/agents/:id/sync",       post(routes::sync_history))
        .route("/api/v1/agents/:id/slos",       get(routes::list_slos).post(routes::create_slo))
        .route("/api/v1/agents/:id/slos/evaluate", post(routes::evaluate_slos))
        .route("/api/v1/agents/:id/drift",      get(routes::list_drift_events))
        .route("/api/v1/agents/:id/drift/detect", post(routes::detect_drift))

        // Debug
        .route("/api/v1/runs/:id",              get(routes::get_run))
        .route("/api/v1/runs/diff",             post(routes::diff_runs))
        .route("/api/v1/replays",               post(routes::start_replay))
        .route("/api/v1/replays/:id",           get(routes::get_replay))

        // Design
        .route("/api/v1/prompts",               get(routes::list_prompts).post(routes::create_prompt))
        .route("/api/v1/prompts/:id",           get(routes::get_prompt))
        .route("/api/v1/prompts/:id/versions",  post(routes::create_prompt_version))
        .route("/api/v1/prompts/:id/versions/:vid/approve", post(routes::approve_prompt_version))
        .route("/api/v1/datasets",              post(routes::create_dataset))

        // Ship
        .route("/api/v1/experiments",           get(routes::list_experiments).post(routes::create_experiment))
        .route("/api/v1/experiments/:id",       get(routes::get_experiment))
        .route("/api/v1/experiments/:id/start",   post(routes::start_experiment))
        .route("/api/v1/experiments/:id/pause",   post(routes::pause_experiment))
        .route("/api/v1/experiments/:id/promote", post(routes::promote_experiment))
        .route("/api/v1/experiments/:id/rollback", post(routes::rollback_experiment))
        .route("/api/v1/experiments/:id/metrics", post(routes::refresh_experiment_metrics))

        // Optimize
        .route("/api/v1/fleet",                 get(routes::fleet_summary))
        .route("/api/v1/recommendations",       get(routes::list_recommendations))
        .route("/api/v1/recommendations/:id/apply",   post(routes::apply_recommendation))
        .route("/api/v1/recommendations/:id/dismiss", post(routes::dismiss_recommendation))

        // Middleware (outermost = applied last)
        .layer(axum::middleware::from_fn(crate::app_middleware::request_id))
        .layer(axum::middleware::from_fn(crate::app_middleware::require_api_key))
        .layer(axum::middleware::from_fn(crate::app_middleware::trace_request))
        .layer(TimeoutLayer::new(Duration::from_secs(request_timeout_secs)))
        .layer(cors)
        .layer(CompressionLayer::new())
        .layer(RequestBodyLimitLayer::new(body_limit_mb * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // ── Bind ──────────────────────────────────────────────────────────────────
    let port          = std::env::var("PORT").unwrap_or_else(|_| "8084".into());
    let metrics_port  = std::env::var("METRICS_PORT").unwrap_or_else(|_| "9090".into());
    let api_addr      = format!("0.0.0.0:{}", port);
    let metrics_addr  = format!("0.0.0.0:{}", metrics_port);

    let api_listener     = tokio::net::TcpListener::bind(&api_addr).await?;
    let metrics_listener = tokio::net::TcpListener::bind(&metrics_addr).await?;

    tracing::info!(api = %api_addr, metrics = %metrics_addr, "AgentLoop ready");

    // Run both servers concurrently; either exiting shuts both down
    tokio::select! {
        r = axum::serve(api_listener, api).with_graceful_shutdown(shutdown_signal()) => {
            if let Err(e) = r { tracing::error!(err = %e, "API server error"); }
        }
        r = axum::serve(metrics_listener, metrics_app) => {
            if let Err(e) = r { tracing::error!(err = %e, "Metrics server error"); }
        }
    }

    tracing::info!("AgentLoop shut down cleanly");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.expect("ctrl-c handler");
    tracing::info!("Shutdown signal received — draining connections");
}
