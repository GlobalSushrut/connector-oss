//! LedgerLens — AI FinOps Platform
//!
//! Startup sequence:
//!   1. Load env, init tracing, install panic hook
//!   2. Connect PgPool, run SQLx migrations
//!   3. Build ConnectorOS client, verify connectivity
//!   4. Install Prometheus recorder on METRICS_PORT
//!   5. Build Axum router with full middleware stack
//!   6. Spawn background tasks:
//!        a. Cost sync from ConnectorOS (COST_SYNC_SECS)
//!        b. Budget enforcement sweeper (BUDGET_SWEEP_SECS)
//!        c. Anomaly detection (ANOMALY_SWEEP_SECS)
//!        d. Optimization run (every 6 hours)
//!   7. Serve API on PORT, Prometheus on METRICS_PORT
//!   8. Graceful drain on Ctrl-C

use std::time::Duration;

use axum::{
    middleware,
    routing::{get, post, delete},
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

mod alerts;
mod app_middleware;
mod attribution;
mod budgets;
mod connector;
mod csv_export;
mod dashboard;
mod db_decimal;
mod error;
mod executive;
mod exports;
mod forecast;
mod optimize;
mod routes;
mod state;
mod types;

use connector::{ConnectorClient, ConnectorConfig};
use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Environment ───────────────────────────────────────────────────────────
    dotenvy::dotenv().ok();

    // ── Tracing ───────────────────────────────────────────────────────────────
    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::from_env("RUST_LOG").add_directive("ledgerlens=info".parse()?))
        .init();

    // ── Panic hook ────────────────────────────────────────────────────────────
    std::panic::set_hook(Box::new(|info| {
        let loc = info.location().map(|l| l.to_string()).unwrap_or_default();
        let msg = info.payload().downcast_ref::<&str>().copied().unwrap_or("panic");
        tracing::error!(location = %loc, message = msg, "Thread panicked — LedgerLens will exit");
    }));

    // ── Database ──────────────────────────────────────────────────────────────
    let db_url    = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_max    = std::env::var("DB_MAX_CONNECTIONS").unwrap_or_else(|_| "20".into())
                        .parse::<u32>().unwrap_or(20);
    let db_min    = std::env::var("DB_MIN_CONNECTIONS").unwrap_or_else(|_| "2".into())
                        .parse::<u32>().unwrap_or(2);

    let pool = PgPoolOptions::new()
        .max_connections(db_max)
        .min_connections(db_min)
        .acquire_timeout(Duration::from_secs(10))
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(1800))
        .test_before_acquire(true)
        .connect(&db_url)
        .await?;

    tracing::info!("Connected to Postgres (max={db_max}, min={db_min})");

    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("Migrations applied");

    // ── ConnectorOS ───────────────────────────────────────────────────────────
    let connector = ConnectorClient::new(ConnectorConfig::from_env())?;
    match connector.health().await {
        Ok(())   => tracing::info!("ConnectorOS reachable"),
        Err(e)   => tracing::warn!("ConnectorOS unreachable on startup: {e} — continuing"),
    }

    // ── Prometheus ────────────────────────────────────────────────────────────
    let metrics_port: u16 = std::env::var("METRICS_PORT")
        .unwrap_or_else(|_| "9091".into()).parse().unwrap_or(9091);

    let recorder = PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], metrics_port))
        .install_recorder()?;

    tracing::info!("Prometheus metrics on :{metrics_port}/metrics");

    // ── App state ─────────────────────────────────────────────────────────────
    let state = AppState { pool: pool.clone(), connector: connector.clone() };

    // ── Background tasks ──────────────────────────────────────────────────────

    // a. Cost sync from ConnectorOS
    {
        let p = pool.clone(); let c = connector.clone();
        let secs: u64 = std::env::var("COST_SYNC_SECS")
            .unwrap_or_else(|_| "60".into()).parse().unwrap_or(60);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(secs));
            loop {
                interval.tick().await;
                match attribution::sync_from_connector(&p, &c).await {
                    Ok(n) => {
                        if n > 0 { tracing::debug!(synced = n, "Cost sync"); }
                        metrics::counter!("ledgerlens_cost_sync_total").increment(1);
                    }
                    Err(e) => tracing::warn!("Cost sync error: {e}"),
                }
            }
        });
    }

    // b. Budget enforcement sweeper
    {
        let p = pool.clone();
        let secs: u64 = std::env::var("BUDGET_SWEEP_SECS")
            .unwrap_or_else(|_| "30".into()).parse().unwrap_or(30);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(secs));
            loop {
                interval.tick().await;
                if let Err(e) = budgets::enforcement_sweep(&p).await {
                    tracing::error!("Budget sweep error: {e}");
                }
                metrics::counter!("ledgerlens_budget_sweeps_total").increment(1);
            }
        });
    }

    // c. Anomaly detection
    {
        let p = pool.clone();
        let secs: u64 = std::env::var("ANOMALY_SWEEP_SECS")
            .unwrap_or_else(|_| "300".into()).parse().unwrap_or(300);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(secs));
            loop {
                interval.tick().await;
                match forecast::run_anomaly_detection(&p).await {
                    Ok(n) => { if n > 0 { tracing::warn!(detected = n, "Anomalies detected"); } }
                    Err(e) => tracing::error!("Anomaly detection error: {e}"),
                }
            }
        });
    }

    // d. Optimization recommendations (every 6 hours)
    {
        let p = pool.clone(); let c = connector.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(6 * 3600));
            loop {
                interval.tick().await;
                match optimize::run_optimization(&p, &c).await {
                    Ok(n) => tracing::info!(created = n, "Optimization run"),
                    Err(e) => tracing::error!("Optimization error: {e}"),
                }
            }
        });
    }

    // ── Router ────────────────────────────────────────────────────────────────
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let req_timeout: u64 = std::env::var("REQUEST_TIMEOUT_SECS")
        .unwrap_or_else(|_| "60".into()).parse().unwrap_or(60);

    let middleware_stack = ServiceBuilder::new()
        .layer(TimeoutLayer::new(Duration::from_secs(req_timeout)))
        .layer(CompressionLayer::new())
        .layer(cors)
        .layer(middleware::from_fn(app_middleware::request_id))
        .layer(middleware::from_fn(app_middleware::trace_request))
        .layer(middleware::from_fn(app_middleware::require_api_key));

    let app = Router::new()
        // ── System ──────────────────────────────────────────────────────────
        .route("/health",   get(routes::health))
        .route("/readyz",   get(routes::readyz))

        // ── Tags ─────────────────────────────────────────────────────────────
        .route("/api/v1/tags",          get(routes::list_tag_keys).post(routes::create_tag_key))

        // ── Usage ingest ──────────────────────────────────────────────────────
        .route("/api/v1/ingest",        post(routes::ingest_usage))
        .route("/api/v1/sync",          post(routes::sync_from_connector))

        // ── Cost query ────────────────────────────────────────────────────────
        .route("/api/v1/costs",         get(routes::query_costs))
        .route("/api/v1/costs/fleet",   get(routes::fleet_cost_summary))
        .route("/api/v1/costs/agents/:agent_id", get(routes::agent_cost))

        // ── Budgets ───────────────────────────────────────────────────────────
        .route("/api/v1/budgets",        get(routes::list_budgets).post(routes::create_budget))
        .route("/api/v1/budgets/status", get(routes::budget_status))
        .route("/api/v1/budgets/:id",    get(routes::get_budget).delete(routes::delete_budget))
        .route("/api/v1/budgets/:id/events", get(routes::get_budget_events))

        // ── Anomalies ─────────────────────────────────────────────────────────
        .route("/api/v1/anomalies",                  get(routes::list_anomalies))
        .route("/api/v1/anomalies/:id/acknowledge",  post(routes::acknowledge_anomaly))
        .route("/api/v1/anomalies/:id/resolve",      post(routes::resolve_anomaly))

        // ── Revenue / unit economics ──────────────────────────────────────────
        .route("/api/v1/revenue",        post(routes::create_revenue))

        // ── Forecasts ─────────────────────────────────────────────────────────
        .route("/api/v1/forecast",       get(routes::get_forecast))

        // ── Waste & optimization ──────────────────────────────────────────────
        .route("/api/v1/waste",          get(routes::waste_heatmap))
        .route("/api/v1/cache-roi",      get(routes::cache_roi))
        .route("/api/v1/optimize",       post(routes::run_optimization))
        .route("/api/v1/recommendations",              get(routes::list_recommendations))
        .route("/api/v1/recommendations/:id/apply",    post(routes::apply_recommendation))
        .route("/api/v1/recommendations/:id/dismiss",  post(routes::dismiss_recommendation))

        // ── Exports ───────────────────────────────────────────────────────────
        .route("/api/v1/exports",         get(routes::list_exports).post(routes::create_export))
        .route("/api/v1/exports/:id",     get(routes::get_export))
        .route("/api/v1/exports/:id/run", post(routes::run_export))

        // ── CFO Dashboard ─────────────────────────────────────────────────────
        .route("/api/v1/dashboard",                get(routes::cfo_dashboard))
        .route("/api/v1/costs/realtime",           get(routes::realtime_burn))

        // ── Executive ─────────────────────────────────────────────────────────────
        .route("/api/v1/dashboard/executive",      get(routes::executive_dashboard))
        .route("/api/v1/simulate/savings",         post(routes::simulate_savings))
        .route("/api/v1/roi",                      get(routes::roi_calculator))

        // ── CSV Downloads ─────────────────────────────────────────────────────
        .route("/api/v1/csv/chargeback",      get(routes::download_chargeback_csv))
        .route("/api/v1/csv/unit-economics",  get(routes::download_unit_economics_csv))
        .route("/api/v1/csv/waste",           get(routes::download_waste_csv))
        .route("/api/v1/csv/anomalies",       get(routes::download_anomaly_csv))

        // ── Notification channels ─────────────────────────────────────────────
        .route("/api/v1/channels",                   get(routes::list_channels).post(routes::create_channel))
        .route("/api/v1/channels/:id/test",          post(routes::test_alert))

        .layer(middleware_stack)
        .with_state(state);

    // ── Serve ─────────────────────────────────────────────────────────────────
    let port: u16 = std::env::var("PORT").unwrap_or_else(|_| "8085".into())
        .parse().unwrap_or(8085);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    tracing::info!("LedgerLens API on http://0.0.0.0:{port}");
    tracing::info!("  /health     — service health");
    tracing::info!("  /readyz     — readiness probe");
    tracing::info!("  /api/v1/dashboard   — CFO money-on-fire view");
    tracing::info!("  /api/v1/costs/realtime — live burn rate");
    tracing::info!("  /api/v1/csv/*       — Excel-ready CSV exports");
    tracing::info!("  /api/v1/*           — all endpoints");
    tracing::info!("  :{metrics_port}/metrics — Prometheus");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("Shutting down LedgerLens…");
        })
        .await?;

    Ok(())
}
