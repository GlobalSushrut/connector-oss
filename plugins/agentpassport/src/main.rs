//! AgentPassport — Agent Identity Platform
//!
//! Startup sequence:
//!   1. Load env (.env file), init JSON structured logging, install panic hook
//!   2. Connect PgPool, run SQLx migrations
//!   3. Build ConnectorOS client, verify connectivity
//!   4. Generate or load Ed25519 signing key
//!   5. Install Prometheus recorder on METRICS_PORT
//!   6. Build Axum router with full middleware stack
//!   7. Spawn background tasks:
//!        a. Reputation decay sweep (nightly)
//!        b. Trust score sync from ConnectorOS (every 5 min)
//!   8. Serve API on PORT, Prometheus on METRICS_PORT
//!   9. Graceful drain on Ctrl-C

mod agents;
mod app_middleware;
mod attestation;
mod connector;
mod credentials;
mod crypto;
mod error;
mod federation;
mod incidents;
mod reputation;
mod routes;
mod state;
mod types;
mod verify;

use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use ed25519_dalek::SigningKey;
use metrics_exporter_prometheus::PrometheusBuilder;
use rand::rngs::OsRng;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    timeout::TimeoutLayer,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use uuid::Uuid;

use crate::connector::{ConnectorClient, ConnectorConfig};
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── 1. Environment + logging ───────────────────────────────────────────────
    dotenvy::dotenv().ok();

    let log_format = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "json".into());
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,agentpassport=debug"));

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

    // Structured panic hook — ensure panics surface in structured logs
    std::panic::set_hook(Box::new(|info| {
        tracing::error!(panic = %info, "PANIC — thread panicked");
    }));

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "AgentPassport starting"
    );

    // ── 2. Database ────────────────────────────────────────────────────────────
    let db_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

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
        .expect("Failed to run migrations");

    tracing::info!("Postgres connected and migrations applied");

    // ── 3. ConnectorOS client ──────────────────────────────────────────────────
    let connector = ConnectorClient::new(ConnectorConfig::from_env())
        .expect("Failed to build ConnectorOS client");

    match connector.health().await {
        Ok(_)  => tracing::info!("ConnectorOS reachable"),
        Err(e) => tracing::warn!(error = %e, "ConnectorOS unreachable — continuing in standalone mode"),
    }

    // ── 4. Signing key ─────────────────────────────────────────────────────────
    let signing_key: SigningKey = match std::env::var("AGENTPASSPORT_SIGNING_KEY") {
        Ok(hex) if !hex.is_empty() => {
            crypto::signing_key_from_hex(&hex).expect("Invalid AGENTPASSPORT_SIGNING_KEY hex")
        }
        _ => {
            tracing::warn!("AGENTPASSPORT_SIGNING_KEY not set — generating ephemeral key (not suitable for production)");
            SigningKey::generate(&mut OsRng)
        }
    };

    let key_id        = std::env::var("AGENTPASSPORT_KEY_ID").unwrap_or_else(|_| "key-1".into());
    let instance_id   = std::env::var("AGENTPASSPORT_INSTANCE_ID").unwrap_or_else(|_| "default".into());
    let instance_did  = crypto::mint_passport_did(&instance_id);

    tracing::info!(instance_did = %instance_did, "Identity key loaded");

    // ── Default org (single-tenant mode) ──────────────────────────────────────
    let default_org_str = std::env::var("AGENTPASSPORT_ORG_ID")
        .unwrap_or_else(|_| Uuid::nil().to_string());
    let default_org = Uuid::parse_str(&default_org_str)
        .unwrap_or_else(|_| {
            tracing::warn!("Invalid AGENTPASSPORT_ORG_ID — using nil UUID");
            Uuid::nil()
        });

    // Ensure default org exists
    sqlx::query(
        "INSERT INTO ap_organisations (id, name, slug)
         VALUES ($1, 'Default Organisation', 'default')
         ON CONFLICT (id) DO NOTHING"
    ).bind(default_org).execute(&pool).await.ok();

    // ── HTTP client for federation ─────────────────────────────────────────────
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(format!("agentpassport/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    let app_state = AppState {
        pool: pool.clone(),
        connector,
        http,
        signing_key,
        instance_did,
        key_id,
        default_org,
    };

    // ── 5. Prometheus ──────────────────────────────────────────────────────────
    let metrics_port: u16 = std::env::var("METRICS_PORT")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(9092);
    let metrics_addr = SocketAddr::from(([0, 0, 0, 0], metrics_port));

    PrometheusBuilder::new()
        .with_http_listener(metrics_addr)
        .install()
        .expect("Failed to install Prometheus recorder");

    tracing::info!(port = metrics_port, "Prometheus metrics listening");

    // ── 6. Router ──────────────────────────────────────────────────────────────
    let timeout_secs: u64 = std::env::var("REQUEST_TIMEOUT_SECS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(30);

    let api_router = Router::new()
        // ── Agent registration + directory
        .route("/api/v1/agents",                      post(routes::register_agent))
        .route("/api/v1/agents",                      get(routes::list_agents))
        .route("/api/v1/agents/:did",                 get(routes::get_agent))
        .route("/api/v1/agents/:did/revoke",          post(routes::revoke_agent))
        // ── Sponsor approval (public — no auth)
        .route("/api/v1/sponsors/approve/:token",     get(routes::approve_sponsorship))
        // ── Passport
        .route("/api/v1/passport/:did",               get(routes::get_passport))
        // ── Public verification (no auth)
        .route("/api/v1/verify",                      post(routes::public_verify))
        .route("/api/v1/crl",                         get(routes::get_crl))
        // ── Credentials
        .route("/api/v1/credentials",                 post(routes::issue_credential))
        .route("/api/v1/agents/:did/credentials",     get(routes::list_credentials))
        .route("/api/v1/credentials/:id/revoke",      post(routes::revoke_credential))
        // ── Reputation
        .route("/api/v1/reputation/:did",             get(routes::get_reputation))
        // ── Attestation export
        .route("/api/v1/attestation/:did/export",     get(routes::export_attestation))
        // ── Incidents
        .route("/api/v1/incidents",                   post(routes::create_incident))
        .route("/api/v1/incidents",                   get(routes::list_incidents))
        .route("/api/v1/incidents/:id/resolve",       post(routes::resolve_incident))
        // ── Federation
        .route("/api/v1/federation/peers",            post(routes::register_peer))
        .route("/api/v1/federation/peers",            get(routes::list_peers))
        .route("/api/v1/federation/peers/:id/sync",   post(routes::sync_peer))
        // ── Audit log
        .route("/api/v1/audit",                       get(routes::get_audit))
        // ── Public agent export (for federation peers)
        .route("/api/v1/agents/export",               get(routes::export_agents))
        // ── System
        .route("/health",                             get(routes::health))
        .route("/readyz",                             get(routes::readyz));

    let app = api_router
        .with_state(app_state.clone())
        .layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(app_middleware::trace_request))
                .layer(middleware::from_fn(app_middleware::require_api_key))
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
        let pool_clone = pool.clone();
        tokio::spawn(async move {
            let interval_secs: u64 = std::env::var("TRUST_SYNC_SECS")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(300);
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;
                let connector_bg = ConnectorClient::new(ConnectorConfig::from_env()).ok();
                if let Some(c) = connector_bg {
                    match agents::sync_trust_from_connector(&pool_clone, &c).await {
                        Ok(n) => tracing::info!(updated = n, "Trust sync complete"),
                        Err(e) => tracing::error!(error = %e, "Trust sync failed"),
                    }
                }
            }
        });
    }

    {
        let pool_clone = pool.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(86_400)); // daily
            loop {
                ticker.tick().await;
                match reputation::run_decay_sweep(&pool_clone).await {
                    Ok(n) => tracing::info!(recovered = n, "Reputation decay sweep complete"),
                    Err(e) => tracing::error!(error = %e, "Decay sweep failed"),
                }
            }
        });
    }

    // ── 8. Serve ───────────────────────────────────────────────────────────────
    let port: u16 = std::env::var("PORT")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(8086);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!(
        port         = port,
        metrics_port = metrics_port,
        instance_did = %app_state.instance_did,
        "AgentPassport listening"
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
