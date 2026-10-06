use tracing::{info, error};
use std::net::SocketAddr;

mod config;
mod types;
mod connector;
mod gateway;
mod resolver;
mod view;
mod control;
mod evidence;
mod admin;
mod storage;
mod auth;
mod error;

use config::Config;
use error::AppError;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tracetramp=info,tower_http=info".into())
        )
        .with_target(true)
        .with_thread_ids(true)
        .init();

    info!("Starting TraceTramp v{}", env!("CARGO_PKG_VERSION"));

    let config = Config::from_env()?;
    info!("Configuration loaded: data_plane_port={}, management_plane_port={}", 
        config.data_plane_port, config.management_plane_port);

    let db_pool = storage::init_postgres(&config.database_url).await?;
    info!("PostgreSQL connection pool initialized");

    let redis_pool = storage::init_redis_optional(config.redis_url.as_deref()).await?;
    if redis_pool.is_some() {
        info!("Redis connection pool initialized");
    }

    let connector_client = connector::ConnectorClient::new(
        &config.connector_base_url,
        &config.connector_api_key,
    );
    info!("Connector client initialized: base_url={}", config.connector_base_url);

    let state = AppState {
        config: config.clone(),
        db_pool,
        redis_pool,
        connector_client,
    };

    let data_plane_addr: SocketAddr = ([0, 0, 0, 0], config.data_plane_port).into();
    let data_app = gateway::create_router(state.clone());
    
    let management_addr: SocketAddr = ([0, 0, 0, 0], config.management_plane_port).into();
    let management_app = admin::create_router(state);

    info!("Data plane listening on {}", data_plane_addr);
    info!("Management plane listening on {}", management_addr);

    let data_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(data_plane_addr).await.unwrap();
        axum::serve(listener, data_app).await.unwrap();
    });

    let management_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(management_addr).await.unwrap();
        axum::serve(listener, management_app).await.unwrap();
    });

    tokio::try_join!(data_handle, management_handle)?;

    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db_pool: sqlx::PgPool,
    pub redis_pool: Option<redis::aio::ConnectionManager>,
    pub connector_client: connector::ConnectorClient,
}
