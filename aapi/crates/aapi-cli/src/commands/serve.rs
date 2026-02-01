//! Serve command - start the gateway server

use aapi_gateway::{GatewayServerBuilder, GatewayConfig};
use tracing::info;

pub async fn run(host: String, port: u16, database: String) -> Result<(), Box<dyn std::error::Error>> {
    info!(host = %host, port = %port, database = %database, "Starting AAPI Gateway");

    let server = GatewayServerBuilder::new()
        .host(&host)
        .port(port)
        .database_url(&database)
        .build()
        .await?;

    // Handle Ctrl+C for graceful shutdown
    let shutdown = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        info!("Shutdown signal received");
    };

    server.run_with_shutdown(shutdown).await?;

    info!("Gateway stopped");
    Ok(())
}
