//! Health check command

use aapi_sdk::{AapiClient, ClientConfig};

pub async fn run(gateway: &str, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::new(gateway);
    let client = AapiClient::new(config)?;

    let response = client.health().await?;

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        _ => {
            let status_icon = if response.status == "healthy" { "✓" } else { "✗" };
            println!("{} Gateway Status: {}", status_icon, response.status);
            println!("  Gateway ID: {}", response.gateway_id);
            println!("  Version:    {}", response.version);
            println!("  Timestamp:  {}", response.timestamp);
        }
    }

    Ok(())
}
