//! Submit command - submit a VĀKYA request

use aapi_sdk::{AapiClient, ClientConfig, VakyaRequestBuilder};

pub async fn run(
    gateway: &str,
    actor: String,
    resource: String,
    action: String,
    body: String,
    capability: Option<String>,
    ttl: i64,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::new(gateway);
    let client = AapiClient::new(config)?;

    let body_json: serde_json::Value = serde_json::from_str(&body)?;

    let mut builder = VakyaRequestBuilder::new()
        .actor(&actor)
        .resource(&resource)
        .action(&action)
        .body(body_json)
        .ttl_secs(ttl);

    if let Some(cap) = capability {
        builder = builder.capability(cap);
    }

    let vakya = builder.build().map_err(|e| e)?;
    let response = client.submit(vakya).await?;

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        _ => {
            println!("VĀKYA submitted successfully!");
            println!("  ID:          {}", response.vakya_id);
            println!("  Hash:        {}", response.vakya_hash);
            println!("  Status:      {}", response.status);
            if let Some(idx) = response.leaf_index {
                println!("  Leaf Index:  {}", idx);
            }
            if let Some(root) = response.merkle_root {
                println!("  Merkle Root: {}", root);
            }
        }
    }

    Ok(())
}
