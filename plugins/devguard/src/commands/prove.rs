//! `devguard prove <subject>` — call Connector SOE prove API.

use anyhow::Result;
use crate::connector_client::ConnectorClient;

pub async fn run(client: &ConnectorClient, subject: &str) -> Result<()> {
    let resp = client.surface_prove(subject).await?;
    println!("{}", serde_json::to_string_pretty(&resp)?);
    Ok(())
}
