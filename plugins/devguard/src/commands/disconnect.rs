//! `devguard disconnect <session>` — end a governed session.

use anyhow::Result;
use crate::connector_client::ConnectorClient;

pub async fn run(client: &ConnectorClient, session_id: &str) -> Result<()> {
    println!("Disconnecting session: {}", session_id);

    let resp = client.session_end(session_id).await?;

    let status = resp.get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("ended");

    println!("✓ Session {} {}", session_id, status);

    // Print final stats if available
    if let Some(stats) = resp.get("stats") {
        if let Some(files_read) = stats.get("files_read").and_then(|v| v.as_u64()) {
            println!("  Files read: {}", files_read);
        }
        if let Some(files_written) = stats.get("files_written").and_then(|v| v.as_u64()) {
            println!("  Files written: {}", files_written);
        }
        if let Some(commands) = stats.get("commands_run").and_then(|v| v.as_u64()) {
            println!("  Commands run: {}", commands);
        }
        if let Some(blocked) = stats.get("commands_blocked").and_then(|v| v.as_u64()) {
            println!("  Commands blocked: {}", blocked);
        }
        if let Some(tokens) = stats.get("total_tokens").and_then(|v| v.as_u64()) {
            println!("  Tokens used: {}", tokens);
        }
    }

    Ok(())
}
