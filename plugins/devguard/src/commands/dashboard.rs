use anyhow::Result;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use crate::commands::status;
use crate::connector_client::ConnectorClient;

pub async fn run(
    client: &ConnectorClient,
    session: Option<&str>,
    interval_seconds: u64,
    once: bool,
) -> Result<()> {
    loop {
        print!("\x1B[2J\x1B[H");
        std::io::stdout().flush()?;

        println!("DevGuard Live Dashboard");
        println!("refresh={}s | press Ctrl+C to stop\n", interval_seconds);
        status::run(client, session).await?;
        if let Some(state) = crate::commands::monitor::read_live_state(PathBuf::from(".")) {
            println!("\n── Live Monitor ─────────────────────────────────────────────");
            let working = state.get("working").and_then(|v| v.as_bool()).unwrap_or(false);
            let last_action = state.get("last_action").and_then(|v| v.as_str()).unwrap_or("none");
            let blocked = state.get("blocked_count").and_then(|v| v.as_u64()).unwrap_or(0);
            let pending = state.get("approvals_pending").and_then(|v| v.as_u64()).unwrap_or(0);
            let ts = state.get("timestamp").and_then(|v| v.as_str()).unwrap_or("-");
            println!("  Working:          {}", if working { "YES" } else { "NO" });
            println!("  Last action:      {}", last_action);
            println!("  Blocked actions:  {}", blocked);
            println!("  Pending approvals:{}", pending);
            println!("  Last heartbeat:   {}", ts);
        }

        if once {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(interval_seconds.max(1))).await;
    }
}
