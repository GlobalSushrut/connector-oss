//! `devguard status` — show status of active DevGuard sessions.

use anyhow::Result;
use crate::connector_client::ConnectorClient;
use std::path::PathBuf;

pub async fn run(client: &ConnectorClient, session_id: Option<&str>) -> Result<()> {
    if let Some(state) = crate::commands::monitor::read_live_state(PathBuf::from(".")) {
        let working = state.get("working").and_then(|v| v.as_bool()).unwrap_or(false);
        let ts = state.get("timestamp").and_then(|v| v.as_str()).unwrap_or("-");
        println!(
            "Live monitor: {} (last heartbeat {})",
            if working { "WORKING" } else { "NOT_WORKING" },
            ts
        );
    }
    if let Some(id) = session_id {
        // Show specific session with full stats
        let resp = client.session_status(id).await?;
        let session = resp.get("session").unwrap_or(&resp);

        let sid = session.get("session_id").and_then(|v| v.as_str()).unwrap_or(id);
        let tool = session.get("tool").and_then(|v| v.as_str()).unwrap_or("?");
        let role = session.get("role").and_then(|v| v.as_str()).unwrap_or("?");
        let workspace = session.get("workspace").and_then(|v| v.as_str()).unwrap_or("?");
        let active = session.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
        let created = session.get("created_at").and_then(|v| v.as_str()).unwrap_or("?");

        let stats = session.get("stats").cloned().unwrap_or_default();
        let llm = stats.get("llm_calls").and_then(|v| v.as_u64()).unwrap_or(0);
        let fr = stats.get("files_read").and_then(|v| v.as_u64()).unwrap_or(0);
        let fw = stats.get("files_written").and_then(|v| v.as_u64()).unwrap_or(0);
        let ce = stats.get("commands_executed").and_then(|v| v.as_u64()).unwrap_or(0);
        let cd = stats.get("commands_denied").and_then(|v| v.as_u64()).unwrap_or(0);
        let sr = stats.get("secrets_redacted").and_then(|v| v.as_u64()).unwrap_or(0);
        let tokens = stats.get("tokens_consumed").and_then(|v| v.as_u64()).unwrap_or(0);
        let cost = stats.get("cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);

        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  DevGuard — Session Status                                 ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        println!("  Session:     {} {}", sid, if active { "(ACTIVE)" } else { "(ENDED)" });
        println!("  Tool:        {}", tool);
        println!("  Role:        {}", role);
        println!("  Workspace:   {}", workspace);
        println!("  Started:     {}", created);

        println!("\n── Enforcement Stats ─────────────────────────────────────────");
        println!("  Files read:       {:<8}  Files written:    {}", fr, fw);
        println!("  Commands run:     {:<8}  Commands blocked: {}", ce, cd);
        println!("  Secrets redacted: {}", sr);

        println!("\n── LLM Usage ─────────────────────────────────────────────────");
        println!("  LLM calls:  {:<8}  Tokens: {:<12}  Cost: ${:.4}", llm, tokens, cost);

        // Fetch audit trail summary
        if let Ok(trail) = client.audit_trail(sid).await {
            let count = trail.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            println!("\n── Audit ─────────────────────────────────────────────────────");
            println!("  {} audit entries recorded", count);

            // Show last 5 entries
            if let Some(entries) = trail.get("entries").and_then(|v| v.as_array()) {
                let recent: Vec<_> = entries.iter().rev().take(5).collect();
                if !recent.is_empty() {
                    println!("  Recent:");
                    for e in &recent {
                        let action = e.get("action").and_then(|v| v.as_str()).unwrap_or("?");
                        let ts = e.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
                        let short_ts = if ts.len() > 19 { &ts[11..19] } else { ts };
                        let details = e.get("details").cloned().unwrap_or_default();
                        let detail_str = if let Some(cmd) = details.get("command").and_then(|v| v.as_str()) {
                            cmd.to_string()
                        } else if let Some(path) = details.get("path").and_then(|v| v.as_str()) {
                            path.to_string()
                        } else {
                            String::new()
                        };
                        println!("    {} {:<16} {}", short_ts, action,
                            if detail_str.len() > 40 { format!("{}...", &detail_str[..37]) } else { detail_str });
                    }
                }
            }
        }
    } else {
        // List all sessions
        let resp = client.session_list().await?;
        let empty = vec![];
        let arr = resp.get("sessions").and_then(|v| v.as_array()).unwrap_or(&empty);

        if arr.is_empty() {
            println!("No active DevGuard sessions.");
            println!("Run `devguard connect <tool>` to start one.");
            return Ok(());
        }

        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║  DevGuard — Active Sessions                                ║");
        println!("╚══════════════════════════════════════════════════════════════╝\n");

        println!("{:<16} {:<14} {:<12} {:<8} {:<8} {:<8} {:<8}",
            "SESSION", "TOOL", "ROLE", "FILES", "CMDS", "DENIED", "LLM");
        println!("{}", "─".repeat(74));

        for s in arr {
            let sid = s.get("session_id").and_then(|v| v.as_str()).unwrap_or("?");
            let tool = s.get("tool").and_then(|v| v.as_str()).unwrap_or("?");
            let role = s.get("role").and_then(|v| v.as_str()).unwrap_or("?");
            let active = s.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
            let stats = s.get("stats").cloned().unwrap_or_default();
            let fw = stats.get("files_written").and_then(|v| v.as_u64()).unwrap_or(0);
            let ce = stats.get("commands_executed").and_then(|v| v.as_u64()).unwrap_or(0);
            let cd = stats.get("commands_denied").and_then(|v| v.as_u64()).unwrap_or(0);
            let llm = stats.get("llm_calls").and_then(|v| v.as_u64()).unwrap_or(0);

            if !active { continue; }

            println!("{:<16} {:<14} {:<12} {:<8} {:<8} {:<8} {:<8}",
                if sid.len() > 15 { &sid[..15] } else { sid },
                tool, role, fw, ce, cd, llm);
        }

        println!("\n{} session(s) active.", arr.iter().filter(|s| s.get("active").and_then(|v| v.as_bool()).unwrap_or(false)).count());
        println!("Use `devguard status <session_id>` for details.");
    }

    Ok(())
}
