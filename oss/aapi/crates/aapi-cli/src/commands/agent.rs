//! AIOS-A1 — `connector agent` subcommand implementations
//!
//! Provides `kubectl`-style operator commands for managing live agents:
//!
//! ```text
//! aapi agent ps                      — list all live AgentControlBlocks
//! aapi agent inspect <pid>           — full ACB dump (JSON or table)
//! aapi agent pause <pid>             — POST AgentSignal::Suspend
//! aapi agent resume <pid>            — POST AgentSignal::Resume
//! aapi agent kill <pid> [--reason]   — POST AgentSignal::Terminate
//! aapi agent logs <pid> [--follow]   — tail audit log for agent
//! aapi agent top                     — live 1s refreshing ranked view
//! ```
//!
//! All commands hit the platform server (default `http://localhost:9090`)
//! via plain HTTP JSON — no SDK dependency required for these operator commands.

use std::time::Duration;

// ── helpers ───────────────────────────────────────────────────────────────────

fn platform_url(gateway: &str) -> String {
    // If the caller passes the AAPI gateway (8080), redirect to platform server (9090).
    // Both are configurable via --gateway / CONNECTOR_SERVER_URL.
    std::env::var("CONNECTOR_SERVER_URL")
        .unwrap_or_else(|_| gateway.replace(":8080", ":9090"))
}

fn auth_header() -> Option<String> {
    std::env::var("CONNECTOR_API_KEY")
        .ok()
        .or_else(|| std::env::var("CONNECTOR_TOKEN").ok())
        .map(|k| format!("Bearer {}", k))
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("failed to build HTTP client")
}

fn add_auth(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Some(h) = auth_header() {
        rb.header("Authorization", h)
    } else {
        rb
    }
}

// ── ps ────────────────────────────────────────────────────────────────────────

/// `aapi agent ps` — list all live AgentControlBlocks from the kernel store.
///
/// Fields shown: pid, name, status, phase, namespace, trust_score,
/// tokens_used / budget, priority.
pub async fn ps(gateway: &str, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/agents", platform_url(gateway));
    let resp = add_auth(http_client().get(&url))
        .send().await?
        .error_for_status()?
        .json::<serde_json::Value>().await?;

    let agents = resp.get("agents")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&agents)?),
        _ => {
            if agents.is_empty() {
                println!("No agents registered.");
                return Ok(());
            }
            // Table header
            println!("{:<36}  {:<20}  {:<12}  {:<10}  {:<20}  {:>8}  {:>10}",
                "PID", "NAME", "STATUS", "PRIORITY", "NAMESPACE",
                "TRUST", "TOKENS");
            println!("{}", "-".repeat(124));
            for a in &agents {
                let pid       = a.get("pid").and_then(|v| v.as_str()).unwrap_or("-");
                let name      = a.get("agent_name").or_else(|| a.get("name"))
                    .and_then(|v| v.as_str()).unwrap_or("-");
                let status    = a.get("status").and_then(|v| v.as_str()).unwrap_or("-");
                let priority  = a.get("priority").and_then(|v| v.as_str()).unwrap_or("-");
                let ns        = a.get("namespace").and_then(|v| v.as_str()).unwrap_or("-");
                let trust     = a.get("trust_score")
                    .and_then(|v| v.as_f64())
                    .map(|f| format!("{:.2}", f))
                    .unwrap_or_else(|| "-".to_string());
                let used      = a.get("total_tokens_consumed")
                    .or_else(|| a.get("tokens_used"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let budget    = a.get("quota_tokens")
                    .or_else(|| a.get("token_budget"))
                    .and_then(|v| v.as_u64());
                let tok_col = match budget {
                    Some(b) => format!("{}/{}", used, b),
                    None    => format!("{}", used),
                };
                println!("{:<36}  {:<20}  {:<12}  {:<10}  {:<20}  {:>8}  {:>10}",
                    &pid[..pid.len().min(36)],
                    &name[..name.len().min(20)],
                    &status[..status.len().min(12)],
                    &priority[..priority.len().min(10)],
                    &ns[..ns.len().min(20)],
                    trust, tok_col);
            }
            println!("\n{} agent(s) listed.", agents.len());
        }
    }
    Ok(())
}

// ── inspect ───────────────────────────────────────────────────────────────────

/// `aapi agent inspect <pid>` — full ACB dump.
pub async fn inspect(gateway: &str, pid: &str, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/agents/{}", platform_url(gateway), pid);
    let resp = add_auth(http_client().get(&url))
        .send().await?
        .error_for_status()?
        .json::<serde_json::Value>().await?;

    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&resp)?),
        _ => print_acb_table(&resp),
    }
    Ok(())
}

fn print_acb_table(acb: &serde_json::Value) {
    println!("Agent Control Block");
    println!("{}", "═".repeat(60));
    let fields = [
        ("PID",             "pid"),
        ("Name",            "agent_name"),
        ("Status",          "status"),
        ("Phase",           "phase"),
        ("Priority",        "priority"),
        ("Namespace",       "namespace"),
        ("Model",           "model"),
        ("Trust Score",     "trust_score"),
        ("Tokens Used",     "total_tokens_consumed"),
        ("Token Budget",    "quota_tokens"),
        ("Cost (USD)",      "total_cost_usd"),
        ("Sessions",        "session_count"),
        ("Packets",         "total_packets"),
        ("Registered At",   "registered_at"),
        ("Last Active",     "last_active_at"),
    ];
    for (label, key) in &fields {
        if let Some(v) = acb.get(key) {
            println!("  {:<20}  {}", label, v);
        }
    }
    // Expertise record
    if let Some(exp) = acb.get("expertise_record") {
        println!("\n  Expertise Record:");
        if let Some(obj) = exp.as_object() {
            for (k, v) in obj {
                println!("    {:<18}  {}", k, v);
            }
        }
    }
    // Namespace mounts
    if let Some(mounts) = acb.get("namespace_mounts").and_then(|v| v.as_array()) {
        println!("\n  Namespace Mounts ({}):", mounts.len());
        for m in mounts {
            println!("    - {}", m);
        }
    }
    // Delegation chains
    if let Some(chains) = acb.get("delegation_chains").and_then(|v| v.as_array()) {
        println!("\n  Delegation Chains ({}):", chains.len());
        for c in chains {
            println!("    - {}", c.get("chain_cid").unwrap_or(c));
        }
    }
}

// ── pause ─────────────────────────────────────────────────────────────────────

/// `aapi agent pause <pid>` — POST `AgentSignal::Suspend`.
pub async fn pause(gateway: &str, pid: &str) -> Result<(), Box<dyn std::error::Error>> {
    send_signal(gateway, pid, "Suspend", None, "paused").await
}

// ── resume ────────────────────────────────────────────────────────────────────

/// `aapi agent resume <pid>` — POST `AgentSignal::Resume`.
pub async fn resume(gateway: &str, pid: &str) -> Result<(), Box<dyn std::error::Error>> {
    send_signal(gateway, pid, "Resume", None, "resumed").await
}

// ── kill ──────────────────────────────────────────────────────────────────────

/// `aapi agent kill <pid> [--reason <reason>]` — POST `AgentSignal::Terminate`.
pub async fn kill(gateway: &str, pid: &str, reason: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    send_signal(gateway, pid, "Terminate", reason.as_deref(), "terminated").await
}

async fn send_signal(
    gateway: &str,
    pid: &str,
    signal: &str,
    reason: Option<&str>,
    past_tense: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/agents/{}/signal", platform_url(gateway), pid);
    let mut body = serde_json::json!({ "signal": signal });
    if let Some(r) = reason {
        body["reason"] = serde_json::Value::String(r.to_string());
    }
    let resp = add_auth(http_client().post(&url).json(&body))
        .send().await?
        .error_for_status()?
        .json::<serde_json::Value>().await?;

    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        println!("Agent {} {}.", pid, past_tense);
    } else {
        let msg = resp.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error");
        eprintln!("Failed to send {} signal to {}: {}", signal, pid, msg);
        std::process::exit(1);
    }
    Ok(())
}

// ── logs ──────────────────────────────────────────────────────────────────────

/// `aapi agent logs <pid> [--follow] [--limit N]` — tail audit log for agent.
///
/// Without `--follow`: fetches the last `limit` audit entries and prints them.
/// With `--follow`: polls every second and prints new entries as they arrive
/// (SSE streaming is server-side; this client polls until interrupted).
pub async fn logs(
    gateway: &str,
    pid: &str,
    follow: bool,
    limit: usize,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let base = platform_url(gateway);
    let url = format!("{}/api/v1/agents/{}/audit?limit={}", base, pid, limit);

    // Initial fetch
    let entries = fetch_audit_entries(&url).await?;
    print_audit_entries(&entries, format);

    if !follow {
        return Ok(());
    }

    // Follow mode: poll every second for new entries
    let mut last_ts = entries.last()
        .and_then(|e| e.get("timestamp").and_then(|v| v.as_i64()))
        .unwrap_or(0);

    println!("--- following audit log for {} (Ctrl-C to stop) ---", pid);
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let poll_url = format!("{}/api/v1/agents/{}/audit?limit={}&since_ms={}",
            base, pid, limit, last_ts + 1);
        let new_entries = fetch_audit_entries(&poll_url).await.unwrap_or_default();
        if !new_entries.is_empty() {
            if let Some(ts) = new_entries.last()
                .and_then(|e| e.get("timestamp").and_then(|v| v.as_i64()))
            {
                last_ts = ts;
            }
            print_audit_entries(&new_entries, format);
        }
    }
}

async fn fetch_audit_entries(url: &str) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let resp = add_auth(http_client().get(url))
        .send().await?
        .error_for_status()?
        .json::<serde_json::Value>().await?;

    Ok(resp.get("entries")
        .or_else(|| resp.get("audit"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default())
}

fn print_audit_entries(entries: &[serde_json::Value], format: &str) {
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(entries).unwrap_or_default());
        return;
    }
    for e in entries {
        let ts  = e.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
        let op  = e.get("op").or_else(|| e.get("operation"))
            .and_then(|v| v.as_str()).unwrap_or("-");
        let out = e.get("outcome").and_then(|v| v.as_str()).unwrap_or("-");
        let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("-");
        println!("[{}] {:12}  {:<10}  {}", ts, op, out, tgt);
    }
}

// ── top ───────────────────────────────────────────────────────────────────────

/// `aapi agent top` — live 1s refreshing view ranked by token_used / threat_score.
pub async fn top(gateway: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/agents", platform_url(gateway));
    println!("aapi agent top — refreshing every 1s (Ctrl-C to stop)");

    loop {
        let resp = add_auth(http_client().get(&url))
            .send().await?
            .error_for_status()?
            .json::<serde_json::Value>().await?;

        let mut agents = resp.get("agents")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        // Sort by tokens used descending
        agents.sort_by(|a, b| {
            let ta = a.get("total_tokens_consumed").and_then(|v| v.as_u64()).unwrap_or(0);
            let tb = b.get("total_tokens_consumed").and_then(|v| v.as_u64()).unwrap_or(0);
            tb.cmp(&ta)
        });

        // Clear terminal (ANSI escape)
        print!("\x1B[2J\x1B[H");
        println!("aapi agent top — {} agents   (Ctrl-C to stop)\n", agents.len());
        println!("{:<36}  {:<20}  {:<12}  {:>10}  {:>8}  {:>8}  {:>10}",
            "PID", "NAME", "STATUS", "TOKENS", "TRUST", "THREAT", "COST USD");
        println!("{}", "-".repeat(114));

        for a in agents.iter().take(30) {
            let pid     = a.get("pid").and_then(|v| v.as_str()).unwrap_or("-");
            let name    = a.get("agent_name").and_then(|v| v.as_str()).unwrap_or("-");
            let status  = a.get("status").and_then(|v| v.as_str()).unwrap_or("-");
            let tokens  = a.get("total_tokens_consumed").and_then(|v| v.as_u64()).unwrap_or(0);
            let trust   = a.get("trust_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let threat  = a.get("threat_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let cost    = a.get("total_cost_usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
            println!("{:<36}  {:<20}  {:<12}  {:>10}  {:>8.2}  {:>8.4}  {:>10.6}",
                &pid[..pid.len().min(36)],
                &name[..name.len().min(20)],
                &status[..status.len().min(12)],
                tokens, trust, threat, cost);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
