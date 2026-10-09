//! `devguard doctor` — health check.
//!
//! Architecture: Connector = OS (standalone). DevGuard = App (needs Connector).
//! DevGuard boots Connector when needed, not the other way around.

use anyhow::Result;
use crate::connector_client::ConnectorClient;

pub async fn run(client: &ConnectorClient) -> Result<()> {
    println!("DevGuard Doctor\n");

    // 1. Check Connector OS (DevGuard's runtime dependency)
    print!("  Connector OS ... ");
    let connector_up = match client.health().await {
        Ok(resp) => {
            let status = resp.get("status").and_then(|v| v.as_str()).unwrap_or("ok");
            println!("✓ {} ({})", client.base_url(), status);
            true
        }
        Err(_) => {
            println!("✗ NOT RUNNING");
            println!("    DevGuard will auto-start Connector on `devguard connect`.");
            println!("    Or start manually: connector-platform &");
            false
        }
    };

    let mut chain_connector = connector_up;
    let mut chain_aapi = false;
    let mut chain_audit = false;
    let mut chain_llm = false;

    // 1b. AAPI reachability
    print!("  AAPI capabilities ... ");
    if connector_up {
        match get_json(client, "/aapi/capabilities").await {
            Ok(resp) => {
                let count = resp
                    .get("capabilities")
                    .and_then(|v| v.as_array())
                    .map(|v| v.len())
                    .or_else(|| resp.as_array().map(|v| v.len()))
                    .unwrap_or(0);
                println!("✓ reachable ({} entries)", count);
                chain_aapi = true;
            }
            Err(e) => {
                println!("✗ {}", e);
            }
        }
    } else {
        println!("✗ skipped (connector down)");
    }

    // 1c. Audit write/read test
    print!("  Audit chain write/read ... ");
    if connector_up {
        let marker = format!("devguard_doctor_{}", uuid::Uuid::new_v4().simple());
        let write_body = serde_json::json!({
            "agent_pid": "devguard-doctor",
            "action": "doctor.chain_test",
            "resource": "doctor",
            "outcome": "success",
            "metadata": {
                "marker": marker,
                "source": "devguard_doctor"
            }
        });
        let write_ok = post_json(client, "/actionlog/record", &write_body).await.is_ok();
        let read_ok = if write_ok {
            match get_json(client, "/actionlog/actions").await {
                Ok(v) => serde_json::to_string(&v).map(|s| s.contains(&marker)).unwrap_or(false),
                Err(_) => false,
            }
        } else {
            false
        };
        if write_ok && read_ok {
            println!("✓ write OK, read-back OK");
            chain_audit = true;
        } else if write_ok {
            println!("⚠ write OK, read-back not confirmed");
        } else {
            println!("✗ write failed");
        }
    } else {
        println!("✗ skipped (connector down)");
    }

    // 1d. LLM gateway models endpoint
    print!("  LLM gateway (/v1/models) ... ");
    if connector_up {
        match get_json(client, "/v1/models").await {
            Ok(v) => {
                let count = v
                    .get("data")
                    .and_then(|d| d.as_array())
                    .map(|d| d.len())
                    .or_else(|| v.as_array().map(|a| a.len()))
                    .unwrap_or(0);
                println!("✓ reachable ({} model entries)", count);
                chain_llm = true;
            }
            Err(e) => println!("✗ {}", e),
        }
    } else {
        println!("✗ skipped (connector down)");
    }

    // 2. Check devguard.yaml
    print!("  devguard.yaml ... ");
    if std::path::Path::new("devguard.yaml").exists() {
        match crate::config::DevGuardConfig::load("devguard.yaml") {
            Ok(config) => {
                let errors = config.validate();
                if errors.is_empty() {
                    let roles = config.roles.len();
                    let assignments = config.assignments.len();
                    println!("✓ {} roles, {} assignments", roles, assignments);
                } else {
                    println!("⚠ Loaded with {} error(s):", errors.len());
                    for e in &errors {
                        println!("    ✗ {}", e);
                    }
                }
            }
            Err(e) => {
                println!("✗ Parse error: {}", e);
            }
        }
    } else {
        println!("✗ Not found. Run `devguard init`.");
    }

    // 3. Detect coding tools
    println!();
    println!("  Tools detected:");
    let tools: Vec<(&str, &str)> = vec![
        ("claude", "Claude Code"),
        ("cursor", "Cursor"),
        ("windsurf", "Windsurf"),
        ("aider", "Aider"),
    ];

    for (cmd, name) in &tools {
        print!("    {} ... ", name);
        let found = std::process::Command::new("which")
            .arg(cmd)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if found {
            println!("✓ on PATH");
        } else {
            println!("○ not found");
        }
    }

    // Check if we're inside Windsurf right now
    let in_windsurf = std::env::var("WINDSURF_SESSION").is_ok()
        || std::env::var("TERM_PROGRAM").map(|v| v.contains("windsurf")).unwrap_or(false)
        || std::env::current_dir()
            .map(|p| p.join(".windsurf").exists())
            .unwrap_or(false);
    if in_windsurf {
        println!("    ⮕ You appear to be running INSIDE Windsurf");
    }

    // 4. Active sessions (only if Connector is up)
    if connector_up {
        println!();
        print!("  Active sessions ... ");
        match client.session_list().await {
            Ok(resp) => {
                let empty = vec![];
                let arr = resp.get("sessions").and_then(|v| v.as_array()).unwrap_or(&empty);
                let active = arr.iter().filter(|s| {
                    s.get("active").and_then(|v| v.as_bool()).unwrap_or(false)
                }).count();
                if active > 0 {
                    println!("{} active", active);
                    for s in arr {
                        if s.get("active").and_then(|v| v.as_bool()).unwrap_or(false) {
                            let sid = s.get("session_id").and_then(|v| v.as_str()).unwrap_or("?");
                            let tool = s.get("tool").and_then(|v| v.as_str()).unwrap_or("?");
                            let role = s.get("role").and_then(|v| v.as_str()).unwrap_or("?");
                            println!("    {} — {} ({})", sid, tool, role);
                        }
                    }
                } else {
                    println!("none");
                }
            }
            Err(_) => println!("? (could not query)"),
        }
    }

    // 5. Summary
    println!();
    println!(
        "  Chain: devguard --► connector-os --► aapi --► audit --► llm-gateway = {}",
        if chain_connector && chain_aapi && chain_audit && chain_llm {
            "HEALTHY"
        } else {
            "DEGRADED"
        }
    );
    if connector_up && std::path::Path::new("devguard.yaml").exists() {
        println!("  ✓ Ready. Run `devguard connect windsurf` to govern your agent.");
    } else if !connector_up && std::path::Path::new("devguard.yaml").exists() {
        println!("  ⚠ Connector not running. `devguard connect` will auto-start it.");
    } else {
        println!("  ✗ Run `devguard init` first, then `devguard connect <tool>`.");
    }

    Ok(())
}

async fn get_json(client: &ConnectorClient, path: &str) -> Result<serde_json::Value> {
    let url = format!("{}{}", client.base_url(), path);
    let mut req = reqwest::Client::new().get(url);
    if let Ok(key) = std::env::var("CONNECTOR_ACCESS_KEY") {
        if !key.trim().is_empty() {
            req = req.header("Authorization", format!("Bearer {}", key.trim()));
        }
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("GET {} returned {}", path, resp.status());
    }
    Ok(resp.json().await?)
}

async fn post_json(client: &ConnectorClient, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    let url = format!("{}{}", client.base_url(), path);
    let mut req = reqwest::Client::new().post(url).json(body);
    if let Ok(key) = std::env::var("CONNECTOR_ACCESS_KEY") {
        if !key.trim().is_empty() {
            req = req.header("Authorization", format!("Bearer {}", key.trim()));
        }
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("POST {} returned {}", path, resp.status());
    }
    Ok(resp.json().await?)
}
