//! AIOS-B15 — `connector doctor` — self-diagnosing environment health check
//!
//! Runs a series of checks and prints pass/fail with actionable fix instructions.
//! Exit code 0 = all pass, 1 = any fail.
//!
//! ```text
//! connector doctor
//! connector doctor --format json
//! ```

use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug)]
struct Check {
    name: &'static str,
    status: CheckStatus,
    message: String,
    fix: Option<String>,
}

#[derive(Debug, PartialEq)]
enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl CheckStatus {
    fn icon(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "✓",
            CheckStatus::Warn => "⚠",
            CheckStatus::Fail => "✗",
        }
    }
    fn label(&self) -> &'static str {
        match self {
            CheckStatus::Pass => "pass",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
        }
    }
}

// ── Individual checks ─────────────────────────────────────────────────────────

fn check_connector_dir() -> Check {
    let path = expand_home("~/.connector");
    if std::path::Path::new(&path).exists() {
        Check {
            name: "connector dir",
            status: CheckStatus::Pass,
            message: format!("{} exists", path),
            fix: None,
        }
    } else {
        Check {
            name: "connector dir",
            status: CheckStatus::Warn,
            message: format!("{} not found", path),
            fix: Some("Run `connector init` to scaffold the default data directory.".to_string()),
        }
    }
}

fn check_config() -> Check {
    let path = expand_home("~/.connector/connector.toml");
    let p = std::path::Path::new(&path);
    if !p.exists() {
        return Check {
            name: "config file",
            status: CheckStatus::Warn,
            message: format!("{} not found", path),
            fix: Some("Run `connector init` to generate a default connector.toml.".to_string()),
        };
    }
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            // Basic structural check: must have [server] section
            if contents.contains("[server]") {
                Check {
                    name: "config file",
                    status: CheckStatus::Pass,
                    message: format!("{} is valid", path),
                    fix: None,
                }
            } else {
                Check {
                    name: "config file",
                    status: CheckStatus::Warn,
                    message: format!("{} exists but is missing [server] section", path),
                    fix: Some("Add a [server] section: `host = \"0.0.0.0\"` and `port = 9090`.".to_string()),
                }
            }
        }
        Err(e) => Check {
            name: "config file",
            status: CheckStatus::Fail,
            message: format!("Cannot read {}: {}", path, e),
            fix: Some(format!("Fix file permissions: `chmod 644 {}`", path)),
        },
    }
}

fn check_signing_key() -> Check {
    let path = expand_home("~/.connector/keys/platform_signing.key");
    let p = std::path::Path::new(&path);
    if !p.exists() {
        return Check {
            name: "signing key",
            status: CheckStatus::Warn,
            message: format!("{} not found", path),
            fix: Some("Run `connector init` to generate a 32-byte Ed25519 signing key.".to_string()),
        };
    }
    match std::fs::metadata(&path) {
        Ok(meta) => {
            let size = meta.len();
            if size == 32 {
                Check {
                    name: "signing key",
                    status: CheckStatus::Pass,
                    message: format!("{} (32 bytes)", path),
                    fix: None,
                }
            } else {
                Check {
                    name: "signing key",
                    status: CheckStatus::Fail,
                    message: format!("{} has unexpected size: {} bytes (expected 32)", path, size),
                    fix: Some("Delete the file and run `connector init` to regenerate.".to_string()),
                }
            }
        }
        Err(e) => Check {
            name: "signing key",
            status: CheckStatus::Fail,
            message: format!("Cannot read key metadata: {}", e),
            fix: Some(format!("Fix permissions: `chmod 600 {}`", path)),
        },
    }
}

fn check_api_key() -> Check {
    let has_key = std::env::var("CONNECTOR_API_KEY").is_ok()
        || std::env::var("CONNECTOR_TOKEN").is_ok();
    if has_key {
        Check {
            name: "api key",
            status: CheckStatus::Pass,
            message: "CONNECTOR_API_KEY or CONNECTOR_TOKEN is set".to_string(),
            fix: None,
        }
    } else {
        Check {
            name: "api key",
            status: CheckStatus::Warn,
            message: "Neither CONNECTOR_API_KEY nor CONNECTOR_TOKEN is set".to_string(),
            fix: Some(
                "Set: `export CONNECTOR_API_KEY=cpk_live_...` or use dev mode: `export CONNECTOR_DEV_MODE=1`".to_string(),
            ),
        }
    }
}

fn check_port_free(port: u16) -> Check {
    let name = "port available";
    match TcpListener::bind(format!("0.0.0.0:{}", port)) {
        Ok(_) => Check {
            name,
            status: CheckStatus::Pass,
            message: format!("Port {} is free", port),
            fix: None,
        },
        Err(_) => Check {
            name,
            status: CheckStatus::Fail,
            message: format!("Port {} is already in use", port),
            fix: Some(format!(
                "Stop the process using port {}: `lsof -ti:{} | xargs kill` or use `--port <other>` on start.",
                port, port
            )),
        },
    }
}

async fn check_server_reachable(gateway: &str) -> Check {
    let server_url = std::env::var("CONNECTOR_SERVER_URL")
        .unwrap_or_else(|_| gateway.replace(":8080", ":9090"));
    let url = format!("{}/healthz", server_url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap_or_default();

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => Check {
            name: "server reachable",
            status: CheckStatus::Pass,
            message: format!("GET {} → {}", url, resp.status()),
            fix: None,
        },
        Ok(resp) => Check {
            name: "server reachable",
            status: CheckStatus::Warn,
            message: format!("GET {} → {} (unexpected status)", url, resp.status()),
            fix: Some("Check server logs: `connector logs` or review platform startup output.".to_string()),
        },
        Err(e) => Check {
            name: "server reachable",
            status: CheckStatus::Warn,
            message: format!("GET {} failed: {}", url, e),
            fix: Some(format!(
                "Start the server: `connector start` or check CONNECTOR_SERVER_URL={}",
                server_url
            )),
        },
    }
}

async fn check_llm_provider() -> Check {
    let provider = std::env::var("CONNECTOR_LLM_PROVIDER")
        .unwrap_or_else(|_| "stub".to_string());
    let api_key = std::env::var("CONNECTOR_LLM_API_KEY").ok()
        .or_else(|| std::env::var("OPENAI_API_KEY").ok());
    let dev_mode = std::env::var("CONNECTOR_DEV_MODE").is_ok();

    if dev_mode || provider == "stub" {
        return Check {
            name: "llm provider",
            status: CheckStatus::Pass,
            message: format!("provider=stub (dev mode — no real LLM calls)"),
            fix: None,
        };
    }

    if api_key.is_none() {
        return Check {
            name: "llm provider",
            status: CheckStatus::Fail,
            message: format!("provider={} but no API key set", provider),
            fix: Some(
                "Set CONNECTOR_LLM_API_KEY=sk-... or OPENAI_API_KEY=sk-... in your environment.".to_string(),
            ),
        };
    }

    Check {
        name: "llm provider",
        status: CheckStatus::Pass,
        message: format!("provider={} — API key found", provider),
        fix: None,
    }
}

fn check_data_dir_writable() -> Check {
    let data_dir = std::env::var("CONNECTOR_DATA_DIR")
        .unwrap_or_else(|_| expand_home("~/.connector/data"));
    let p = PathBuf::from(&data_dir);

    if !p.exists() {
        // Try creating it
        match std::fs::create_dir_all(&p) {
            Ok(_) => return Check {
                name: "data dir writable",
                status: CheckStatus::Pass,
                message: format!("{} created successfully", data_dir),
                fix: None,
            },
            Err(e) => return Check {
                name: "data dir writable",
                status: CheckStatus::Fail,
                message: format!("{} does not exist and cannot be created: {}", data_dir, e),
                fix: Some(format!("Create manually: `mkdir -p {}`", data_dir)),
            },
        }
    }

    let test_path = p.join(".doctor_write_test");
    match std::fs::write(&test_path, b"ok") {
        Ok(_) => {
            let _ = std::fs::remove_file(&test_path);
            Check {
                name: "data dir writable",
                status: CheckStatus::Pass,
                message: format!("{} is writable", data_dir),
                fix: None,
            }
        }
        Err(e) => Check {
            name: "data dir writable",
            status: CheckStatus::Fail,
            message: format!("{} is not writable: {}", data_dir, e),
            fix: Some(format!("Fix permissions: `chmod 755 {} && chown $USER {}`", data_dir, data_dir)),
        },
    }
}

// ── Main doctor command ───────────────────────────────────────────────────────

pub async fn run(gateway: &str, port: u16, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut checks = vec![
        check_connector_dir(),
        check_config(),
        check_signing_key(),
        check_api_key(),
        check_data_dir_writable(),
        check_port_free(port),
    ];

    // Async checks
    checks.push(check_server_reachable(gateway).await);
    checks.push(check_llm_provider().await);

    let failures: usize = checks.iter().filter(|c| c.status == CheckStatus::Fail).count();
    let warnings: usize = checks.iter().filter(|c| c.status == CheckStatus::Warn).count();
    let passes: usize   = checks.iter().filter(|c| c.status == CheckStatus::Pass).count();

    match format {
        "json" => {
            let json = serde_json::json!({
                "checks": checks.iter().map(|c| serde_json::json!({
                    "name": c.name,
                    "status": c.status.label(),
                    "message": c.message,
                    "fix": c.fix,
                })).collect::<Vec<_>>(),
                "summary": {
                    "pass": passes,
                    "warn": warnings,
                    "fail": failures,
                    "ok": failures == 0,
                }
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        _ => {
            println!("connector doctor\n");
            for c in &checks {
                println!("  {} [{}] {}", c.status.icon(), c.name, c.message);
                if let Some(fix) = &c.fix {
                    println!("      Fix: {}", fix);
                }
            }
            println!("\n  {} passed  {} warning{}  {} failed",
                passes, warnings, if warnings == 1 { "" } else { "s" }, failures
            );

            if failures == 0 && warnings == 0 {
                println!("\n  All checks passed. Run `connector start` to launch the platform.");
            } else if failures == 0 {
                println!("\n  No blocking failures. Run `connector start` (warnings are advisory).");
            } else {
                println!("\n  Fix the failing checks above before running `connector start`.");
            }
        }
    }

    if failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}

// ── Path helper ───────────────────────────────────────────────────────────────

fn expand_home(path: &str) -> String {
    if path.starts_with("~/") {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        format!("{}/{}", home, &path[2..])
    } else {
        path.to_string()
    }
}
