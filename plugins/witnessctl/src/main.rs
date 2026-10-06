use std::sync::Arc;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use sqlx::postgres::PgPoolOptions;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{info, warn};

mod capture;
mod compliance;
mod compliance_ledger;
mod config;
mod connector;
mod custody;
mod custody_node {
    pub use ::witnessctl::custody_node::*;
}
mod error;
mod export;
mod pii;
mod proxy;
mod routes;
mod schema;
mod session;
mod watchdog;
mod webhook;

// Re-export library modules for `crate::types` / `crate::receipt` in binary submodules.
mod types {
    pub use ::witnessctl::types::*;
}
mod receipt {
    pub use ::witnessctl::receipt::*;
}
mod bundle_file {
    pub use ::witnessctl::bundle_file::*;
}

use capture::CaptureEngine;
use compliance::ComplianceEngine;
use config::Config;
use connector::ConnectorClient;
use export::ExportEngine;
use proxy::ProxyEngine;
use session::SessionManager;
use webhook::WebhookEngine;

static WITNESSCTL_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn resolve_log_format() -> &'static str {
    if let Ok(explicit) = std::env::var("LOG_FORMAT") {
        let normalized = explicit.trim().to_ascii_lowercase();
        if normalized == "json" {
            return "json";
        }
    }
    let env_name = std::env::var("RUST_ENV")
        .or_else(|_| std::env::var("APP_ENV"))
        .or_else(|_| std::env::var("ENV"))
        .unwrap_or_else(|_| "dev".to_string())
        .to_ascii_lowercase();
    if matches!(env_name.as_str(), "prod" | "production") {
        "json"
    } else {
        "text"
    }
}

async fn assert_startup_migrations_applied(db: &sqlx::PgPool) -> anyhow::Result<()> {
    let expected_version = expected_latest_migration_version()?;
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(1) FROM _sqlx_migrations")
        .fetch_one(db)
        .await
        .map_err(|_| anyhow::anyhow!(
            "WitnessCtl startup refused: migrations table _sqlx_migrations not found. Run `sqlx migrate run` (or `witnessctl setup`) first."
        ))?;
    if count <= 0 {
        anyhow::bail!(
            "WitnessCtl startup refused: no migrations applied. Run `sqlx migrate run` (or `witnessctl setup`) before starting."
        );
    }

    let db_version = sqlx::query_scalar::<_, String>(
        "SELECT version::text FROM _sqlx_migrations ORDER BY version DESC LIMIT 1"
    )
    .fetch_optional(db)
    .await
    .map_err(|e| anyhow::anyhow!("Unable to query migration version: {}", e))?
    .ok_or_else(|| anyhow::anyhow!("Unable to determine DB migration version from _sqlx_migrations"))?;

    // expected_version == "0" is a sentinel meaning the migrations directory was absent
    // at runtime (Docker container). The embedded sqlx::migrate! is authoritative; skip
    // the filesystem cross-check entirely in that case.
    if expected_version != "0" && db_version < expected_version {
        anyhow::bail!(
            "WitnessCtl startup refused: DB schema is behind (db={}, expected={}). Run migrations: sqlx migrate run",
            db_version,
            expected_version
        );
    }
    if expected_version != "0" && db_version > expected_version {
        anyhow::bail!(
            "WitnessCtl startup refused: DB schema is ahead of this binary (db={}, expected={}). Use a newer WitnessCtl build.",
            db_version,
            expected_version
        );
    }
    Ok(())
}

fn migrations_dir() -> std::path::PathBuf {
    if let Ok(d) = std::env::var("WITNESSCTL_MIGRATIONS_DIR") {
        return std::path::PathBuf::from(d);
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/var/lib/connector"));
    let candidate = cwd.join("witnessctl-migrations");
    if candidate.is_dir() { return candidate; }
    cwd.join("migrations")
}

fn expected_latest_migration_version() -> anyhow::Result<String> {
    let migrations_dir = migrations_dir();
    if !migrations_dir.is_dir() {
        // In production the embedded migrator (sqlx::migrate!) handles this;
        // skip version cross-check when the migrations directory is absent.
        return Ok("0".to_string());
    }
    let mut versions = std::fs::read_dir(&migrations_dir)
        .map_err(|e| anyhow::anyhow!("Failed to read migrations directory {}: {}", migrations_dir.display(), e))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(".sql"))
        .filter_map(|name| name.split('_').next().map(|s| s.to_string()))
        .filter(|prefix| prefix.chars().all(|c| c.is_ascii_digit()))
        .collect::<Vec<_>>();
    versions.sort();
    versions
        .last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("No migration files found in {}", migrations_dir.display()))
}

fn generate_hmac_secret() -> String {
    format!(
        "wctl_{}_{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn witness_base_url() -> String {
    std::env::var("WITNESSCTL_BASE_URL").unwrap_or_else(|_| {
        let port = std::env::var("WITNESSCTL_PORT").unwrap_or_else(|_| "7443".to_string());
        format!("http://127.0.0.1:{}", port)
    })
}

fn admin_token() -> anyhow::Result<String> {
    std::env::var("WITNESSCTL_ADMIN_TOKEN")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("WITNESSCTL_ADMIN_TOKEN is required for this command"))
}

async fn cli_get(path: &str) -> anyhow::Result<reqwest::Response> {
    let token = admin_token()?;
    let client = reqwest::Client::new();
    let url = format!("{}{}", witness_base_url(), path);
    let resp = client.get(url).bearer_auth(token).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Request failed: {}", resp.status());
    }
    Ok(resp)
}

async fn cli_post_json(path: &str, body: serde_json::Value) -> anyhow::Result<reqwest::Response> {
    let token = admin_token()?;
    let client = reqwest::Client::new();
    let url = format!("{}{}", witness_base_url(), path);
    let resp = client.post(url).bearer_auth(token).json(&body).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Request failed: {}", resp.status());
    }
    Ok(resp)
}

async fn run_cli_session(args: &[String]) -> anyhow::Result<()> {
    let sub = args.get(2).map(|s| s.as_str()).unwrap_or("");
    match sub {
        "open" => {
            let upstream = flag_value(args, "--upstream")
                .ok_or_else(|| anyhow::anyhow!("Usage: witnessctl session open --upstream <url> --role <role>"))?;
            let role = flag_value(args, "--role").unwrap_or_else(|| "analyst".to_string());
            let resp = cli_post_json(
                "/api/v1/sessions",
                serde_json::json!({
                    "upstream": upstream,
                    "role": role,
                    "mode": "proxy"
                }),
            )
            .await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        "list" => {
            let resp = cli_get("/api/v1/sessions").await?;
            let body: serde_json::Value = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        "seal" => {
            let id = args
                .get(3)
                .ok_or_else(|| anyhow::anyhow!("Usage: witnessctl session seal <id> [--output path.witness]"))?;
            let resp = cli_post_json(
                &format!("/api/v1/sessions/{}/seal?force_seal=true", id),
                serde_json::json!({}),
            )
            .await?;
            let body: serde_json::Value = resp.json().await?;
            if let Some(out) = flag_value(args, "--output") {
                let bundle_path = body
                    .get("bundle_path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("seal response missing bundle_path"))?;
                let src = std::path::Path::new(bundle_path);
                let dest = std::path::Path::new(&out);
                if let Some(parent) = dest.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)?;
                    }
                }
                std::fs::copy(src, dest)?;
                let meta_src = if bundle_path.ends_with(".witness") {
                    format!("{}.json", bundle_path)
                } else {
                    format!("{}.witness.json", bundle_path)
                };
                if std::path::Path::new(&meta_src).exists() {
                    let meta_out = if out.ends_with(".witness") {
                        format!("{}.json", out)
                    } else {
                        format!("{}.witness.json", out)
                    };
                    let _ = std::fs::copy(&meta_src, &meta_out);
                }
                println!(
                    "{}",
                    serde_json::json!({
                        "sealed": true,
                        "bundle_path": bundle_path,
                        "output": dest.display().to_string(),
                    })
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&body)?);
            }
        }
        _ => {
            anyhow::bail!("Usage: witnessctl session <open|list|seal> ...");
        }
    }
    Ok(())
}

async fn run_cli_export(args: &[String]) -> anyhow::Result<()> {
    let id = args
        .get(2)
        .ok_or_else(|| anyhow::anyhow!("Usage: witnessctl export <id> --format <pdf|json|csv|markdown> [--output file]"))?;
    let format = flag_value(args, "--format").unwrap_or_else(|| "pdf".to_string());
    let output = flag_value(args, "--output").unwrap_or_else(|| format!("witness-{}.{}", id, format));
    let resp = cli_get(&format!("/api/v1/export/{}?format={}", id, format)).await?;
    let bytes = resp.bytes().await?;
    std::fs::write(&output, &bytes)?;
    println!("Exported {} bytes to {}", bytes.len(), output);
    Ok(())
}

async fn run_cli_verify(args: &[String]) -> anyhow::Result<()> {
    let id = args
        .get(2)
        .ok_or_else(|| anyhow::anyhow!("Usage: witnessctl verify <id>"))?;
    let resp = cli_get(&format!("/api/v1/verify/{}", id)).await?;
    let body: serde_json::Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&body)?);
    let chain_valid = body.get("chain_valid").and_then(|v| v.as_bool()).unwrap_or(false);
    if !chain_valid {
        anyhow::bail!("Verification failed for session {}", id);
    }
    Ok(())
}

fn run_cli_verify_bundle(args: &[String]) -> anyhow::Result<()> {
    let path = args
        .get(2)
        .ok_or_else(|| anyhow::anyhow!("Usage: witnessctl verify-bundle <bundle_path> [--hmac-secret <secret>]"))?;
    let secret = flag_value(args, "--hmac-secret")
        .or_else(|| std::env::var("WITNESSCTL_HMAC_SECRET").ok())
        .ok_or_else(|| anyhow::anyhow!("WITNESSCTL_HMAC_SECRET or --hmac-secret is required"))?;
    let value = crate::bundle_file::load_bundle_json(std::path::Path::new(path))
        .map_err(|e| anyhow::anyhow!(e))?;
    let report = crate::receipt::verify_bundle_value(&value, &secret)
        .map_err(|e| anyhow::anyhow!("bundle verification failed: {}", e))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.tamper_detected {
        anyhow::bail!("bundle verification failed: tamper detected");
    }
    Ok(())
}

fn run_cli_compliance_map(args: &[String]) -> anyhow::Result<()> {
    let sub = args.get(2).map(|s| s.as_str()).unwrap_or("");
    match sub {
        "export" => {
            let output = flag_value(args, "--output")
                .unwrap_or_else(|| "plugins/witnessctl/internal/compliance_map.generated.yaml".to_string());
            let yaml = compliance::canonical_map_yaml()?;
            std::fs::write(&output, yaml)?;
            println!("Exported canonical compliance map to {}", output);
        }
        "check" => {
            let input = flag_value(args, "--input")
                .unwrap_or_else(|| "plugins/witnessctl/internal/compliance_map.yaml".to_string());
            let content = std::fs::read_to_string(&input)?;
            let drift = compliance::check_canonical_map_drift(&content)?;
            if drift.is_empty() {
                println!("Compliance map is in sync with canonical Rust controls.");
            } else {
                println!("Compliance map drift detected ({}):", drift.len());
                for d in drift {
                    println!("- {}", d);
                }
                anyhow::bail!("compliance map drift detected");
            }
        }
        "bridge" => {
            let input = flag_value(args, "--input")
                .unwrap_or_else(|| "plugins/witnessctl/internal/compliance_map.yaml".to_string());
            let in_place = has_flag(args, "--in-place");
            let dry_run = has_flag(args, "--dry-run");
            let output = if in_place {
                input.clone()
            } else {
                flag_value(args, "--output")
                    .unwrap_or_else(|| "plugins/witnessctl/internal/compliance_map.canonical.yaml".to_string())
            };
            if in_place && !dry_run && !has_flag(args, "--yes") {
                anyhow::bail!(
                    "Refusing to overwrite in place without confirmation. Re-run with --in-place --yes"
                );
            }
            let content = std::fs::read_to_string(&input)?;
            let (yaml, warnings) = compliance::bridge_legacy_to_canonical_yaml(&content)?;
            if dry_run {
                let existing = std::fs::read_to_string(&output).unwrap_or_default();
                if existing == yaml {
                    println!("No changes (dry run): {}", output);
                } else {
                    print_unified_diff(&output, &existing, &yaml)?;
                }
                println!("Dry run complete. No files written.");
            } else {
                std::fs::write(&output, yaml)?;
                println!("Bridged legacy map to canonical YAML: {}", output);
            }
            if warnings.is_empty() {
                println!("No mapping warnings.");
            } else {
                println!("Mapping warnings ({}):", warnings.len());
                for w in warnings {
                    println!("- {}", w);
                }
            }
        }
        _ => {
            anyhow::bail!("Usage: witnessctl compliance-map <export|check|bridge> [--output path|--input path|--in-place --yes|--dry-run]");
        }
    }
    Ok(())
}

fn print_unified_diff(path_label: &str, before: &str, after: &str) -> anyhow::Result<()> {
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let before_path = std::env::temp_dir().join(format!("witnessctl-before-{}.yaml", nonce));
    let after_path = std::env::temp_dir().join(format!("witnessctl-after-{}.yaml", nonce));
    std::fs::write(&before_path, before)?;
    std::fs::write(&after_path, after)?;

    let output = Command::new("git")
        .arg("diff")
        .arg("--no-index")
        .arg("--")
        .arg(&before_path)
        .arg(&after_path)
        .output();

    let _ = std::fs::remove_file(&before_path);
    let _ = std::fs::remove_file(&after_path);

    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.trim().is_empty() {
                println!("No textual diff for {}", path_label);
            } else {
                println!("{}", text);
            }
            Ok(())
        }
        Err(err) => Err(anyhow::anyhow!(
            "failed to generate unified diff with git: {}",
            err
        )),
    }
}

fn run_setup() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let env_path = Path::new(".env");
    let mut lines = if env_path.exists() {
        std::fs::read_to_string(env_path)?
            .lines()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    } else {
        vec![]
    };

    let mut hmac_updated = false;
    if let Some(idx) = lines.iter().position(|l| l.starts_with("WITNESSCTL_HMAC_SECRET=")) {
        let current = lines[idx]
            .split_once('=')
            .map(|(_, v)| v.trim())
            .unwrap_or("");
        if current.is_empty() || current.eq_ignore_ascii_case("change-me-in-production") {
            lines[idx] = format!("WITNESSCTL_HMAC_SECRET={}", generate_hmac_secret());
            hmac_updated = true;
        }
    } else {
        lines.push(format!("WITNESSCTL_HMAC_SECRET={}", generate_hmac_secret()));
        hmac_updated = true;
    }
    if !lines.iter().any(|l| l.starts_with("WITNESSCTL_PORT=")) {
        lines.push("WITNESSCTL_PORT=7443".to_string());
    }
    if !lines.iter().any(|l| l.starts_with("CONNECTOR_BASE_URL=")) {
        lines.push("CONNECTOR_BASE_URL=http://localhost:9735".to_string());
    }
    let connector_api_key = lines
        .iter()
        .find(|l| l.starts_with("CONNECTOR_API_KEY="))
        .and_then(|l| l.split_once('=').map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| "replace_with_connector_api_key".to_string());
    if !lines.iter().any(|l| l.starts_with("CONNECTOR_API_KEY=")) {
        lines.push(format!("CONNECTOR_API_KEY={}", connector_api_key));
    }
    if !lines.iter().any(|l| l.starts_with("CONNECTOR_KEY=")) {
        lines.push(format!("CONNECTOR_KEY={}", connector_api_key));
    }
    if !lines.iter().any(|l| l.starts_with("WITNESSCTL_REQUESTED_AGENTS=")) {
        lines.push("WITNESSCTL_REQUESTED_AGENTS=1".to_string());
    }
    // Respect environment variable if set, otherwise add default
    if let Ok(env_db_url) = std::env::var("WITNESSCTL_DATABASE_URL") {
        if !lines.iter().any(|l| l.starts_with("WITNESSCTL_DATABASE_URL=")) {
            lines.push(format!("WITNESSCTL_DATABASE_URL={}", env_db_url));
        }
    } else if !lines.iter().any(|l| l.starts_with("WITNESSCTL_DATABASE_URL="))
        && !lines.iter().any(|l| l.starts_with("DATABASE_URL="))
    {
        lines.push("WITNESSCTL_DATABASE_URL=postgres://postgres:postgres@localhost:5432/witnessctl".to_string());
    }

    std::fs::write(env_path, format!("{}\n", lines.join("\n")))?;
    println!("WitnessCtl setup complete: wrote/updated .env");
    if hmac_updated {
        println!("Generated secure WITNESSCTL_HMAC_SECRET");
    }
    Ok(())
}

async fn run_doctor() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let database_url = std::env::var("WITNESSCTL_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_default();
    let connector_base_url = std::env::var("CONNECTOR_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:9735".to_string());
    let connector_api_key = std::env::var("CONNECTOR_API_KEY")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            std::env::var("CONNECTOR_KEY")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .unwrap_or_else(|| "replace_with_connector_api_key".to_string());
    let hmac_secret = std::env::var("WITNESSCTL_HMAC_SECRET")
        .unwrap_or_else(|_| "change-me-in-production".to_string());

    let mut ok = true;
    if database_url.trim().is_empty() {
        ok = false;
        println!("FAIL db: missing WITNESSCTL_DATABASE_URL/DATABASE_URL");
    } else {
        match PgPoolOptions::new().max_connections(1).connect(&database_url).await {
            Ok(pool) => {
                let db_ok = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(1) FROM information_schema.tables WHERE table_name = 'witness_sessions'"
                )
                .fetch_one(&pool)
                .await
                .map(|v| v > 0)
                .unwrap_or(false);
                if db_ok {
                    println!("PASS db: reachable and migrations detected");
                } else {
                    ok = false;
                    println!("FAIL db: reachable but witness migrations missing");
                }
            }
            Err(e) => {
                ok = false;
                println!("FAIL db: {}", e);
            }
        }
    }

    if hmac_secret == "change-me-in-production" || hmac_secret.trim().is_empty() {
        ok = false;
        println!("FAIL hmac: insecure or missing WITNESSCTL_HMAC_SECRET");
    } else {
        println!("PASS hmac: non-default secret configured");
    }

    let connector_key_missing = connector_api_key.trim().is_empty()
        || connector_api_key.trim().eq_ignore_ascii_case("replace_with_connector_api_key");
    if connector_key_missing {
        ok = false;
        println!("FAIL connector: CONNECTOR_API_KEY missing/placeholder");
    } else {
        let connector = ConnectorClient::new(&connector_base_url, &connector_api_key);
        match connector.validate_access_key().await {
            Ok(_) => println!("PASS connector: key validated"),
            Err(e) => {
                ok = false;
                println!("FAIL connector: {}", e);
            }
        }
    }

    if ok {
        println!("Doctor result: PASS");
        return Ok(());
    }
    anyhow::bail!("Doctor result: FAIL")
}

async fn resolve_unlock_summary(
    config: &Config,
    connector: &ConnectorClient,
) -> anyhow::Result<serde_json::Value> {
    let requested_agents = config.requested_agents;
    if !config.connector_api_key_present {
        if requested_agents <= 3 {
            return Ok(json!({
                "unlock_mode": "dev_bypass",
                "requested_agents": requested_agents,
                "license_tier": "dev",
                "max_agents": 3,
                "current_agents": null,
                "connector_status": "key_missing_local_mode"
            }));
        }
        return Err(anyhow::anyhow!(
            "CONNECTOR_API_KEY/CONNECTOR_KEY is required when WITNESSCTL_REQUESTED_AGENTS > 3"
        ));
    }

    let connector_ready = connector.validate_access_key().await;
    if let Err(err) = connector_ready {
        if requested_agents <= 3 {
            tracing::warn!(
                "Connector validation failed ({}); continuing in local mode because requested_agents <= 3",
                err
            );
            return Ok(json!({
                "unlock_mode": "dev_bypass",
                "requested_agents": requested_agents,
                "license_tier": "dev",
                "max_agents": 3,
                "current_agents": null,
                "connector_status": "unreachable_local_mode"
            }));
        }
        return Err(anyhow::anyhow!(
            "Connector unreachable and WITNESSCTL_REQUESTED_AGENTS={} requires Connector license checks: {}",
            requested_agents,
            err
        ));
    }
    let license = connector
        .get_license_status()
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    if requested_agents > 3 {
        let max = license
            .max_agents
            .ok_or_else(|| anyhow::anyhow!("Connector license max_agents unavailable"))?;
        if requested_agents > max {
            return Err(anyhow::anyhow!(
                "Requested agents ({}) exceeds license max_agents ({})",
                requested_agents,
                max
            ));
        }
    }

    Ok(json!({
        "unlock_mode": "connector_key",
        "requested_agents": requested_agents,
        "license_tier": license.tier,
        "max_agents": license.max_agents,
        "current_agents": license.current_agents,
        "connector_status": "healthy",
    }))
}

async fn ensure_db_exists(database_url: &str) -> anyhow::Result<()> {
    use sqlx::postgres::{PgConnectOptions, PgSslMode};
    use std::str::FromStr;

    let ssl_mode = std::env::var("WITNESSCTL_SSL_MODE")
        .ok()
        .and_then(|v| match v.to_ascii_lowercase().as_str() {
            "require" => Some(PgSslMode::Require),
            "prefer"  => Some(PgSslMode::Prefer),
            _         => Some(PgSslMode::Disable),
        })
        .unwrap_or(PgSslMode::Disable);

    let probe_opts = PgConnectOptions::from_str(database_url)
        .map(|o| o.ssl_mode(ssl_mode))
        .map_err(|e| anyhow::anyhow!("Invalid DATABASE_URL: {}", e))?;

    if PgPoolOptions::new()
        .max_connections(1)
        .connect_with(probe_opts)
        .await
        .is_ok()
    {
        return Ok(());
    }

    let url = reqwest::Url::parse(database_url)
        .map_err(|e| anyhow::anyhow!("Invalid DATABASE_URL: {}", e))?;
    let db_name = url.path().trim_start_matches('/').to_string();
    if db_name.is_empty() {
        return Ok(());
    }
    let mut admin_url = url.clone();
    admin_url.set_path("/postgres");

    let admin_opts = PgConnectOptions::from_str(admin_url.as_ref())
        .map(|o| o.ssl_mode(ssl_mode))
        .map_err(|e| anyhow::anyhow!("Invalid admin DB URL: {}", e))?;

    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(admin_opts)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to postgres maintenance DB: {}", e))?;

    let create_stmt = format!("CREATE DATABASE \"{}\"", db_name.replace('"', ""));
    match sqlx::query(&create_stmt).execute(&admin_pool).await {
        Ok(_) => {
            info!("Created database {}", db_name);
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            if msg.contains("already exists") {
                Ok(())
            } else {
                Err(anyhow::anyhow!("Failed to create database {}: {}", db_name, e))
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    connector_plugin_handshake::apply_from_env().map_err(|e| anyhow::anyhow!("{e}"))?;

    let _ = run_setup();
    let args: Vec<String> = std::env::args().collect();
    if let Some(cmd) = args.get(1) {
        match cmd.as_str() {
            "session" => return run_cli_session(&args).await,
            "export" => return run_cli_export(&args).await,
            "verify" => return run_cli_verify(&args).await,
            "verify-bundle" => return run_cli_verify_bundle(&args),
            "compliance-map" => return run_cli_compliance_map(&args),
            "watch" => {
                anyhow::bail!(
                    "witnessctl watch was removed with the terminal UI. Inspect the session via the HTTP API or database."
                );
            }
            "cage" => {
                let sub = args.get(2).map(|s| s.as_str()).unwrap_or("");
                if sub != "start" {
                    anyhow::bail!("Usage: witnessctl cage start [--route-profile <standard|vps-prod>] [--route-allowlist host1,host2]");
                }
                std::env::set_var("WITNESSCTL_CAGE_MODE", "1");
                if let Some(v) = flag_value(&args, "--route-profile") {
                    std::env::set_var("WITNESSCTL_ROUTE_PROFILE", v);
                }
                if let Some(v) = flag_value(&args, "--route-allowlist") {
                    std::env::set_var("WITNESSCTL_ROUTE_ALLOWLIST", v);
                }
            }
            "setup" => return run_setup(),
            "doctor" => return run_doctor().await,
            "tui" => {
                anyhow::bail!(
                    "The terminal UI was removed. Use the WitnessCtl HTTP API (this process listens on WITNESSCTL_PORT) or a future web console."
                );
            }
            _ => {}
        }
    }

    let config = Config::from_env()?;
    config.validate_license_tier()?;
    if !config.hmac_secret_secure() {
        let prodish = std::env::var("CONNECTOR_ENV")
            .or_else(|_| std::env::var("WITNESSCTL_ENV"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let require = matches!(
            prodish.as_str(),
            "production" | "prod" | "staging" | "pilots" | "pilot"
        ) || std::env::var("WITNESSCTL_REQUIRE_SECURE_HMAC")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        if require {
            anyhow::bail!(
                "WITNESSCTL_HMAC_SECRET is missing or still the lab default; refusing to start under production-like env. \
                 Set a strong secret (≥32 chars, not change-me-in-production)."
            );
        }
        warn!("WitnessCtl: WITNESSCTL_HMAC_SECRET is insecure/default; running in degraded local mode");
    }

    let env_filter = tracing_subscriber::EnvFilter::try_new(config.log_level.clone())
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("witnessctl=info"));
    match resolve_log_format() {
        "json" => {
            let subscriber = tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .with_target(false)
                .with_thread_ids(true)
                .with_line_number(true)
                .finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        _ => {
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_target(false)
                .with_thread_ids(true)
                .with_line_number(true)
                .finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
    }

    info!("WitnessCtl starting...");
    if !config.connector_base_url_explicit {
        warn!("WitnessCtl: CONNECTOR_BASE_URL not configured — compliance enforcement may be degraded");
    }
    info!("Connecting to database...");

    // Auto-create the database if it doesn't exist (e.g. fresh Fly Postgres).
    if let Err(e) = ensure_db_exists(&config.database_url).await {
        warn!("ensure_db_exists: {} — continuing", e);
    }

    let db = {
        use sqlx::postgres::{PgConnectOptions, PgSslMode};
        use std::str::FromStr;
        // Fly Postgres (internal 6PN) is plain TCP — disable TLS to avoid
        // the "unexpected end of file" error from a failed SSL negotiation.
        // If DATABASE_URL already contains sslmode=require this override will
        // be the safer direction; adjust WITNESSCTL_SSL_MODE if needed.
        let ssl_mode = std::env::var("WITNESSCTL_SSL_MODE")
            .ok()
            .and_then(|v| match v.to_ascii_lowercase().as_str() {
                "require" => Some(PgSslMode::Require),
                "prefer"  => Some(PgSslMode::Prefer),
                "disable" => Some(PgSslMode::Disable),
                _ => None,
            })
            .unwrap_or(PgSslMode::Disable);
        let opts = PgConnectOptions::from_str(&config.database_url)
            .map(|o| o.ssl_mode(ssl_mode))
            .unwrap_or_else(|_| PgConnectOptions::from_str(&config.database_url).expect("invalid DATABASE_URL"));
        PgPoolOptions::new()
            .max_connections(20)
            .connect_with(opts)
            .await?
    };

    let keep_records = witnessctl::reset::keep_records(
        std::env::var("WITNESSCTL_KEEP_RECORDS").ok().as_deref(),
        std::env::var("CONNECTOR_KEEP_RECORDS").ok().as_deref(),
    );
    let auto_migrate = !keep_records
        || env_truthy("WITNESSCTL_AUTO_MIGRATE")
        || std::env::var("WITNESSCTL_MIGRATIONS_DIR").is_ok()
        || std::env::var("CONNECTOR_PRESET").map(|v| v == "playground").unwrap_or(false);
    if auto_migrate {
        info!("Applying WitnessCtl migrations (auto-migrate enabled)");
        WITNESSCTL_MIGRATOR.run(&db).await?;
    }
    assert_startup_migrations_applied(&db).await?;
    if keep_records {
        info!("WITNESSCTL_KEEP_RECORDS is set — WitnessCtl rows survive this restart");
    } else {
        witnessctl::reset::clear_public_tables(&db).await?;
        info!("WitnessCtl restart cleared database rows");
    }
    info!("Database migration preflight passed");

    let connector = ConnectorClient::new(&config.connector_base_url, &config.connector_api_key);
    let unlock_summary = resolve_unlock_summary(&config, &connector).await?;
    info!(
        "WitnessCtl unlock resolved: mode={}, connector_status={}, requested_agents={}, max_agents={:?}",
        unlock_summary.get("unlock_mode").and_then(|v| v.as_str()).unwrap_or("unknown"),
        unlock_summary.get("connector_status").and_then(|v| v.as_str()).unwrap_or("unknown"),
        unlock_summary.get("requested_agents").and_then(|v| v.as_u64()).unwrap_or(0),
        unlock_summary.get("max_agents"),
    );

    let sessions = SessionManager::new(db.clone(), connector.clone(), &config);
    let capture = CaptureEngine::new(db.clone(), connector.clone(), &config);
    let compliance = ComplianceEngine::new(db.clone(), connector.clone(), &config);
    let proxy_engine = ProxyEngine::new(db.clone());
    let export_engine = ExportEngine::new(db.clone(), &config);
    let webhook_engine = WebhookEngine::new(
        db.clone(),
        config.webhook_urls.clone(),
        config.webhook_bearer.clone(),
    );
    webhook_engine.start_worker();
    let replicas = std::env::var("WITNESSCTL_CUSTODY_REPLICAS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    custody::start_worker(db.clone(), replicas);
    if config.cage_mode {
        watchdog::start_proxy_watchdog(
            db.clone(),
            config.route_profile.clone(),
            config.watchdog_interval_secs,
        );
        info!(
            "WitnessCtl cage mode active: profile={}, route_allowlist={:?}",
            config.route_profile, config.route_allowlist
        );
    }

    let state = Arc::new(routes::AppState {
        db: db.clone(),
        config: config.clone(),
        connector,
        sessions,
        capture,
        compliance,
        proxy_engine,
        export_engine,
        webhook: webhook_engine,
        export_rate_limit: Mutex::new(HashMap::new()),
        proxy_rate_limit: Mutex::new(HashMap::new()),
        unlock_summary,
        connector_unlock_cache: Mutex::new(None),
    });

    let app = routes::create_router(state);
    let addr = format!("0.0.0.0:{}", config.port);

    info!("WitnessCtl listening on {}", addr);

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
