//! TraceTramp - Runtime proxy and execution control plane for AI agents
//! 
//! A Connector plugin providing:
//! - Data Plane (:9741): API Gateway — **Control** pipeline by default (meter + filter + quarantine + traces);
//!   optional **View** passthrough when `TRACETRAMP_ALLOW_VIEW_PIPELINE=1`
//! - Management Plane (:9742): Admin, Tenants, Providers, Approvals

#![allow(dependency_on_unit_never_type_fallback)]

use tracing::{info, error, warn};
use std::net::{SocketAddr, TcpListener};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

mod cage;
mod tenancy;
mod config;
mod types;
mod connector;
mod gateway;
mod resolver;
mod view;
mod control;
mod evidence;
mod admin;
mod storage;
mod auth;
mod error;
mod tools;
mod providers;
mod workflows;
mod functions;
mod decision;
mod decision_envelope;
mod trace_projection;
mod pii;

use config::Config;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    connector_plugin_handshake::apply_from_env().map_err(|e| anyhow::anyhow!("{e}"))?;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "tracetramp=info,tower_http=info".into());
    match resolve_log_format() {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .with_target(true)
                .with_thread_ids(true)
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_target(true)
                .with_thread_ids(true)
                .init();
        }
    }

    info!("Starting TraceTramp v{}", env!("CARGO_PKG_VERSION"));

    let args = std::env::args().collect::<Vec<_>>();
    match args.get(1).map(|s| s.as_str()) {
        Some("doctor") => return run_doctor().await,
        Some("setup") => return run_setup().await,
        Some("start") => return run_start(&args).await,
        Some("stop") => return run_stop().await,
        Some("status") => return run_status().await,
        Some("tui") => {
            anyhow::bail!(
                "The terminal UI was removed. Use the management HTTP API (e.g. GET /admin/traces, /admin/approvals) on the management plane port."
            );
        }
        Some("serve") => return run_server().await,
        _ => {}
    }

    run_start(&args).await
}

async fn run_server() -> anyhow::Result<()> {
    write_env_if_missing()?;
    let jwt_generated = ensure_jwt_secret()?;
    let config = Config::from_env()?;
    config.validate_license_tier()?;
    info!("Configuration loaded: data_plane_port={}, management_plane_port={}", 
        config.data_plane_port, config.management_plane_port);

    if jwt_generated {
        warn!("TraceTramp: generated TRACETRAMP_JWT_SECRET and wrote it to .env for local startup");
    }
    if !config.jwt_secret_present() {
        warn!("TraceTramp: TRACETRAMP_JWT_SECRET still missing; management auth may be degraded");
    }

    if !std::env::var("TRACETRAMP_CONNECTOR_BASE_URL").is_ok() {
        warn!("TraceTramp: TRACETRAMP_CONNECTOR_BASE_URL not configured — using default {}", config.connector_base_url);
    }
    if !config.connector_api_key_present() {
        error!("ERROR: TRACETRAMP_CONNECTOR_API_KEY/CONNECTOR_KEY not set — all Connector calls will fail");
    }

    if let Ok(parsed_url) = reqwest::Url::parse(&config.connector_base_url) {
        if let Some(port) = parsed_url.port_or_known_default() {
            if port == config.data_plane_port {
                return Err(anyhow::anyhow!(
                    "TRACETRAMP_CONNECTOR_BASE_URL points to TraceTramp data plane port {} (self-loop). Refusing to start.",
                    config.data_plane_port
                ));
            }
        }
    }

    ensure_port_available(config.data_plane_port, "data plane")?;
    ensure_port_available(config.management_plane_port, "management plane")?;

    if let Err(e) = ensure_database_exists(&config.database_url).await {
        warn!("ensure_database_exists: {} — continuing (DB may already exist)", e);
    }
    let db_pool = storage::init_postgres(&config.database_url).await?;
    info!("PostgreSQL connection pool initialized");

    let mut redis_pool = storage::init_redis_optional(config.redis_url.as_deref()).await?;
    if redis_pool.is_some() {
        info!("Redis connection pool initialized");
    }
    storage::reset_on_restart(&db_pool, redis_pool.as_mut()).await?;

    let connector_client = connector::ConnectorClient::new(
        &config.connector_base_url,
        &config.connector_api_key,
    );
    info!("Connector client initialized: base_url={}", config.connector_base_url);

    let state = AppState {
        config: config.clone(),
        db_pool,
        redis_pool,
        connector_client,
        active_calls: Arc::new(AtomicUsize::new(0)),
    };

    let data_plane_addr: SocketAddr = ([0, 0, 0, 0], config.data_plane_port).into();
    let data_app = gateway::create_router(state.clone());
    
    let management_addr: SocketAddr = ([0, 0, 0, 0], config.management_plane_port).into();
    let management_app = admin::create_router(state.clone());

    // Expire pending HITL approvals past TTL (default set on enqueue).
    {
        let pool = state.db_pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                match admin::expire_pending_approvals(&pool).await {
                    Ok(n) if n > 0 => info!(expired = n, "[approval_ttl] expired pending approvals"),
                    Ok(_) => {}
                    Err(e) => warn!(error = %e, "[approval_ttl] sweep failed"),
                }
            }
        });
    }

    info!("Data plane listening on {}", data_plane_addr);
    info!("Management plane listening on {}", management_addr);

    let data_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(data_plane_addr).await.unwrap();
        axum::serve(listener, data_app).await.unwrap();
    });

    let management_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(management_addr).await.unwrap();
        axum::serve(listener, management_app).await.unwrap();
    });

    tokio::try_join!(data_handle, management_handle)?;

    Ok(())
}

async fn run_start(args: &[String]) -> anyhow::Result<()> {
    println!("TraceTramp Start\n");
    let mut summary = Vec::new();
    run_setup().await?;
    summary.push(("setup", "ok".to_string()));
    let config = Config::from_env()?;
    let local_api_key = ensure_local_cage_api_key()?;
    ensure_workflow_runtime_ready(&config.database_url).await?;
    println!("✓ workflow runtime tables: ready");
    summary.push(("workflow", "ok".to_string()));

    if config.connector_api_key_present() {
        match wait_for_connector_health(&config, 30).await {
            Ok(_) => {
                println!("✓ connector: healthy (startup gate)");
                summary.push(("connector", "healthy".to_string()));
            }
            Err(e) => {
                println!("⚠ connector: degraded at startup ({}) — continuing in local mode", e);
                summary.push(("connector", "degraded_local_mode".to_string()));
            }
        }
    } else {
        println!("⚠ connector: api key missing, startup gate skipped");
        summary.push(("connector", "skipped_no_key".to_string()));
    }

    if has_flag(args, "--foreground") {
        println!("Starting TraceTramp server in foreground...");
        print_start_summary(&summary);
        return run_server().await;
    }

    let pid = spawn_server_background()?;
    write_pid_file(pid)?;
    println!("✓ TraceTramp server started in background (pid={})", pid);
    summary.push(("server", format!("background_pid={}", pid)));
    println!(
        "Live endpoints: data=http://127.0.0.1:{} management=http://127.0.0.1:{}",
        config.data_plane_port, config.management_plane_port
    );
    print_credential_box(&config, &local_api_key);
    print_start_summary(&summary);
    println!("Use `tracetramp status` for lifecycle health. Use `tracetramp stop` to stop.");
    Ok(())
}

async fn run_status() -> anyhow::Result<()> {
    println!("TraceTramp Status\n");
    let pid = read_pid_file();
    match pid {
        Some(pid) if process_alive(pid) => println!("✓ server: running (pid={})", pid),
        Some(pid) => println!("✗ server: stale pid file (pid={} not alive)", pid),
        None => println!("✗ server: not running (pid file missing)"),
    }

    let config = Config::from_env()?;
    let connector_client = connector::ConnectorClient::new(
        &config.connector_base_url,
        &config.connector_api_key,
    );
    let connector_ok = config.connector_api_key_present() && connector_client.health_check().await.is_ok();
    println!(
        "{} connector: {}",
        if connector_ok { "✓" } else { "⚠" },
        if connector_ok { "healthy" } else { "degraded_or_unauthed" }
    );
    println!(
        "endpoints: data=http://127.0.0.1:{} management=http://127.0.0.1:{}",
        config.data_plane_port, config.management_plane_port
    );
    Ok(())
}

async fn run_stop() -> anyhow::Result<()> {
    println!("TraceTramp Stop\n");
    let Some(pid) = read_pid_file() else {
        println!("No pid file found. Nothing to stop.");
        return Ok(());
    };
    if !process_alive(pid) {
        remove_pid_file();
        println!("Removed stale pid file for pid={}", pid);
        return Ok(());
    }
    let status = Command::new("kill")
        .arg(pid.to_string())
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to stop process {}: {}", pid, e))?;
    if !status.success() {
        return Err(anyhow::anyhow!("Failed to stop process {}", pid));
    }
    remove_pid_file();
    println!("✓ stopped TraceTramp server (pid={})", pid);
    Ok(())
}

async fn run_doctor() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    println!("TraceTramp Doctor\n");

    let mut failures = 0usize;
    let mut warnings = 0usize;

    match sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            let db_ok = sqlx::query("SELECT 1").fetch_one(&pool).await.is_ok();
            if db_ok {
                println!("✓ database: connected");
            } else {
                failures += 1;
                println!("✗ database: connected but query failed");
            }
        }
        Err(e) => {
            failures += 1;
            println!("✗ database: {}", e);
        }
    }

    if config.redis_enabled() {
        match redis::Client::open(config.redis_url.as_deref().unwrap_or("redis://localhost:6379")) {
            Ok(client) => match client.get_multiplexed_tokio_connection().await {
                Ok(mut conn) => {
                    let ping: Result<String, _> = redis::cmd("PING").query_async(&mut conn).await;
                    if ping.is_ok() {
                        println!("✓ redis: connected");
                    } else {
                        println!("⚠ redis: ping failed (start without TRACETRAMP_REDIS_URL for postgres-only)");
                    }
                }
                Err(e) => {
                    println!("⚠ redis: {} (optional — unset TRACETRAMP_REDIS_URL for postgres-only)", e);
                }
            },
            Err(e) => {
                println!("⚠ redis: {} (optional — unset TRACETRAMP_REDIS_URL for postgres-only)", e);
            }
        }
    } else {
        println!("○ redis: disabled (PostgreSQL approval_queue)");
    }

    let connector_client = connector::ConnectorClient::new(
        &config.connector_base_url,
        &config.connector_api_key,
    );
    if config.connector_api_key_present() {
        match connector_client.health_check().await {
            Ok(_) => println!("✓ connector: reachable ({})", config.connector_base_url),
            Err(e) => {
                failures += 1;
                println!("✗ connector: {}", e);
            }
        }
    } else {
        failures += 1;
        println!("✗ connector: TRACETRAMP_CONNECTOR_API_KEY/CONNECTOR_KEY missing or placeholder");
    }

    if config.jwt_secret_present() {
        println!("✓ jwt: TRACETRAMP_JWT_SECRET configured");
    } else {
        failures += 1;
        println!("✗ jwt: TRACETRAMP_JWT_SECRET missing");
    }
    let admin_token_present = std::env::var("TRACETRAMP_ADMIN_TOKEN")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let dev_bypass = std::env::var("TRACETRAMP_DEV_BYPASS").ok().as_deref() == Some("1");
    let allow_insecure = std::env::var("TRACETRAMP_ALLOW_INSECURE_ADMIN").ok().as_deref() == Some("1");
    if admin_token_present || (dev_bypass && allow_insecure) {
        println!(
            "✓ auth-mode: {}",
            if admin_token_present { "admin token configured" } else { "dev bypass enabled (explicitly insecure)" }
        );
    } else if dev_bypass && !allow_insecure {
        failures += 1;
        println!("✗ auth-mode: TRACETRAMP_DEV_BYPASS=1 ignored unless TRACETRAMP_ALLOW_INSECURE_ADMIN=1");
    } else {
        warnings += 1;
        println!("⚠ auth-mode: no TRACETRAMP_ADMIN_TOKEN; JWT admin role auth required");
    }

    // Migrations + runtime tables check
    match sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            let mig_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(1) FROM _sqlx_migrations")
                .fetch_one(&pool)
                .await;
            match mig_count {
                Ok(c) if c > 0 => println!("✓ migrations: {} applied", c),
                Ok(_) => {
                    failures += 1;
                    println!("✗ migrations: _sqlx_migrations empty");
                }
                Err(e) => {
                    failures += 1;
                    println!("✗ migrations: {}", e);
                }
            }
            let workflows_ok = sqlx::query("SELECT 1 FROM workflows LIMIT 1")
                .fetch_optional(&pool)
                .await
                .is_ok()
                && sqlx::query("SELECT 1 FROM workflow_runs LIMIT 1")
                    .fetch_optional(&pool)
                    .await
                    .is_ok();
            if workflows_ok {
                println!("✓ workflow runtime: workflows + workflow_runs available");
            } else {
                failures += 1;
                println!("✗ workflow runtime: workflows/workflow_runs table check failed");
            }

            match storage::TRACETRAMP_MIGRATOR.run(&pool).await {
                Ok(()) => println!("✓ migrations: embedded sources match applied rows"),
                Err(sqlx::migrate::MigrateError::VersionMismatch(v)) => {
                    warnings += 1;
                    println!(
                        "⚠ migrations: checksum drift on applied version {} (file changed after apply).",
                        v
                    );
                    println!(
                        "    DEV ONLY: set TRACETRAMP_ALLOW_MIGRATION_CHECKSUM_REPAIR=1, run `tracetramp serve` once to repair _sqlx_migrations, then unset the variable."
                    );
                }
                Err(e) => {
                    warnings += 1;
                    println!("⚠ migrations: reconcile check: {}", e);
                }
            }
        }
        Err(e) => {
            failures += 1;
            println!("✗ migrations/workflow runtime: {}", e);
        }
    }

    match check_port_conflict(config.data_plane_port) {
        Ok(_) => println!("✓ data-plane port {}: available", config.data_plane_port),
        Err(e) => {
            failures += 1;
            println!("✗ data-plane port {}: {}", config.data_plane_port, e);
        }
    }
    match check_port_conflict(config.management_plane_port) {
        Ok(_) => println!("✓ management-plane port {}: available", config.management_plane_port),
        Err(e) => {
            failures += 1;
            println!("✗ management-plane port {}: {}", config.management_plane_port, e);
        }
    }

    // Probe live auth + cage route if data plane is running.
    let client = reqwest::Client::new();
    let mgmt_url = format!("http://127.0.0.1:{}/api/v1/approvals", config.management_plane_port);
    match client.get(&mgmt_url).send().await {
        Ok(resp) => {
            if resp.status().as_u16() == 401 || resp.status().as_u16() == 403 {
                println!("✓ management auth: unauthenticated request blocked ({})", resp.status());
            } else {
                failures += 1;
                println!("✗ management auth: unauthenticated request not blocked ({})", resp.status());
            }
        }
        Err(_) => {
            warnings += 1;
            println!("⚠ management auth probe: management plane not reachable on localhost");
        }
    }
    let cage_probe = format!(
        "http://127.0.0.1:{}/cage/{}/health",
        config.data_plane_port,
        "0".repeat(64)
    );
    match client.get(&cage_probe).send().await {
        Ok(resp) => {
            if resp.status().as_u16() == 404 {
                failures += 1;
                println!("✗ cage route: probe returned 404 (route missing)");
            } else {
                println!("✓ cage route: probe reachable ({})", resp.status());
            }
        }
        Err(_) => {
            warnings += 1;
            println!("⚠ cage route probe: data plane not reachable on localhost");
        }
    }

    println!("\nSummary: {} failure(s), {} warning(s)", failures, warnings);
    if failures > 0 {
        anyhow::bail!("doctor detected failures");
    }
    Ok(())
}

async fn run_setup() -> anyhow::Result<()> {
    println!("TraceTramp Setup\n");
    write_env_if_missing()?;
    if ensure_jwt_secret()? {
        println!("✓ generated TRACETRAMP_JWT_SECRET in .env");
    }

    let config = Config::from_env()?;
    ensure_database_exists(&config.database_url).await?;

    let _db_pool = storage::init_postgres(&config.database_url).await?;
    println!("✓ database: reachable and migrations applied");

    if config.redis_enabled() {
        let _redis = storage::init_redis(config.redis_url.as_deref().unwrap()).await?;
        println!("✓ redis: reachable");
    } else {
        println!("○ redis: skipped (postgres-only mode)");
    }

    let connector_client = connector::ConnectorClient::new(
        &config.connector_base_url,
        &config.connector_api_key,
    );
    if config.connector_api_key_present() {
        match connector_client.health_check().await {
            Ok(_) => println!("✓ connector: reachable ({})", config.connector_base_url),
            Err(e) => println!("⚠ connector: not reachable yet ({})", e),
        }
    } else {
        println!("⚠ connector: TRACETRAMP_CONNECTOR_API_KEY/CONNECTOR_KEY missing (set it in .env)");
    }

    println!("\nSetup complete.");
    println!("Next: cargo run --manifest-path plugins/tracetramp/Cargo.toml");
    Ok(())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn spawn_server_background() -> anyhow::Result<u32> {
    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("Unable to determine tracetramp binary path: {}", e))?;
    let child = Command::new(exe)
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to start TraceTramp server in background: {}", e))?;
    Ok(child.id())
}

fn pid_file_path() -> PathBuf {
    std::env::temp_dir().join("tracetramp.pid")
}

fn write_pid_file(pid: u32) -> anyhow::Result<()> {
    std::fs::write(pid_file_path(), pid.to_string())
        .map_err(|e| anyhow::anyhow!("Failed to write pid file: {}", e))
}

fn read_pid_file() -> Option<u32> {
    let content = std::fs::read_to_string(pid_file_path()).ok()?;
    content.trim().parse::<u32>().ok()
}

fn remove_pid_file() {
    let _ = std::fs::remove_file(pid_file_path());
}

fn process_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

fn print_start_summary(summary: &[(&str, String)]) {
    println!("\nStartup Summary");
    for (k, v) in summary {
        println!("  - {:10} {}", k, v);
    }
    println!();
}

async fn ensure_workflow_runtime_ready(database_url: &str) -> anyhow::Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .map_err(|e| anyhow::anyhow!("Unable to connect for workflow readiness check: {}", e))?;
    sqlx::query("SELECT 1 FROM workflows LIMIT 1")
        .fetch_optional(&pool)
        .await
        .map_err(|e| anyhow::anyhow!("Workflow table check failed: {}", e))?;
    sqlx::query("SELECT 1 FROM workflow_runs LIMIT 1")
        .fetch_optional(&pool)
        .await
        .map_err(|e| anyhow::anyhow!("Workflow runs table check failed: {}", e))?;
    Ok(())
}

async fn wait_for_connector_health(config: &Config, timeout_secs: u64) -> anyhow::Result<()> {
    let connector_client = connector::ConnectorClient::new(
        &config.connector_base_url,
        &config.connector_api_key,
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut attempt = 1u32;
    loop {
        match connector_client.health_check().await {
            Ok(_) => return Ok(()),
            Err(e) => {
                if std::time::Instant::now() >= deadline {
                    return Err(anyhow::anyhow!(
                        "Connector health gate failed after {} attempts: {}",
                        attempt,
                        e
                    ));
                }
                println!("⚠ connector not healthy yet (attempt {}): {}", attempt, e);
                attempt += 1;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

fn write_env_if_missing() -> anyhow::Result<()> {
    let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/tmp"));
    let env_path = base_dir.join(".env");
    if env_path.exists() {
        return Ok(());
    }
    let example = base_dir.join(".env.example");
    if example.exists() {
        if let Err(e) = std::fs::copy(&example, &env_path) {
            warn!("Could not copy .env.example to .env: {e} — continuing with env vars");
        }
    } else {
        let minimal = [
            "TRACETRAMP_DATA_PLANE_PORT=9741",
            "TRACETRAMP_MANAGEMENT_PLANE_PORT=9742",
            "TRACETRAMP_DATABASE_URL=postgres://postgres:postgres@localhost:5432/tracetramp",
            "# TRACETRAMP_REDIS_URL=redis://localhost:6379  # optional; omit for postgres-only",
            "TRACETRAMP_CONNECTOR_BASE_URL=http://localhost:9735",
            "TRACETRAMP_CONNECTOR_API_KEY=replace_with_connector_api_key",
            "CONNECTOR_KEY=replace_with_connector_api_key",
            "TRACETRAMP_JWT_SECRET=",
            "RUST_LOG=tracetramp=info,tower_http=info",
            "",
        ]
        .join("\n");
        if let Err(e) = std::fs::write(&env_path, minimal) {
            warn!("Could not write minimal .env: {e} — continuing with env vars");
        }
    }
    Ok(())
}

fn ensure_jwt_secret() -> anyhow::Result<bool> {
    let existing = std::env::var("TRACETRAMP_JWT_SECRET").unwrap_or_default();
    if !existing.trim().is_empty() {
        return Ok(false);
    }

    let secret = format!("tt_{}_{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/tmp"));
    let env_path = base_dir.join(".env");
    if let Err(e) = upsert_env_var(&env_path, "TRACETRAMP_JWT_SECRET", &secret) {
        warn!("Could not persist TRACETRAMP_JWT_SECRET to .env: {e} — using in-process value only");
    }
    #[allow(unused_unsafe)]
    unsafe { std::env::set_var("TRACETRAMP_JWT_SECRET", &secret); }
    Ok(true)
}

fn upsert_env_var(env_path: &Path, key: &str, value: &str) -> anyhow::Result<()> {
    let mut lines = if env_path.exists() {
        fs::read_to_string(env_path)?
            .lines()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let target = format!("{key}=");
    let mut replaced = false;
    for line in &mut lines {
        if line.starts_with(&target) {
            *line = format!("{key}={value}");
            replaced = true;
            break;
        }
    }
    if !replaced {
        lines.push(format!("{key}={value}"));
    }
    fs::write(env_path, format!("{}\n", lines.join("\n")))?;
    Ok(())
}

fn ensure_local_cage_api_key() -> anyhow::Result<String> {
    let existing = std::env::var("TRACETRAMP_LOCAL_API_KEY").unwrap_or_default();
    if !existing.trim().is_empty() {
        return Ok(existing.trim().to_string());
    }
    let generated = format!("cpk_live_{}", uuid::Uuid::new_v4().simple());
    let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/tmp"));
    let env_path = base_dir.join(".env");
    if let Err(e) = upsert_env_var(&env_path, "TRACETRAMP_LOCAL_API_KEY", &generated) {
        warn!("Could not persist TRACETRAMP_LOCAL_API_KEY to .env: {e} — using in-process value only");
    }
    #[allow(unused_unsafe)]
    unsafe { std::env::set_var("TRACETRAMP_LOCAL_API_KEY", &generated); }
    Ok(generated)
}

fn print_credential_box(config: &Config, api_key: &str) {
    let cage_addr = &sha256::digest(api_key)[..16];
    println!("\n==============================================================");
    println!("TraceTramp Local Credential Box");
    println!("API Key:     {}", api_key);
    println!("Cage URL:    http://127.0.0.1:{}/cage/{}", config.data_plane_port, cage_addr);
    println!("Data Plane:  http://127.0.0.1:{}", config.data_plane_port);
    println!("Management:  http://127.0.0.1:{}", config.management_plane_port);
    println!("Export for SDKs:");
    println!("  OPENAI_BASE_URL=http://127.0.0.1:{}", config.data_plane_port);
    println!("  OPENAI_API_KEY={}", api_key);
    println!("==============================================================\n");
}

async fn ensure_database_exists(database_url: &str) -> anyhow::Result<()> {
    use sqlx::postgres::{PgConnectOptions, PgSslMode};
    use std::str::FromStr;

    let ssl_mode = std::env::var("TRACETRAMP_SSL_MODE")
        .ok()
        .and_then(|v| match v.to_ascii_lowercase().as_str() {
            "require" => Some(PgSslMode::Require),
            "prefer"  => Some(PgSslMode::Prefer),
            _         => Some(PgSslMode::Disable),
        })
        .unwrap_or(PgSslMode::Disable);

    let probe_opts = PgConnectOptions::from_str(database_url)
        .map(|o| o.ssl_mode(ssl_mode))
        .map_err(|e| anyhow::anyhow!("Invalid TRACETRAMP_DATABASE_URL: {}", e))?;

    if sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(probe_opts)
        .await
        .is_ok()
    {
        return Ok(());
    }

    let url = reqwest::Url::parse(database_url)
        .map_err(|e| anyhow::anyhow!("Invalid TRACETRAMP_DATABASE_URL: {}", e))?;
    let db_name = url.path().trim_start_matches('/').to_string();
    if db_name.is_empty() {
        return Ok(());
    }
    let mut admin_url = url.clone();
    admin_url.set_path("/postgres");

    let admin_opts = PgConnectOptions::from_str(admin_url.as_ref())
        .map(|o| o.ssl_mode(ssl_mode))
        .map_err(|e| anyhow::anyhow!("Invalid admin DB URL: {}", e))?;

    let admin_pool = sqlx::postgres::PgPoolOptions::new()
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

fn ensure_port_available(port: u16, label: &str) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    match TcpListener::bind(&addr) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!(
            "Port conflict detected for {} on {}: {}",
            label,
            addr,
            e
        )),
    }
}

fn check_port_conflict(port: u16) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    match TcpListener::bind(&addr) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("{}", e)),
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db_pool: sqlx::PgPool,
    pub redis_pool: Option<redis::aio::ConnectionManager>,
    pub connector_client: connector::ConnectorClient,
    pub active_calls: Arc<AtomicUsize>,
}
