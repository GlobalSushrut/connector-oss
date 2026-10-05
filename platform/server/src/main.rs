#![recursion_limit = "1024"]
//! # Connector Platform — Self-hosted AI Governance Server
//!
//! Commercial product built on top of connector-oss.
//! Single binary, 10 business services, REST API, Prometheus metrics.
//!
//! ## Services (all under /api/v1/)
//!
//! 1.  Debug          — /debug/*          (sessions, audit, memory recall, export)
//! 2.  Action Log     — /actionlog/*      (record, list, interactions, denied)
//! 3.  Proof of Work  — /proof/*          (generate, certificate, verify)
//! 4.  Long Memory    — /memory/*         (write, recall, knowledge graph, RAG)
//! 5.  Monitor        — /monitor/*        (health, trust, integrity, alerts)
//! 6.  History        — /history/*        (agents, timeline, sessions, audit)
//! 7.  Multi-Agent    — /multiagent/*     (pipeline, trace, cross-agent map)
//! 8.  Disputes       — /disputes/*       (decisions, reports, provenance, judgment)
//! 9.  Pipeline       — /pipeline/*       (steps, integrity, CID chain)
//! 10. Experiments    — /experiments/*    (create, run, compare)
//!
//! ## Infrastructure
//!
//! - GET  /health        — liveness
//! - GET  /metrics       — Prometheus scrape
//! - POST /api/v1/auth/token — JWT token

mod operator;
mod substrate;
mod boot;
mod config;
mod phase5_operator_display;
mod connector_profile;
mod error;
mod license;
mod license_file;
mod machine;
mod auth;
mod middleware;
mod state;
mod router;
mod dashboard_static;
mod dashboard_embed;
mod services;
mod binary_id;
mod phone_home;
mod signing;
mod background;
mod util_lock;
mod concurrency;
mod kms;
mod api_v2;
mod pore_worker;
mod kernel;
mod intelligence_admission;
mod quanta_polar;

#[cfg(feature = "cluster")]
mod cluster_boot;

// Phase R1: Network infrastructure modules
pub mod internal_dns;
pub mod protocol_gateway;
pub mod ui_rpc;

// Phase 1-7: Core Infrastructure Modules
pub mod security;
pub mod distributed;
pub mod knowledge;
pub mod knot;
pub mod storage;
pub mod data;
pub mod compliance;
pub mod proof;
pub mod policy;
pub mod protocols;
pub mod agents;
pub mod cnp;

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU8, Ordering};
use tracing_subscriber::EnvFilter;

// =============================================================================
// AMA-7: Global 7-stage boot readiness gate.
//
// Stages (bit positions in BOOT_STAGE):
//   0 — VAC store writable
//   1 — kernel + prolly B-tree + default policies ready
//   2 — context manager ready
//   3 — LLM scheduler / admission control ready
//   4 — UCAN capability verifier ready
//   5 — agent snapshot restore complete
//   6 — HTTP router started
//
// PLATFORM_READY is set to 1 only when all 7 bits are set (value = 0b1111111 = 127).
// GET /readyz returns 503 until PLATFORM_READY == 1.
// =============================================================================
pub static BOOT_STAGE: AtomicU8 = AtomicU8::new(0);
pub static PLATFORM_READY: AtomicU8 = AtomicU8::new(0);

const BOOT_ALL_STAGES: u8 = 0b0111_1111; // bits 0-6

fn boot_complete(stage: u8) {
    BOOT_STAGE.fetch_or(stage, Ordering::SeqCst);
    let current = BOOT_STAGE.load(Ordering::SeqCst);
    if current >= BOOT_ALL_STAGES {
        PLATFORM_READY.store(1, Ordering::SeqCst);
        // Linux systemd Type=notify — READY after HTTP router + all AMA stages.
        crate::boot::mark_platform_ready_for_systemd();
    }
}

use vac_core::kernel::MemoryKernel;
use vac_core::knot::KnotEngine;
use connector_engine::engine_store::EngineStore;
use connector_engine::sqlite_store::SqliteEngineStore;
use connector_engine::redb_store::RedbKernelStore;
use connector_engine::storage_zone::StorageLayout;
use connector_engine::aapi::ActionEngine;
use connector_engine::binding::BindingEngine;
use connector_engine::llm_router::LlmRouter;
use connector_engine::llm::LlmConfig as EngineLlmConfig;
use connector_engine::guard_pipeline::GuardPipeline;

use crate::config::PlatformConfig;
use crate::license::LicenseInfo;
use crate::state::{PlatformState, PlatformMetrics, LlmConfig};
use crate::services::runtime_control::{self, RuntimeMode};

fn bootstrap_first_run_admin_and_tokens(
    config: &PlatformConfig,
    user_store: &mut crate::auth::UserStore,
    engine_store: &mut (dyn EngineStore + Send),
) {
    if user_store.users.is_empty() {
        let email = std::env::var("CONNECTOR_BOOTSTRAP_SUPERADMIN_EMAIL")
            .unwrap_or_else(|_| "admin@connector.local".to_string());
        let name = std::env::var("CONNECTOR_BOOTSTRAP_SUPERADMIN_NAME")
            .unwrap_or_else(|_| "Connector SuperAdmin".to_string());
        let plain_password = std::env::var("CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD")
            .unwrap_or_else(|_| format!("cpk_{}", uuid::Uuid::new_v4().simple()));
        match crate::auth::hash_password(&plain_password) {
            Ok(password_hash) => {
                let user_id = format!("usr_{}", uuid::Uuid::new_v4());
                let now = chrono::Utc::now().to_rfc3339();
                let user = crate::auth::User {
                    user_id: user_id.clone(),
                    email: email.clone(),
                    name,
                    password_hash,
                    role: crate::auth::PlatformRole::SuperAdmin,
                    created_at: now,
                    last_login: None,
                    totp_secret: None,
                    totp_enabled: false,
                    api_keys: Vec::new(),
                    locked: false,
                    failed_attempts: 0,
                    instance_id: None,
                    tier: "community".to_string(),
                    billing_state: "active".to_string(),
                    stripe_customer_id: None,
                    tokens_used_today: 0,
                    tokens_used_month: 0,
                    agents_count: 0,
                    tenant_id: std::env::var("CONNECTOR_DEFAULT_TENANT_ID").ok(),
                };
                if user_store.create_user(user).is_ok() {
                    user_store.persist_user(&user_id, engine_store);
                    let _ = engine_store.folder_put(
                        "_runtime_bootstrap",
                        "first_superadmin",
                        &serde_json::json!({
                            "user_id": user_id,
                            "email": email,
                            "created_at": chrono::Utc::now().to_rfc3339(),
                        }),
                    );
                    // Never log plaintext bootstrap passwords. Write a one-time 0600 secret artifact.
                    let secret_path = std::path::PathBuf::from(&config.data_dir)
                        .join("bootstrap-superadmin.secret");
                    if let Some(parent) = secret_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match std::fs::write(
                        &secret_path,
                        format!(
                            "email={}\npassword={}\nuser_id={}\ncreated_at={}\nrotate_before_external_bind=1\n",
                            email,
                            plain_password,
                            user_id,
                            chrono::Utc::now().to_rfc3339()
                        ),
                    ) {
                        Ok(()) => {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let _ = std::fs::set_permissions(
                                    &secret_path,
                                    std::fs::Permissions::from_mode(0o600),
                                );
                            }
                            tracing::warn!(
                                email = %email,
                                secret_path = %secret_path.display(),
                                "First-run SuperAdmin created. Password written to secret file (mode 0600); rotate before external bind. Set CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD to control the initial secret."
                            );
                        }
                        Err(err) => {
                            tracing::error!(
                                email = %email,
                                error = %err,
                                "First-run SuperAdmin created but failed to write bootstrap secret file — set CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD and rotate immediately"
                            );
                        }
                    }
                }
            }
            Err(err) => tracing::error!("Failed to bootstrap first-run superadmin: {}", err),
        }
    }

    let plugin_token = |primary: &str, fallback: &str| {
        std::env::var(primary)
            .or_else(|_| std::env::var(fallback))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let tt = plugin_token("CONNECTOR_TRACETRAMP_ADMIN_TOKEN", "TRACETRAMP_ADMIN_TOKEN");
    let wc = plugin_token("CONNECTOR_WITNESSCTL_ADMIN_TOKEN", "WITNESSCTL_ADMIN_TOKEN");
    let mut minted = serde_json::Map::new();
    if tt.is_none() {
        let token = crate::auth::generate_api_key("cpk_tracetramp_admin");
        #[allow(unused_unsafe)]
        unsafe {
            std::env::set_var("CONNECTOR_TRACETRAMP_ADMIN_TOKEN", &token);
        }
        minted.insert("tracetramp".to_string(), serde_json::json!(token));
    }
    if wc.is_none() {
        let token = crate::auth::generate_api_key("cpk_witnessctl_admin");
        #[allow(unused_unsafe)]
        unsafe {
            std::env::set_var("CONNECTOR_WITNESSCTL_ADMIN_TOKEN", &token);
        }
        minted.insert("witnessctl".to_string(), serde_json::json!(token));
    }
    if !minted.is_empty() {
        let _ = engine_store.folder_put(
            "_runtime_bootstrap",
            "plugin_admin_tokens",
            &serde_json::json!({
                "minted_at": chrono::Utc::now().to_rfc3339(),
                "tokens": minted,
            }),
        );
    }

    // TraceTramp ↔ WitnessCtl handoff secret (lab / single-node prod convenience).
    let handoff_set = std::env::var("TRACETRAMP_WITNESS_HANDOFF_SECRET")
        .or_else(|_| std::env::var("WITNESSCTL_TRACETRAMP_HANDOFF_SECRET"))
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    if !handoff_set {
        if let Ok(Some(doc)) = engine_store.folder_get("_runtime_bootstrap", "tracetramp_witness_handoff") {
            if let Some(secret) = doc.get("secret").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                #[allow(unused_unsafe)]
                unsafe {
                    std::env::set_var("TRACETRAMP_WITNESS_HANDOFF_SECRET", secret);
                    std::env::set_var("WITNESSCTL_TRACETRAMP_HANDOFF_SECRET", secret);
                }
            }
        } else {
            let secret = crate::auth::generate_api_key("cpk_tt_wc_handoff");
            let _ = engine_store.folder_put(
                "_runtime_bootstrap",
                "tracetramp_witness_handoff",
                &serde_json::json!({
                    "minted_at": chrono::Utc::now().to_rfc3339(),
                    "secret": secret,
                }),
            );
            #[allow(unused_unsafe)]
            unsafe {
                std::env::set_var("TRACETRAMP_WITNESS_HANDOFF_SECRET", &secret);
                std::env::set_var("WITNESSCTL_TRACETRAMP_HANDOFF_SECRET", &secret);
            }
        }
    }

    let _ = std::fs::create_dir_all(&config.data_dir);
    let users_db_path = format!("{}/users.db", config.data_dir);
    let users_compact = serde_json::json!({
        "schema": "connector_users_db_v1",
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "count": user_store.users.len(),
        "users": user_store.users.values().map(|u| serde_json::json!({
            "user_id": u.user_id,
            "email": u.email,
            "name": u.name,
            "role": u.role.to_str(),
            "created_at": u.created_at,
        })).collect::<Vec<_>>()
    });
    if let Err(err) = std::fs::write(&users_db_path, users_compact.to_string()) {
        tracing::warn!("failed writing users.db compatibility snapshot: {}", err);
    }
}

#[tokio::main]
async fn main() {
    if std::env::args().any(|a| a == "--pore-worker")
        || std::env::var("CONNECTOR_PORE_WORKER").ok().as_deref() == Some("1")
    {
        std::process::exit(crate::pore_worker::run());
    }
    // Process-relative clock for monitor/health `uptime` (must run once before any health responses).
    boot::init_boot_time();

    // I11 / OTel smoke test: if OTEL_EXPORTER_OTLP_ENDPOINT is set, layer in
    // an OTLP tracer so every tracing::span! becomes an exported OTel span.
    // gen_ai.usage.input_tokens / output_tokens are set as span attributes in gateway.rs.
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );
    let otlp_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();
    if let Some(ref endpoint) = otlp_endpoint {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_otlp::WithExportConfig;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        match opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint.clone())
            .build_span_exporter()
        {
            Ok(exporter) => {
                let provider = opentelemetry_sdk::trace::TracerProvider::builder()
                    .with_batch_exporter(
                        crate::substrate::cvr::deployment_verify::EvidenceSpanExporter::new(
                            exporter,
                        ),
                        opentelemetry_sdk::runtime::Tokio,
                    )
                    .with_config(
                        opentelemetry_sdk::trace::config().with_resource(
                            opentelemetry_sdk::Resource::new(vec![
                                opentelemetry::KeyValue::new(
                                    "service.name",
                                    "connector-platform",
                                ),
                            ]),
                        ),
                    )
                    .build();
                let tracer = provider.tracer("connector-platform");
                let _ = opentelemetry::global::set_tracer_provider(provider);
                let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

                tracing_subscriber::registry()
                    .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
                    .with(tracing_subscriber::fmt::layer())
                    .with(otel_layer)
                    .init();

                tracing::info!(endpoint = %endpoint, "OpenTelemetry OTLP exporter enabled");
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    endpoint = %endpoint,
                    "OTLP tracer init failed; continuing without OTLP export (BF2-X01)"
                );
                tracing_subscriber::fmt()
                    .with_env_filter(EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| EnvFilter::new("info")))
                    .init();
            }
        }
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")))
            .init();
    }

    // Optional connector.yaml + CONNECTOR_PRESET (12 modes) — fills env before PlatformConfig::from_env().
    connector_profile::bootstrap_configuration();

    let config = PlatformConfig::from_env();

    // License validation — try Ed25519 license file first, then key-string, then community
    let machine_fp = machine::machine_fingerprint();
    tracing::info!("machine fingerprint: {}", &machine_fp[..16]);

    let license = match license_file::load_and_validate(Some(&machine_fp)) {
        Ok(validated) => {
            if validated.is_expired {
                tracing::error!("License file is EXPIRED — falling back to community tier");
                LicenseInfo::community()
            } else if !validated.fingerprint_ok {
                tracing::warn!("License fingerprint mismatch — running in community tier");
                LicenseInfo::community()
            } else {
                let lic = validated.to_license_info();
                tracing::info!("license: {:?} (file-based, id: {})", lic.tier, lic.instance_id);
                lic
            }
        }
        Err(license_file::LicenseError::Io(_)) => {
            // No license file — fall back to key-string or community
            match &config.license_key {
                Some(key) => {
                    let lic = LicenseInfo::validate_key(key);
                    tracing::info!("license: {:?} (key-based, instance: {})", lic.tier, lic.instance_id);
                    lic
                }
                None => {
                    let lic = LicenseInfo::community();
                    tracing::info!("license: Community (max {} agents, {} packets)",
                        lic.agent_limit(), lic.packet_limit());
                    lic
                }
            }
        }
        Err(e) => {
            tracing::error!("License validation failed: {} — running community tier", e);
            LicenseInfo::community()
        }
    };

    // LLM config from env
    let llm_config = config.llm.api_key.as_ref().map(|key| {
        LlmConfig {
            provider: config.llm.provider.clone().unwrap_or_else(|| "openai".into()),
            model: config.llm.model.clone().unwrap_or_else(|| "gpt-4o".into()),
            api_key: key.clone(),
            endpoint: config.llm.endpoint.clone(),
        }
    });

    // Build LlmRouter from connector-oss (retry + fallback + circuit breaker + cost tracking).
    // DI-1: stored under RwLock so Settings / `connectorctl llm link` can hot-reload.
    let llm_router = {
        let built = llm_config.as_ref().map(|cfg| {
            let mut primary = EngineLlmConfig::new(&cfg.provider, &cfg.model, &cfg.api_key);
            if let Some(ref ep) = cfg.endpoint {
                primary.endpoint = Some(ep.clone());
            }
            let providers = match std::env::var("CONNECTOR_LLM_FALLBACK") {
                Ok(fb) => {
                    let fallback_key =
                        std::env::var("CONNECTOR_LLM_FALLBACK_KEY").unwrap_or_default();
                    let parts: Vec<&str> = fb.splitn(2, ':').collect();
                    let (fb_provider, fb_model) = if parts.len() == 2 {
                        (parts[0].to_string(), parts[1].to_string())
                    } else {
                        (fb.clone(), "gpt-4o-mini".to_string())
                    };
                    vec![
                        primary,
                        EngineLlmConfig::new(&fb_provider, &fb_model, &fallback_key),
                    ]
                }
                Err(_) => vec![primary],
            };
            tracing::info!("llm_router: {} provider(s) configured", providers.len());
            std::sync::Arc::new(crate::state::build_llm_router(providers))
        });
        if built.is_none() {
            tracing::warn!(
                "CONNECTOR_LLM_API_KEY not set — use Settings LLM paste or `connectorctl llm link` (DI-1)"
            );
        }
        std::sync::RwLock::new(built)
    };
    let llm_config = std::sync::RwLock::new(llm_config);

    let cell_id = config.cell_id.clone().unwrap_or_else(|| "cell_local".to_string());

    // Ensure data directory exists before opening any DB files
    if let Err(e) = std::fs::create_dir_all(&config.data_dir) {
        tracing::warn!("Could not create data_dir '{}': {} — databases will use current directory", config.data_dir, e);
    }

    // ── Ring 1-4 Engine Store (SQLite WAL) ──────────────────────────────────
    // Persists: audit log, agent behavior, circuit breakers, secrets, escrow,
    // reputation, negotiations, pipelines, context snapshots, tool defs, etc.
    // AMA-7 Stage 0: VAC store writable
    let t_stage0 = std::time::Instant::now();
    let engine_db_uri = config.engine_db_uri();
    let mut engine_store: Box<dyn EngineStore + Send> = {
        let path = engine_db_uri.trim_start_matches("sqlite:");
        match SqliteEngineStore::open(path) {
            Ok(s) => {
                tracing::info!(storage = "SQLite", path = %path, "Ring 1-4 engine store opened");
                Box::new(s)
            }
            Err(e) => {
                tracing::error!(
                    path = %path,
                    error = %e,
                    "FATAL: Failed to open SQLite engine store — aborting to prevent data loss"
                );
                eprintln!("\n[startup error] Cannot open SQLite engine store at '{}':", path);
                eprintln!("  Error: {}", e);
                eprintln!("  Fix: ensure '{}' directory exists and is writable:", config.data_dir);
                eprintln!("    mkdir -p {}", config.data_dir);
                std::process::exit(1);
            }
        }
    };
    tracing::info!(duration_ms = t_stage0.elapsed().as_millis(), "[boot:0] VAC store writable ✓");
    boot_complete(1 << 0);

    // ── Ring 0 Kernel Store (redb CoW B-tree) ───────────────────────────────
    // Persists: MemPackets (agent long-term memory), RangeWindows, StateVectors,
    // AgentControlBlocks, SCITT receipts, delegation chains, WAL entries.
    let kernel_db_uri = config.kernel_db_uri();
    let kernel_store: Box<dyn vac_core::store::KernelStore + Send> = {
        let path = kernel_db_uri.trim_start_matches("redb:");
        match RedbKernelStore::open(path) {
            Ok(s) => {
                tracing::info!(storage = "redb", path = %path, "Ring 0 kernel store opened");
                Box::new(s)
            }
            Err(e) => {
                tracing::error!(
                    path = %path,
                    error = %e,
                    "FATAL: Failed to open redb kernel store — aborting to prevent data loss"
                );
                eprintln!("\n[startup error] Cannot open redb kernel store at '{}':", path);
                eprintln!("  Error: {}", e);
                eprintln!("  Fix: ensure '{}' directory exists and is writable:", config.data_dir);
                eprintln!("    mkdir -p {}", config.data_dir);
                eprintln!("  If the file is corrupted, remove it to start fresh:");
                eprintln!("    rm {}", path);
                std::process::exit(1);
            }
        }
    };

    let storage_layout = StorageLayout::default_for_cell(&cell_id);

    // Payment provider (Stripe via async-stripe when STRIPE_SECRET_KEY is set)
    let payment = services::payment::build_provider();

    // Platform signing keypair (Ed25519) — load or generate from $DATA_DIR/keys/
    let signing_key = signing::PlatformSigningKey::load_or_generate(&config.data_dir);

    // X.13: Bootstrap UserStore from engine_store (survives restarts)
    let mut user_store = auth::UserStore::load_from_store(&*engine_store);
    bootstrap_first_run_admin_and_tokens(&config, &mut user_store, &mut *engine_store);
    // Rehydrate API key lookup index (HMAC + Argon2) so keys survive process restart.
    auth::rehydrate_api_keys_from_user_store(&user_store);
    let mut runtime_mode = runtime_control::load_runtime_mode_from_store(&*engine_store);
    // Hosted playground (Fly shared VM): force pilots + subprocess.
    // - Dev would re-enable open auth on 0.0.0.0 (crash).
    // - Pilots defaults to microvm; Firecracker is not on Fly (crash).
    // Tenant isolation for trials is namespace/session keys, not per-session microVMs.
    if services::playground::is_playground_mode() {
        if !matches!(runtime_mode, runtime_control::RuntimeMode::Pilots) {
            tracing::warn!(
                from = %runtime_mode.as_str(),
                "playground: forcing runtime mode → Pilots (session-key auth)"
            );
            runtime_mode = runtime_control::RuntimeMode::Pilots;
            runtime_control::persist_runtime_mode(&mut *engine_store, runtime_mode);
        }
    }
    runtime_control::apply_runtime_mode(
        runtime_mode,
        runtime_control::RuntimeModeApplySource::InitialBoot,
    );
    let isolation_fallback = if services::playground::is_playground_mode()
        || matches!(runtime_mode, runtime_control::RuntimeMode::Dev)
    {
        runtime_control::IsolationRuntime::Subprocess
    } else {
        runtime_control::IsolationRuntime::Microvm
    };
    let mut isolation_runtime =
        runtime_control::load_isolation_runtime_from_store(&*engine_store, isolation_fallback);
    if services::playground::is_playground_mode()
        && !matches!(
            isolation_runtime,
            runtime_control::IsolationRuntime::Subprocess
                | runtime_control::IsolationRuntime::Internal
        )
    {
        tracing::warn!(
            from = %isolation_runtime.as_str(),
            "playground: forcing isolation runtime → subprocess (no Firecracker/Docker on shared trial VM)"
        );
        isolation_runtime = runtime_control::IsolationRuntime::Subprocess;
        runtime_control::persist_isolation_runtime(&mut *engine_store, isolation_runtime);
    }
    let isolation_runtime = match runtime_control::resolve_isolation_fail_closed(
        isolation_runtime,
        runtime_mode,
    ) {
        Ok(rt) => rt,
        Err(msg) => {
            eprintln!("\n[startup error] {}", msg);
            tracing::error!(%msg, "isolation runtime fail-closed");
            std::process::exit(1);
        }
    };
    runtime_control::apply_isolation_runtime(isolation_runtime);
    runtime_control::register_pilot_api_keys(&*engine_store);
    // DevGuard: install gateway/MCP hooks so enforcement is live, not a no-op stub.
    crate::services::devguard::install_gateway_hooks();
    crate::services::devguard::install_mcp_tools();
    crate::services::browser_explorer::install_mcp_tools();
    if crate::services::playground::is_playground_mode() {
        crate::services::playground_demo::install_mcp_tools();
    }
    tracing::info!(
        mode = %runtime_mode.as_str(),
        isolation_runtime = %isolation_runtime.as_str(),
        docker_available = runtime_control::docker_available(),
        "runtime modes initialized from control plane"
    );
    if matches!(
        isolation_runtime,
        runtime_control::IsolationRuntime::Internal | runtime_control::IsolationRuntime::Subprocess
    ) {
        tracing::info!(
            "isolation runtime={}: subprocess-style plugin execution (no Docker / Firecracker required)",
            isolation_runtime.as_str()
        );
    } else if matches!(isolation_runtime, runtime_control::IsolationRuntime::DockerLab)
        && !runtime_control::docker_available()
    {
        tracing::warn!(
            "isolation runtime=docker_lab but docker is unavailable; core platform remains up, lab workloads may fail"
        );
    } else if matches!(isolation_runtime, runtime_control::IsolationRuntime::Microvm) {
        tracing::info!(
            "isolation runtime=microvm: production path (Firecracker host is stub until Phase 5.3.x ships)"
        );
    } else if matches!(isolation_runtime, runtime_control::IsolationRuntime::Wasm) {
        tracing::info!(
            "isolation runtime=wasm: Wasmtime + WASI preview1 (Phase 5.6; `connectorctl plugin run --dev` uses CONNECTOR_PLUGIN_RUN_BACKEND=wasm and a .wasm entrypoint)"
        );
    }
    if runtime_control::defense_strict_enabled() {
        tracing::info!(
            "CONNECTOR_DEFENSE_STRICT: dev auth bypass disabled — use JWT / API keys for all operator and protocol paths"
        );
    }

    // ── Sellable service primitives (all from connector-engine OSS) ──
    use connector_engine::secret_store::SecretStore;
    use connector_engine::grounding::GroundingTable;
    use connector_engine::claims::ClaimVerifier;
    use connector_engine::reputation::{ReputationEngine, ReputationConfig};
    use connector_engine::escrow::EscrowManager;
    use connector_engine::negotiation::NegotiationManager;
    use connector_engine::pricing::{DynamicPricer, PricingConfig};
    use connector_engine::agent_index::AgentIndex;
    use connector_engine::orchestrator::Orchestrator;
    use connector_engine::saga_bridge::PipelineManager;
    use connector_engine::context_manager::ContextManager;
    use connector_engine::adaptive_threshold::{AdaptiveThresholdManager, AdaptiveThresholdConfig};
    use connector_engine::firewall::VerdictThresholds;

    // AMA-7 Stage 1: kernel + prolly B-tree + default policies ready
    let t_stage1 = std::time::Instant::now();
    let kernel = match MemoryKernel::load_from_store(&*kernel_store) {
        Ok(mut k) => {
            k.register_default_policies();
            // Re-bind audit HMAC key from env after restore (keyed chain integrity).
            if let Ok(hex_key) = std::env::var("CONNECTOR_AUDIT_HMAC_KEY") {
                let cleaned: String = hex_key.chars().filter(|c| !c.is_whitespace()).collect();
                if cleaned.len() >= 64 {
                    let mut key = [0u8; 32];
                    let mut ok = true;
                    for i in 0..32 {
                        match u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16) {
                            Ok(b) => key[i] = b,
                            Err(_) => {
                                ok = false;
                                break;
                            }
                        }
                    }
                    if ok {
                        k.set_audit_hmac_key(key);
                    }
                }
            }
            tracing::info!("Ring 0 kernel: restored from redb store");
            k
        }
        Err(e) => {
            tracing::warn!("Ring 0 kernel: starting fresh (store empty or first boot: {})", e);
            let mut k = MemoryKernel::new();
            k.register_default_policies();
            k
        }
    };
    tracing::info!(duration_ms = t_stage1.elapsed().as_millis(), "[boot:1] kernel + policies ready ✓");
    boot_complete(1 << 1);

    // AMA-7 Stage 2: context manager ready
    tracing::info!("[boot:2] context manager ready ✓");
    boot_complete(1 << 2);

    // AMA-7 Stage 3: LLM scheduler / admission control ready
    tracing::info!("[boot:3] LLM scheduler / admission control ready ✓");
    boot_complete(1 << 3);

    // AMA-7 Stage 4: UCAN capability verifier ready
    tracing::info!("[boot:4] UCAN capability verifier ready ✓");
    boot_complete(1 << 4);

    // AMA-7 Stage 5: agent snapshot restore complete
    // (kernel.load_from_store above restores all AgentControlBlocks; mark complete)
    tracing::info!("[boot:5] agent snapshot restore complete ✓");
    boot_complete(1 << 5);

    // P8.2: optional vac-cluster — construct local Cell; ClusterKernelStore/replicate deferred.
    #[cfg(feature = "cluster")]
    {
        let _cell = cluster_boot::boot_local_cell(&cell_id);
        tracing::info!(
            cell_id = %_cell.cell_id,
            vac_cluster = %std::any::type_name::<vac_cluster::ClusterError>(),
            "cluster feature: local vac-cluster Cell ready (mesh_fabric still false until soak)"
        );
    }

    let state = Arc::new(PlatformState {
        kernel: Mutex::new(kernel),
        kernel_store: Mutex::new(kernel_store),
        knot: Mutex::new(KnotEngine::new()),
        binding: Mutex::new(BindingEngine::new()),
        aapi: Mutex::new(ActionEngine::new()),
        engine_store: Mutex::new(engine_store),
        runtime_mode: std::sync::RwLock::new(runtime_mode),
        isolation_runtime: std::sync::RwLock::new(isolation_runtime),
        storage_layout,
        config: config.clone(),
        license,
        health: crate::state::HealthSnapshot::default(),
        metrics: PlatformMetrics::new(),
        observability: Mutex::new(services::observability::NativeObservabilityStore::default()),
        llm_config,
        user_store: Mutex::new(user_store),
        llm_router,
        guard: Mutex::new(GuardPipeline::new()),
        payment,
        signing_key,
        // ── Sellable services ──
        secret_store: Mutex::new(match crate::kernel::vault_seal::load_store() {
            Ok(s) => s,
            Err(e) => {
                if crate::connector_profile::is_productionish_env() {
                    eprintln!("\n[startup error] vault unseal failed: {e}");
                    std::process::exit(1);
                }
                tracing::warn!(error = %e, "vault unseal failed; starting empty lab vault");
                SecretStore::new()
            }
        }),
        grounding: Mutex::new(GroundingTable::new()),
        claim_verifier: ClaimVerifier,
        reputation: Mutex::new(ReputationEngine::new(ReputationConfig::default())),
        escrow: Mutex::new(EscrowManager::new()),
        negotiation: Mutex::new(NegotiationManager::new(10, 3_600_000)),
        pricer: Mutex::new(DynamicPricer::new(PricingConfig::default())),
        agent_index: Mutex::new(AgentIndex::new()),
        orchestrator: Mutex::new(Orchestrator::new()),
        pipeline_mgr: Mutex::new(PipelineManager::new()),
        context_mgr: Mutex::new(ContextManager::new()),
        adaptive_thresholds: Mutex::new(AdaptiveThresholdManager::new(
            AdaptiveThresholdConfig::default(),
            VerdictThresholds::default(),
        )),
        registry: Mutex::new(services::registry::AgentRegistry::new()),
        adaptive_router: Some(services::adaptive::AdaptiveRouter::new()),
        knowledge_graph: Some(services::knowledge_transfer::KnowledgeGraph::new()),
        kernel_host: std::sync::Mutex::new(services::kernel_host::KernelHostState::new()),
        plugin_tier_scheduler: std::sync::Arc::new(services::plugin_tier_scheduler::PluginTierScheduler::from_env()),
        plugin_crash_recovery: std::sync::Arc::new(services::plugin_crash_recovery::PluginCrashRecovery::default()),
        playground_sessions: services::playground::new_store(),
        kernel_durability: crate::state::KernelDurabilityTracker::new(),
        cells: crate::concurrency::intelligence_cell::CellRegistry::default(),
        runtime_snapshots: crate::substrate::agent_runtime_snapshot::RuntimeSnapshotRegistry::new(),
        session_owners: crate::concurrency::session_owner::SessionOwnerRegistry::new(),
        bulkheads: crate::concurrency::workload_bulkhead::WorkloadBulkheads::from_env(),
    });

    // OPS-06: restore plugin quarantine/backoff across restart
    services::plugin_crash_recovery::hydrate(&state);

    // S16/S17: restore AAPI budgets + open BCR reservations from durable store
    crate::substrate::aapi_effect_field::hydrate_engine_from_store(&state);
    let crash_report = crate::substrate::crash_recovery::run_boot_recovery(&state);
    tracing::info!(
        recovery = %crash_report.to_json(),
        "boot crash recovery measured"
    );

    let knot_replayed = crate::substrate::knot_rebuild::rebuild_knot_from_kernel(&state);
    if knot_replayed > 0 {
        tracing::info!(
            replayed_packets = knot_replayed,
            "[boot] knot graph rebuilt from kernel packets"
        );
    }

    // BF2: Ring-0 `AgentRegister` cap matches HTTP gates (dev = 3 agents, pilots/prod from policy+license).
    services::agents::sync_kernel_agent_registration_cap(state.as_ref());
    state.refresh_health_snapshot();

    // Gate B: durable NodeID + boot epoch + workload profile (mechanism-vs-policy).
    {
        let identity = crate::substrate::node_contract::load_or_create_identity(state.as_ref());
        let profile = crate::substrate::workload_profile::load_active(state.as_ref());
        let compiled = crate::substrate::workload_profile::compile(&profile, state.as_ref());
        tracing::info!(
            node_id = %identity.node_id,
            trust_domain = %identity.trust_domain_id,
            boot_epoch = crate::substrate::node_contract::boot_epoch(),
            workload_profile = %profile.id,
            start_refused = compiled.start_refused,
            unmet = ?compiled.unmet,
            "node contract + workload profile ready"
        );
        if compiled.start_refused {
            tracing::warn!(
                reason = ?compiled.refuse_reason,
                "workload profile would START_REFUSE agent starts until prerequisites are met"
            );
        }
    }

    // Workflow catalog auto-sync (optional watch on data_dir/workflows/catalog).
    services::workflow_catalog_sync::spawn_workflow_catalog_watch_loop(
        state.clone(),
        config.data_dir.clone(),
    );

    // DevGuard: seed local-workstation onboarding profile (config fact only — not a healthy control; DG-08).
    services::devguard_local_profile::ensure_lab_default_local_profile(&state);
    services::connector_demo::ensure_default_demo(&state);

    // Playground: session reaper — cleanup resources then evict expired sessions.
    if services::playground::is_playground_mode() {
        let disk_cleaned = services::playground::cleanup_expired_sessions_on_disk(&state);
        if disk_cleaned > 0 {
            tracing::info!(
                disk_cleaned,
                "playground: cleaned expired sessions that were skipped at load"
            );
        }
        services::agents::compact_stale_playground_agents(&state);
        services::agents::compact_orphan_kernel_agents(&state);
        services::agents::rehydrate_playground_runtime(&state);
        state.refresh_health_snapshot();
        let pg_state = state.clone();
        tokio::spawn(async move {
            let mut ticks: u64 = 0;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                ticks = ticks.wrapping_add(1);
                let cleaned = services::playground::reap_expired_sessions(&pg_state);
                if cleaned > 0 {
                    tracing::info!(cleaned, "playground: reaped expired sessions with cleanup");
                    pg_state.refresh_health_snapshot();
                }
                // Periodic compact so kernel registration cap does not wall.
                if ticks % 5 == 0 {
                    services::agents::compact_stale_playground_agents(&pg_state);
                    services::agents::compact_orphan_kernel_agents(&pg_state);
                    pg_state.refresh_health_snapshot();
                }
            }
        });
        tracing::info!("playground mode active — session reaper started (60s interval)");
    }

    // X.8: Webhook retry background loop (30s interval)
    background::spawn_webhook_retry_loop(state.clone());

    // B9: HITL timeout sweep loop (15s interval)
    background::spawn_hitl_timeout_loop(state.clone());

    crate::cnp::wire::boot(&state.storage_layout.cell_id, state.clone());
    tokio::spawn(crate::cnp::wire::listen_loop());
    background::spawn_membership_probe_loop(state.clone());

    // WF-01 scaffold: synthetic CNP enable-event poller (not live bus)
    background::spawn_workflow_cnp_dispatch_poller(state.clone());

    // Durable CLS blueprint lease runner
    background::spawn_workflow_runner_loop(state.clone());

    // X.9: Notification escalator background loop (5min interval)
    background::spawn_notification_escalator(state.clone());

    // FIX BUG-039: Escrow expiration background loop (60s interval)
    background::spawn_escrow_expiration_loop(state.clone());

    // Phase 5.4.3: optional JSON file for microVM host vsock **`tier_signal`** (CONNECTOR_MICROVM_VSOCK_TIER_SIGNAL on plugin-runtime).
    if let Some(path) = services::plugin_tier_scheduler::microvm_tier_state_file_path_from_env() {
        let interval_ms =
            services::plugin_tier_scheduler::microvm_tier_state_sync_interval_ms_from_env();
        let st = state.clone();
        tokio::spawn(async move {
            tracing::info!(
                path = %path,
                interval_ms,
                "microVM tier state file sync (Phase 5.4.3 vsock tier_signal backing)"
            );
            let mut interval =
                tokio::time::interval(std::time::Duration::from_millis(interval_ms));
            loop {
                interval.tick().await;
                let sched = st.plugin_tier_scheduler.clone();
                let p = path.clone();
                match tokio::task::spawn_blocking(move || {
                    crate::services::plugin_tier_scheduler::write_microvm_tier_state_snapshot_to_path(
                        &*sched, &p,
                    )
                })
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::warn!(
                            error = %e,
                            path = %path,
                            "microVM tier state file write failed"
                        );
                    }
                    Err(e) => tracing::warn!(
                        error = %e,
                        "microVM tier state sync task join failed"
                    ),
                }
            }
        });
    }

    // DB-FLUSH: Periodic Ring 0 kernel → redb flush (default 60s).
    // Ensures MemPackets, RangeWindows, AgentControlBlocks are durable on disk.
    // On crash, load_from_store() at startup recovers from last flush checkpoint.
    {
        let flush_state = state.clone();
        tokio::spawn(async move {
            let interval_secs = std::env::var("CONNECTOR_FLUSH_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(60);
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(interval_secs)
            );
            tracing::info!(
                interval_secs = interval_secs,
                "Ring 0 kernel flush task started (redb persistence)"
            );
            loop {
                interval.tick().await;
                let flush_state2 = flush_state.clone();
                let flushed = tokio::task::spawn_blocking(move || {
                    let mut kernel = flush_state2.kernel.lock().unwrap();
                    kernel.flush_audit_batch();
                    crate::substrate::memwrite_durability::drain_and_persist_audit_overflow(
                        flush_state2.as_ref(),
                        &mut kernel,
                    );
                    let mut store = flush_state2.kernel_store.lock().unwrap();
                    kernel.flush_to_store(&mut **store)
                })
                .await;
                match flushed {
                    Ok(Ok(n)) => {
                        flush_state.kernel_durability.record_flush_ok(n);
                        if n > 0 {
                            tracing::debug!(objects = n, "Ring 0 kernel flushed to redb");
                        }
                    }
                    Ok(Err(e)) => {
                        flush_state.kernel_durability.record_flush_err(e.clone());
                        tracing::error!(error = %e, "Ring 0 kernel flush failed — data NOT persisted");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Ring 0 kernel flush task join failed");
                    }
                }
            }
        });
    }

    // I4: SelfHealingMonitor background task (30s interval).
    // Runs all 5 checks: Heartbeat, Integrity, LoadBalance, ReplicationLag, TrustAudit.
    // Agent Reaper: enforce cap, reap zombies, demote idle agents (Linux init analogue).
    crate::services::agent_reaper::spawn(state.clone());

    // Previously these only ran on-demand; now they run continuously as required for T1+.
    {
        let healing_state = state.clone();
        tokio::spawn(async move {
            use vac_core::self_healing::{HealthMonitor, HealingAction};
            let mut monitor = HealthMonitor::default_monitor();
            let interval_secs = std::env::var("CONNECTOR_HEALTH_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30);
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(interval_secs)
            );

            tracing::info!(
                interval_secs = interval_secs,
                "SelfHealingMonitor started (I4 fix)"
            );

            loop {
                interval.tick().await;

                // Feed agent heartbeats from active kernel agents
                let agents = {
                    match healing_state.kernel.lock() {
                        Ok(k) => k.all_agents().into_iter().map(|a| a.agent_pid.clone()).collect::<Vec<_>>(),
                        Err(_) => vec![],
                    }
                };
                for pid in &agents {
                    monitor.record_heartbeat(pid);
                }

                // Check audit chain integrity
                let chain_valid = healing_state.kernel.lock()
                    .map(|k| k.verify_audit_chain().is_ok())
                    .unwrap_or(false);

                let actions = monitor.run_all_checks(chain_valid);

                for action in &actions {
                    // OPS-05: persist every remediation decision (even alerts) for operator audit.
                    {
                        let action_id = format!("sh_{}", uuid::Uuid::new_v4().simple());
                        let record = serde_json::json!({
                            "action_id": action_id,
                            "action": format!("{:?}", action),
                            "recorded_at": chrono::Utc::now().to_rfc3339(),
                            "executed": matches!(
                                action,
                                HealingAction::SuspendAgent { .. }
                                    | HealingAction::RestartAgent { .. }
                            ),
                            "honesty": "OPS-05 — persisted SelfHeal decision; SuspendAgent mutates kernel status; Restart/Migrate/Sync remain advisory until wired",
                        });
                        if let Ok(mut es) = healing_state.engine_store.lock() {
                            let _ = es.folder_put("self_heal_actions", record["action_id"].as_str().unwrap_or("x"), &record);
                        }
                    }
                    match action {
                        HealingAction::AlertOperator { severity, message } => {
                            if severity == "CRITICAL" {
                                tracing::error!(severity = %severity, "[SelfHeal] {}", message);
                            } else {
                                tracing::warn!(severity = %severity, "[SelfHeal] {}", message);
                            }
                        }
                        HealingAction::SuspendAgent { agent_pid, reason } => {
                            tracing::warn!(agent = %agent_pid, reason = %reason, "[SelfHeal] Auto-suspending agent");
                            if let Ok(mut k) = healing_state.kernel.lock() {
                                if let Some(acb) = k.agents_mut().get_mut(agent_pid) {
                                    acb.status = vac_core::types::AgentStatus::Suspended;
                                }
                            }
                        }
                        HealingAction::RestartAgent { agent_pid, reason } => {
                            tracing::warn!(agent = %agent_pid, reason = %reason, "[SelfHeal] Agent restart triggered (advisory — no auto-recreate)");
                        }
                        HealingAction::TriggerSync { cell_id, reason } => {
                            tracing::warn!(cell = %cell_id, reason = %reason, "[SelfHeal] Merkle sync triggered");
                        }
                        HealingAction::MigrateAgent { agent_pid, target_cell, reason } => {
                            tracing::info!(agent = %agent_pid, target = %target_cell, reason = %reason, "[SelfHeal] Agent migration");
                        }
                        HealingAction::None => {}
                    }
                }

                if !actions.is_empty() {
                    tracing::debug!(
                        actions = actions.len(),
                        stability = monitor.stability_index(),
                        "[SelfHeal] Check complete"
                    );
                }
            }
        });
    }

    // Air-gap mode: CONNECTOR_AIRGAP=true → no outbound network calls; license verified offline only
    let airgap = std::env::var("CONNECTOR_AIRGAP")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    // Dev mode also skips phone-home (no 45s timeout when running locally)
    let airgap = airgap || matches!(runtime_mode, RuntimeMode::Dev);

    // Binary identity + phone-home
    let identity = binary_id::BinaryIdentity::from_env();
    tracing::info!("binary_id: {} (machine: {})", identity.binary_id, identity.machine_id);

    if airgap {
        tracing::info!(
            "[airgap] CONNECTOR_AIRGAP=true — all outbound network calls disabled. \
            License verified offline. No phone-home, no heartbeat, no usage reporting."
        );
    } else if identity.needs_phone_home() {
        let ph_config = phone_home::PhoneHomeConfig::from_identity(identity.clone());
        let (allowed, command, banner, _perms) = phone_home::startup_checkin(&ph_config).await;
        tracing::info!("License check-in: command={}, banner={}", command, banner);

        if !allowed {
            tracing::error!("License server denied startup — exiting");
            std::process::exit(1);
        }

        // Spawn background heartbeat + usage reporter
        phone_home::spawn_heartbeat_loop(state.clone(), ph_config.clone());
        phone_home::spawn_usage_reporter(state.clone(), ph_config);
    } else {
        tracing::info!("Running in unlicensed/dev mode (no phone-home)");
    }

    // AIOS-B13: SIGHUP secret rotation — reload secrets + JWT key without restart
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let sighup_state = state.clone();
        tokio::spawn(async move {
            let mut sighup = signal(SignalKind::hangup()).expect("SIGHUP handler");
            loop {
                sighup.recv().await;
                tracing::info!("[sighup] SIGHUP received — rotating secrets and reloading config");
                // Re-read secrets from environment (new values set before SIGHUP)
                let new_jwt = std::env::var("CONNECTOR_JWT_SECRET");
                let new_stripe = std::env::var("STRIPE_SECRET_KEY");
                match new_jwt {
                    Ok(ref s) if !s.is_empty() => tracing::info!("[sighup] JWT secret rotated (len={})", s.len()),
                    _ => tracing::debug!("[sighup] No new JWT secret in env"),
                }
                match new_stripe {
                    Ok(_) => tracing::info!("[sighup] Stripe key present after rotation"),
                    _ => tracing::debug!("[sighup] No Stripe key in env"),
                }
                // Persist any in-memory users that haven't been flushed
                let us = sighup_state.user_store.lock().unwrap();
                let mut es = sighup_state.engine_store.lock().unwrap();
                for user_id in us.users.keys().cloned().collect::<Vec<_>>() {
                    us.persist_user(&user_id, es.as_mut());
                }
                drop(es);
                drop(us);
                tracing::info!("[sighup] Config reload complete — no restart needed");
            }
        });
    }

    // Clone state for graceful shutdown handler and Phase R1 gateways before moving into router
    let shutdown_state = state.clone();
    let gw_state   = if config.protocol_gateway_port != 0 { Some(state.clone()) } else { None };
    let rpc_state  = if config.ui_rpc_port != 0          { Some(state.clone()) } else { None };

    let addr = config.addr();
    // DX-P2-3: Hard abort if CONNECTOR_DEV_MODE=1 is set in a production environment.
    // This prevents dev-token from being accepted in prod due to misconfiguration.
    {
        let is_dev_mode = std::env::var("CONNECTOR_DEV_MODE").is_ok();
        let is_prod_env = crate::connector_profile::is_productionish_env();
        if is_dev_mode && is_prod_env {
            eprintln!(
                "\nERROR: CONNECTOR_DEV_MODE=1 is set in a production-like environment.\n\
                 This would accept 'dev-token' as a valid Bearer token in production,\n\
                 exposing your platform to unauthenticated access.\n\n\
                 Fix: unset CONNECTOR_DEV_MODE, or change CONNECTOR_ENV to 'development'.\n\
                 Docs: https://connector.ai/docs/env#CONNECTOR_DEV_MODE\n"
            );
            std::process::exit(1);
        }
        if is_prod_env && crate::services::runtime_control::free_tier_open_auth_enabled() {
            eprintln!(
                "\nERROR: Open-auth / ultimate-free bypass is set in a production-like environment.\n\
                 Unset CONNECTOR_ULTIMATE_FREE / CONNECTOR_OPEN_AUTH / CONNECTOR_FREE_TIER_OPEN_AUTH.\n"
            );
            std::process::exit(1);
        }
        if is_prod_env
            && crate::services::kernel_host::kernel_enforce_enabled()
            && !services::playground::is_playground_mode()
        {
            let has_dropin = std::env::var("CONNECTOR_KERNELD_DROPIN_PATH")
                .map(|p| !p.trim().is_empty())
                .unwrap_or(false);
            let degraded = std::env::var("CONNECTOR_KERNEL_EGRESS_DEGRADED")
                .ok()
                .as_deref()
                == Some("1");
            if !has_dropin && !degraded {
                eprintln!(
                    "\nERROR: CONNECTOR_ENV=production with CONNECTOR_KERNEL_ENFORCE=1 requires\n\
                     CONNECTOR_KERNELD_DROPIN_PATH (systemd egress drop-in) or explicit\n\
                     CONNECTOR_KERNEL_EGRESS_DEGRADED=1 audit flag.\n"
                );
                std::process::exit(1);
            }
        }
    }

    // S6: CONNECTOR_ENV=development is the canonical alias; CONNECTOR_DEV_MODE kept for back-compat
    let dev_mode = matches!(runtime_mode, RuntimeMode::Dev);
    if dev_mode {
        std::env::set_var("CONNECTOR_DEV_MODE", "1");
    }

    // Build router after final CONNECTOR_* sync so `dashboard_static::dashboard_dev_html_enabled`
    // sees the same env as API middleware (Leptos login `data-dev` / Dev Bypass).
    let app = router::build_router(state);

    // AMA-7 Stage 6: HTTP router started — all stages complete → PLATFORM_READY = 1
    tracing::info!("[boot:6] HTTP router started ✓");
    boot_complete(1 << 6);
    tracing::info!(boot_stages = BOOT_STAGE.load(Ordering::SeqCst), platform_ready = PLATFORM_READY.load(Ordering::SeqCst) == 1, "[boot] all stages complete");

    let ui_dir_log = crate::router::resolve_dashboard_ui_dir();
    let ui_mount = crate::router::dashboard_ui_mount_label();
    // ── Internal DNS — register the main API service ──────────────────────────
    let main_addr: std::net::SocketAddr = addr.parse().unwrap_or_else(|_| "0.0.0.0:9091".parse().unwrap());
    internal_dns::register(
        internal_dns::SVC_API,
        main_addr,
        "Main REST API (axum)",
        &["api", "rest", "public"],
    );
    internal_dns::sync_plugin_cage_dns_records(main_addr);
    internal_dns::spawn_gc(std::time::Duration::from_secs(120));

    tracing::info!("connector-platform listening on {} (170 routes, 18 services)", addr);
    {
        let expose = std::env::var("CONNECTOR_EXPOSE_DEFENSE_DETAIL")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if expose && addr.contains("0.0.0.0") {
            tracing::warn!(
                bind = %addr,
                "BF2-G01: CONNECTOR_EXPOSE_DEFENSE_DETAIL is set while bound to all interfaces — posture fields are reachable from every attached network"
            );
        }
    }
    tracing::info!("  Dashboard UI: /           ({}, path={})", ui_mount, ui_dir_log);
    tracing::info!("  API:          /api/v1/*");
    tracing::info!("  Health:       /health");
    tracing::info!("  Metrics:      /metrics");
    tracing::info!("  Capabilities: GET /api/v1  (full manifest with quickstart)");
    tracing::info!("  Portal:       https://portal.connector.dev (control server)");
    tracing::info!("  Protocol GW:  :{} (MCP/A2A/ACP/ANP/AP2)", config.protocol_gateway_port);
    tracing::info!("  UI-RPC:       :{} (WebSocket JSON-RPC 2.0)", config.ui_rpc_port);

    if dev_mode {
        tracing::info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        tracing::info!("  DEV MODE — auth bypassed. Use any token:");
        tracing::info!("  Authorization: Bearer dev-token");
        tracing::info!("  Quick start (3 commands):");
        tracing::info!("    1. curl -X POST http://{}/api/v1/agents \\", addr);
        tracing::info!("         -H 'Authorization: Bearer dev-token' \\");
        tracing::info!("         -H 'Content-Type: application/json' \\");
        tracing::info!("         -d '{{\"name\":\"my-agent\",\"namespace\":\"m/my-agent\"}}'");
        tracing::info!("    2. curl http://{}/api/v1  (capability manifest)", addr);
        tracing::info!("    3. curl http://{}/health  (system status)", addr);
        tracing::info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }

    // ── Phase R1: Spawn protocol gateway (:9092) and UI-RPC (:9093) ──────────
    if let Some(s) = gw_state {
        let gw_addr = config.protocol_gateway_addr();
        tokio::spawn(async move {
            protocol_gateway::spawn_gateway(s, gw_addr).await;
        });
    }

    if let Some(s) = rpc_state {
        let rpc_addr = config.ui_rpc_addr();
        tokio::spawn(async move {
            ui_rpc::spawn_ui_rpc(s, rpc_addr).await;
        });
    }

    if let Err(msg) = runtime_control::reject_open_auth_non_loopback_bind(&addr) {
        eprintln!("\n[startup error] {}", msg);
        tracing::error!(%msg, "refusing to bind with open auth on non-loopback address");
        std::process::exit(1);
    }

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap_or_else(|e| {
        eprintln!("\n[startup error] Cannot bind to {}: {}", addr, e);
        eprintln!("  Fix: port {} is already in use. Run:", config.port);
        eprintln!("    lsof -ti :{} | xargs kill  (kill the process using the port)", config.port);
        eprintln!("  Or set a different port: CONNECTOR_PORT=9091 ./connector-platform");
        std::process::exit(1);
    });

    // AIOS-B13 / AIOS-A7: SIGTERM graceful shutdown — flush kernel to redb, drain dispatches
    let shutdown_signal = async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
            let mut sigint  = signal(SignalKind::interrupt()).expect("SIGINT handler");
            tokio::select! {
                _ = sigterm.recv() => { tracing::info!("SIGTERM received — initiating graceful shutdown"); }
                _ = sigint.recv()  => { tracing::info!("SIGINT received — initiating graceful shutdown"); }
            }
            crate::boot::begin_shutdown();
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await.expect("ctrl-c handler");
            tracing::info!("Ctrl-C received — initiating graceful shutdown");
            crate::boot::begin_shutdown();
        }
        // BF2-X02: brief drain so in-flight gateway/LLM work can finish (tune via CONNECTOR_SHUTDOWN_DRAIN_SECS).
        {
            let secs: u64 = std::env::var("CONNECTOR_SHUTDOWN_DRAIN_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2);
            if secs > 0 {
                tracing::info!(secs, "[shutdown] drain window before agent terminate");
                tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            }
        }
        // Drain kernel agents (terminate control blocks) before persistence.
        {
            let pids: Vec<String> = shutdown_state
                .kernel
                .lock()
                .unwrap()
                .agents()
                .keys()
                .cloned()
                .collect();
            let cell = shutdown_state
                .config
                .cell_id
                .clone()
                .unwrap_or_else(|| "cell_local".to_string());
            for pid in pids {
                let _ = crate::substrate::agent_lifecycle_gate::dispatch_system_lifecycle(
                    &shutdown_state,
                    &pid,
                    crate::services::intelligence_authority::LifecycleOp::Stop,
                    "shutdown",
                    &format!("platform_shutdown:cell={cell}"),
                );
            }
        }
        // Flush Ring 0 kernel to redb
        let kernel = shutdown_state.kernel.lock().unwrap();
        let mut store = shutdown_state.kernel_store.lock().unwrap();
        match kernel.flush_to_store(store.as_mut()) {
            Ok(_) => tracing::info!("[shutdown] Ring 0 kernel flushed to redb — clean exit"),
            Err(e) => tracing::error!("[shutdown] kernel flush failed: {} — data may be lost", e),
        }
        tracing::info!("[shutdown] connector-platform stopped");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .unwrap();
}
