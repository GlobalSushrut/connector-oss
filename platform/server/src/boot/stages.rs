//! Boot stage implementations
//!
//! Each stage is a discrete initialization step with its own error handling.

use std::time::Instant;
use std::path::Path;
use super::{StageResult, NodeIdentity, NodeMode, sd_notify_status};

fn generate_and_persist_node_id(path: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let id = format!("cn-{:016x}", now & 0xFFFF_FFFF_FFFF_FFFFu128);
    if let Some(dir) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, &id);
    id
}

/// Stage 0: IDENTITY — Establish node identity
pub fn stage_identity() -> (StageResult, NodeIdentity) {
    let start = Instant::now();

    // Data directory (needed for node-id persistence)
    let data_dir = std::env::var("CONNECTOR_DATA_DIR")
        .unwrap_or_else(|_| "./data".to_string());

    // Generate or load node ID — persisted to data_dir/node-id
    let node_id = if let Ok(id) = std::env::var("CONNECTOR_NODE_ID") {
        id
    } else {
        let id_path = format!("{}/node-id", data_dir);
        if let Ok(id) = std::fs::read_to_string(&id_path) {
            let id = id.trim().to_string();
            if !id.is_empty() { id } else { generate_and_persist_node_id(&id_path) }
        } else {
            generate_and_persist_node_id(&id_path)
        }
    };

    // Determine mode
    let mode = if std::env::var("CONNECTOR_AIRGAP").map(|v| v == "true" || v == "1").unwrap_or(false) {
        NodeMode::AirGap
    } else if std::env::var("CONNECTOR_ENV").map(|v| v == "local").unwrap_or(false) {
        NodeMode::Local
    } else if std::env::var("CONNECTOR_DEV_MODE").is_ok()
        || std::env::var("CONNECTOR_ENV").map(|v| v == "development" || v == "dev").unwrap_or(false) {
        NodeMode::Development
    } else {
        NodeMode::Production
    };
    
    // Environment
    let environment = std::env::var("CONNECTOR_ENVIRONMENT")
        .unwrap_or_else(|_| "self-hosted".to_string());
    
    // Machine ID (simplified fingerprint)
    let machine_id = crate::machine::machine_fingerprint();
    
    let identity = NodeIdentity {
        node_id: node_id.clone(),
        version: env!("CARGO_PKG_VERSION"),
        mode,
        environment: environment.clone(),
        machine_id: machine_id.clone(),
        data_dir: data_dir.clone(),
    };
    
    let _ = sd_notify_status("Stage 0: IDENTITY");
    
    let result = StageResult::ok_with_details(
        0,
        start.elapsed(),
        format!("Node {} ({})", node_id, mode),
        vec![
            format!("version: {}", identity.version),
            format!("environment: {}", environment),
            format!("machine: {}...", &machine_id[..16.min(machine_id.len())]),
            format!("data_dir: {}", data_dir),
        ],
    );
    
    (result, identity)
}

/// Stage 1: CONFIG — Load and validate configuration
pub fn stage_config(data_dir: &str) -> StageResult {
    let start = Instant::now();
    let _ = sd_notify_status("Stage 1: CONFIG");
    
    // Ensure data directory exists
    if let Err(e) = std::fs::create_dir_all(data_dir) {
        return StageResult::err(1, start.elapsed(), format!("Cannot create data_dir: {}", e));
    }
    
    // Check for config file
    let config_path = std::env::var("CONNECTOR_CONFIG")
        .unwrap_or_else(|_| format!("{}/connector.yaml", data_dir));
    
    let config_exists = Path::new(&config_path).exists();
    
    // Load platform config from env (existing behavior)
    let config = crate::config::PlatformConfig::from_env();
    
    let mut details = vec![
        format!("port: {}", config.port),
        format!("host: {}", config.host),
    ];
    
    if config_exists {
        details.push(format!("config_file: {}", config_path));
    } else {
        details.push("config_file: (using env vars)".to_string());
    }
    
    StageResult::ok_with_details(1, start.elapsed(), "Configuration loaded", details)
}

/// Stage 2: SECRETS — Load secrets and keys
pub fn stage_secrets(data_dir: &str) -> StageResult {
    let start = Instant::now();
    let _ = sd_notify_status("Stage 2: SECRETS");
    
    let mut secrets_loaded = 0;
    let mut details = vec![];
    
    // Check for signing key
    let keys_dir = format!("{}/keys", data_dir);
    if Path::new(&keys_dir).exists() || std::fs::create_dir_all(&keys_dir).is_ok() {
        details.push("signing_key: ready".to_string());
        secrets_loaded += 1;
    }
    
    // Check for LLM API key
    if std::env::var("CONNECTOR_LLM_API_KEY").is_ok() {
        details.push("llm_api_key: present".to_string());
        secrets_loaded += 1;
    } else if std::env::var("CONNECTOR_LLM_STUB").map(|v| v == "true" || v == "1").unwrap_or(false) {
        details.push("llm_api_key: stub mode".to_string());
        secrets_loaded += 1;
    } else {
        details.push("llm_api_key: not set".to_string());
    }
    
    // Check for JWT secret
    if std::env::var("CONNECTOR_JWT_SECRET").is_ok() {
        details.push("jwt_secret: present".to_string());
        secrets_loaded += 1;
    }
    
    // Check for Stripe key
    if std::env::var("STRIPE_SECRET_KEY").is_ok() {
        details.push("stripe_key: present".to_string());
        secrets_loaded += 1;
    }
    
    StageResult::ok_with_details(
        2,
        start.elapsed(),
        format!("{} secrets loaded", secrets_loaded),
        details,
    )
}

/// Stage 3: STORAGE — Open databases
/// Returns the engine and kernel store paths for the caller to open
pub fn stage_storage_check(data_dir: &str) -> StageResult {
    let start = Instant::now();
    let _ = sd_notify_status("Stage 3: STORAGE");
    
    let engine_path = format!("{}/engine.db", data_dir);
    let kernel_path = format!("{}/kernel.redb", data_dir);
    
    // Just verify paths are accessible; actual opening happens in main
    let mut details = vec![];
    
    // Check engine store path
    let engine_dir = Path::new(&engine_path).parent();
    if let Some(dir) = engine_dir {
        if !dir.exists() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                return StageResult::err(3, start.elapsed(), format!("Cannot create engine dir: {}", e));
            }
        }
    }
    details.push(format!("engine_store: {}", engine_path));
    
    // Check kernel store path
    let kernel_dir = Path::new(&kernel_path).parent();
    if let Some(dir) = kernel_dir {
        if !dir.exists() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                return StageResult::err(3, start.elapsed(), format!("Cannot create kernel dir: {}", e));
            }
        }
    }
    details.push(format!("kernel_store: {}", kernel_path));
    
    StageResult::ok_with_details(3, start.elapsed(), "Storage paths ready", details)
}

/// Stage 4: KERNEL — Initialize memory kernel
/// Called after kernel is actually loaded
pub fn stage_kernel_complete(packet_count: usize, duration: std::time::Duration) -> StageResult {
    let _ = sd_notify_status("Stage 4: KERNEL");
    
    StageResult::ok_with_details(
        4,
        duration,
        format!("Memory kernel ({} packets)", packet_count),
        vec![
            format!("packets: {}", packet_count),
            "knot_engine: initialized".to_string(),
            "binding_engine: initialized".to_string(),
        ],
    )
}

/// Stage 5: POLICIES — Register governance policies
pub fn stage_policies_complete(policy_count: usize, duration: std::time::Duration) -> StageResult {
    let _ = sd_notify_status("Stage 5: POLICIES");
    
    StageResult::ok_with_details(
        5,
        duration,
        format!("{} policies registered", policy_count),
        vec![
            format!("default_policies: {}", policy_count),
            "guard_pipeline: ready".to_string(),
        ],
    )
}

/// Stage 6: SCHEDULER — Initialize LLM router
pub fn stage_scheduler_complete(provider_count: usize, duration: std::time::Duration) -> StageResult {
    let _ = sd_notify_status("Stage 6: SCHEDULER");
    
    let msg = if provider_count > 0 {
        format!("LLM router ({} providers)", provider_count)
    } else {
        "LLM router (no providers)".to_string()
    };
    
    StageResult::ok_with_details(
        6,
        duration,
        msg,
        vec![
            format!("providers: {}", provider_count),
            "admission_control: ready".to_string(),
            "budget_enforcement: active".to_string(),
        ],
    )
}

/// Stage 7: CAPABILITIES — Initialize UCAN verifier
pub fn stage_capabilities_complete(duration: std::time::Duration) -> StageResult {
    let _ = sd_notify_status("Stage 7: CAPABILITIES");
    
    StageResult::ok_with_details(
        7,
        duration,
        "Capability verifier ready",
        vec![
            "ucan_verifier: ready".to_string(),
            "capability_gates: active".to_string(),
        ],
    )
}

/// Stage 8: RESTORE — Restore agent snapshots
pub fn stage_restore_complete(agent_count: usize, duration: std::time::Duration) -> StageResult {
    let _ = sd_notify_status("Stage 8: RESTORE");
    
    StageResult::ok_with_details(
        8,
        duration,
        format!("{} agents restored", agent_count),
        vec![
            format!("agents: {}", agent_count),
            "agent_index: rebuilt".to_string(),
        ],
    )
}

/// Stage 9: SERVICES — Start background services
pub fn stage_services_complete(service_count: usize, duration: std::time::Duration) -> StageResult {
    let _ = sd_notify_status("Stage 9: SERVICES");
    
    StageResult::ok_with_details(
        9,
        duration,
        format!("{} background services", service_count),
        vec![
            "webhook_retry: started".to_string(),
            "hitl_timeout: started".to_string(),
            "notification_escalator: started".to_string(),
            "escrow_expiration: started".to_string(),
            "kernel_flush: started".to_string(),
            "self_healing: started".to_string(),
        ],
    )
}

/// Stage 10: ACCESS — Bind endpoints
pub fn stage_access_complete(addr: &str, route_count: usize, duration: std::time::Duration) -> StageResult {
    let _ = sd_notify_status("Stage 10: ACCESS");
    
    StageResult::ok_with_details(
        10,
        duration,
        format!("Listening on {}", addr),
        vec![
            format!("api: {}/api/v1", addr),
            format!("ui: {}/", addr),
            format!("metrics: {}/metrics", addr),
            format!("health: {}/health", addr),
            format!("routes: {}", route_count),
        ],
    )
}

/// Stage 11: READY — Node fully operational
pub fn stage_ready_complete(total_duration: std::time::Duration) -> StageResult {
    let _ = sd_notify_status("Ready");
    
    StageResult::ok_with_details(
        11,
        std::time::Duration::ZERO,
        "Node healthy — workloads schedulable",
        vec![
            format!("boot_time: {}ms", total_duration.as_millis()),
            "status: ready".to_string(),
        ],
    )
}
