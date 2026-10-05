//! System Management API
//!
//! Provides endpoints for system information using real metrics and kernel state.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use chrono::Utc;

use crate::state::SharedState;
use super::{V2Response, NextAction};

/// Get real system information
pub async fn get_system_info(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    // Get real metrics
    let metrics = &state.metrics;
    
    // Get kernel info
    let kernel_info = {
        let kernel = state.kernel.lock().unwrap();
        (
            kernel.agents().len(),
            kernel.packet_count(),
        )
    };
    
    let info = SystemInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        uptime_hours: Some(crate::boot::uptime_secs() / 3600),
        start_time: boot_start_rfc3339(),
        license: LicenseInfo {
            tier: format!("{:?}", state.license.tier),
            valid_until: state.license.valid_until
                .and_then(|ts| chrono::DateTime::from_timestamp(ts / 1000, 0))
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|| "never".to_string()),
            features: vec![
                "agents".to_string(),
                "memory".to_string(),
                "tools".to_string(),
                "audit".to_string(),
            ],
        },
        stats: SystemStats {
            total_agents: kernel_info.0 as u64,
            total_packets: kernel_info.1 as u64,
            total_executions: metrics.requests_total.get(),
            active_deployments: metrics.agents_active.get(),
        },
    };
    
    V2Response::success(info)
}

/// Get real system health
pub async fn get_system_health(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    // Real health checks
    let kernel_healthy = {
        let kernel = state.kernel.lock().unwrap();
        !kernel.agents().is_empty() || kernel.packet_count() > 0
    };
    
    let store_healthy = {
        let engine_store = state.engine_store.lock().unwrap();
        engine_store.folder_exists("system").is_ok()
    };
    
    // Calculate real health score
    let score = if kernel_healthy && store_healthy { 100 } else { 0 };
    
    let health = SystemHealth {
        status: if score > 80 { "healthy".to_string() } else { "degraded".to_string() },
        score: score as u32,
        checks: vec![
            HealthCheck {
                name: "kernel".to_string(),
                healthy: kernel_healthy,
                message: if kernel_healthy { "Kernel active".to_string() } else { "Kernel empty".to_string() },
                last_check: Utc::now().to_rfc3339(),
            },
            HealthCheck {
                name: "storage".to_string(),
                healthy: store_healthy,
                message: if store_healthy { "Storage accessible".to_string() } else { "Storage error".to_string() },
                last_check: Utc::now().to_rfc3339(),
            },
            // A "guard_pipeline" check used to be reported here as healthy:true
            // without probing anything. Only checks that actually run are listed.
        ],
        components: vec![
            ComponentHealth {
                name: "api".to_string(),
                status: "up".to_string(),
                latency_ms: None,
            },
            ComponentHealth {
                name: "kernel".to_string(),
                status: if kernel_healthy { "up".to_string() } else { "down".to_string() },
                latency_ms: None,
            },
        ],
    };
    
    V2Response::success(health)
}

/// Get real system metrics from Prometheus
pub async fn get_system_metrics(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    let metrics = &state.metrics;
    
    let (cpu_percent, memory_percent, disk_percent) = host_resource_sample(&state.config.data_dir);
    let system_metrics = SystemMetrics {
        cpu_percent,
        memory_percent,
        disk_percent,
        network_in_mbps: None,
        network_out_mbps: None,
        agent_count: metrics.agents_active.get(),
        execution_count: metrics.requests_total.get(),
        deployment_count: metrics.agents_active.get(),
        active_sessions: state.user_store.lock().unwrap().users.len(),
        tokens_consumed: metrics.tokens_consumed_total.get(),
        llm_calls: metrics.llm_calls_total.get(),
        trust_score: metrics.trust_score.get(),
    };
    
    V2Response::success(system_metrics)
}

/// Get system logs from real sources
pub async fn get_system_logs(
    State(state): State<SharedState>,
    Query(params): Query<SystemLogsQuery>,
) -> impl IntoResponse {
    // Get from engine store if available
    let logs = {
        let engine_store = state.engine_store.lock().unwrap();
        engine_store.folder_get("system_logs", "recent").ok().flatten()
    };
    
    let log_entries: Vec<SystemLogEntry> = if let Some(stored) = logs {
        serde_json::from_value(stored).unwrap_or_default()
    } else {
        vec![]
    };
    
    let response = serde_json::json!({
        "logs": log_entries,
        "total": log_entries.len(),
    });
    
    V2Response::success(response)
}

/// POST /api/v2/system/backup — gzip tar of `config.data_dir` (same tree as `connectorctl backup`).
///
/// The archive is written next to the data directory, not inside it, so the
/// snapshot cannot recurse into itself. There is no download route; the
/// response reports the local path, size and SHA-256.
pub async fn create_backup(State(state): State<SharedState>) -> impl IntoResponse {
    match snapshot_data_dir(&state.config.data_dir) {
        Ok(backup) => V2Response::success(backup).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            V2Response::<()>::error_with_hint(
                "backup_failed",
                &e,
                "The data directory must exist and be readable. Same tree as `connectorctl backup`.",
            ),
        )
            .into_response(),
    }
}

fn snapshot_data_dir(data_dir: &str) -> Result<BackupResponse, String> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::{BufWriter, Write};
    use std::path::Path;

    let data_path = Path::new(data_dir);
    if !data_path.is_dir() {
        return Err(format!(
            "data_dir missing or not a directory: {data_dir} (see docs/TRUST_DOMAIN_BACKUP.md)"
        ));
    }

    let parent = data_path.parent().filter(|p| !p.as_os_str().is_empty());
    let backup_root = match parent {
        Some(p) => p.join("connector-backups"),
        None => Path::new("connector-backups").to_path_buf(),
    };
    std::fs::create_dir_all(&backup_root)
        .map_err(|e| format!("create backup directory {}: {e}", backup_root.display()))?;

    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let name = format!("backup-{stamp}.tar.gz");
    let dest = backup_root.join(&name);
    let file = File::create(&dest).map_err(|e| format!("create {}: {e}", dest.display()))?;
    let enc = GzEncoder::new(BufWriter::new(file), Compression::default());
    let mut tar = tar::Builder::new(enc);
    tar.append_dir_all(".", data_path)
        .map_err(|e| format!("archive {}: {e}", data_path.display()))?;
    let enc = tar
        .into_inner()
        .map_err(|e| format!("finish tar {}: {e}", dest.display()))?;
    enc.finish()
        .map_err(|e| format!("finish gzip {}: {e}", dest.display()))?
        .flush()
        .map_err(|e| format!("flush {}: {e}", dest.display()))?;

    let bytes = std::fs::read(&dest).map_err(|e| format!("read {}: {e}", dest.display()))?;
    let size_bytes = bytes.len() as u64;
    let sha256 = format!("{:x}", Sha256::digest(&bytes));

    let includes: Vec<String> = std::fs::read_dir(data_path)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();

    Ok(BackupResponse {
        backup_id: name,
        size_bytes,
        sha256,
        path: dest.display().to_string(),
        created_at: Utc::now().to_rfc3339(),
        includes,
        download_url: None,
        honesty: "Local gzip tar of config.data_dir. No HTTP download route is mounted.".to_string(),
    })
}

/// GET /api/v2/system/upgrade — current build only; no update channel is wired.
///
/// `latest_version` used to be the hardcoded string "2.1.0", which made
/// `update_available` a comparison against a version that was never published.
pub async fn check_upgrade(State(_state): State<SharedState>) -> impl IntoResponse {
    let status = UpgradeStatus {
        current_version: env!("CARGO_PKG_VERSION").to_string(),
        latest_version: None,
        update_available: None,
        release_notes: None,
    };

    V2Response::success(status)
}

// Types
#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub version: String,
    pub build: String,
    pub platform: String,
    pub arch: String,
    pub uptime_hours: Option<u64>,
    pub start_time: Option<String>,
    pub license: LicenseInfo,
    pub stats: SystemStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemStats {
    pub total_agents: u64,
    pub total_packets: u64,
    pub total_executions: u64,
    pub active_deployments: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LicenseInfo {
    pub tier: String,
    pub valid_until: String,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemHealth {
    pub status: String,
    pub score: u32,
    pub checks: Vec<HealthCheck>,
    pub components: Vec<ComponentHealth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthCheck {
    pub name: String,
    pub healthy: bool,
    pub message: String,
    pub last_check: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: String,
    /// Present only when a latency probe actually ran.
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemMetrics {
    /// Host sample from /proc (Linux) or null when unmeasured.
    pub cpu_percent: Option<f64>,
    pub memory_percent: Option<f64>,
    pub disk_percent: Option<f64>,
    pub network_in_mbps: Option<f64>,
    pub network_out_mbps: Option<f64>,
    pub agent_count: i64,
    pub execution_count: u64,
    pub deployment_count: i64,
    pub active_sessions: usize,
    pub tokens_consumed: u64,
    pub llm_calls: u64,
    pub trust_score: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SystemLogsQuery {
    #[serde(default = "default_lines")]
    lines: usize,
    #[serde(default)]
    level: Option<String>,
}

fn default_lines() -> usize { 100 }

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemLogEntry {
    pub timestamp: String,
    pub level: String,
    pub component: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupResponse {
    pub backup_id: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub path: String,
    pub created_at: String,
    pub includes: Vec<String>,
    /// Always null — there is no download endpoint for this snapshot.
    pub download_url: Option<String>,
    pub honesty: String,
}

fn boot_start_rfc3339() -> Option<String> {
    use std::sync::atomic::Ordering;
    let ms = crate::boot::BOOT_START_MS.load(Ordering::SeqCst);
    if ms == 0 {
        return None;
    }
    chrono::DateTime::from_timestamp((ms / 1000) as i64, ((ms % 1000) * 1_000_000) as u32)
        .map(|d| d.to_rfc3339())
}

/// Linux /proc + statvfs. Other OS: all null (unmeasured, not zero).
fn host_resource_sample(data_dir: &str) -> (Option<f64>, Option<f64>, Option<f64>) {
    #[cfg(target_os = "linux")]
    {
        (sample_cpu_percent(), mem_percent(), disk_percent(data_dir))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = data_dir;
        (None, None, None)
    }
}

#[cfg(target_os = "linux")]
fn read_cpu_times() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "cpu" {
        return None;
    }
    let mut nums = Vec::new();
    for p in parts {
        nums.push(p.parse::<u64>().ok()?);
    }
    if nums.len() < 4 {
        return None;
    }
    let idle = nums[3] + nums.get(4).copied().unwrap_or(0);
    let total: u64 = nums.iter().sum();
    Some((idle, total))
}

#[cfg(target_os = "linux")]
fn sample_cpu_percent() -> Option<f64> {
    let (idle1, total1) = read_cpu_times()?;
    std::thread::sleep(std::time::Duration::from_millis(100));
    let (idle2, total2) = read_cpu_times()?;
    let dt = total2.saturating_sub(total1);
    if dt == 0 {
        return None;
    }
    let di = idle2.saturating_sub(idle1);
    Some(((dt - di) as f64 / dt as f64) * 100.0)
}

#[cfg(target_os = "linux")]
fn mem_percent() -> Option<f64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = None;
    let mut avail = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = rest.split_whitespace().next().and_then(|n| n.parse::<f64>().ok());
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail = rest.split_whitespace().next().and_then(|n| n.parse::<f64>().ok());
        }
    }
    let total = total.filter(|t| *t > 0.0)?;
    let avail = avail?;
    Some(((total - avail) / total) * 100.0)
}

#[cfg(target_os = "linux")]
fn disk_percent(data_dir: &str) -> Option<f64> {
    let cpath = std::ffi::CString::new(data_dir).ok()?;
    unsafe {
        let mut s: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(cpath.as_ptr(), &mut s) != 0 {
            return None;
        }
        if s.f_blocks == 0 {
            return None;
        }
        let used = s.f_blocks.saturating_sub(s.f_bavail);
        Some((used as f64 / s.f_blocks as f64) * 100.0)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UpgradeStatus {
    pub current_version: String,
    /// Null until an update channel is configured — never a guessed version.
    pub latest_version: Option<String>,
    pub update_available: Option<bool>,
    pub release_notes: Option<String>,
}
