//! Health probes for Kubernetes-compatible health checks
//!
//! Implements liveness, readiness, and startup probes following
//! Kubernetes conventions.

use super::{is_ready, is_shutting_down, boot_progress, BOOT_STAGES_COMPLETE, BOOT_STAGE_NAMES, BOOT_START_MS};
use std::sync::atomic::Ordering;
use std::time::Instant;

/// Liveness probe result
#[derive(Debug, Clone, serde::Serialize)]
pub struct LivenessProbe {
    pub status: &'static str,
    pub pid: u32,
}

/// Readiness probe result
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReadinessProbe {
    pub status: &'static str,
    pub boot_stages: u16,
    pub boot_complete: bool,
    pub shutting_down: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
}

/// Startup probe result
#[derive(Debug, Clone, serde::Serialize)]
pub struct StartupProbe {
    pub status: &'static str,
    pub stage: u16,
    pub stage_name: &'static str,
    pub progress_percent: u8,
    pub elapsed_ms: u64,
}

/// Full health status
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthStatus {
    pub status: &'static str,
    pub version: &'static str,
    pub node_id: String,
    pub mode: String,
    pub ready: bool,
    pub shutting_down: bool,
    pub boot_progress: u8,
    pub uptime_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subsystems: Option<SubsystemHealth>,
}

/// Subsystem health details
#[derive(Debug, Clone, serde::Serialize)]
pub struct SubsystemHealth {
    pub kernel: bool,
    pub storage: bool,
    pub scheduler: bool,
    pub services: bool,
}

static BOOT_START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

/// Initialize boot start time (call once at startup)
pub fn init_boot_time() {
    let _ = BOOT_START.set(Instant::now());
    let epoch_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    BOOT_START_MS.store(epoch_ms, Ordering::SeqCst);
}

/// Get uptime in seconds
pub fn uptime_secs() -> u64 {
    BOOT_START.get()
        .map(|start| start.elapsed().as_secs())
        .unwrap_or(0)
}

/// Liveness probe — returns true if process is alive and not deadlocked
///
/// This should always return true unless the process is completely stuck.
/// Used by Kubernetes to know when to restart the container.
pub fn liveness_probe() -> LivenessProbe {
    LivenessProbe {
        status: "alive",
        pid: std::process::id(),
    }
}

/// Readiness probe — returns true only when node is ready to accept traffic
///
/// Returns false during boot and shutdown.
/// Used by Kubernetes to know when to send traffic to the pod.
pub fn readiness_probe() -> ReadinessProbe {
    let ready = is_ready();
    let shutting_down = is_shutting_down();
    let stages = BOOT_STAGES_COMPLETE.load(Ordering::SeqCst);
    
    ReadinessProbe {
        status: if ready && !shutting_down { "ready" } else { "not_ready" },
        boot_stages: stages.count_ones() as u16,
        boot_complete: ready,
        shutting_down,
        uptime_secs: if ready { Some(uptime_secs()) } else { None },
    }
}

/// Startup probe — returns true once storage is ready (Stage 3)
///
/// For slow-starting nodes. Kubernetes won't kill the container
/// until this probe succeeds or times out.
pub fn startup_probe() -> StartupProbe {
    let stages = BOOT_STAGES_COMPLETE.load(Ordering::SeqCst);
    let current_stage = stages.trailing_ones() as u16;
    let stage_name = BOOT_STAGE_NAMES.get(current_stage as usize).unwrap_or(&"UNKNOWN");
    
    // Startup is considered complete once storage (stage 3) is ready
    let storage_ready = (stages & (1 << 3)) != 0;
    
    StartupProbe {
        status: if storage_ready { "started" } else { "starting" },
        stage: current_stage,
        stage_name,
        progress_percent: boot_progress(),
        elapsed_ms: BOOT_START.get()
            .map(|start| start.elapsed().as_millis() as u64)
            .unwrap_or(0),
    }
}

/// Full health status — comprehensive health information
pub fn health_status(node_id: &str, mode: &str) -> HealthStatus {
    let stages = BOOT_STAGES_COMPLETE.load(Ordering::SeqCst);
    let ready = is_ready();
    let shutting_down = is_shutting_down();
    
    let subsystems = if ready {
        Some(SubsystemHealth {
            kernel: (stages & (1 << 4)) != 0,   // Stage 4: KERNEL
            storage: (stages & (1 << 3)) != 0,  // Stage 3: STORAGE
            scheduler: (stages & (1 << 6)) != 0, // Stage 6: SCHEDULER
            services: (stages & (1 << 9)) != 0,  // Stage 9: SERVICES
        })
    } else {
        None
    };
    
    let status = if shutting_down {
        "shutting_down"
    } else if ready {
        "healthy"
    } else {
        "starting"
    };
    
    HealthStatus {
        status,
        version: env!("CARGO_PKG_VERSION"),
        node_id: node_id.to_string(),
        mode: mode.to_string(),
        ready,
        shutting_down,
        boot_progress: boot_progress(),
        uptime_secs: uptime_secs(),
        subsystems,
    }
}

/// Check if the node should accept new requests
pub fn should_accept_requests() -> bool {
    is_ready() && !is_shutting_down()
}

/// HTTP status code for readiness probe
pub fn readiness_status_code() -> u16 {
    if should_accept_requests() { 200 } else { 503 }
}

/// HTTP status code for liveness probe
pub fn liveness_status_code() -> u16 {
    200 // Always alive if we can respond
}

/// HTTP status code for startup probe
pub fn startup_status_code() -> u16 {
    let stages = BOOT_STAGES_COMPLETE.load(Ordering::SeqCst);
    let storage_ready = (stages & (1 << 3)) != 0;
    if storage_ready { 200 } else { 503 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_liveness_probe() {
        let probe = liveness_probe();
        assert_eq!(probe.status, "alive");
        assert!(probe.pid > 0);
    }

    #[test]
    fn test_readiness_probe_not_ready() {
        // Reset state
        BOOT_STAGES_COMPLETE.store(0, Ordering::SeqCst);
        super::super::NODE_READY.store(false, Ordering::SeqCst);
        
        let probe = readiness_probe();
        assert_eq!(probe.status, "not_ready");
        assert!(!probe.boot_complete);
    }

    #[test]
    fn test_startup_probe() {
        init_boot_time();
        let probe = startup_probe();
        assert!(probe.stage_name.len() > 0);
    }
}
