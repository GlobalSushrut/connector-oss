//! # Connector Node Boot System
//!
//! 12-stage infrastructure boot for the Connector AI runtime node.
//! Designed for service-grade reliability with systemd integration.
//!
//! ## Boot Stages
//!
//! | Stage | Name | Description |
//! |-------|------|-------------|
//! | 0 | IDENTITY | Node ID, version, mode, environment |
//! | 1 | CONFIG | Configuration loaded, validated |
//! | 2 | SECRETS | Secrets/keys loaded, vault ready |
//! | 3 | STORAGE | Databases opened, WAL ready |
//! | 4 | KERNEL | Memory kernel initialized |
//! | 5 | POLICIES | Default policies registered |
//! | 6 | SCHEDULER | LLM router, admission control |
//! | 7 | CAPABILITIES | UCAN verifier, capability gates |
//! | 8 | RESTORE | Agent snapshots restored |
//! | 9 | SERVICES | Background services started |
//! | 10 | ACCESS | API, UI, metrics endpoints bound |
//! | 11 | READY | Node healthy, workloads schedulable |

mod stages;
mod reporter;
mod probes;
mod recovery;

pub use stages::*;
pub use reporter::*;
pub use probes::*;
pub use recovery::*;

use std::sync::atomic::{AtomicU16, AtomicU64, AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Total number of boot stages
pub const BOOT_STAGE_COUNT: u16 = 12;

/// Boot stage names for display
pub const BOOT_STAGE_NAMES: [&str; 12] = [
    "IDENTITY",
    "CONFIG",
    "SECRETS",
    "STORAGE",
    "KERNEL",
    "POLICIES",
    "SCHEDULER",
    "CAPABILITIES",
    "RESTORE",
    "SERVICES",
    "ACCESS",
    "READY",
];

/// Global boot state — tracks which stages have completed
pub static BOOT_STAGES_COMPLETE: AtomicU16 = AtomicU16::new(0);

/// Global ready flag — set when all stages complete
pub static NODE_READY: AtomicBool = AtomicBool::new(false);

/// Global shutting down flag — set when shutdown initiated
pub static NODE_SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

/// Boot start time in epoch-ms (set once at boot, via init_boot_time)
pub static BOOT_START_MS: AtomicU64 = AtomicU64::new(0);

/// Node identity information
#[derive(Debug, Clone)]
pub struct NodeIdentity {
    pub node_id: String,
    pub version: &'static str,
    pub mode: NodeMode,
    pub environment: String,
    pub machine_id: String,
    pub data_dir: String,
}

/// Node operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    Production,
    Development,
    Local,
    AirGap,
}

/// Node topology
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeTopology {
    SingleNode,
    Distributed,
}

impl std::fmt::Display for NodeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeMode::Production => write!(f, "production"),
            NodeMode::Development => write!(f, "development"),
            NodeMode::Local => write!(f, "local"),
            NodeMode::AirGap => write!(f, "airgap"),
        }
    }
}

impl std::fmt::Display for NodeTopology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeTopology::SingleNode => write!(f, "single-node"),
            NodeTopology::Distributed => write!(f, "distributed"),
        }
    }
}

/// Boot stage result
#[derive(Debug, Clone)]
pub struct StageResult {
    pub stage: u16,
    pub name: &'static str,
    pub success: bool,
    pub duration: Duration,
    pub message: String,
    pub details: Vec<String>,
}

impl StageResult {
    pub fn ok(stage: u16, duration: Duration, message: impl Into<String>) -> Self {
        Self {
            stage,
            name: BOOT_STAGE_NAMES.get(stage as usize).unwrap_or(&"UNKNOWN"),
            success: true,
            duration,
            message: message.into(),
            details: vec![],
        }
    }

    pub fn ok_with_details(stage: u16, duration: Duration, message: impl Into<String>, details: Vec<String>) -> Self {
        Self {
            stage,
            name: BOOT_STAGE_NAMES.get(stage as usize).unwrap_or(&"UNKNOWN"),
            success: true,
            duration,
            message: message.into(),
            details,
        }
    }

    pub fn err(stage: u16, duration: Duration, message: impl Into<String>) -> Self {
        Self {
            stage,
            name: BOOT_STAGE_NAMES.get(stage as usize).unwrap_or(&"UNKNOWN"),
            success: false,
            duration,
            message: message.into(),
            details: vec![],
        }
    }
}

/// Mark a boot stage as complete
pub fn complete_stage(stage: u16) {
    if stage < BOOT_STAGE_COUNT {
        BOOT_STAGES_COMPLETE.fetch_or(1 << stage, Ordering::SeqCst);
        
        // Check if all stages complete
        let all_complete = (1u16 << BOOT_STAGE_COUNT) - 1;
        if BOOT_STAGES_COMPLETE.load(Ordering::SeqCst) >= all_complete {
            NODE_READY.store(true, Ordering::SeqCst);
            notify_systemd_ready();
        }
    }
}

/// Check if a specific stage is complete
pub fn is_stage_complete(stage: u16) -> bool {
    if stage >= BOOT_STAGE_COUNT {
        return false;
    }
    (BOOT_STAGES_COMPLETE.load(Ordering::SeqCst) & (1 << stage)) != 0
}

/// Get the current boot progress (0-100)
pub fn boot_progress() -> u8 {
    let complete = BOOT_STAGES_COMPLETE.load(Ordering::SeqCst);
    let count = complete.count_ones() as u8;
    ((count as u16 * 100) / BOOT_STAGE_COUNT) as u8
}

/// Check if node is ready to accept traffic
pub fn is_ready() -> bool {
    NODE_READY.load(Ordering::SeqCst)
}

/// Check if node is shutting down
pub fn is_shutting_down() -> bool {
    NODE_SHUTTING_DOWN.load(Ordering::SeqCst)
}

/// Mark node as shutting down
pub fn begin_shutdown() {
    NODE_SHUTTING_DOWN.store(true, Ordering::SeqCst);
    NODE_READY.store(false, Ordering::SeqCst);
    notify_systemd_stopping();
}

/// Called from `main` when PLATFORM_READY flips — bridges AMA bitmask boot to sd_notify.
pub fn mark_platform_ready_for_systemd() {
    NODE_READY.store(true, Ordering::SeqCst);
    notify_systemd_ready();
    spawn_watchdog_loop();
}

/// Ping systemd WatchdogSec for the life of the process when WATCHDOG_USEC is set.
fn spawn_watchdog_loop() {
    let Some(timeout) = watchdog_enabled() else {
        return;
    };
    // Ping at half the watchdog interval (systemd recommendation).
    let interval = timeout / 2;
    if interval.is_zero() {
        return;
    }
    std::thread::Builder::new()
        .name("sd-watchdog".into())
        .spawn(move || loop {
            let _ = sd_notify_watchdog();
            std::thread::sleep(interval);
        })
        .ok();
}

/// Notify systemd that we're ready (Type=notify)
fn notify_systemd_ready() {
    #[cfg(target_os = "linux")]
    {
        let _ = sd_notify_ready();
    }
}

/// Notify systemd that we're stopping
fn notify_systemd_stopping() {
    #[cfg(target_os = "linux")]
    {
        let _ = sd_notify_stopping();
    }
}

/// Send sd_notify READY=1
#[cfg(target_os = "linux")]
fn sd_notify_ready() -> std::io::Result<()> {
    // Check if NOTIFY_SOCKET is set (running under systemd)
    if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
        use std::os::unix::net::UnixDatagram;
        let socket = UnixDatagram::unbound()?;
        let path = if socket_path.starts_with('@') {
            // Abstract socket
            format!("\0{}", &socket_path[1..])
        } else {
            socket_path
        };
        socket.send_to(b"READY=1", &path)?;
        tracing::debug!("sd_notify: READY=1");
    }
    Ok(())
}

/// Send sd_notify STOPPING=1
#[cfg(target_os = "linux")]
fn sd_notify_stopping() -> std::io::Result<()> {
    if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
        use std::os::unix::net::UnixDatagram;
        let socket = UnixDatagram::unbound()?;
        let path = if socket_path.starts_with('@') {
            format!("\0{}", &socket_path[1..])
        } else {
            socket_path
        };
        socket.send_to(b"STOPPING=1", &path)?;
        tracing::debug!("sd_notify: STOPPING=1");
    }
    Ok(())
}

/// Send sd_notify STATUS=<message>
#[cfg(target_os = "linux")]
pub fn sd_notify_status(status: &str) -> std::io::Result<()> {
    if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
        use std::os::unix::net::UnixDatagram;
        let socket = UnixDatagram::unbound()?;
        let path = if socket_path.starts_with('@') {
            format!("\0{}", &socket_path[1..])
        } else {
            socket_path
        };
        let msg = format!("STATUS={}", status);
        socket.send_to(msg.as_bytes(), &path)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn sd_notify_status(_status: &str) -> std::io::Result<()> {
    Ok(())
}

/// Send sd_notify WATCHDOG=1 (ping)
#[cfg(target_os = "linux")]
pub fn sd_notify_watchdog() -> std::io::Result<()> {
    if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
        use std::os::unix::net::UnixDatagram;
        let socket = UnixDatagram::unbound()?;
        let path = if socket_path.starts_with('@') {
            format!("\0{}", &socket_path[1..])
        } else {
            socket_path
        };
        socket.send_to(b"WATCHDOG=1", &path)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn sd_notify_watchdog() -> std::io::Result<()> {
    Ok(())
}

/// Check if running under systemd with watchdog enabled
pub fn watchdog_enabled() -> Option<Duration> {
    std::env::var("WATCHDOG_USEC")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|usec| Duration::from_micros(usec))
}

/// Boot context for tracking boot progress
pub struct BootContext {
    pub identity: NodeIdentity,
    pub start_time: Instant,
    pub stages: Vec<StageResult>,
}

impl BootContext {
    pub fn new(identity: NodeIdentity) -> Self {
        Self {
            identity,
            start_time: Instant::now(),
            stages: Vec::with_capacity(BOOT_STAGE_COUNT as usize),
        }
    }

    pub fn record(&mut self, result: StageResult) {
        if result.success {
            complete_stage(result.stage);
        }
        self.stages.push(result);
    }

    pub fn total_duration(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn is_complete(&self) -> bool {
        is_ready()
    }

    pub fn failed_stages(&self) -> Vec<&StageResult> {
        self.stages.iter().filter(|s| !s.success).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage_completion() {
        // Reset state
        BOOT_STAGES_COMPLETE.store(0, Ordering::SeqCst);
        NODE_READY.store(false, Ordering::SeqCst);

        assert!(!is_stage_complete(0));
        complete_stage(0);
        assert!(is_stage_complete(0));
        assert!(!is_ready()); // Not all stages complete
    }

    #[test]
    fn test_boot_progress() {
        BOOT_STAGES_COMPLETE.store(0, Ordering::SeqCst);
        assert_eq!(boot_progress(), 0);

        // Complete 6 stages (50%)
        BOOT_STAGES_COMPLETE.store(0b111111, Ordering::SeqCst);
        assert_eq!(boot_progress(), 50);
    }

    #[test]
    fn test_stage_names() {
        assert_eq!(BOOT_STAGE_NAMES[0], "IDENTITY");
        assert_eq!(BOOT_STAGE_NAMES[11], "READY");
    }
}
