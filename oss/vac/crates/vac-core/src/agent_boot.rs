//! # Agent Boot System
//!
//! Graceful agent initialization with staged boot, sandbox setup,
//! health verification, and proper failure handling.
//!
//! ## Boot Stages
//!
//! | Stage | Name | Description |
//! |-------|------|-------------|
//! | 0 | INIT | Agent control block created |
//! | 1 | SANDBOX | Sandbox environment prepared |
//! | 2 | MEMORY | Memory region allocated |
//! | 3 | CONTEXT | Execution context initialized |
//! | 4 | CAPABILITIES | Capabilities verified |
//! | 5 | TOOLS | Tool bindings validated |
//! | 6 | HEALTH | Health check passed |
//! | 7 | READY | Agent ready for work |
//!
//! ## Failure Modes
//!
//! Each stage can fail with detailed diagnostics:
//! - `BootError::SandboxFailed` — Isolation setup failed
//! - `BootError::MemoryAllocationFailed` — Quota exceeded or region unavailable
//! - `BootError::CapabilityDenied` — Required capability not granted
//! - `BootError::ToolBindingFailed` — Tool not available or access denied
//! - `BootError::HealthCheckFailed` — Agent failed readiness probe
//! - `BootError::Timeout` — Boot took too long

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Get current timestamp in milliseconds
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Total number of agent boot stages
pub const AGENT_BOOT_STAGES: u8 = 8;

/// Boot stage names
pub const AGENT_BOOT_STAGE_NAMES: [&str; 8] = [
    "INIT",
    "SANDBOX",
    "MEMORY",
    "CONTEXT",
    "CAPABILITIES",
    "TOOLS",
    "HEALTH",
    "READY",
];

/// Agent boot stage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentBootStage {
    /// Stage 0: Agent control block created
    Init = 0,
    /// Stage 1: Sandbox environment prepared
    Sandbox = 1,
    /// Stage 2: Memory region allocated
    Memory = 2,
    /// Stage 3: Execution context initialized
    Context = 3,
    /// Stage 4: Capabilities verified
    Capabilities = 4,
    /// Stage 5: Tool bindings validated
    Tools = 5,
    /// Stage 6: Health check passed
    Health = 6,
    /// Stage 7: Agent ready for work
    Ready = 7,
}

impl AgentBootStage {
    pub fn name(&self) -> &'static str {
        AGENT_BOOT_STAGE_NAMES[*self as usize]
    }

    pub fn next(&self) -> Option<AgentBootStage> {
        match self {
            AgentBootStage::Init => Some(AgentBootStage::Sandbox),
            AgentBootStage::Sandbox => Some(AgentBootStage::Memory),
            AgentBootStage::Memory => Some(AgentBootStage::Context),
            AgentBootStage::Context => Some(AgentBootStage::Capabilities),
            AgentBootStage::Capabilities => Some(AgentBootStage::Tools),
            AgentBootStage::Tools => Some(AgentBootStage::Health),
            AgentBootStage::Health => Some(AgentBootStage::Ready),
            AgentBootStage::Ready => None,
        }
    }
}

impl std::fmt::Display for AgentBootStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Agent boot error with detailed diagnostics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBootError {
    /// Stage where boot failed
    pub stage: AgentBootStage,
    /// Error category
    pub kind: BootErrorKind,
    /// Human-readable error message
    pub message: String,
    /// Detailed diagnostics for investigation
    pub diagnostics: Vec<String>,
    /// Suggested remediation steps
    pub remediation: Vec<String>,
    /// Whether the error is recoverable
    pub recoverable: bool,
    /// Timestamp when error occurred
    pub timestamp: i64,
}

impl AgentBootError {
    pub fn new(stage: AgentBootStage, kind: BootErrorKind, message: impl Into<String>) -> Self {
        Self {
            stage,
            kind,
            message: message.into(),
            diagnostics: vec![],
            remediation: vec![],
            recoverable: kind.is_recoverable(),
            timestamp: now_ms(),
        }
    }

    pub fn with_diagnostic(mut self, diagnostic: impl Into<String>) -> Self {
        self.diagnostics.push(diagnostic.into());
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation.push(remediation.into());
        self
    }

    /// Format error for logging
    pub fn to_log_string(&self) -> String {
        let mut s = format!(
            "[AGENT BOOT FAILED] Stage: {} | Kind: {:?} | Message: {}",
            self.stage, self.kind, self.message
        );
        if !self.diagnostics.is_empty() {
            s.push_str("\n  Diagnostics:");
            for d in &self.diagnostics {
                s.push_str(&format!("\n    - {}", d));
            }
        }
        if !self.remediation.is_empty() {
            s.push_str("\n  Remediation:");
            for r in &self.remediation {
                s.push_str(&format!("\n    - {}", r));
            }
        }
        s
    }
}

impl std::fmt::Display for AgentBootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} (stage: {})", self.kind, self.message, self.stage)
    }
}

impl std::error::Error for AgentBootError {}

/// Boot error categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootErrorKind {
    /// Sandbox isolation setup failed
    SandboxFailed,
    /// Memory allocation failed (quota exceeded)
    MemoryAllocationFailed,
    /// Execution context creation failed
    ContextCreationFailed,
    /// Required capability not granted
    CapabilityDenied,
    /// Tool binding failed
    ToolBindingFailed,
    /// Health check failed
    HealthCheckFailed,
    /// Boot timeout exceeded
    Timeout,
    /// Configuration error
    ConfigurationError,
    /// Internal error
    InternalError,
}

impl BootErrorKind {
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            BootErrorKind::Timeout
                | BootErrorKind::HealthCheckFailed
                | BootErrorKind::ToolBindingFailed
        )
    }
}

impl std::fmt::Display for BootErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootErrorKind::SandboxFailed => write!(f, "SandboxFailed"),
            BootErrorKind::MemoryAllocationFailed => write!(f, "MemoryAllocationFailed"),
            BootErrorKind::ContextCreationFailed => write!(f, "ContextCreationFailed"),
            BootErrorKind::CapabilityDenied => write!(f, "CapabilityDenied"),
            BootErrorKind::ToolBindingFailed => write!(f, "ToolBindingFailed"),
            BootErrorKind::HealthCheckFailed => write!(f, "HealthCheckFailed"),
            BootErrorKind::Timeout => write!(f, "Timeout"),
            BootErrorKind::ConfigurationError => write!(f, "ConfigurationError"),
            BootErrorKind::InternalError => write!(f, "InternalError"),
        }
    }
}

/// Agent boot configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBootConfig {
    /// Maximum time allowed for boot (ms)
    pub boot_timeout_ms: u64,
    /// Whether to run health check after boot
    pub health_check_enabled: bool,
    /// Number of health check retries
    pub health_check_retries: u8,
    /// Delay between health check retries (ms)
    pub health_check_retry_delay_ms: u64,
    /// Whether sandbox is required
    pub sandbox_required: bool,
    /// Sandbox resource limits
    pub sandbox_limits: SandboxLimits,
    /// Required capabilities (must all be granted)
    pub required_capabilities: Vec<String>,
    /// Required tools (must all be available)
    pub required_tools: Vec<String>,
    /// Memory quota (packets)
    pub memory_quota_packets: u64,
    /// Memory quota (tokens)
    pub memory_quota_tokens: u64,
}

impl Default for AgentBootConfig {
    fn default() -> Self {
        Self {
            boot_timeout_ms: 30_000, // 30 seconds
            health_check_enabled: true,
            health_check_retries: 3,
            health_check_retry_delay_ms: 1000,
            sandbox_required: true,
            sandbox_limits: SandboxLimits::default(),
            required_capabilities: vec![],
            required_tools: vec![],
            memory_quota_packets: 10_000,
            memory_quota_tokens: 1_000_000,
        }
    }
}

/// Sandbox resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxLimits {
    /// Maximum CPU time (ms per second)
    pub cpu_limit_ms: u64,
    /// Maximum memory (bytes)
    pub memory_limit_bytes: u64,
    /// Maximum file descriptors
    pub max_fds: u32,
    /// Maximum network connections
    pub max_connections: u32,
    /// Allowed syscalls (empty = all allowed)
    pub allowed_syscalls: Vec<String>,
    /// Blocked syscalls
    pub blocked_syscalls: Vec<String>,
    /// Network access allowed
    pub network_allowed: bool,
    /// Filesystem access allowed
    pub filesystem_allowed: bool,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            cpu_limit_ms: 800, // 80% of one core
            memory_limit_bytes: 512 * 1024 * 1024, // 512 MB
            max_fds: 256,
            max_connections: 64,
            allowed_syscalls: vec![],
            blocked_syscalls: vec![],
            network_allowed: true,
            filesystem_allowed: false,
        }
    }
}

/// Agent boot state — tracks boot progress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBootState {
    /// Agent PID
    pub agent_pid: String,
    /// Current boot stage
    pub current_stage: AgentBootStage,
    /// Completed stages (bitmask)
    pub completed_stages: u8,
    /// Stage timings (stage → duration_ms)
    pub stage_timings: HashMap<u8, u64>,
    /// Boot start time
    pub boot_started_at: i64,
    /// Boot end time (if complete)
    pub boot_completed_at: Option<i64>,
    /// Boot error (if failed)
    pub boot_error: Option<AgentBootError>,
    /// Whether boot is complete
    pub is_complete: bool,
    /// Whether boot succeeded
    pub is_success: bool,
    /// Sandbox state
    pub sandbox_state: SandboxState,
    /// Health check results
    pub health_checks: Vec<HealthCheckResult>,
}

impl AgentBootState {
    pub fn new(agent_pid: String) -> Self {
        Self {
            agent_pid,
            current_stage: AgentBootStage::Init,
            completed_stages: 0,
            stage_timings: HashMap::new(),
            boot_started_at: now_ms(),
            boot_completed_at: None,
            boot_error: None,
            is_complete: false,
            is_success: false,
            sandbox_state: SandboxState::default(),
            health_checks: vec![],
        }
    }

    /// Mark a stage as complete
    pub fn complete_stage(&mut self, stage: AgentBootStage, duration_ms: u64) {
        self.completed_stages |= 1 << (stage as u8);
        self.stage_timings.insert(stage as u8, duration_ms);
        
        if let Some(next) = stage.next() {
            self.current_stage = next;
        } else {
            // All stages complete
            self.is_complete = true;
            self.is_success = true;
            self.boot_completed_at = Some(now_ms());
        }
    }

    /// Mark boot as failed
    pub fn fail(&mut self, error: AgentBootError) {
        self.is_complete = true;
        self.is_success = false;
        self.boot_completed_at = Some(now_ms());
        self.boot_error = Some(error);
    }

    /// Check if a stage is complete
    pub fn is_stage_complete(&self, stage: AgentBootStage) -> bool {
        (self.completed_stages & (1 << (stage as u8))) != 0
    }

    /// Get boot progress percentage
    pub fn progress_percent(&self) -> u8 {
        let complete_count = self.completed_stages.count_ones() as u8;
        ((complete_count as u16 * 100) / AGENT_BOOT_STAGES as u16) as u8
    }

    /// Get total boot duration
    pub fn total_duration_ms(&self) -> u64 {
        let end = self.boot_completed_at
            .unwrap_or_else(|| now_ms());
        (end - self.boot_started_at).max(0) as u64
    }

    /// Format boot state for logging
    pub fn to_log_string(&self) -> String {
        if self.is_success {
            format!(
                "[AGENT BOOT OK] pid={} stages={}/{} duration={}ms",
                self.agent_pid,
                self.completed_stages.count_ones(),
                AGENT_BOOT_STAGES,
                self.total_duration_ms()
            )
        } else if let Some(ref err) = self.boot_error {
            format!(
                "[AGENT BOOT FAILED] pid={} stage={} error={} duration={}ms",
                self.agent_pid,
                err.stage,
                err.kind,
                self.total_duration_ms()
            )
        } else {
            format!(
                "[AGENT BOOT IN PROGRESS] pid={} stage={} progress={}%",
                self.agent_pid,
                self.current_stage,
                self.progress_percent()
            )
        }
    }
}

/// Sandbox state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxState {
    /// Whether sandbox is active
    pub active: bool,
    /// Sandbox ID
    pub sandbox_id: Option<String>,
    /// Resource limits applied
    pub limits: Option<SandboxLimits>,
    /// Isolation level
    pub isolation_level: IsolationLevel,
    /// Violations detected
    pub violations: Vec<SandboxViolation>,
}

/// Isolation level
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationLevel {
    /// No isolation (development mode)
    #[default]
    None,
    /// Process-level isolation
    Process,
    /// Container-level isolation
    Container,
    /// VM-level isolation
    VirtualMachine,
}

/// Sandbox violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxViolation {
    /// Violation type
    pub kind: ViolationKind,
    /// Description
    pub description: String,
    /// Timestamp
    pub timestamp: i64,
    /// Whether violation was blocked
    pub blocked: bool,
}

/// Violation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// CPU limit exceeded
    CpuLimitExceeded,
    /// Memory limit exceeded
    MemoryLimitExceeded,
    /// File descriptor limit exceeded
    FdLimitExceeded,
    /// Network access denied
    NetworkAccessDenied,
    /// Filesystem access denied
    FilesystemAccessDenied,
    /// Syscall blocked
    SyscallBlocked,
    /// Resource exhaustion
    ResourceExhaustion,
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Check name
    pub name: String,
    /// Whether check passed
    pub passed: bool,
    /// Check duration (ms)
    pub duration_ms: u64,
    /// Error message if failed
    pub error: Option<String>,
    /// Timestamp
    pub timestamp: i64,
}

/// Agent boot manager — orchestrates the boot process
pub struct AgentBootManager {
    /// Boot configuration
    config: AgentBootConfig,
}

impl AgentBootManager {
    pub fn new(config: AgentBootConfig) -> Self {
        Self { config }
    }

    pub fn with_default_config() -> Self {
        Self::new(AgentBootConfig::default())
    }

    /// Execute the full boot sequence
    pub fn boot(&self, agent_pid: &str) -> Result<AgentBootState, AgentBootError> {
        let mut state = AgentBootState::new(agent_pid.to_string());
        let boot_start = Instant::now();
        let timeout = Duration::from_millis(self.config.boot_timeout_ms);

        tracing::info!(
            agent_pid = %agent_pid,
            timeout_ms = self.config.boot_timeout_ms,
            "[agent_boot] Starting boot sequence"
        );

        // Stage 0: INIT (already done when ACB created)
        self.execute_stage(&mut state, AgentBootStage::Init, boot_start, timeout)?;

        // Stage 1: SANDBOX
        self.execute_stage(&mut state, AgentBootStage::Sandbox, boot_start, timeout)?;

        // Stage 2: MEMORY
        self.execute_stage(&mut state, AgentBootStage::Memory, boot_start, timeout)?;

        // Stage 3: CONTEXT
        self.execute_stage(&mut state, AgentBootStage::Context, boot_start, timeout)?;

        // Stage 4: CAPABILITIES
        self.execute_stage(&mut state, AgentBootStage::Capabilities, boot_start, timeout)?;

        // Stage 5: TOOLS
        self.execute_stage(&mut state, AgentBootStage::Tools, boot_start, timeout)?;

        // Stage 6: HEALTH
        if self.config.health_check_enabled {
            self.execute_stage(&mut state, AgentBootStage::Health, boot_start, timeout)?;
        } else {
            state.complete_stage(AgentBootStage::Health, 0);
        }

        // Stage 7: READY
        self.execute_stage(&mut state, AgentBootStage::Ready, boot_start, timeout)?;

        tracing::info!(
            agent_pid = %agent_pid,
            duration_ms = state.total_duration_ms(),
            "[agent_boot] Boot complete"
        );

        Ok(state)
    }

    /// Execute a single boot stage with timeout checking
    fn execute_stage(
        &self,
        state: &mut AgentBootState,
        stage: AgentBootStage,
        boot_start: Instant,
        timeout: Duration,
    ) -> Result<(), AgentBootError> {
        // Check timeout
        if boot_start.elapsed() > timeout {
            let err = AgentBootError::new(
                stage,
                BootErrorKind::Timeout,
                format!("Boot timeout exceeded at stage {}", stage),
            )
            .with_diagnostic(format!("Timeout: {}ms", timeout.as_millis()))
            .with_diagnostic(format!("Elapsed: {}ms", boot_start.elapsed().as_millis()))
            .with_remediation("Increase boot_timeout_ms in agent config")
            .with_remediation("Check for slow dependencies (network, storage)");

            state.fail(err.clone());
            tracing::error!(
                agent_pid = %state.agent_pid,
                stage = %stage,
                "[agent_boot] Timeout"
            );
            return Err(err);
        }

        let stage_start = Instant::now();
        tracing::debug!(
            agent_pid = %state.agent_pid,
            stage = %stage,
            "[agent_boot] Starting stage"
        );

        // Execute the stage-specific logic
        let result = match stage {
            AgentBootStage::Init => Ok(()),
            AgentBootStage::Sandbox => self.setup_sandbox(state),
            AgentBootStage::Memory => self.allocate_memory(&state.agent_pid),
            AgentBootStage::Context => self.create_context(&state.agent_pid),
            AgentBootStage::Capabilities => self.verify_capabilities(&state.agent_pid),
            AgentBootStage::Tools => self.validate_tools(&state.agent_pid),
            AgentBootStage::Health => self.run_health_checks(state),
            AgentBootStage::Ready => Ok(()),
        };

        match result {
            Ok(()) => {
                let duration_ms = stage_start.elapsed().as_millis() as u64;
                state.complete_stage(stage, duration_ms);
                tracing::debug!(
                    agent_pid = %state.agent_pid,
                    stage = %stage,
                    duration_ms = duration_ms,
                    "[agent_boot] Stage complete"
                );
                Ok(())
            }
            Err(err) => {
                state.fail(err.clone());
                tracing::error!(
                    agent_pid = %state.agent_pid,
                    stage = %stage,
                    error = %err,
                    "[agent_boot] Stage failed"
                );
                Err(err)
            }
        }
    }

    /// Stage 1: Setup sandbox
    fn setup_sandbox(&self, state: &mut AgentBootState) -> Result<(), AgentBootError> {
        if !self.config.sandbox_required {
            state.sandbox_state.active = false;
            state.sandbox_state.isolation_level = IsolationLevel::None;
            return Ok(());
        }

        // Generate sandbox ID
        let sandbox_id = format!("sbx-{}-{}", state.agent_pid, now_ms());

        // Apply limits
        state.sandbox_state = SandboxState {
            active: true,
            sandbox_id: Some(sandbox_id),
            limits: Some(self.config.sandbox_limits.clone()),
            isolation_level: IsolationLevel::Process,
            violations: vec![],
        };

        // In a real implementation, this would:
        // - Create cgroup for resource limits
        // - Set up seccomp filters
        // - Configure namespace isolation
        // - Apply network policies

        Ok(())
    }

    /// Stage 2: Allocate memory region
    fn allocate_memory(&self, _agent_pid: &str) -> Result<(), AgentBootError> {
        // Verify quotas are within limits
        if self.config.memory_quota_packets == 0 {
            return Err(AgentBootError::new(
                AgentBootStage::Memory,
                BootErrorKind::MemoryAllocationFailed,
                "Memory quota cannot be zero",
            )
            .with_diagnostic("memory_quota_packets = 0")
            .with_remediation("Set memory_quota_packets > 0 in agent config"));
        }

        // In a real implementation, this would:
        // - Reserve memory region in kernel
        // - Set up quota tracking
        // - Initialize eviction policy

        Ok(())
    }

    /// Stage 3: Create execution context
    fn create_context(&self, _agent_pid: &str) -> Result<(), AgentBootError> {
        // In a real implementation, this would:
        // - Create ExecutionContext
        // - Initialize context window
        // - Set up reasoning chain

        Ok(())
    }

    /// Stage 4: Verify capabilities
    fn verify_capabilities(&self, agent_pid: &str) -> Result<(), AgentBootError> {
        for cap in &self.config.required_capabilities {
            // In a real implementation, check UCAN delegation chain
            // For now, just log
            tracing::debug!(
                agent_pid = %agent_pid,
                capability = %cap,
                "[agent_boot] Verifying capability"
            );
        }

        Ok(())
    }

    /// Stage 5: Validate tool bindings
    fn validate_tools(&self, agent_pid: &str) -> Result<(), AgentBootError> {
        for tool in &self.config.required_tools {
            // In a real implementation, check tool registry
            tracing::debug!(
                agent_pid = %agent_pid,
                tool = %tool,
                "[agent_boot] Validating tool binding"
            );
        }

        Ok(())
    }

    /// Stage 6: Run health checks
    fn run_health_checks(&self, state: &mut AgentBootState) -> Result<(), AgentBootError> {
        let checks = vec![
            ("memory_accessible", self.check_memory_accessible(state)),
            ("context_valid", self.check_context_valid(state)),
            ("sandbox_stable", self.check_sandbox_stable(state)),
        ];

        let mut all_passed = true;
        for (name, result) in checks {
            let check_result = HealthCheckResult {
                name: name.to_string(),
                passed: result.is_ok(),
                duration_ms: 0, // Would measure in real impl
                error: result.err().map(|e| e.to_string()),
                timestamp: now_ms(),
            };
            
            if !check_result.passed {
                all_passed = false;
                tracing::warn!(
                    agent_pid = %state.agent_pid,
                    check = %name,
                    error = ?check_result.error,
                    "[agent_boot] Health check failed"
                );
            }
            
            state.health_checks.push(check_result);
        }

        if !all_passed {
            // Retry logic
            for retry in 0..self.config.health_check_retries {
                std::thread::sleep(Duration::from_millis(self.config.health_check_retry_delay_ms));
                
                tracing::debug!(
                    agent_pid = %state.agent_pid,
                    retry = retry + 1,
                    "[agent_boot] Retrying health checks"
                );

                // Re-run failed checks
                let recheck_passed = state.health_checks.iter()
                    .filter(|c| !c.passed)
                    .all(|c| {
                        match c.name.as_str() {
                            "memory_accessible" => self.check_memory_accessible(state).is_ok(),
                            "context_valid" => self.check_context_valid(state).is_ok(),
                            "sandbox_stable" => self.check_sandbox_stable(state).is_ok(),
                            _ => true,
                        }
                    });

                if recheck_passed {
                    return Ok(());
                }
            }

            return Err(AgentBootError::new(
                AgentBootStage::Health,
                BootErrorKind::HealthCheckFailed,
                "Health checks failed after retries",
            )
            .with_diagnostic(format!(
                "Failed checks: {:?}",
                state.health_checks.iter()
                    .filter(|c| !c.passed)
                    .map(|c| &c.name)
                    .collect::<Vec<_>>()
            ))
            .with_remediation("Check agent configuration")
            .with_remediation("Verify resource availability"));
        }

        Ok(())
    }

    fn check_memory_accessible(&self, _state: &AgentBootState) -> Result<(), String> {
        // Would verify memory region is accessible
        Ok(())
    }

    fn check_context_valid(&self, _state: &AgentBootState) -> Result<(), String> {
        // Would verify execution context is valid
        Ok(())
    }

    fn check_sandbox_stable(&self, state: &AgentBootState) -> Result<(), String> {
        if state.sandbox_state.active && !state.sandbox_state.violations.is_empty() {
            return Err(format!(
                "Sandbox has {} violations",
                state.sandbox_state.violations.len()
            ));
        }
        Ok(())
    }
}

/// Boot result for external consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentBootResult {
    /// Whether boot succeeded
    pub success: bool,
    /// Agent PID
    pub agent_pid: String,
    /// Boot duration (ms)
    pub duration_ms: u64,
    /// Completed stages
    pub stages_completed: u8,
    /// Error if failed
    pub error: Option<AgentBootError>,
    /// Sandbox info
    pub sandbox: Option<SandboxInfo>,
}

/// Sandbox info for external consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInfo {
    pub active: bool,
    pub sandbox_id: Option<String>,
    pub isolation_level: IsolationLevel,
}

impl From<AgentBootState> for AgentBootResult {
    fn from(state: AgentBootState) -> Self {
        let duration_ms = state.total_duration_ms();
        Self {
            success: state.is_success,
            agent_pid: state.agent_pid,
            duration_ms,
            stages_completed: state.completed_stages.count_ones() as u8,
            error: state.boot_error,
            sandbox: Some(SandboxInfo {
                active: state.sandbox_state.active,
                sandbox_id: state.sandbox_state.sandbox_id,
                isolation_level: state.sandbox_state.isolation_level,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_stages() {
        assert_eq!(AgentBootStage::Init.name(), "INIT");
        assert_eq!(AgentBootStage::Ready.name(), "READY");
        assert_eq!(AgentBootStage::Init.next(), Some(AgentBootStage::Sandbox));
        assert_eq!(AgentBootStage::Ready.next(), None);
    }

    #[test]
    fn test_boot_state_progress() {
        let mut state = AgentBootState::new("test-agent".to_string());
        assert_eq!(state.progress_percent(), 0);

        state.complete_stage(AgentBootStage::Init, 10);
        state.complete_stage(AgentBootStage::Sandbox, 20);
        state.complete_stage(AgentBootStage::Memory, 15);
        state.complete_stage(AgentBootStage::Context, 5);

        assert_eq!(state.progress_percent(), 50);
        assert!(state.is_stage_complete(AgentBootStage::Init));
        assert!(!state.is_stage_complete(AgentBootStage::Ready));
    }

    #[test]
    fn test_boot_error() {
        let err = AgentBootError::new(
            AgentBootStage::Sandbox,
            BootErrorKind::SandboxFailed,
            "Failed to create cgroup",
        )
        .with_diagnostic("cgroup v2 not available")
        .with_remediation("Enable cgroup v2 in kernel");

        assert_eq!(err.stage, AgentBootStage::Sandbox);
        assert!(!err.recoverable);
        assert_eq!(err.diagnostics.len(), 1);
        assert_eq!(err.remediation.len(), 1);
    }

    #[test]
    fn test_boot_manager_success() {
        let manager = AgentBootManager::with_default_config();
        let result = manager.boot("test-agent-1");
        
        assert!(result.is_ok());
        let state = result.unwrap();
        assert!(state.is_success);
        assert_eq!(state.completed_stages.count_ones(), AGENT_BOOT_STAGES as u32);
    }
}
