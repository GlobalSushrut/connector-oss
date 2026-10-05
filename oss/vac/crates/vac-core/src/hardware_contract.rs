//! Hardware Contract — POSIX-like resource governance for agents
//!
//! This module implements a comprehensive hardware contract system:
//! - Resource limits (rlimit equivalent)
//! - Scheduling policies (sched_setscheduler equivalent)
//! - Hardware affinity (taskset/numactl equivalent)
//! - I/O priority (ionice equivalent)
//! - Network QoS
//! - Complete AgentHardwareContract specification
//!
//! Design sources: POSIX.1-2017, Linux cgroups v2, Kubernetes resource quotas

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Resource Limits (rlimit)
// =============================================================================

/// Resource limit value
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LimitValue {
    /// Specific limit value
    Value(u64),
    /// Unlimited (RLIM_INFINITY)
    Unlimited,
}

impl LimitValue {
    pub fn is_unlimited(&self) -> bool {
        matches!(self, Self::Unlimited)
    }

    pub fn value(&self) -> Option<u64> {
        match self {
            Self::Value(v) => Some(*v),
            Self::Unlimited => None,
        }
    }

    pub fn exceeds(&self, current: u64) -> bool {
        match self {
            Self::Value(limit) => current > *limit,
            Self::Unlimited => false,
        }
    }
}

impl Default for LimitValue {
    fn default() -> Self {
        Self::Unlimited
    }
}

impl From<u64> for LimitValue {
    fn from(v: u64) -> Self {
        Self::Value(v)
    }
}

/// Resource limit pair (soft/hard)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ResourceLimit {
    /// Soft limit (current)
    pub soft: LimitValue,
    /// Hard limit (maximum)
    pub hard: LimitValue,
}

impl ResourceLimit {
    pub fn new(soft: impl Into<LimitValue>, hard: impl Into<LimitValue>) -> Self {
        Self {
            soft: soft.into(),
            hard: hard.into(),
        }
    }

    pub fn unlimited() -> Self {
        Self {
            soft: LimitValue::Unlimited,
            hard: LimitValue::Unlimited,
        }
    }

    pub fn fixed(value: u64) -> Self {
        Self {
            soft: LimitValue::Value(value),
            hard: LimitValue::Value(value),
        }
    }

    /// Check if current value exceeds soft limit
    pub fn exceeds_soft(&self, current: u64) -> bool {
        self.soft.exceeds(current)
    }

    /// Check if current value exceeds hard limit
    pub fn exceeds_hard(&self, current: u64) -> bool {
        self.hard.exceeds(current)
    }

    /// Get percentage of soft limit used
    pub fn soft_usage_percent(&self, current: u64) -> f32 {
        match self.soft {
            LimitValue::Value(limit) if limit > 0 => (current as f32 / limit as f32) * 100.0,
            _ => 0.0,
        }
    }
}

impl Default for ResourceLimit {
    fn default() -> Self {
        Self::unlimited()
    }
}

/// Agent resource limits — comprehensive rlimit-style limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResourceLimits {
    // --- POSIX-style limits ---
    /// Max CPU time in seconds (RLIMIT_CPU)
    pub cpu_time_sec: ResourceLimit,
    /// Max memory in bytes (RLIMIT_AS)
    pub memory_bytes: ResourceLimit,
    /// Max open file descriptors (RLIMIT_NOFILE)
    pub open_files: ResourceLimit,
    /// Max child processes/agents (RLIMIT_NPROC)
    pub child_agents: ResourceLimit,
    /// Max pending signals (RLIMIT_SIGPENDING)
    pub pending_signals: ResourceLimit,
    /// Max locked memory (RLIMIT_MEMLOCK)
    pub locked_memory: ResourceLimit,
    /// Max message queue bytes (RLIMIT_MSGQUEUE)
    pub message_queue_bytes: ResourceLimit,
    /// Max nice value (RLIMIT_NICE)
    pub nice_ceiling: ResourceLimit,
    /// Max realtime priority (RLIMIT_RTPRIO)
    pub realtime_priority: ResourceLimit,

    // --- Connector-specific limits ---
    /// Max concurrent sessions
    pub max_sessions: ResourceLimit,
    /// Max tool calls per second
    pub tool_calls_per_sec: ResourceLimit,
    /// Max tool calls per minute
    pub tool_calls_per_min: ResourceLimit,
    /// Max tokens per hour
    pub tokens_per_hour: ResourceLimit,
    /// Max tokens per day
    pub tokens_per_day: ResourceLimit,
    /// Max memory packets
    pub memory_packets: ResourceLimit,
    /// Max port connections
    pub port_connections: ResourceLimit,
    /// Max delegation depth
    pub delegation_depth: ResourceLimit,
    /// Max execution time per syscall (ms)
    pub syscall_timeout_ms: ResourceLimit,
    /// Max concurrent tool invocations
    pub concurrent_tools: ResourceLimit,
    /// Max knowledge base queries per minute
    pub kb_queries_per_min: ResourceLimit,
    /// Max outbound network connections
    pub network_connections: ResourceLimit,
    /// Max bytes sent per minute
    pub network_egress_per_min: ResourceLimit,
    /// Max bytes received per minute
    pub network_ingress_per_min: ResourceLimit,
}

impl Default for AgentResourceLimits {
    fn default() -> Self {
        Self {
            // POSIX-style defaults
            cpu_time_sec: ResourceLimit::unlimited(),
            memory_bytes: ResourceLimit::new(1_073_741_824u64, 4_294_967_296u64), // 1GB soft, 4GB hard
            open_files: ResourceLimit::new(1024u64, 4096u64),
            child_agents: ResourceLimit::new(64u64, 256u64),
            pending_signals: ResourceLimit::new(128u64, 512u64),
            locked_memory: ResourceLimit::new(67_108_864u64, 268_435_456u64), // 64MB soft, 256MB hard
            message_queue_bytes: ResourceLimit::new(819_200u64, 3_276_800u64), // 800KB soft, 3.2MB hard
            nice_ceiling: ResourceLimit::fixed(0),
            realtime_priority: ResourceLimit::fixed(0),

            // Connector-specific defaults
            max_sessions: ResourceLimit::new(16u64, 64u64),
            tool_calls_per_sec: ResourceLimit::new(10u64, 100u64),
            tool_calls_per_min: ResourceLimit::new(300u64, 1000u64),
            tokens_per_hour: ResourceLimit::new(100_000u64, 1_000_000u64),
            tokens_per_day: ResourceLimit::new(1_000_000u64, 10_000_000u64),
            memory_packets: ResourceLimit::new(10_000u64, 100_000u64),
            port_connections: ResourceLimit::new(32u64, 128u64),
            delegation_depth: ResourceLimit::new(3u64, 5u64),
            syscall_timeout_ms: ResourceLimit::new(30_000u64, 300_000u64), // 30s soft, 5min hard
            concurrent_tools: ResourceLimit::new(4u64, 16u64),
            kb_queries_per_min: ResourceLimit::new(60u64, 300u64),
            network_connections: ResourceLimit::new(16u64, 64u64),
            network_egress_per_min: ResourceLimit::new(10_485_760u64, 104_857_600u64), // 10MB soft, 100MB hard
            network_ingress_per_min: ResourceLimit::new(104_857_600u64, 1_073_741_824u64), // 100MB soft, 1GB hard
        }
    }
}

impl AgentResourceLimits {
    /// Create minimal limits for sandboxed/restricted agents
    pub fn restricted() -> Self {
        Self {
            cpu_time_sec: ResourceLimit::new(60u64, 300u64),
            memory_bytes: ResourceLimit::new(134_217_728u64, 268_435_456u64), // 128MB soft, 256MB hard
            open_files: ResourceLimit::new(64u64, 128u64),
            child_agents: ResourceLimit::fixed(0), // No child agents
            pending_signals: ResourceLimit::new(16u64, 32u64),
            locked_memory: ResourceLimit::fixed(0),
            message_queue_bytes: ResourceLimit::new(65_536u64, 131_072u64),
            nice_ceiling: ResourceLimit::fixed(19), // Lowest priority
            realtime_priority: ResourceLimit::fixed(0),
            max_sessions: ResourceLimit::new(2u64, 4u64),
            tool_calls_per_sec: ResourceLimit::new(1u64, 5u64),
            tool_calls_per_min: ResourceLimit::new(30u64, 60u64),
            tokens_per_hour: ResourceLimit::new(10_000u64, 50_000u64),
            tokens_per_day: ResourceLimit::new(50_000u64, 100_000u64),
            memory_packets: ResourceLimit::new(100u64, 500u64),
            port_connections: ResourceLimit::new(2u64, 4u64),
            delegation_depth: ResourceLimit::fixed(0),
            syscall_timeout_ms: ResourceLimit::new(5_000u64, 10_000u64),
            concurrent_tools: ResourceLimit::new(1u64, 2u64),
            kb_queries_per_min: ResourceLimit::new(10u64, 30u64),
            network_connections: ResourceLimit::fixed(0), // No network
            network_egress_per_min: ResourceLimit::fixed(0),
            network_ingress_per_min: ResourceLimit::fixed(0),
        }
    }

    /// Create elevated limits for trusted/privileged agents
    pub fn privileged() -> Self {
        Self {
            cpu_time_sec: ResourceLimit::unlimited(),
            memory_bytes: ResourceLimit::new(17_179_869_184u64, LimitValue::Unlimited), // 16GB soft
            open_files: ResourceLimit::new(65536u64, 1_048_576u64),
            child_agents: ResourceLimit::new(1024u64, 4096u64),
            pending_signals: ResourceLimit::new(4096u64, 16384u64),
            locked_memory: ResourceLimit::new(1_073_741_824u64, LimitValue::Unlimited), // 1GB soft
            message_queue_bytes: ResourceLimit::new(33_554_432u64, 134_217_728u64),
            nice_ceiling: ResourceLimit::unlimited(), // Highest priority (can set any nice)
            realtime_priority: ResourceLimit::fixed(99),
            max_sessions: ResourceLimit::new(256u64, 1024u64),
            tool_calls_per_sec: ResourceLimit::new(1000u64, 10000u64),
            tool_calls_per_min: ResourceLimit::unlimited(),
            tokens_per_hour: ResourceLimit::unlimited(),
            tokens_per_day: ResourceLimit::unlimited(),
            memory_packets: ResourceLimit::unlimited(),
            port_connections: ResourceLimit::new(1024u64, 4096u64),
            delegation_depth: ResourceLimit::new(10u64, 20u64),
            syscall_timeout_ms: ResourceLimit::unlimited(),
            concurrent_tools: ResourceLimit::new(64u64, 256u64),
            kb_queries_per_min: ResourceLimit::unlimited(),
            network_connections: ResourceLimit::new(1024u64, 4096u64),
            network_egress_per_min: ResourceLimit::unlimited(),
            network_ingress_per_min: ResourceLimit::unlimited(),
        }
    }
}

// =============================================================================
// Scheduling Policy
// =============================================================================

/// Scheduling policy — sched_setscheduler equivalent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SchedulingPolicy {
    /// Normal time-sharing (CFS)
    SchedOther,
    /// FIFO real-time
    SchedFifo,
    /// Round-robin real-time
    SchedRr,
    /// Batch processing (non-interactive)
    SchedBatch,
    /// Idle priority (only when system is idle)
    SchedIdle,
    /// Deadline scheduling (EDF)
    SchedDeadline,
}

impl Default for SchedulingPolicy {
    fn default() -> Self {
        Self::SchedOther
    }
}

impl SchedulingPolicy {
    /// Check if this is a real-time policy
    pub fn is_realtime(&self) -> bool {
        matches!(self, Self::SchedFifo | Self::SchedRr | Self::SchedDeadline)
    }

    /// Get minimum priority for this policy
    pub fn min_priority(&self) -> i32 {
        match self {
            Self::SchedOther | Self::SchedBatch | Self::SchedIdle => 0,
            Self::SchedFifo | Self::SchedRr => 1,
            Self::SchedDeadline => 0,
        }
    }

    /// Get maximum priority for this policy
    pub fn max_priority(&self) -> i32 {
        match self {
            Self::SchedOther | Self::SchedBatch | Self::SchedIdle => 0,
            Self::SchedFifo | Self::SchedRr => 99,
            Self::SchedDeadline => 0,
        }
    }
}

/// Scheduling parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingParams {
    /// Scheduling policy
    pub policy: SchedulingPolicy,
    /// Priority (0-99 for RT, nice value for SCHED_OTHER)
    pub priority: i32,
    /// Nice value (-20 to 19)
    pub nice: i8,
    /// Time slice in microseconds (for SCHED_RR)
    pub time_slice_us: Option<u64>,
    /// Runtime in nanoseconds (for SCHED_DEADLINE)
    pub runtime_ns: Option<u64>,
    /// Deadline in nanoseconds (for SCHED_DEADLINE)
    pub deadline_ns: Option<u64>,
    /// Period in nanoseconds (for SCHED_DEADLINE)
    pub period_ns: Option<u64>,
    /// Reset on fork flag
    pub reset_on_fork: bool,
}

impl Default for SchedulingParams {
    fn default() -> Self {
        Self {
            policy: SchedulingPolicy::default(),
            priority: 0,
            nice: 0,
            time_slice_us: None,
            runtime_ns: None,
            deadline_ns: None,
            period_ns: None,
            reset_on_fork: false,
        }
    }
}

impl SchedulingParams {
    /// Create real-time FIFO parameters
    pub fn realtime_fifo(priority: i32) -> Self {
        Self {
            policy: SchedulingPolicy::SchedFifo,
            priority: priority.clamp(1, 99),
            nice: 0,
            ..Default::default()
        }
    }

    /// Create real-time round-robin parameters
    pub fn realtime_rr(priority: i32, time_slice_us: u64) -> Self {
        Self {
            policy: SchedulingPolicy::SchedRr,
            priority: priority.clamp(1, 99),
            nice: 0,
            time_slice_us: Some(time_slice_us),
            ..Default::default()
        }
    }

    /// Create batch parameters
    pub fn batch(nice: i8) -> Self {
        Self {
            policy: SchedulingPolicy::SchedBatch,
            priority: 0,
            nice: nice.clamp(-20, 19),
            ..Default::default()
        }
    }

    /// Create idle parameters
    pub fn idle() -> Self {
        Self {
            policy: SchedulingPolicy::SchedIdle,
            priority: 0,
            nice: 19,
            ..Default::default()
        }
    }

    /// Create deadline parameters
    pub fn deadline(runtime_ns: u64, deadline_ns: u64, period_ns: u64) -> Self {
        Self {
            policy: SchedulingPolicy::SchedDeadline,
            priority: 0,
            nice: 0,
            runtime_ns: Some(runtime_ns),
            deadline_ns: Some(deadline_ns),
            period_ns: Some(period_ns),
            ..Default::default()
        }
    }
}

// =============================================================================
// Hardware Affinity
// =============================================================================

/// CPU affinity mask
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuAffinity {
    /// CPU mask (bit per CPU)
    pub mask: u64,
    /// Preferred CPUs (soft affinity)
    pub preferred: Vec<u32>,
    /// Excluded CPUs
    pub excluded: Vec<u32>,
}

impl Default for CpuAffinity {
    fn default() -> Self {
        Self {
            mask: u64::MAX, // All CPUs
            preferred: vec![],
            excluded: vec![],
        }
    }
}

impl CpuAffinity {
    /// Create affinity for specific CPUs
    pub fn cpus(cpus: &[u32]) -> Self {
        let mut mask = 0u64;
        for &cpu in cpus {
            if cpu < 64 {
                mask |= 1 << cpu;
            }
        }
        Self {
            mask,
            preferred: cpus.to_vec(),
            excluded: vec![],
        }
    }

    /// Check if CPU is allowed
    pub fn allows_cpu(&self, cpu: u32) -> bool {
        if cpu >= 64 {
            return false;
        }
        (self.mask & (1 << cpu)) != 0 && !self.excluded.contains(&cpu)
    }
}

/// NUMA node affinity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NumaAffinity {
    /// Preferred NUMA nodes
    pub nodes: Vec<u32>,
    /// Memory policy
    pub policy: NumaPolicy,
    /// Strict binding
    pub strict: bool,
}

/// NUMA memory policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumaPolicy {
    /// Default system policy
    Default,
    /// Prefer specified nodes
    Preferred,
    /// Bind to specified nodes
    Bind,
    /// Interleave across nodes
    Interleave,
    /// Local allocation
    Local,
}

impl Default for NumaPolicy {
    fn default() -> Self {
        Self::Default
    }
}

impl Default for NumaAffinity {
    fn default() -> Self {
        Self {
            nodes: vec![],
            policy: NumaPolicy::Default,
            strict: false,
        }
    }
}

/// Cell affinity (Connector-specific)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellAffinity {
    /// Preferred cells
    pub preferred_cells: Vec<String>,
    /// Excluded cells
    pub excluded_cells: Vec<String>,
    /// Geographic region preference
    pub region: Option<String>,
    /// Data locality preference (prefer cells with specific data)
    pub data_locality: Vec<String>,
    /// Strict binding (fail if preferred cells unavailable)
    pub strict: bool,
}

impl Default for CellAffinity {
    fn default() -> Self {
        Self {
            preferred_cells: vec![],
            excluded_cells: vec![],
            region: None,
            data_locality: vec![],
            strict: false,
        }
    }
}

/// GPU affinity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuAffinity {
    /// Required GPU
    pub required: bool,
    /// Preferred GPU indices
    pub preferred_gpus: Vec<u32>,
    /// Minimum GPU memory in bytes
    pub min_memory: u64,
    /// Required GPU capabilities
    pub capabilities: Vec<String>,
    /// GPU type preference (e.g., "nvidia", "amd", "tpu")
    pub gpu_type: Option<String>,
}

impl Default for GpuAffinity {
    fn default() -> Self {
        Self {
            required: false,
            preferred_gpus: vec![],
            min_memory: 0,
            capabilities: vec![],
            gpu_type: None,
        }
    }
}

/// Complete hardware affinity specification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardwareAffinity {
    pub cpu: CpuAffinity,
    pub numa: NumaAffinity,
    pub cell: CellAffinity,
    pub gpu: GpuAffinity,
}

// =============================================================================
// I/O Priority
// =============================================================================

/// I/O scheduling class (ionice equivalent)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IoClass {
    /// Real-time I/O (highest priority)
    Realtime,
    /// Best-effort I/O (default)
    BestEffort,
    /// Idle I/O (only when system is idle)
    Idle,
}

impl Default for IoClass {
    fn default() -> Self {
        Self::BestEffort
    }
}

/// I/O priority
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoPriority {
    /// I/O class
    pub class: IoClass,
    /// Priority within class (0-7, lower is higher priority)
    pub priority: u8,
    /// Read bandwidth limit (bytes/sec, 0 = unlimited)
    pub read_bps_limit: u64,
    /// Write bandwidth limit (bytes/sec, 0 = unlimited)
    pub write_bps_limit: u64,
    /// Read IOPS limit (0 = unlimited)
    pub read_iops_limit: u64,
    /// Write IOPS limit (0 = unlimited)
    pub write_iops_limit: u64,
}

impl Default for IoPriority {
    fn default() -> Self {
        Self {
            class: IoClass::BestEffort,
            priority: 4, // Middle priority
            read_bps_limit: 0,
            write_bps_limit: 0,
            read_iops_limit: 0,
            write_iops_limit: 0,
        }
    }
}

impl IoPriority {
    /// Create high-priority I/O
    pub fn high() -> Self {
        Self {
            class: IoClass::Realtime,
            priority: 0,
            ..Default::default()
        }
    }

    /// Create low-priority I/O
    pub fn low() -> Self {
        Self {
            class: IoClass::Idle,
            priority: 7,
            ..Default::default()
        }
    }

    /// Create rate-limited I/O
    pub fn rate_limited(read_bps: u64, write_bps: u64) -> Self {
        Self {
            read_bps_limit: read_bps,
            write_bps_limit: write_bps,
            ..Default::default()
        }
    }
}

// =============================================================================
// Network QoS
// =============================================================================

/// Network QoS class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkClass {
    /// Real-time traffic (VoIP, control)
    Realtime,
    /// Interactive traffic (API calls)
    Interactive,
    /// Bulk transfer
    Bulk,
    /// Background traffic
    Background,
}

impl Default for NetworkClass {
    fn default() -> Self {
        Self::Interactive
    }
}

/// Network QoS specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkQos {
    /// Traffic class
    pub class: NetworkClass,
    /// Egress bandwidth limit (bytes/sec, 0 = unlimited)
    pub egress_bps: u64,
    /// Ingress bandwidth limit (bytes/sec, 0 = unlimited)
    pub ingress_bps: u64,
    /// Max concurrent connections
    pub max_connections: u32,
    /// Max connections per second
    pub connections_per_sec: u32,
    /// Latency target in milliseconds (0 = no target)
    pub latency_target_ms: u32,
    /// Allowed destination patterns (empty = all)
    pub allowed_destinations: Vec<String>,
    /// Blocked destination patterns
    pub blocked_destinations: Vec<String>,
    /// DSCP marking
    pub dscp: u8,
}

impl Default for NetworkQos {
    fn default() -> Self {
        Self {
            class: NetworkClass::Interactive,
            egress_bps: 0,
            ingress_bps: 0,
            max_connections: 64,
            connections_per_sec: 10,
            latency_target_ms: 0,
            allowed_destinations: vec![],
            blocked_destinations: vec![],
            dscp: 0,
        }
    }
}

// =============================================================================
// Complete Hardware Contract
// =============================================================================

/// Agent Hardware Contract — complete resource governance specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHardwareContract {
    /// Contract version
    pub version: String,
    /// Contract ID
    pub contract_id: String,
    /// Agent ID this contract applies to
    pub agent_id: String,
    /// Contract creation time (epoch ms)
    pub created_at: i64,
    /// Contract expiration time (epoch ms, 0 = never)
    pub expires_at: i64,

    // --- Resource Limits ---
    pub resource_limits: AgentResourceLimits,

    // --- Scheduling ---
    pub scheduling: SchedulingParams,

    // --- Affinity ---
    pub affinity: HardwareAffinity,

    // --- I/O ---
    pub io_priority: IoPriority,

    // --- Network ---
    pub network_qos: NetworkQos,

    // --- Enforcement ---
    /// Action on soft limit breach
    pub soft_limit_action: LimitAction,
    /// Action on hard limit breach
    pub hard_limit_action: LimitAction,
    /// Grace period before enforcement (ms)
    pub grace_period_ms: u64,
    /// Enable OOM killer
    pub oom_killer_enabled: bool,
    /// OOM score adjustment (-1000 to 1000)
    pub oom_score_adj: i16,

    // --- Metadata ---
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
}

/// Action to take on limit breach
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitAction {
    /// Log warning only
    Warn,
    /// Throttle/slow down
    Throttle,
    /// Suspend agent
    Suspend,
    /// Terminate agent
    Terminate,
    /// Send signal
    Signal,
}

impl Default for LimitAction {
    fn default() -> Self {
        Self::Warn
    }
}

impl Default for AgentHardwareContract {
    fn default() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            version: "1.0".to_string(),
            contract_id: String::new(),
            agent_id: String::new(),
            created_at: now,
            expires_at: 0,
            resource_limits: AgentResourceLimits::default(),
            scheduling: SchedulingParams::default(),
            affinity: HardwareAffinity::default(),
            io_priority: IoPriority::default(),
            network_qos: NetworkQos::default(),
            soft_limit_action: LimitAction::Warn,
            hard_limit_action: LimitAction::Throttle,
            grace_period_ms: 5000,
            oom_killer_enabled: true,
            oom_score_adj: 0,
            labels: HashMap::new(),
            annotations: HashMap::new(),
        }
    }
}

impl AgentHardwareContract {
    /// Create a new contract for an agent
    pub fn new(agent_id: impl Into<String>) -> Self {
        let agent_id = agent_id.into();
        let contract_id = format!("hwc_{}", agent_id);
        Self {
            contract_id,
            agent_id,
            ..Default::default()
        }
    }

    /// Create a restricted contract
    pub fn restricted(agent_id: impl Into<String>) -> Self {
        let mut contract = Self::new(agent_id);
        contract.resource_limits = AgentResourceLimits::restricted();
        contract.scheduling = SchedulingParams::batch(10);
        contract.io_priority = IoPriority::low();
        contract.hard_limit_action = LimitAction::Terminate;
        contract
    }

    /// Create a privileged contract
    pub fn privileged(agent_id: impl Into<String>) -> Self {
        let mut contract = Self::new(agent_id);
        contract.resource_limits = AgentResourceLimits::privileged();
        contract.scheduling = SchedulingParams::realtime_fifo(50);
        contract.io_priority = IoPriority::high();
        contract.oom_score_adj = -500;
        contract
    }

    /// Validate the contract
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = vec![];

        if self.agent_id.is_empty() {
            errors.push("agent_id is required".to_string());
        }

        if self.scheduling.policy.is_realtime() {
            let min = self.scheduling.policy.min_priority();
            let max = self.scheduling.policy.max_priority();
            if self.scheduling.priority < min || self.scheduling.priority > max {
                errors.push(format!(
                    "priority {} out of range [{}, {}] for {:?}",
                    self.scheduling.priority, min, max, self.scheduling.policy
                ));
            }
        }

        if self.scheduling.nice < -20 || self.scheduling.nice > 19 {
            errors.push(format!("nice value {} out of range [-20, 19]", self.scheduling.nice));
        }

        if self.oom_score_adj < -1000 || self.oom_score_adj > 1000 {
            errors.push(format!("oom_score_adj {} out of range [-1000, 1000]", self.oom_score_adj));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Check if contract has expired
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        now > self.expires_at
    }
}

// =============================================================================
// Resource Usage Tracking
// =============================================================================

/// Current resource usage
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_time_sec: u64,
    pub memory_bytes: u64,
    pub open_files: u64,
    pub child_agents: u64,
    pub sessions: u64,
    pub tool_calls_this_sec: u64,
    pub tool_calls_this_min: u64,
    pub tokens_this_hour: u64,
    pub tokens_this_day: u64,
    pub memory_packets: u64,
    pub port_connections: u64,
    pub network_connections: u64,
    pub network_egress_this_min: u64,
    pub network_ingress_this_min: u64,
}

impl ResourceUsage {
    /// Check usage against contract limits
    pub fn check_limits(&self, contract: &AgentHardwareContract) -> Vec<LimitViolation> {
        let mut violations = vec![];
        let limits = &contract.resource_limits;

        macro_rules! check {
            ($field:ident, $limit:expr, $name:expr) => {
                if $limit.exceeds_hard(self.$field) {
                    violations.push(LimitViolation {
                        resource: $name.to_string(),
                        current: self.$field,
                        soft_limit: $limit.soft.value(),
                        hard_limit: $limit.hard.value(),
                        severity: ViolationSeverity::Hard,
                    });
                } else if $limit.exceeds_soft(self.$field) {
                    violations.push(LimitViolation {
                        resource: $name.to_string(),
                        current: self.$field,
                        soft_limit: $limit.soft.value(),
                        hard_limit: $limit.hard.value(),
                        severity: ViolationSeverity::Soft,
                    });
                }
            };
        }

        check!(cpu_time_sec, limits.cpu_time_sec, "cpu_time");
        check!(memory_bytes, limits.memory_bytes, "memory");
        check!(open_files, limits.open_files, "open_files");
        check!(child_agents, limits.child_agents, "child_agents");
        check!(sessions, limits.max_sessions, "sessions");
        check!(tool_calls_this_sec, limits.tool_calls_per_sec, "tool_calls_per_sec");
        check!(tool_calls_this_min, limits.tool_calls_per_min, "tool_calls_per_min");
        check!(tokens_this_hour, limits.tokens_per_hour, "tokens_per_hour");
        check!(tokens_this_day, limits.tokens_per_day, "tokens_per_day");
        check!(memory_packets, limits.memory_packets, "memory_packets");
        check!(port_connections, limits.port_connections, "port_connections");
        check!(network_connections, limits.network_connections, "network_connections");

        violations
    }
}

/// Limit violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitViolation {
    pub resource: String,
    pub current: u64,
    pub soft_limit: Option<u64>,
    pub hard_limit: Option<u64>,
    pub severity: ViolationSeverity,
}

/// Violation severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationSeverity {
    Soft,
    Hard,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_limit() {
        let limit = ResourceLimit::new(100u64, 200u64);
        assert!(!limit.exceeds_soft(50));
        assert!(limit.exceeds_soft(150));
        assert!(!limit.exceeds_hard(150));
        assert!(limit.exceeds_hard(250));
    }

    #[test]
    fn test_scheduling_params() {
        let rt = SchedulingParams::realtime_fifo(50);
        assert_eq!(rt.policy, SchedulingPolicy::SchedFifo);
        assert_eq!(rt.priority, 50);
        assert!(rt.policy.is_realtime());

        let batch = SchedulingParams::batch(10);
        assert_eq!(batch.policy, SchedulingPolicy::SchedBatch);
        assert_eq!(batch.nice, 10);
        assert!(!batch.policy.is_realtime());
    }

    #[test]
    fn test_cpu_affinity() {
        let affinity = CpuAffinity::cpus(&[0, 2, 4]);
        assert!(affinity.allows_cpu(0));
        assert!(!affinity.allows_cpu(1));
        assert!(affinity.allows_cpu(2));
    }

    #[test]
    fn test_hardware_contract() {
        let contract = AgentHardwareContract::new("agent_001");
        assert_eq!(contract.agent_id, "agent_001");
        assert!(contract.validate().is_ok());
        assert!(!contract.is_expired());
    }

    #[test]
    fn test_resource_usage_check() {
        let contract = AgentHardwareContract::restricted("test");
        let mut usage = ResourceUsage::default();
        
        // Within limits
        usage.memory_bytes = 100_000_000;
        let violations = usage.check_limits(&contract);
        assert!(violations.is_empty());

        // Exceed soft limit
        usage.memory_bytes = 200_000_000;
        let violations = usage.check_limits(&contract);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, ViolationSeverity::Soft);

        // Exceed hard limit
        usage.memory_bytes = 500_000_000;
        let violations = usage.check_limits(&contract);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].severity, ViolationSeverity::Hard);
    }

    #[test]
    fn test_contract_validation() {
        let mut contract = AgentHardwareContract::new("test");
        assert!(contract.validate().is_ok());

        // Invalid nice value
        contract.scheduling.nice = 25;
        let result = contract.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err()[0].contains("nice"));
    }
}
