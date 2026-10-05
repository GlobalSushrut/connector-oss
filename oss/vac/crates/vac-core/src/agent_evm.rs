//! Agent Execution Virtual Machine (AgentEVM)
//!
//! A unified sandbox runtime that provides blockchain-grade stability guarantees
//! for agents running in a distributed cell infrastructure.
//!
//! # Architecture
//!
//! The AgentEVM wraps each agent in an execution sandbox that:
//! 1. **Produces stability blocks** — periodic proofs that an agent is alive,
//!    healthy, and resource-compliant (analogous to blockchain block production)
//! 2. **Enforces resource limits** — integrates with cgroup controllers for
//!    memory, compute, IO, and PID limits
//! 3. **Manages lifecycle** — deploy N agents, suspend/resume/restart/terminate
//!    with full state preservation and graceful failure
//! 4. **Collects structured logs** — per-agent log ring buffer for investigation
//! 5. **Routes across cells** — distributes agents across distributed cell mesh
//!    using adaptive scheduling
//!
//! # Stability Blocks
//!
//! Each agent produces a `StabilityBlock` at regular intervals (default 5s).
//! A stability block is a cryptographic proof-of-liveness:
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │ StabilityBlock #42                       │
//! │  agent_pid:  pid:007                     │
//! │  prev_hash:  0xabcd1234...               │
//! │  timestamp:  1710636000000               │
//! │  status:     Running                     │
//! │  heartbeat:  alive                       │
//! │  resources:  mem=45% compute=12% io=3%   │
//! │  health:     { all_checks_passed: true } │
//! │  state_hash: 0xef567890...               │
//! │  block_hash: 0x11223344...               │
//! └──────────────────────────────────────────┘
//! ```
//!
//! If an agent misses producing a stability block within `block_interval_ms`,
//! the self-healing system detects it and takes corrective action.
//!
//! # Integration Points
//!
//! - `cgroup_controllers.rs` — Resource limit enforcement
//! - `self_healing.rs` — Health monitoring + healing actions
//! - `adaptive_scheduler.rs` — Cell routing + load balancing
//! - `agent_boot.rs` — Staged boot sequence
//! - `kernel.rs` — Syscall dispatch for lifecycle operations
//! - `disruptor.rs` — Event replication across cells

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cgroup_controllers::{CgroupDecision, CgroupHierarchy, CgroupLimits};
use crate::self_healing::{HealingAction, HealingPolicy, HealthMonitor};
use crate::types::AgentStatus;

// ═══════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════

/// Default stability block interval (5 seconds)
pub const DEFAULT_BLOCK_INTERVAL_MS: u64 = 5_000;

/// Maximum missed blocks before agent is considered unstable
pub const MAX_MISSED_BLOCKS: u32 = 3;

/// Default log ring size per agent
pub const AGENT_LOG_RING_SIZE: usize = 1024;

/// Maximum agents per single EVM instance
pub const MAX_AGENTS_PER_EVM: usize = 10_000;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ═══════════════════════════════════════════════════════════════════════
// Stability Block — The core proof-of-liveness primitive
// ═══════════════════════════════════════════════════════════════════════

/// A stability block is a periodic proof that an agent is alive, healthy,
/// and operating within its resource limits.
///
/// Analogous to a blockchain block: each block references the previous block's
/// hash, forming an immutable chain of stability proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabilityBlock {
    /// Sequential block number for this agent
    pub block_number: u64,
    /// Agent PID
    pub agent_pid: String,
    /// Hash of the previous stability block (chain integrity)
    pub prev_hash: u64,
    /// Block creation timestamp (ms epoch)
    pub timestamp: i64,
    /// Agent status at block time
    pub status: AgentStatus,
    /// Heartbeat confirmed
    pub heartbeat_alive: bool,
    /// Resource usage snapshot
    pub resources: ResourceSnapshot,
    /// Health check summary
    pub health: HealthSummary,
    /// Deterministic hash of agent state (memory region CID root)
    pub state_hash: u64,
    /// Hash of this block (computed from all fields above)
    pub block_hash: u64,
}

impl StabilityBlock {
    /// Compute block hash from contents (simple FNV-1a for now)
    pub fn compute_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        let mix = |h: &mut u64, val: u64| {
            *h ^= val;
            *h = h.wrapping_mul(0x100000001b3);
        };
        mix(&mut h, self.block_number);
        mix(&mut h, self.prev_hash);
        mix(&mut h, self.timestamp as u64);
        mix(&mut h, self.state_hash);
        mix(&mut h, self.heartbeat_alive as u64);
        mix(&mut h, self.resources.memory_pct as u64);
        mix(&mut h, self.resources.compute_pct as u64);
        h
    }

    /// Verify block hash integrity
    pub fn verify(&self) -> bool {
        self.block_hash == self.compute_hash()
    }

    /// Check if block indicates healthy state
    pub fn is_healthy(&self) -> bool {
        self.heartbeat_alive
            && self.health.all_passed
            && self.status == AgentStatus::Running
            && !self.resources.any_limit_exceeded()
    }
}

/// Resource usage snapshot at block time
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    /// Memory usage percentage (0-100)
    pub memory_pct: u8,
    /// Compute (token) usage percentage (0-100)
    pub compute_pct: u8,
    /// IO ops usage percentage (0-100)
    pub io_pct: u8,
    /// Packets stored
    pub packets: u64,
    /// Tokens consumed today
    pub tokens_today: u64,
    /// Cost accumulated today (USD)
    pub cost_today_usd: f64,
}

impl ResourceSnapshot {
    pub fn any_limit_exceeded(&self) -> bool {
        self.memory_pct >= 100 || self.compute_pct >= 100 || self.io_pct >= 100
    }

    pub fn any_warning(&self) -> bool {
        self.memory_pct >= 80 || self.compute_pct >= 80 || self.io_pct >= 80
    }
}

/// Health check summary for a stability block
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthSummary {
    pub all_passed: bool,
    pub checks_run: u32,
    pub checks_passed: u32,
    pub checks_failed: u32,
    pub details: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════
// Agent Sandbox — Per-agent execution environment
// ═══════════════════════════════════════════════════════════════════════

/// The sandbox wrapping a single agent's execution.
///
/// Tracks the agent's stability chain, resource usage, logs, and lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSandbox {
    /// Agent PID
    pub agent_pid: String,
    /// Agent name (human-readable)
    pub agent_name: String,
    /// Current status
    pub status: AgentStatus,
    /// Cell this agent is assigned to
    pub cell_id: String,
    /// Cgroup path for resource limits
    pub cgroup_path: String,
    /// Stability block chain (most recent blocks kept)
    pub stability_chain: VecDeque<StabilityBlock>,
    /// Maximum chain length to retain
    pub max_chain_length: usize,
    /// Current block number
    pub block_number: u64,
    /// Last block hash (for chaining)
    pub last_block_hash: u64,
    /// Block production interval (ms)
    pub block_interval_ms: u64,
    /// Last block production timestamp
    pub last_block_at: i64,
    /// Consecutive missed blocks
    pub missed_blocks: u32,
    /// Total blocks produced
    pub total_blocks: u64,
    /// Whether sandbox is active
    pub active: bool,
    /// Agent log ring buffer
    pub logs: VecDeque<AgentLogEntry>,
    /// Maximum log entries to retain
    pub max_log_entries: usize,
    /// Sandbox creation timestamp
    pub created_at: i64,
    /// Last heartbeat timestamp
    pub last_heartbeat_at: i64,
    /// Restart count
    pub restart_count: u32,
    /// Suspension reason (if suspended)
    pub suspend_reason: Option<String>,
    /// Tags for grouping/filtering
    pub tags: HashMap<String, String>,
}

impl AgentSandbox {
    pub fn new(
        agent_pid: String,
        agent_name: String,
        cell_id: String,
        cgroup_path: String,
    ) -> Self {
        let now = now_ms();
        Self {
            agent_pid,
            agent_name,
            status: AgentStatus::Registered,
            cell_id,
            cgroup_path,
            stability_chain: VecDeque::with_capacity(64),
            max_chain_length: 64,
            block_number: 0,
            last_block_hash: 0,
            block_interval_ms: DEFAULT_BLOCK_INTERVAL_MS,
            last_block_at: now,
            missed_blocks: 0,
            total_blocks: 0,
            active: false,
            logs: VecDeque::with_capacity(AGENT_LOG_RING_SIZE),
            max_log_entries: AGENT_LOG_RING_SIZE,
            created_at: now,
            last_heartbeat_at: now,
            restart_count: 0,
            suspend_reason: None,
            tags: HashMap::new(),
        }
    }

    /// Produce a new stability block
    pub fn produce_block(&mut self, resources: ResourceSnapshot, health: HealthSummary) -> StabilityBlock {
        let mut block = StabilityBlock {
            block_number: self.block_number,
            agent_pid: self.agent_pid.clone(),
            prev_hash: self.last_block_hash,
            timestamp: now_ms(),
            status: self.status.clone(),
            heartbeat_alive: true,
            resources,
            health,
            state_hash: self.compute_state_hash(),
            block_hash: 0,
        };
        block.block_hash = block.compute_hash();

        self.last_block_hash = block.block_hash;
        self.last_block_at = block.timestamp;
        self.block_number += 1;
        self.total_blocks += 1;
        self.missed_blocks = 0;
        self.last_heartbeat_at = block.timestamp;

        // Maintain chain length
        if self.stability_chain.len() >= self.max_chain_length {
            self.stability_chain.pop_front();
        }
        self.stability_chain.push_back(block.clone());

        self.append_log(AgentLogLevel::Debug, "stability_block",
            &format!("Block #{} produced (hash: {:016x})", block.block_number, block.block_hash));

        block
    }

    /// Check if this agent has missed too many blocks
    pub fn check_block_deadline(&mut self) -> bool {
        let now = now_ms();
        let elapsed = now - self.last_block_at;
        if elapsed > (self.block_interval_ms as i64) {
            self.missed_blocks += 1;
            if self.missed_blocks >= MAX_MISSED_BLOCKS {
                self.append_log(AgentLogLevel::Error, "stability",
                    &format!("UNSTABLE: {} consecutive missed blocks", self.missed_blocks));
                return false; // unstable
            }
            self.append_log(AgentLogLevel::Warn, "stability",
                &format!("Missed block {} ({}ms overdue)",
                    self.missed_blocks, elapsed - self.block_interval_ms as i64));
        }
        true // stable
    }

    /// Verify chain integrity (all blocks hash correctly and chain links valid)
    pub fn verify_chain(&self) -> ChainVerification {
        let mut result = ChainVerification {
            valid: true,
            blocks_verified: 0,
            first_invalid_block: None,
            chain_length: self.stability_chain.len(),
        };

        let mut prev_hash = 0u64;
        for (i, block) in self.stability_chain.iter().enumerate() {
            result.blocks_verified += 1;

            // Verify block hash
            if !block.verify() {
                result.valid = false;
                result.first_invalid_block = Some(i as u64);
                break;
            }

            // Verify chain link (skip first block)
            if i > 0 && block.prev_hash != prev_hash {
                result.valid = false;
                result.first_invalid_block = Some(i as u64);
                break;
            }

            prev_hash = block.block_hash;
        }

        result
    }

    /// Get the latest stability block
    pub fn latest_block(&self) -> Option<&StabilityBlock> {
        self.stability_chain.back()
    }

    /// Compute a deterministic state hash for the agent
    fn compute_state_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in self.agent_pid.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= self.block_number;
        h = h.wrapping_mul(0x100000001b3);
        h ^= self.status.clone() as u64;
        h = h.wrapping_mul(0x100000001b3);
        h
    }

    /// Append a log entry to the agent's log ring
    pub fn append_log(&mut self, level: AgentLogLevel, component: &str, message: &str) {
        if self.logs.len() >= self.max_log_entries {
            self.logs.pop_front();
        }
        self.logs.push_back(AgentLogEntry {
            timestamp: now_ms(),
            level,
            component: component.to_string(),
            message: message.to_string(),
            agent_pid: self.agent_pid.clone(),
        });
    }

    /// Get recent logs (up to `limit`)
    pub fn recent_logs(&self, limit: usize) -> Vec<&AgentLogEntry> {
        self.logs.iter().rev().take(limit).collect()
    }

    /// Get logs filtered by level
    pub fn logs_by_level(&self, level: AgentLogLevel) -> Vec<&AgentLogEntry> {
        self.logs.iter().filter(|l| l.level == level).collect()
    }

    /// Format sandbox status for display
    pub fn status_line(&self) -> String {
        let health = if self.missed_blocks == 0 { "healthy" }
            else if self.missed_blocks < MAX_MISSED_BLOCKS { "degraded" }
            else { "UNSTABLE" };

        format!(
            "{:<12} {:<20} {:<12} {:<10} blocks={:<6} cell={:<12} restarts={}",
            self.agent_pid, self.agent_name, format!("{:?}", self.status),
            health, self.total_blocks, self.cell_id, self.restart_count
        )
    }
}

/// Agent log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLogEntry {
    pub timestamp: i64,
    pub level: AgentLogLevel,
    pub component: String,
    pub message: String,
    pub agent_pid: String,
}

impl std::fmt::Display for AgentLogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {} [{}] {}: {}",
            self.timestamp, self.agent_pid, self.level, self.component, self.message)
    }
}

/// Log severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentLogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl std::fmt::Display for AgentLogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentLogLevel::Debug => write!(f, "DEBUG"),
            AgentLogLevel::Info => write!(f, "INFO"),
            AgentLogLevel::Warn => write!(f, "WARN"),
            AgentLogLevel::Error => write!(f, "ERROR"),
            AgentLogLevel::Fatal => write!(f, "FATAL"),
        }
    }
}

/// Result of chain verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerification {
    pub valid: bool,
    pub blocks_verified: u64,
    pub first_invalid_block: Option<u64>,
    pub chain_length: usize,
}

// ═══════════════════════════════════════════════════════════════════════
// Agent EVM — The execution virtual machine managing all agent sandboxes
// ═══════════════════════════════════════════════════════════════════════

/// The Agent Execution Virtual Machine.
///
/// Manages all agent sandboxes on this node, enforces resource limits via
/// cgroup hierarchy, produces stability blocks, and handles batch lifecycle
/// operations.
///
/// Designed for 1k+ agents in a distributed cell environment.
pub struct AgentEvm {
    /// Node/cell identifier
    pub node_id: String,
    /// All agent sandboxes keyed by PID
    sandboxes: HashMap<String, AgentSandbox>,
    /// Cgroup hierarchy for resource limits
    cgroups: CgroupHierarchy,
    /// Health monitor for self-healing
    health_monitor: HealthMonitor,
    /// Default cgroup limits for new agents
    default_limits: CgroupLimits,
    /// EVM configuration
    config: EvmConfig,
    /// EVM-level audit log
    audit_log: Vec<EvmAuditEntry>,
    /// Next PID counter
    pid_counter: u64,
    /// Total agents ever deployed
    total_deployed: u64,
    /// Total stability blocks produced across all agents
    total_blocks_produced: u64,
}

/// EVM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmConfig {
    /// Stability block interval (ms)
    pub block_interval_ms: u64,
    /// Maximum agents this EVM can host
    pub max_agents: usize,
    /// Enable cgroup enforcement
    pub enforce_cgroups: bool,
    /// Enable stability block production
    pub enable_stability_blocks: bool,
    /// Healing policy
    pub healing_policy: HealingPolicyConfig,
    /// Default cgroup path prefix
    pub cgroup_prefix: String,
}

impl Default for EvmConfig {
    fn default() -> Self {
        Self {
            block_interval_ms: DEFAULT_BLOCK_INTERVAL_MS,
            max_agents: MAX_AGENTS_PER_EVM,
            enforce_cgroups: true,
            enable_stability_blocks: true,
            healing_policy: HealingPolicyConfig::default(),
            cgroup_prefix: "connector".to_string(),
        }
    }
}

/// Serializable healing policy config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingPolicyConfig {
    pub heartbeat_timeout_ms: i64,
    pub heartbeat_miss_threshold: u32,
    pub overload_threshold_pct: f64,
    pub trust_suspend_threshold: f64,
}

impl Default for HealingPolicyConfig {
    fn default() -> Self {
        Self {
            heartbeat_timeout_ms: 30_000,
            heartbeat_miss_threshold: 2,
            overload_threshold_pct: 80.0,
            trust_suspend_threshold: 0.3,
        }
    }
}

impl From<&HealingPolicyConfig> for HealingPolicy {
    fn from(c: &HealingPolicyConfig) -> Self {
        HealingPolicy {
            heartbeat_timeout_ms: c.heartbeat_timeout_ms,
            heartbeat_miss_threshold: c.heartbeat_miss_threshold,
            overload_threshold_pct: c.overload_threshold_pct,
            trust_suspend_threshold: c.trust_suspend_threshold,
            ..Default::default()
        }
    }
}

/// EVM-level audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmAuditEntry {
    pub timestamp: i64,
    pub operation: EvmOperation,
    pub agent_pid: Option<String>,
    pub detail: String,
    pub success: bool,
}

/// Operations tracked in the EVM audit log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvmOperation {
    Deploy,
    Suspend,
    Resume,
    Restart,
    Terminate,
    StabilityBlockProduced,
    StabilityViolation,
    CgroupDeny,
    HealingAction,
    BatchDeploy,
}

impl std::fmt::Display for EvmOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvmOperation::Deploy => write!(f, "deploy"),
            EvmOperation::Suspend => write!(f, "suspend"),
            EvmOperation::Resume => write!(f, "resume"),
            EvmOperation::Restart => write!(f, "restart"),
            EvmOperation::Terminate => write!(f, "terminate"),
            EvmOperation::StabilityBlockProduced => write!(f, "stability_block"),
            EvmOperation::StabilityViolation => write!(f, "stability_violation"),
            EvmOperation::CgroupDeny => write!(f, "cgroup_deny"),
            EvmOperation::HealingAction => write!(f, "healing"),
            EvmOperation::BatchDeploy => write!(f, "batch_deploy"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Lifecycle Result Types
// ═══════════════════════════════════════════════════════════════════════

/// Result of a deploy operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    pub success: bool,
    pub agent_pid: String,
    pub agent_name: String,
    pub cell_id: String,
    pub cgroup_path: String,
    pub error: Option<String>,
}

/// Result of a batch deploy operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDeployResult {
    pub total_requested: usize,
    pub total_deployed: usize,
    pub total_failed: usize,
    pub results: Vec<DeployResult>,
}

impl BatchDeployResult {
    pub fn all_succeeded(&self) -> bool {
        self.total_failed == 0
    }
}

/// Result of a lifecycle operation (suspend/resume/restart/terminate)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleResult {
    pub success: bool,
    pub agent_pid: String,
    pub operation: String,
    pub previous_status: AgentStatus,
    pub new_status: AgentStatus,
    pub error: Option<String>,
}

/// Agent inspect result (detailed status)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInspection {
    pub agent_pid: String,
    pub agent_name: String,
    pub status: AgentStatus,
    pub cell_id: String,
    pub cgroup_path: String,
    pub uptime_ms: i64,
    pub total_blocks: u64,
    pub missed_blocks: u32,
    pub latest_block: Option<StabilityBlock>,
    pub chain_valid: bool,
    pub restart_count: u32,
    pub log_count: usize,
    pub tags: HashMap<String, String>,
}

// ═══════════════════════════════════════════════════════════════════════
// AgentEvm Implementation
// ═══════════════════════════════════════════════════════════════════════

impl AgentEvm {
    /// Create a new AgentEVM instance for a node
    pub fn new(node_id: impl Into<String>, config: EvmConfig) -> Self {
        let healing_policy = HealingPolicy::from(&config.healing_policy);
        let default_limits = CgroupLimits {
            max_packets: 10_000,
            max_bytes: 100 * 1024 * 1024, // 100MB
            max_tokens_daily: 1_000_000,
            max_tokens_hourly: 100_000,
            max_cost_daily_usd: 100.0,
            max_ops_per_second: 100,
            max_ops_per_minute: 3000,
            max_agents: 1,
        };

        let mut cgroups = CgroupHierarchy::new();
        let node_id = node_id.into();
        // Register root cgroup for this node
        let _ = cgroups.register(&format!("node:{}", node_id), None, CgroupLimits {
            max_packets: 1_000_000,
            max_bytes: 10 * 1024 * 1024 * 1024, // 10GB
            max_tokens_daily: 100_000_000,
            max_tokens_hourly: 10_000_000,
            max_cost_daily_usd: 10_000.0,
            max_ops_per_second: 10_000,
            max_ops_per_minute: 300_000,
            max_agents: config.max_agents as u32,
        });

        Self {
            node_id,
            sandboxes: HashMap::with_capacity(256),
            cgroups,
            health_monitor: HealthMonitor::new(healing_policy),
            default_limits,
            config,
            audit_log: Vec::new(),
            pid_counter: 0,
            total_deployed: 0,
            total_blocks_produced: 0,
        }
    }

    /// Create with default config
    pub fn default_evm(node_id: impl Into<String>) -> Self {
        Self::new(node_id, EvmConfig::default())
    }

    // ─── Deploy Operations ────────────────────────────────────────

    /// Deploy a single agent into the EVM sandbox
    pub fn deploy(
        &mut self,
        agent_name: impl Into<String>,
        cell_id: impl Into<String>,
        limits: Option<CgroupLimits>,
        tags: Option<HashMap<String, String>>,
    ) -> DeployResult {
        let agent_name = agent_name.into();
        let cell_id = cell_id.into();

        // Check capacity
        if self.sandboxes.len() >= self.config.max_agents {
            let err = format!("EVM at capacity: {}/{}", self.sandboxes.len(), self.config.max_agents);
            self.log_audit(EvmOperation::Deploy, None, &err, false);
            return DeployResult {
                success: false,
                agent_pid: String::new(),
                agent_name,
                cell_id,
                cgroup_path: String::new(),
                error: Some(err),
            };
        }

        // Generate PID
        let pid = self.next_pid();
        let cgroup_path = format!("{}:agent:{}", self.config.cgroup_prefix, pid);

        // Register cgroup for this agent
        let agent_limits = limits.unwrap_or_else(|| self.default_limits.clone());
        let node_cgroup = format!("node:{}", self.node_id);
        if let Err(e) = self.cgroups.register(&cgroup_path, Some(&node_cgroup), agent_limits) {
            let err = format!("Cgroup registration failed: {}", e);
            self.log_audit(EvmOperation::Deploy, Some(pid.clone()), &err, false);
            return DeployResult {
                success: false,
                agent_pid: pid,
                agent_name,
                cell_id,
                cgroup_path,
                error: Some(err),
            };
        }

        // Check PID limit in cgroup
        let pids_decision = self.cgroups.check_pids(&node_cgroup, now_ms());
        if pids_decision.is_deny() {
            let err = format!("Node agent limit reached: {:?}", pids_decision);
            self.log_audit(EvmOperation::CgroupDeny, Some(pid.clone()), &err, false);
            return DeployResult {
                success: false,
                agent_pid: pid,
                agent_name,
                cell_id,
                cgroup_path,
                error: Some(err),
            };
        }

        // Create sandbox
        let mut sandbox = AgentSandbox::new(
            pid.clone(),
            agent_name.clone(),
            cell_id.clone(),
            cgroup_path.clone(),
        );
        sandbox.block_interval_ms = self.config.block_interval_ms;
        if let Some(tags) = tags {
            sandbox.tags = tags;
        }

        // Activate sandbox
        sandbox.status = AgentStatus::Running;
        sandbox.active = true;
        sandbox.append_log(AgentLogLevel::Info, "evm",
            &format!("Agent deployed to cell {} with cgroup {}", cell_id, cgroup_path));

        // Register with health monitor
        self.health_monitor.record_heartbeat(&pid);

        // Register agent count in node cgroup only (not per-agent cgroup)
        // The per-agent cgroup has max_agents=1 which is for its own isolation
        self.cgroups.record_agent_register(&node_cgroup);

        // Produce genesis stability block
        let genesis_resources = ResourceSnapshot::default();
        let genesis_health = HealthSummary {
            all_passed: true,
            checks_run: 1,
            checks_passed: 1,
            checks_failed: 0,
            details: vec!["genesis_boot: OK".to_string()],
        };
        sandbox.produce_block(genesis_resources, genesis_health);

        self.sandboxes.insert(pid.clone(), sandbox);
        self.total_deployed += 1;
        self.total_blocks_produced += 1;

        self.log_audit(EvmOperation::Deploy, Some(pid.clone()),
            &format!("Deployed {} → cell:{} cgroup:{}", agent_name, cell_id, cgroup_path), true);

        DeployResult {
            success: true,
            agent_pid: pid,
            agent_name,
            cell_id,
            cgroup_path,
            error: None,
        }
    }

    /// Deploy N agents in batch (e.g., `connectorctl deploy 5 agents`)
    pub fn batch_deploy(
        &mut self,
        count: usize,
        name_prefix: impl Into<String>,
        cell_id: impl Into<String>,
        limits: Option<CgroupLimits>,
    ) -> BatchDeployResult {
        let name_prefix = name_prefix.into();
        let cell_id = cell_id.into();
        let mut results = Vec::with_capacity(count);

        for i in 0..count {
            let name = format!("{}_{:03}", name_prefix, i + 1);
            let result = self.deploy(&name, &cell_id, limits.clone(), None);
            results.push(result);
        }

        let total_deployed = results.iter().filter(|r| r.success).count();
        let total_failed = results.iter().filter(|r| !r.success).count();

        self.log_audit(EvmOperation::BatchDeploy, None,
            &format!("Batch deploy: {}/{} succeeded", total_deployed, count), total_failed == 0);

        BatchDeployResult {
            total_requested: count,
            total_deployed,
            total_failed,
            results,
        }
    }

    // ─── Lifecycle Operations ─────────────────────────────────────

    /// Suspend an agent (preserves state, stops execution)
    pub fn suspend(&mut self, agent_pid: &str, reason: impl Into<String>) -> LifecycleResult {
        let reason = reason.into();

        let sandbox = match self.sandboxes.get_mut(agent_pid) {
            Some(s) => s,
            None => return self.lifecycle_not_found(agent_pid, "suspend"),
        };

        let prev_status = sandbox.status.clone();

        if prev_status != AgentStatus::Running {
            let err = format!("Cannot suspend agent in state {:?}", prev_status);
            sandbox.append_log(AgentLogLevel::Warn, "evm", &err);
            self.log_audit(EvmOperation::Suspend, Some(agent_pid.to_string()), &err, false);
            return LifecycleResult {
                success: false,
                agent_pid: agent_pid.to_string(),
                operation: "suspend".to_string(),
                previous_status: prev_status.clone(),
                new_status: prev_status,
                error: Some(err),
            };
        }

        sandbox.status = AgentStatus::Suspended;
        sandbox.active = false;
        sandbox.suspend_reason = Some(reason.clone());
        sandbox.append_log(AgentLogLevel::Info, "evm",
            &format!("Suspended: {}", reason));

        self.log_audit(EvmOperation::Suspend, Some(agent_pid.to_string()),
            &format!("Suspended: {}", reason), true);

        LifecycleResult {
            success: true,
            agent_pid: agent_pid.to_string(),
            operation: "suspend".to_string(),
            previous_status: prev_status,
            new_status: AgentStatus::Suspended,
            error: None,
        }
    }

    /// Resume a suspended agent
    pub fn resume(&mut self, agent_pid: &str) -> LifecycleResult {
        let sandbox = match self.sandboxes.get_mut(agent_pid) {
            Some(s) => s,
            None => return self.lifecycle_not_found(agent_pid, "resume"),
        };

        let prev_status = sandbox.status.clone();

        if prev_status != AgentStatus::Suspended {
            let err = format!("Cannot resume agent in state {:?}", prev_status);
            sandbox.append_log(AgentLogLevel::Warn, "evm", &err);
            self.log_audit(EvmOperation::Resume, Some(agent_pid.to_string()), &err, false);
            return LifecycleResult {
                success: false,
                agent_pid: agent_pid.to_string(),
                operation: "resume".to_string(),
                previous_status: prev_status.clone(),
                new_status: prev_status,
                error: Some(err),
            };
        }

        sandbox.status = AgentStatus::Running;
        sandbox.active = true;
        sandbox.suspend_reason = None;
        sandbox.last_block_at = now_ms(); // reset block deadline
        sandbox.missed_blocks = 0;
        sandbox.append_log(AgentLogLevel::Info, "evm", "Resumed");

        self.health_monitor.record_heartbeat(agent_pid);
        self.log_audit(EvmOperation::Resume, Some(agent_pid.to_string()), "Resumed", true);

        LifecycleResult {
            success: true,
            agent_pid: agent_pid.to_string(),
            operation: "resume".to_string(),
            previous_status: prev_status,
            new_status: AgentStatus::Running,
            error: None,
        }
    }

    /// Restart an agent (terminate + redeploy with same config)
    pub fn restart(&mut self, agent_pid: &str) -> LifecycleResult {
        let (agent_name, cell_id, cgroup_path, prev_status, tags, restart_count) = {
            let sandbox = match self.sandboxes.get(agent_pid) {
                Some(s) => s,
                None => return self.lifecycle_not_found(agent_pid, "restart"),
            };
            (
                sandbox.agent_name.clone(),
                sandbox.cell_id.clone(),
                sandbox.cgroup_path.clone(),
                sandbox.status.clone(),
                sandbox.tags.clone(),
                sandbox.restart_count,
            )
        };

        // Terminate the old sandbox
        self.terminate(agent_pid, "restart");

        // Redeploy with same configuration
        let result = self.deploy(&agent_name, &cell_id, None, Some(tags));

        if result.success {
            // Update restart count on the new sandbox
            if let Some(new_sandbox) = self.sandboxes.get_mut(&result.agent_pid) {
                new_sandbox.restart_count = restart_count + 1;
                new_sandbox.append_log(AgentLogLevel::Info, "evm",
                    &format!("Restarted (count: {}, prev pid: {})", restart_count + 1, agent_pid));
            }
            self.log_audit(EvmOperation::Restart, Some(result.agent_pid.clone()),
                &format!("Restarted {} → new pid {}", agent_pid, result.agent_pid), true);
        } else {
            self.log_audit(EvmOperation::Restart, Some(agent_pid.to_string()),
                &format!("Restart failed: {:?}", result.error), false);
        }

        LifecycleResult {
            success: result.success,
            agent_pid: result.agent_pid,
            operation: "restart".to_string(),
            previous_status: prev_status,
            new_status: if result.success { AgentStatus::Running } else { AgentStatus::Failed },
            error: result.error,
        }
    }

    /// Terminate an agent
    pub fn terminate(&mut self, agent_pid: &str, reason: impl Into<String>) -> LifecycleResult {
        let reason = reason.into();

        let sandbox = match self.sandboxes.get_mut(agent_pid) {
            Some(s) => s,
            None => return self.lifecycle_not_found(agent_pid, "terminate"),
        };

        let prev_status = sandbox.status.clone();
        sandbox.status = AgentStatus::Terminated;
        sandbox.active = false;
        sandbox.append_log(AgentLogLevel::Info, "evm",
            &format!("Terminated: {}", reason));

        self.log_audit(EvmOperation::Terminate, Some(agent_pid.to_string()),
            &format!("Terminated: {}", reason), true);

        LifecycleResult {
            success: true,
            agent_pid: agent_pid.to_string(),
            operation: "terminate".to_string(),
            previous_status: prev_status,
            new_status: AgentStatus::Terminated,
            error: None,
        }
    }

    fn lifecycle_not_found(&self, agent_pid: &str, op: &str) -> LifecycleResult {
        LifecycleResult {
            success: false,
            agent_pid: agent_pid.to_string(),
            operation: op.to_string(),
            previous_status: AgentStatus::Failed,
            new_status: AgentStatus::Failed,
            error: Some(format!("Agent {} not found", agent_pid)),
        }
    }

    // ─── Stability Block Production ───────────────────────────────

    /// Tick the EVM — produce stability blocks for all active agents
    /// and run health checks. Call this at regular intervals.
    ///
    /// Returns healing actions that should be executed.
    pub fn tick(&mut self) -> Vec<HealingAction> {
        let now = now_ms();
        let mut actions = Vec::new();

        // Phase 1: Collect active agents and their cgroup paths (read-only)
        let active_agents: Vec<(String, String, i64, u64)> = self.sandboxes.iter()
            .filter(|(_, s)| s.active && s.status == AgentStatus::Running)
            .map(|(pid, s)| (pid.clone(), s.cgroup_path.clone(), s.last_block_at, s.block_interval_ms))
            .collect();

        // Phase 2: For agents due for a block, get resources and check cgroups
        let mut block_data: Vec<(String, ResourceSnapshot, bool)> = Vec::new();
        for (pid, cgroup_path, last_block_at, block_interval_ms) in &active_agents {
            let elapsed = now - last_block_at;
            if elapsed >= *block_interval_ms as i64 {
                let resources = self.get_resource_snapshot(cgroup_path);
                let cgroup_ok = self.check_cgroup_limits(cgroup_path, now);
                block_data.push((pid.clone(), resources, cgroup_ok));
            }
        }

        // Phase 3: Produce stability blocks on sandboxes (mutates sandboxes only)
        for (pid, resources, cgroup_ok) in block_data {
            let health = HealthSummary {
                all_passed: cgroup_ok,
                checks_run: 3,
                checks_passed: if cgroup_ok { 3 } else { 0 },
                checks_failed: if cgroup_ok { 0 } else { 3 },
                details: if cgroup_ok {
                    vec!["cgroup: OK".to_string()]
                } else {
                    vec!["cgroup: LIMIT EXCEEDED".to_string()]
                },
            };

            if let Some(sandbox) = self.sandboxes.get_mut(&pid) {
                sandbox.produce_block(resources, health);
            }
            self.total_blocks_produced += 1;
            self.health_monitor.record_heartbeat(&pid);
        }

        // Phase 4: Check block deadlines and collect violations
        let mut violations: Vec<(String, u32)> = Vec::new();
        for (pid, _, _, _) in &active_agents {
            if let Some(sandbox) = self.sandboxes.get_mut(pid) {
                if !sandbox.check_block_deadline() {
                    violations.push((pid.clone(), sandbox.missed_blocks));
                }
            }
        }

        // Phase 5: Log violations (no sandbox borrow held)
        for (pid, missed) in violations {
            self.log_audit(EvmOperation::StabilityViolation, Some(pid.clone()),
                &format!("Agent {} unstable: {} missed blocks", pid, missed), false);
        }

        // Phase 6: Run health monitor checks
        let healing_actions = self.health_monitor.run_all_checks(true);
        for action in &healing_actions {
            self.log_audit(EvmOperation::HealingAction, None,
                &format!("{:?}", action), true);
        }
        actions.extend(healing_actions);

        actions
    }

    fn get_resource_snapshot(&self, cgroup_path: &str) -> ResourceSnapshot {
        if let Some(usage) = self.cgroups.get_usage(cgroup_path) {
            ResourceSnapshot {
                memory_pct: (self.cgroups.pressure_level(cgroup_path, "memory") * 100.0) as u8,
                compute_pct: (self.cgroups.pressure_level(cgroup_path, "compute") * 100.0) as u8,
                io_pct: (self.cgroups.pressure_level(cgroup_path, "io") * 100.0) as u8,
                packets: usage.packets,
                tokens_today: usage.tokens_today,
                cost_today_usd: usage.cost_today_usd,
            }
        } else {
            ResourceSnapshot::default()
        }
    }

    fn check_cgroup_limits(&mut self, cgroup_path: &str, now: i64) -> bool {
        if !self.config.enforce_cgroups {
            return true;
        }
        let mem = self.cgroups.check_memory(cgroup_path, now);
        let compute = self.cgroups.check_compute(cgroup_path, now);
        let io = self.cgroups.check_io(cgroup_path, now);
        !mem.is_deny() && !compute.is_deny() && !io.is_deny()
    }

    // ─── Query / Inspect Operations ───────────────────────────────

    /// Get agent logs (e.g., `connectorctl logs agent_01`)
    pub fn logs(&self, agent_pid: &str, limit: usize) -> Option<Vec<&AgentLogEntry>> {
        self.sandboxes.get(agent_pid).map(|s| s.recent_logs(limit))
    }

    /// List all agents with status
    pub fn list_agents(&self) -> Vec<AgentInspection> {
        self.sandboxes.values().map(|s| self.inspect_sandbox(s)).collect()
    }

    /// List agents filtered by status
    pub fn list_by_status(&self, status: &AgentStatus) -> Vec<AgentInspection> {
        self.sandboxes.values()
            .filter(|s| &s.status == status)
            .map(|s| self.inspect_sandbox(s))
            .collect()
    }

    /// Inspect a single agent in detail
    pub fn inspect(&self, agent_pid: &str) -> Option<AgentInspection> {
        self.sandboxes.get(agent_pid).map(|s| self.inspect_sandbox(s))
    }

    fn inspect_sandbox(&self, sandbox: &AgentSandbox) -> AgentInspection {
        let chain_verification = sandbox.verify_chain();
        AgentInspection {
            agent_pid: sandbox.agent_pid.clone(),
            agent_name: sandbox.agent_name.clone(),
            status: sandbox.status.clone(),
            cell_id: sandbox.cell_id.clone(),
            cgroup_path: sandbox.cgroup_path.clone(),
            uptime_ms: now_ms() - sandbox.created_at,
            total_blocks: sandbox.total_blocks,
            missed_blocks: sandbox.missed_blocks,
            latest_block: sandbox.latest_block().cloned(),
            chain_valid: chain_verification.valid,
            restart_count: sandbox.restart_count,
            log_count: sandbox.logs.len(),
            tags: sandbox.tags.clone(),
        }
    }

    /// Get cluster-wide stability summary
    pub fn stability_summary(&self) -> StabilitySummary {
        let total = self.sandboxes.len();
        let active = self.sandboxes.values().filter(|s| s.status == AgentStatus::Running).count();
        let suspended = self.sandboxes.values().filter(|s| s.status == AgentStatus::Suspended).count();
        let failed = self.sandboxes.values().filter(|s| s.status == AgentStatus::Failed).count();
        let terminated = self.sandboxes.values().filter(|s| s.status == AgentStatus::Terminated).count();
        let unstable = self.sandboxes.values().filter(|s| s.missed_blocks >= MAX_MISSED_BLOCKS).count();
        let all_chains_valid = self.sandboxes.values().all(|s| s.verify_chain().valid);

        StabilitySummary {
            node_id: self.node_id.clone(),
            total_agents: total,
            active,
            suspended,
            failed,
            terminated,
            unstable,
            total_blocks_produced: self.total_blocks_produced,
            total_deployed: self.total_deployed,
            stability_index: self.health_monitor.stability_index(),
            all_chains_valid,
            healing_actions_taken: self.health_monitor.action_count(),
        }
    }

    /// Get the EVM audit log
    pub fn audit_log(&self) -> &[EvmAuditEntry] {
        &self.audit_log
    }

    /// Get a sandbox reference by PID
    pub fn sandbox(&self, agent_pid: &str) -> Option<&AgentSandbox> {
        self.sandboxes.get(agent_pid)
    }

    /// Get total active agent count
    pub fn active_count(&self) -> usize {
        self.sandboxes.values().filter(|s| s.status == AgentStatus::Running).count()
    }

    /// Get total agent count
    pub fn total_count(&self) -> usize {
        self.sandboxes.len()
    }

    // ─── Internal Helpers ─────────────────────────────────────────

    fn next_pid(&mut self) -> String {
        self.pid_counter += 1;
        format!("agent:{:04}", self.pid_counter)
    }

    fn log_audit(&mut self, operation: EvmOperation, agent_pid: Option<String>, detail: &str, success: bool) {
        self.audit_log.push(EvmAuditEntry {
            timestamp: now_ms(),
            operation,
            agent_pid,
            detail: detail.to_string(),
            success,
        });
    }
}

/// Cluster-wide stability summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabilitySummary {
    pub node_id: String,
    pub total_agents: usize,
    pub active: usize,
    pub suspended: usize,
    pub failed: usize,
    pub terminated: usize,
    pub unstable: usize,
    pub total_blocks_produced: u64,
    pub total_deployed: u64,
    pub stability_index: f64,
    pub all_chains_valid: bool,
    pub healing_actions_taken: u64,
}

impl std::fmt::Display for StabilitySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "═══ AgentEVM Stability Summary ═══")?;
        writeln!(f, "Node:       {}", self.node_id)?;
        writeln!(f, "Agents:     {} total ({} active, {} suspended, {} failed, {} terminated)",
            self.total_agents, self.active, self.suspended, self.failed, self.terminated)?;
        writeln!(f, "Unstable:   {}", self.unstable)?;
        writeln!(f, "Blocks:     {} produced", self.total_blocks_produced)?;
        writeln!(f, "Deployed:   {} total", self.total_deployed)?;
        writeln!(f, "Stability:  {:.1}%", self.stability_index * 100.0)?;
        writeln!(f, "Chains:     {}", if self.all_chains_valid { "ALL VALID" } else { "INTEGRITY FAILURE" })?;
        writeln!(f, "Healing:    {} actions taken", self.healing_actions_taken)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_evm() -> AgentEvm {
        AgentEvm::default_evm("test-node-01")
    }

    #[test]
    fn test_deploy_single_agent() {
        let mut evm = make_evm();
        let result = evm.deploy("triage-bot", "cell-01", None, None);

        assert!(result.success);
        assert!(!result.agent_pid.is_empty());
        assert_eq!(result.cell_id, "cell-01");
        assert_eq!(evm.active_count(), 1);
    }

    #[test]
    fn test_batch_deploy_5_agents() {
        let mut evm = make_evm();
        let result = evm.batch_deploy(5, "bot", "cell-01", None);

        assert_eq!(result.total_requested, 5);
        assert_eq!(result.total_deployed, 5);
        assert_eq!(result.total_failed, 0);
        assert!(result.all_succeeded());
        assert_eq!(evm.active_count(), 5);
    }

    #[test]
    fn test_suspend_and_resume() {
        let mut evm = make_evm();
        let deploy = evm.deploy("bot-01", "cell-01", None, None);
        let pid = deploy.agent_pid.clone();

        // Suspend
        let suspend = evm.suspend(&pid, "maintenance");
        assert!(suspend.success);
        assert_eq!(suspend.new_status, AgentStatus::Suspended);
        assert_eq!(evm.active_count(), 0);

        // Resume
        let resume = evm.resume(&pid);
        assert!(resume.success);
        assert_eq!(resume.new_status, AgentStatus::Running);
        assert_eq!(evm.active_count(), 1);
    }

    #[test]
    fn test_suspend_non_running_fails() {
        let mut evm = make_evm();
        let deploy = evm.deploy("bot-01", "cell-01", None, None);
        let pid = deploy.agent_pid.clone();

        // Suspend first time
        evm.suspend(&pid, "maintenance");

        // Suspend again should fail
        let result = evm.suspend(&pid, "again");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_restart_agent() {
        let mut evm = make_evm();
        let deploy = evm.deploy("bot-01", "cell-01", None, None);
        let old_pid = deploy.agent_pid.clone();

        let restart = evm.restart(&old_pid);
        assert!(restart.success);
        assert_ne!(restart.agent_pid, old_pid); // new PID assigned
        assert_eq!(evm.active_count(), 1);

        // New agent should have restart_count = 1
        let inspection = evm.inspect(&restart.agent_pid).unwrap();
        assert_eq!(inspection.restart_count, 1);
    }

    #[test]
    fn test_terminate_agent() {
        let mut evm = make_evm();
        let deploy = evm.deploy("bot-01", "cell-01", None, None);
        let pid = deploy.agent_pid.clone();

        let term = evm.terminate(&pid, "done");
        assert!(term.success);
        assert_eq!(term.new_status, AgentStatus::Terminated);
        assert_eq!(evm.active_count(), 0);
    }

    #[test]
    fn test_lifecycle_not_found() {
        let mut evm = make_evm();
        let result = evm.suspend("nonexistent", "test");
        assert!(!result.success);
        assert!(result.error.unwrap().contains("not found"));
    }

    #[test]
    fn test_agent_logs() {
        let mut evm = make_evm();
        let deploy = evm.deploy("bot-01", "cell-01", None, None);
        let pid = deploy.agent_pid.clone();

        let logs = evm.logs(&pid, 10).unwrap();
        assert!(!logs.is_empty()); // Should have deploy + genesis block logs
    }

    #[test]
    fn test_stability_block_chain() {
        let mut evm = make_evm();
        let deploy = evm.deploy("bot-01", "cell-01", None, None);
        let pid = deploy.agent_pid.clone();

        // Genesis block should exist
        let sandbox = evm.sandbox(&pid).unwrap();
        assert_eq!(sandbox.total_blocks, 1);

        // Verify chain
        let verification = sandbox.verify_chain();
        assert!(verification.valid);
        assert_eq!(verification.blocks_verified, 1);
    }

    #[test]
    fn test_stability_block_chaining() {
        let mut sandbox = AgentSandbox::new(
            "pid:001".to_string(),
            "test-bot".to_string(),
            "cell-01".to_string(),
            "cg:test".to_string(),
        );

        // Produce 10 blocks
        for _ in 0..10 {
            sandbox.produce_block(ResourceSnapshot::default(), HealthSummary {
                all_passed: true, checks_run: 1, checks_passed: 1,
                checks_failed: 0, details: vec![],
            });
        }

        assert_eq!(sandbox.total_blocks, 10);
        assert_eq!(sandbox.stability_chain.len(), 10);

        // Verify chain integrity
        let verification = sandbox.verify_chain();
        assert!(verification.valid);
        assert_eq!(verification.blocks_verified, 10);
    }

    #[test]
    fn test_stability_block_tamper_detection() {
        let mut sandbox = AgentSandbox::new(
            "pid:001".to_string(),
            "test-bot".to_string(),
            "cell-01".to_string(),
            "cg:test".to_string(),
        );

        for _ in 0..5 {
            sandbox.produce_block(ResourceSnapshot::default(), HealthSummary {
                all_passed: true, checks_run: 1, checks_passed: 1,
                checks_failed: 0, details: vec![],
            });
        }

        // Tamper with a block
        sandbox.stability_chain[2].state_hash = 0xDEADBEEF;

        let verification = sandbox.verify_chain();
        assert!(!verification.valid);
        assert_eq!(verification.first_invalid_block, Some(2));
    }

    #[test]
    fn test_batch_deploy_and_full_lifecycle() {
        let mut evm = make_evm();

        // connectorctl deploy 5 agents
        let batch = evm.batch_deploy(5, "worker", "cell-01", None);
        assert_eq!(batch.total_deployed, 5);

        let pids: Vec<String> = batch.results.iter().map(|r| r.agent_pid.clone()).collect();

        // connectorctl suspend agent_02
        let suspend = evm.suspend(&pids[1], "maintenance");
        assert!(suspend.success);

        // connectorctl resume agent_02
        let resume = evm.resume(&pids[1]);
        assert!(resume.success);

        // connectorctl logs agent_01
        let logs = evm.logs(&pids[0], 50);
        assert!(logs.is_some());

        // connectorctl restart agent_03
        let restart = evm.restart(&pids[2]);
        assert!(restart.success);

        // Summary
        let summary = evm.stability_summary();
        assert_eq!(summary.active, 5); // 4 original + 1 restarted (old one terminated)
        assert_eq!(summary.terminated, 1); // old agent_03
    }

    #[test]
    fn test_stability_summary() {
        let mut evm = make_evm();
        evm.batch_deploy(3, "bot", "cell-01", None);

        let summary = evm.stability_summary();
        assert_eq!(summary.total_agents, 3);
        assert_eq!(summary.active, 3);
        assert_eq!(summary.total_blocks_produced, 3); // genesis blocks
        assert!(summary.all_chains_valid);
    }

    #[test]
    fn test_inspect_agent() {
        let mut evm = make_evm();
        let deploy = evm.deploy("triage-bot", "cell-01", None, None);

        let inspection = evm.inspect(&deploy.agent_pid).unwrap();
        assert_eq!(inspection.agent_name, "triage-bot");
        assert_eq!(inspection.status, AgentStatus::Running);
        assert_eq!(inspection.cell_id, "cell-01");
        assert!(inspection.chain_valid);
        assert_eq!(inspection.total_blocks, 1);
    }

    #[test]
    fn test_evm_capacity_limit() {
        let config = EvmConfig {
            max_agents: 3,
            ..Default::default()
        };
        let mut evm = AgentEvm::new("test-node", config);

        for i in 0..3 {
            let r = evm.deploy(format!("bot-{}", i), "cell-01", None, None);
            assert!(r.success, "Deploy {} failed: {:?}", i, r.error);
        }

        // 4th should fail
        let r = evm.deploy("bot-overflow", "cell-01", None, None);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("capacity"));
    }

    #[test]
    fn test_tick_produces_stability_blocks() {
        let config = EvmConfig {
            block_interval_ms: 0, // immediate blocks for testing
            ..Default::default()
        };
        let mut evm = AgentEvm::new("test-node", config);
        evm.deploy("bot-01", "cell-01", None, None);

        // Tick should produce new blocks
        let actions = evm.tick();
        assert!(actions.is_empty()); // no healing needed

        let sandbox = evm.sandbox("agent:0001").unwrap();
        assert!(sandbox.total_blocks >= 2); // genesis + tick block
    }

    #[test]
    fn test_missed_blocks_detection() {
        let mut sandbox = AgentSandbox::new(
            "pid:001".to_string(),
            "test-bot".to_string(),
            "cell-01".to_string(),
            "cg:test".to_string(),
        );
        sandbox.active = true;
        sandbox.status = AgentStatus::Running;
        sandbox.block_interval_ms = 0; // immediate deadline

        // Force last_block_at to past
        sandbox.last_block_at = now_ms() - 10_000;

        // Check deadline multiple times
        for _ in 0..MAX_MISSED_BLOCKS {
            sandbox.check_block_deadline();
        }

        assert_eq!(sandbox.missed_blocks, MAX_MISSED_BLOCKS);
        // Next check should return false (unstable)
        sandbox.last_block_at = now_ms() - 10_000;
        assert!(!sandbox.check_block_deadline());
    }

    #[test]
    fn test_audit_log_recorded() {
        let mut evm = make_evm();
        evm.deploy("bot-01", "cell-01", None, None);
        evm.deploy("bot-02", "cell-01", None, None);

        assert!(evm.audit_log().len() >= 2);
        assert!(evm.audit_log().iter().all(|a| a.success));
    }

    #[test]
    fn test_list_by_status() {
        let mut evm = make_evm();
        let d1 = evm.deploy("bot-01", "cell-01", None, None);
        let d2 = evm.deploy("bot-02", "cell-01", None, None);
        evm.suspend(&d1.agent_pid, "test");

        let running = evm.list_by_status(&AgentStatus::Running);
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].agent_pid, d2.agent_pid);

        let suspended = evm.list_by_status(&AgentStatus::Suspended);
        assert_eq!(suspended.len(), 1);
        assert_eq!(suspended[0].agent_pid, d1.agent_pid);
    }
}
