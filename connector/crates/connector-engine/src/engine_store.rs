//! # EngineStore — Production persistence for Ring 1-4 engine components.
//!
//! The `KernelStore` (Ring 0) persists kernel data: packets, windows, SVs, audit.
//! But ALL 25+ Ring 1-4 engine components use in-memory HashMaps that vanish on restart.
//!
//! `EngineStore` fills this gap — a trait covering:
//! - Audit & compliance (append-only event log)
//! - Agent state (behavior, circuit breakers, adaptive thresholds)
//! - Security (secrets with TTL, policies)
//! - Economy (escrow, reputation, negotiations)
//! - Discovery (agent index with FTS, knowledge docs)
//! - Distributed (session routes, pipeline state, cross-cell messages)
//! - Tools & config (tool definitions, watchdog history)
//!
//! Default backend: **SQLite WAL mode** (SQL queries, FTS5, ACID, single-file, zero-config).
//! Test backend: **InMemoryEngineStore** (HashMap-based, same interface).
//!
//! Design: `docs/PRODUCTION_DB_ARCHITECTURE.md`

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::EngineError;

// ═══════════════════════════════════════════════════════════════
// Store Error / Result
// ═══════════════════════════════════════════════════════════════

pub type EngineStoreResult<T> = Result<T, EngineStoreError>;

#[derive(Debug, Clone)]
pub struct EngineStoreError {
    pub message: String,
}

impl std::fmt::Display for EngineStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EngineStoreError: {}", self.message)
    }
}

impl std::error::Error for EngineStoreError {}

impl From<EngineStoreError> for EngineError {
    fn from(e: EngineStoreError) -> Self {
        EngineError::StoreError(e.message)
    }
}

fn ese(msg: impl std::fmt::Display) -> EngineStoreError {
    EngineStoreError { message: msg.to_string() }
}

// ═══════════════════════════════════════════════════════════════
// Portable Data Types (used across store implementations)
// ═══════════════════════════════════════════════════════════════

// --- Audit ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineAuditEntry {
    pub timestamp: i64,
    pub category: String,
    pub agent_pid: Option<String>,
    pub action: String,
    pub resource: Option<String>,
    pub verdict: Option<String>,
    pub details: Option<serde_json::Value>,
    pub severity: String,
}

#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub agent_pid: Option<String>,
    pub category: Option<String>,
    pub severity: Option<String>,
    pub limit: Option<usize>,
}

// --- Agent Behavior ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorProfile {
    pub agent_pid: String,
    pub total_actions: u64,
    pub total_errors: u64,
    pub total_tool_calls: u64,
    pub avg_threat_score: f64,
    pub recent_scores: Vec<f64>,
    pub last_action_at: Option<i64>,
    pub updated_at: i64,
}

// --- Circuit Breaker ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerState {
    pub agent_pid: String,
    pub state: String,
    pub failure_count: u32,
    pub failure_threshold: u32,
    pub reset_timeout_ms: i64,
    pub half_open_max_probes: u32,
    pub half_open_success_count: u32,
    pub last_failure_ms: i64,
    pub last_state_change_ms: i64,
}

// --- Adaptive Threshold ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdBaseline {
    pub agent_pid: String,
    pub scores: Vec<f64>,
    pub avg_score: f64,
    pub adapted_thresholds: Option<serde_json::Value>,
    pub updated_at: i64,
}

// --- Secret ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSecret {
    pub secret_id: String,
    pub agent_pid: String,
    pub value: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub description: String,
}

// --- Escrow ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEscrow {
    pub escrow_id: String,
    pub requester_pid: String,
    pub provider_pid: String,
    pub amount: u64,
    pub state: String,
    pub contract_id: String,
    pub invocation_id: Option<String>,
    pub resolution_reason: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub resolved_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSettlement {
    pub escrow_id: String,
    pub to_provider: u64,
    pub to_requester: u64,
    pub slashed: u64,
    pub settled_at: i64,
}

// --- Reputation ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFeedback {
    pub from_agent: String,
    pub to_agent: String,
    pub score: f64,
    pub context: Option<String>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredStake {
    pub agent_pid: String,
    pub stake: u64,
    pub slash_count: u32,
    pub updated_at: i64,
}

// --- Negotiation ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredNegotiation {
    pub negotiation_id: String,
    pub requester_pid: String,
    pub provider_pid: String,
    pub capability_key: String,
    pub state: String,
    pub rounds_json: serde_json::Value,
    pub max_rounds: u32,
    pub created_at: i64,
    pub expires_at: i64,
    pub resolved_at: Option<i64>,
    pub final_terms_json: Option<serde_json::Value>,
}

// --- Agent Index ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAgentIndex {
    pub agent_pid: String,
    pub capabilities: String,
    pub contract_json: Option<serde_json::Value>,
    pub health_json: Option<serde_json::Value>,
    pub reputation_score: f64,
    pub last_indexed_at: i64,
}

// --- Pipeline State ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPipeline {
    pub pipeline_id: String,
    pub state: String,
    pub steps_json: serde_json::Value,
    pub created_at: i64,
    pub updated_at: i64,
}

// --- Context Snapshot ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSnapshot {
    pub snapshot_cid: String,
    pub agent_pid: String,
    pub data_json: serde_json::Value,
    pub created_at: i64,
    pub evicted: bool,
}

// --- Session Route ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRoute {
    pub session_id: String,
    pub cell_id: String,
    pub created_at: i64,
    pub ttl_ms: i64,
    pub access_count: u64,
}

// --- Cross-Cell Message ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCrossCellMessage {
    pub message_id: String,
    pub source_cell: String,
    pub target_cell: String,
    pub source_agent: String,
    pub target_agent: String,
    pub port_id: String,
    pub payload: Option<String>,
    pub timestamp: i64,
    pub delivered: bool,
}

// --- Watchdog ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWatchdogAction {
    pub rule_name: String,
    pub condition_json: serde_json::Value,
    pub action_json: serde_json::Value,
    pub fired_at: i64,
    pub result: String,
}

// --- Tool Definition ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToolDef {
    pub name: String,
    pub description: String,
    pub params_json: serde_json::Value,
    pub rules_json: serde_json::Value,
    pub domain: Option<String>,
    pub created_at: i64,
}

// --- Policy ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPolicy {
    pub policy_id: String,
    pub name: String,
    pub description: String,
    pub rules_json: serde_json::Value,
    pub created_at: i64,
    pub updated_at: i64,
}

// ═══════════════════════════════════════════════════════════════
// Custom Folder / Namespace Types
// ═══════════════════════════════════════════════════════════════

/// Who owns a custom storage folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderOwner {
    /// Owned by an agent (agent PID)
    Agent(String),
    /// Owned by a tool (tool name)
    Tool(String),
    /// Owned by the system / infrastructure
    System,
}

impl std::fmt::Display for FolderOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Agent(pid) => write!(f, "agent:{}", pid),
            Self::Tool(name) => write!(f, "tool:{}", name),
            Self::System => write!(f, "system"),
        }
    }
}

/// Metadata about a custom storage folder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderInfo {
    /// The namespace path (e.g., "agent:nurse/scratchpad" or "tool:search/cache")
    pub namespace: String,
    /// Who owns this folder
    pub owner: FolderOwner,
    /// Human-readable description
    pub description: String,
    /// When the folder was created
    pub created_at: i64,
    /// Number of entries in this folder
    pub entry_count: u64,
}

// ═══════════════════════════════════════════════════════════════
// EngineStore Trait
// ═══════════════════════════════════════════════════════════════

/// Production persistence for all Ring 1-4 engine components.
///
/// Includes both **system zones** (fixed tables like audit, escrow, etc.)
/// and **custom folders** (dynamic namespaces created by agents/tools on demand,
/// like `mkdir` on a filesystem).
///
/// Implementations:
/// - `InMemoryEngineStore` — HashMap-based (testing, dev)
/// - `SqliteEngineStore` — WAL-mode SQLite (production default)
/// - `PostgresEngineStore` — PostgreSQL (enterprise, future)
pub trait EngineStore: Send {
    // ── Audit (append-only) ──────────────────────────────────────

    fn append_audit(&mut self, entry: &EngineAuditEntry) -> EngineStoreResult<()>;
    fn query_audit(&self, filter: &AuditFilter) -> EngineStoreResult<Vec<EngineAuditEntry>>;
    fn audit_count(&self) -> EngineStoreResult<usize>;

    // ── Agent Behavior ───────────────────────────────────────────

    fn save_behavior(&mut self, profile: &BehaviorProfile) -> EngineStoreResult<()>;
    fn load_behavior(&self, agent_pid: &str) -> EngineStoreResult<Option<BehaviorProfile>>;

    // ── Circuit Breakers ─────────────────────────────────────────

    fn save_circuit_breaker(&mut self, cb: &CircuitBreakerState) -> EngineStoreResult<()>;
    fn load_circuit_breaker(&self, agent_pid: &str) -> EngineStoreResult<Option<CircuitBreakerState>>;
    fn load_all_circuit_breakers(&self) -> EngineStoreResult<Vec<CircuitBreakerState>>;

    // ── Adaptive Thresholds ──────────────────────────────────────

    fn save_threshold(&mut self, baseline: &ThresholdBaseline) -> EngineStoreResult<()>;
    fn load_threshold(&self, agent_pid: &str) -> EngineStoreResult<Option<ThresholdBaseline>>;

    // ── Secrets ──────────────────────────────────────────────────

    fn store_secret(&mut self, entry: &StoredSecret) -> EngineStoreResult<()>;
    fn load_secret(&self, secret_id: &str) -> EngineStoreResult<Option<StoredSecret>>;
    fn delete_secret(&mut self, secret_id: &str) -> EngineStoreResult<()>;
    fn purge_expired_secrets(&mut self, now_ms: i64) -> EngineStoreResult<usize>;
    fn load_secrets_by_agent(&self, agent_pid: &str) -> EngineStoreResult<Vec<StoredSecret>>;

    // ── Escrow (ACID critical) ───────────────────────────────────

    fn save_escrow(&mut self, account: &StoredEscrow) -> EngineStoreResult<()>;
    fn load_escrow(&self, escrow_id: &str) -> EngineStoreResult<Option<StoredEscrow>>;
    fn load_escrows_by_state(&self, state: &str) -> EngineStoreResult<Vec<StoredEscrow>>;
    fn save_settlement(&mut self, record: &StoredSettlement) -> EngineStoreResult<()>;

    // ── Reputation ───────────────────────────────────────────────

    fn submit_feedback(&mut self, fb: &StoredFeedback) -> EngineStoreResult<()>;
    fn load_feedback_for(&self, agent_pid: &str, limit: usize) -> EngineStoreResult<Vec<StoredFeedback>>;
    fn compute_avg_reputation(&self, agent_pid: &str) -> EngineStoreResult<f64>;
    fn save_stake(&mut self, stake: &StoredStake) -> EngineStoreResult<()>;
    fn load_stake(&self, agent_pid: &str) -> EngineStoreResult<Option<StoredStake>>;

    // ── Agent Index ──────────────────────────────────────────────

    fn index_agent(&mut self, entry: &StoredAgentIndex) -> EngineStoreResult<()>;
    fn search_agents(&self, query: &str, limit: usize) -> EngineStoreResult<Vec<StoredAgentIndex>>;
    fn load_agent_index(&self, agent_pid: &str) -> EngineStoreResult<Option<StoredAgentIndex>>;

    // ── Negotiations ─────────────────────────────────────────────

    fn save_negotiation(&mut self, neg: &StoredNegotiation) -> EngineStoreResult<()>;
    fn load_negotiation(&self, id: &str) -> EngineStoreResult<Option<StoredNegotiation>>;
    fn load_active_negotiations(&self) -> EngineStoreResult<Vec<StoredNegotiation>>;

    // ── Pipeline State ───────────────────────────────────────────

    fn save_pipeline(&mut self, pipeline: &StoredPipeline) -> EngineStoreResult<()>;
    fn load_pipeline(&self, id: &str) -> EngineStoreResult<Option<StoredPipeline>>;

    // ── Context Snapshots ────────────────────────────────────────

    fn save_snapshot(&mut self, snapshot: &StoredSnapshot) -> EngineStoreResult<()>;
    fn load_snapshot(&self, cid: &str) -> EngineStoreResult<Option<StoredSnapshot>>;
    fn load_snapshots_by_agent(&self, agent_pid: &str, limit: usize) -> EngineStoreResult<Vec<StoredSnapshot>>;

    // ── Session Routes ───────────────────────────────────────────

    fn save_route(&mut self, route: &StoredRoute) -> EngineStoreResult<()>;
    fn load_route(&self, session_id: &str) -> EngineStoreResult<Option<StoredRoute>>;
    fn purge_expired_routes(&mut self, now_ms: i64) -> EngineStoreResult<usize>;

    // ── Cross-Cell Messages ──────────────────────────────────────

    fn log_cross_cell_message(&mut self, msg: &StoredCrossCellMessage) -> EngineStoreResult<()>;
    fn load_messages_for_agent(&self, agent_pid: &str, limit: usize) -> EngineStoreResult<Vec<StoredCrossCellMessage>>;

    // ── Watchdog ─────────────────────────────────────────────────

    fn append_watchdog_action(&mut self, action: &StoredWatchdogAction) -> EngineStoreResult<()>;
    fn load_watchdog_history(&self, limit: usize) -> EngineStoreResult<Vec<StoredWatchdogAction>>;

    // ── Tool Definitions ─────────────────────────────────────────

    fn save_tool_def(&mut self, tool: &StoredToolDef) -> EngineStoreResult<()>;
    fn load_tool_defs(&self) -> EngineStoreResult<Vec<StoredToolDef>>;
    fn delete_tool_def(&mut self, name: &str) -> EngineStoreResult<()>;

    // ── Policies ─────────────────────────────────────────────────

    fn save_policy(&mut self, policy: &StoredPolicy) -> EngineStoreResult<()>;
    fn load_policies(&self) -> EngineStoreResult<Vec<StoredPolicy>>;
    fn delete_policy(&mut self, policy_id: &str) -> EngineStoreResult<()>;

    // ══════════════════════════════════════════════════════════════
    // Custom Folders — dynamic namespaced KV storage (like mkdir)
    // ══════════════════════════════════════════════════════════════
    //
    // Agents and tools can create their own storage folders on demand:
    //   dispatcher.create_folder("agent:nurse", "scratchpad", "Working memory");
    //   dispatcher.folder_put("agent:nurse/scratchpad", "patient_123", json!({...}));
    //   let data = dispatcher.folder_get("agent:nurse/scratchpad", "patient_123");
    //
    // Namespace convention:  {owner}/{folder_name}
    //   - "agent:nurse/scratchpad"      → nurse agent's scratchpad
    //   - "agent:doctor/notes"           → doctor agent's private notes
    //   - "tool:search/cache"            → search tool's result cache
    //   - "tool:db_query/schemas"        → db_query tool's schema store
    //   - "system/global_config"         → infra-level config

    /// Create a new folder (namespace). Like `mkdir`.
    fn create_folder(&mut self, namespace: &str, owner: &FolderOwner, description: &str) -> EngineStoreResult<()>;

    /// List all folders, optionally filtered by owner.
    fn list_folders(&self, owner_filter: Option<&FolderOwner>) -> EngineStoreResult<Vec<FolderInfo>>;

    /// Delete an entire folder and all its entries. Like `rm -rf`.
    fn delete_folder(&mut self, namespace: &str) -> EngineStoreResult<()>;

    /// Put a key-value entry into a folder. Creates the entry or overwrites.
    fn folder_put(&mut self, namespace: &str, key: &str, value: &serde_json::Value) -> EngineStoreResult<()>;

    /// Get a value from a folder by key.
    fn folder_get(&self, namespace: &str, key: &str) -> EngineStoreResult<Option<serde_json::Value>>;

    /// Delete a key from a folder.
    fn folder_delete(&mut self, namespace: &str, key: &str) -> EngineStoreResult<()>;

    /// List all keys in a folder (optionally with a prefix filter).
    fn folder_keys(&self, namespace: &str, prefix: Option<&str>) -> EngineStoreResult<Vec<String>>;

    /// Count entries in a folder.
    fn folder_count(&self, namespace: &str) -> EngineStoreResult<usize>;

    /// Check if a folder exists.
    fn folder_exists(&self, namespace: &str) -> EngineStoreResult<bool>;
}

// ═══════════════════════════════════════════════════════════════
// InMemoryEngineStore — HashMap-based test/dev implementation
// ═══════════════════════════════════════════════════════════════

/// In-memory store for testing and development. Not crash-safe.
#[derive(Default)]
pub struct InMemoryEngineStore {
    audit: Vec<EngineAuditEntry>,
    behaviors: HashMap<String, BehaviorProfile>,
    circuit_breakers: HashMap<String, CircuitBreakerState>,
    thresholds: HashMap<String, ThresholdBaseline>,
    secrets: HashMap<String, StoredSecret>,
    escrows: HashMap<String, StoredEscrow>,
    settlements: Vec<StoredSettlement>,
    feedback: Vec<StoredFeedback>,
    stakes: HashMap<String, StoredStake>,
    agent_index: HashMap<String, StoredAgentIndex>,
    negotiations: HashMap<String, StoredNegotiation>,
    pipelines: HashMap<String, StoredPipeline>,
    snapshots: HashMap<String, StoredSnapshot>,
    routes: HashMap<String, StoredRoute>,
    cross_cell_messages: Vec<StoredCrossCellMessage>,
    watchdog_history: Vec<StoredWatchdogAction>,
    tool_defs: HashMap<String, StoredToolDef>,
    policies: HashMap<String, StoredPolicy>,
    // ── Custom folders (dynamic namespaces) ──────────────────────
    folder_meta: HashMap<String, FolderInfo>,
    folder_data: HashMap<String, HashMap<String, serde_json::Value>>,
}

impl InMemoryEngineStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn total_objects(&self) -> usize {
        self.audit.len()
            + self.behaviors.len()
            + self.circuit_breakers.len()
            + self.thresholds.len()
            + self.secrets.len()
            + self.escrows.len()
            + self.settlements.len()
            + self.feedback.len()
            + self.stakes.len()
            + self.agent_index.len()
            + self.negotiations.len()
            + self.pipelines.len()
            + self.snapshots.len()
            + self.routes.len()
            + self.cross_cell_messages.len()
            + self.watchdog_history.len()
            + self.tool_defs.len()
            + self.policies.len()
    }
}

impl EngineStore for InMemoryEngineStore {
    // ── Audit ────────────────────────────────────────────────────

    fn append_audit(&mut self, entry: &EngineAuditEntry) -> EngineStoreResult<()> {
        self.audit.push(entry.clone());
        Ok(())
    }

    fn query_audit(&self, filter: &AuditFilter) -> EngineStoreResult<Vec<EngineAuditEntry>> {
        let mut results: Vec<_> = self.audit.iter()
            .filter(|e| {
                if let Some(from) = filter.from_ms { if e.timestamp < from { return false; } }
                if let Some(to) = filter.to_ms { if e.timestamp > to { return false; } }
                if let Some(ref pid) = filter.agent_pid { if e.agent_pid.as_deref() != Some(pid) { return false; } }
                if let Some(ref cat) = filter.category { if e.category != *cat { return false; } }
                if let Some(ref sev) = filter.severity { if e.severity != *sev { return false; } }
                true
            })
            .cloned()
            .collect();
        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }
        Ok(results)
    }

    fn audit_count(&self) -> EngineStoreResult<usize> {
        Ok(self.audit.len())
    }

    // ── Agent Behavior ───────────────────────────────────────────

    fn save_behavior(&mut self, profile: &BehaviorProfile) -> EngineStoreResult<()> {
        self.behaviors.insert(profile.agent_pid.clone(), profile.clone());
        Ok(())
    }

    fn load_behavior(&self, agent_pid: &str) -> EngineStoreResult<Option<BehaviorProfile>> {
        Ok(self.behaviors.get(agent_pid).cloned())
    }

    // ── Circuit Breakers ─────────────────────────────────────────

    fn save_circuit_breaker(&mut self, cb: &CircuitBreakerState) -> EngineStoreResult<()> {
        self.circuit_breakers.insert(cb.agent_pid.clone(), cb.clone());
        Ok(())
    }

    fn load_circuit_breaker(&self, agent_pid: &str) -> EngineStoreResult<Option<CircuitBreakerState>> {
        Ok(self.circuit_breakers.get(agent_pid).cloned())
    }

    fn load_all_circuit_breakers(&self) -> EngineStoreResult<Vec<CircuitBreakerState>> {
        Ok(self.circuit_breakers.values().cloned().collect())
    }

    // ── Adaptive Thresholds ──────────────────────────────────────

    fn save_threshold(&mut self, baseline: &ThresholdBaseline) -> EngineStoreResult<()> {
        self.thresholds.insert(baseline.agent_pid.clone(), baseline.clone());
        Ok(())
    }

    fn load_threshold(&self, agent_pid: &str) -> EngineStoreResult<Option<ThresholdBaseline>> {
        Ok(self.thresholds.get(agent_pid).cloned())
    }

    // ── Secrets ──────────────────────────────────────────────────

    fn store_secret(&mut self, entry: &StoredSecret) -> EngineStoreResult<()> {
        self.secrets.insert(entry.secret_id.clone(), entry.clone());
        Ok(())
    }

    fn load_secret(&self, secret_id: &str) -> EngineStoreResult<Option<StoredSecret>> {
        Ok(self.secrets.get(secret_id).cloned())
    }

    fn delete_secret(&mut self, secret_id: &str) -> EngineStoreResult<()> {
        self.secrets.remove(secret_id);
        Ok(())
    }

    fn purge_expired_secrets(&mut self, now_ms: i64) -> EngineStoreResult<usize> {
        let before = self.secrets.len();
        self.secrets.retain(|_, s| {
            s.expires_at.map_or(true, |exp| now_ms <= exp)
        });
        Ok(before - self.secrets.len())
    }

    fn load_secrets_by_agent(&self, agent_pid: &str) -> EngineStoreResult<Vec<StoredSecret>> {
        Ok(self.secrets.values().filter(|s| s.agent_pid == agent_pid).cloned().collect())
    }

    // ── Escrow ───────────────────────────────────────────────────

    fn save_escrow(&mut self, account: &StoredEscrow) -> EngineStoreResult<()> {
        self.escrows.insert(account.escrow_id.clone(), account.clone());
        Ok(())
    }

    fn load_escrow(&self, escrow_id: &str) -> EngineStoreResult<Option<StoredEscrow>> {
        Ok(self.escrows.get(escrow_id).cloned())
    }

    fn load_escrows_by_state(&self, state: &str) -> EngineStoreResult<Vec<StoredEscrow>> {
        Ok(self.escrows.values().filter(|e| e.state == state).cloned().collect())
    }

    fn save_settlement(&mut self, record: &StoredSettlement) -> EngineStoreResult<()> {
        self.settlements.push(record.clone());
        Ok(())
    }

    // ── Reputation ───────────────────────────────────────────────

    fn submit_feedback(&mut self, fb: &StoredFeedback) -> EngineStoreResult<()> {
        self.feedback.push(fb.clone());
        Ok(())
    }

    fn load_feedback_for(&self, agent_pid: &str, limit: usize) -> EngineStoreResult<Vec<StoredFeedback>> {
        let mut results: Vec<_> = self.feedback.iter()
            .filter(|f| f.to_agent == agent_pid)
            .cloned()
            .collect();
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        results.truncate(limit);
        Ok(results)
    }

    fn compute_avg_reputation(&self, agent_pid: &str) -> EngineStoreResult<f64> {
        let scores: Vec<f64> = self.feedback.iter()
            .filter(|f| f.to_agent == agent_pid)
            .map(|f| f.score)
            .collect();
        if scores.is_empty() {
            return Ok(0.0);
        }
        Ok(scores.iter().sum::<f64>() / scores.len() as f64)
    }

    fn save_stake(&mut self, stake: &StoredStake) -> EngineStoreResult<()> {
        self.stakes.insert(stake.agent_pid.clone(), stake.clone());
        Ok(())
    }

    fn load_stake(&self, agent_pid: &str) -> EngineStoreResult<Option<StoredStake>> {
        Ok(self.stakes.get(agent_pid).cloned())
    }

    // ── Agent Index ──────────────────────────────────────────────

    fn index_agent(&mut self, entry: &StoredAgentIndex) -> EngineStoreResult<()> {
        self.agent_index.insert(entry.agent_pid.clone(), entry.clone());
        Ok(())
    }

    fn search_agents(&self, query: &str, limit: usize) -> EngineStoreResult<Vec<StoredAgentIndex>> {
        let query_lower = query.to_lowercase();
        let mut results: Vec<_> = self.agent_index.values()
            .filter(|e| e.capabilities.to_lowercase().contains(&query_lower)
                || e.agent_pid.to_lowercase().contains(&query_lower))
            .cloned()
            .collect();
        results.truncate(limit);
        Ok(results)
    }

    fn load_agent_index(&self, agent_pid: &str) -> EngineStoreResult<Option<StoredAgentIndex>> {
        Ok(self.agent_index.get(agent_pid).cloned())
    }

    // ── Negotiations ─────────────────────────────────────────────

    fn save_negotiation(&mut self, neg: &StoredNegotiation) -> EngineStoreResult<()> {
        self.negotiations.insert(neg.negotiation_id.clone(), neg.clone());
        Ok(())
    }

    fn load_negotiation(&self, id: &str) -> EngineStoreResult<Option<StoredNegotiation>> {
        Ok(self.negotiations.get(id).cloned())
    }

    fn load_active_negotiations(&self) -> EngineStoreResult<Vec<StoredNegotiation>> {
        Ok(self.negotiations.values().filter(|n| n.state == "open").cloned().collect())
    }

    // ── Pipeline State ───────────────────────────────────────────

    fn save_pipeline(&mut self, pipeline: &StoredPipeline) -> EngineStoreResult<()> {
        self.pipelines.insert(pipeline.pipeline_id.clone(), pipeline.clone());
        Ok(())
    }

    fn load_pipeline(&self, id: &str) -> EngineStoreResult<Option<StoredPipeline>> {
        Ok(self.pipelines.get(id).cloned())
    }

    // ── Context Snapshots ────────────────────────────────────────

    fn save_snapshot(&mut self, snapshot: &StoredSnapshot) -> EngineStoreResult<()> {
        self.snapshots.insert(snapshot.snapshot_cid.clone(), snapshot.clone());
        Ok(())
    }

    fn load_snapshot(&self, cid: &str) -> EngineStoreResult<Option<StoredSnapshot>> {
        Ok(self.snapshots.get(cid).cloned())
    }

    fn load_snapshots_by_agent(&self, agent_pid: &str, limit: usize) -> EngineStoreResult<Vec<StoredSnapshot>> {
        let mut results: Vec<_> = self.snapshots.values()
            .filter(|s| s.agent_pid == agent_pid)
            .cloned()
            .collect();
        results.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        results.truncate(limit);
        Ok(results)
    }

    // ── Session Routes ───────────────────────────────────────────

    fn save_route(&mut self, route: &StoredRoute) -> EngineStoreResult<()> {
        self.routes.insert(route.session_id.clone(), route.clone());
        Ok(())
    }

    fn load_route(&self, session_id: &str) -> EngineStoreResult<Option<StoredRoute>> {
        Ok(self.routes.get(session_id).cloned())
    }

    fn purge_expired_routes(&mut self, now_ms: i64) -> EngineStoreResult<usize> {
        let before = self.routes.len();
        self.routes.retain(|_, r| {
            r.created_at + r.ttl_ms > now_ms
        });
        Ok(before - self.routes.len())
    }

    // ── Cross-Cell Messages ──────────────────────────────────────

    fn log_cross_cell_message(&mut self, msg: &StoredCrossCellMessage) -> EngineStoreResult<()> {
        self.cross_cell_messages.push(msg.clone());
        Ok(())
    }

    fn load_messages_for_agent(&self, agent_pid: &str, limit: usize) -> EngineStoreResult<Vec<StoredCrossCellMessage>> {
        let mut results: Vec<_> = self.cross_cell_messages.iter()
            .filter(|m| m.source_agent == agent_pid || m.target_agent == agent_pid)
            .cloned()
            .collect();
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        results.truncate(limit);
        Ok(results)
    }

    // ── Watchdog ─────────────────────────────────────────────────

    fn append_watchdog_action(&mut self, action: &StoredWatchdogAction) -> EngineStoreResult<()> {
        self.watchdog_history.push(action.clone());
        Ok(())
    }

    fn load_watchdog_history(&self, limit: usize) -> EngineStoreResult<Vec<StoredWatchdogAction>> {
        let mut results = self.watchdog_history.clone();
        results.sort_by(|a, b| b.fired_at.cmp(&a.fired_at));
        results.truncate(limit);
        Ok(results)
    }

    // ── Tool Definitions ─────────────────────────────────────────

    fn save_tool_def(&mut self, tool: &StoredToolDef) -> EngineStoreResult<()> {
        self.tool_defs.insert(tool.name.clone(), tool.clone());
        Ok(())
    }

    fn load_tool_defs(&self) -> EngineStoreResult<Vec<StoredToolDef>> {
        Ok(self.tool_defs.values().cloned().collect())
    }

    fn delete_tool_def(&mut self, name: &str) -> EngineStoreResult<()> {
        self.tool_defs.remove(name);
        Ok(())
    }

    // ── Policies ─────────────────────────────────────────────────

    fn save_policy(&mut self, policy: &StoredPolicy) -> EngineStoreResult<()> {
        self.policies.insert(policy.policy_id.clone(), policy.clone());
        Ok(())
    }

    fn load_policies(&self) -> EngineStoreResult<Vec<StoredPolicy>> {
        Ok(self.policies.values().cloned().collect())
    }

    fn delete_policy(&mut self, policy_id: &str) -> EngineStoreResult<()> {
        self.policies.remove(policy_id);
        Ok(())
    }

    // ── Custom Folders ───────────────────────────────────────────

    fn create_folder(&mut self, namespace: &str, owner: &FolderOwner, description: &str) -> EngineStoreResult<()> {
        if self.folder_meta.contains_key(namespace) {
            return Ok(()); // idempotent — already exists
        }
        self.folder_meta.insert(namespace.to_string(), FolderInfo {
            namespace: namespace.to_string(),
            owner: owner.clone(),
            description: description.to_string(),
            created_at: chrono::Utc::now().timestamp_millis(),
            entry_count: 0,
        });
        self.folder_data.insert(namespace.to_string(), HashMap::new());
        Ok(())
    }

    fn list_folders(&self, owner_filter: Option<&FolderOwner>) -> EngineStoreResult<Vec<FolderInfo>> {
        let folders: Vec<FolderInfo> = self.folder_meta.values()
            .filter(|f| {
                if let Some(owner) = owner_filter {
                    &f.owner == owner
                } else {
                    true
                }
            })
            .map(|f| {
                let count = self.folder_data.get(&f.namespace).map_or(0, |d| d.len() as u64);
                FolderInfo { entry_count: count, ..f.clone() }
            })
            .collect();
        Ok(folders)
    }

    fn delete_folder(&mut self, namespace: &str) -> EngineStoreResult<()> {
        self.folder_meta.remove(namespace);
        self.folder_data.remove(namespace);
        Ok(())
    }

    fn folder_put(&mut self, namespace: &str, key: &str, value: &serde_json::Value) -> EngineStoreResult<()> {
        let data = self.folder_data.entry(namespace.to_string()).or_insert_with(HashMap::new);
        data.insert(key.to_string(), value.clone());
        // Auto-create folder metadata if it doesn't exist (implicit mkdir)
        if !self.folder_meta.contains_key(namespace) {
            self.folder_meta.insert(namespace.to_string(), FolderInfo {
                namespace: namespace.to_string(),
                owner: FolderOwner::System,
                description: String::new(),
                created_at: chrono::Utc::now().timestamp_millis(),
                entry_count: 0,
            });
        }
        Ok(())
    }

    fn folder_get(&self, namespace: &str, key: &str) -> EngineStoreResult<Option<serde_json::Value>> {
        Ok(self.folder_data.get(namespace).and_then(|d| d.get(key).cloned()))
    }

    fn folder_delete(&mut self, namespace: &str, key: &str) -> EngineStoreResult<()> {
        if let Some(data) = self.folder_data.get_mut(namespace) {
            data.remove(key);
        }
        Ok(())
    }

    fn folder_keys(&self, namespace: &str, prefix: Option<&str>) -> EngineStoreResult<Vec<String>> {
        let keys = match self.folder_data.get(namespace) {
            Some(data) => {
                let mut keys: Vec<String> = data.keys()
                    .filter(|k| prefix.map_or(true, |p| k.starts_with(p)))
                    .cloned()
                    .collect();
                keys.sort();
                keys
            }
            None => Vec::new(),
        };
        Ok(keys)
    }

    fn folder_count(&self, namespace: &str) -> EngineStoreResult<usize> {
        Ok(self.folder_data.get(namespace).map_or(0, |d| d.len()))
    }

    fn folder_exists(&self, namespace: &str) -> EngineStoreResult<bool> {
        Ok(self.folder_meta.contains_key(namespace))
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> i64 { chrono::Utc::now().timestamp_millis() }

    #[test]
    fn test_audit_append_and_query() {
        let mut store = InMemoryEngineStore::new();
        let ts = now();
        store.append_audit(&EngineAuditEntry {
            timestamp: ts,
            category: "firewall".into(),
            agent_pid: Some("agent:nurse".into()),
            action: "tool.call".into(),
            resource: Some("tool://search".into()),
            verdict: Some("allowed".into()),
            details: None,
            severity: "info".into(),
        }).unwrap();
        store.append_audit(&EngineAuditEntry {
            timestamp: ts + 1,
            category: "guard".into(),
            agent_pid: Some("agent:doctor".into()),
            action: "output.check".into(),
            resource: None,
            verdict: Some("blocked".into()),
            details: None,
            severity: "warning".into(),
        }).unwrap();

        assert_eq!(store.audit_count().unwrap(), 2);

        let all = store.query_audit(&AuditFilter::default()).unwrap();
        assert_eq!(all.len(), 2);

        let firewall = store.query_audit(&AuditFilter {
            category: Some("firewall".into()),
            ..Default::default()
        }).unwrap();
        assert_eq!(firewall.len(), 1);
        assert_eq!(firewall[0].agent_pid.as_deref(), Some("agent:nurse"));

        let nurse = store.query_audit(&AuditFilter {
            agent_pid: Some("agent:nurse".into()),
            ..Default::default()
        }).unwrap();
        assert_eq!(nurse.len(), 1);
    }

    #[test]
    fn test_behavior_save_load() {
        let mut store = InMemoryEngineStore::new();
        let profile = BehaviorProfile {
            agent_pid: "agent:nurse".into(),
            total_actions: 42,
            total_errors: 3,
            total_tool_calls: 15,
            avg_threat_score: 0.12,
            recent_scores: vec![0.1, 0.15, 0.11],
            last_action_at: Some(now()),
            updated_at: now(),
        };
        store.save_behavior(&profile).unwrap();
        let loaded = store.load_behavior("agent:nurse").unwrap().unwrap();
        assert_eq!(loaded.total_actions, 42);
        assert_eq!(loaded.total_tool_calls, 15);
        assert!(store.load_behavior("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_circuit_breaker_persist() {
        let mut store = InMemoryEngineStore::new();
        let cb = CircuitBreakerState {
            agent_pid: "agent:risky".into(),
            state: "open".into(),
            failure_count: 5,
            failure_threshold: 5,
            reset_timeout_ms: 60_000,
            half_open_max_probes: 3,
            half_open_success_count: 0,
            last_failure_ms: now(),
            last_state_change_ms: now(),
        };
        store.save_circuit_breaker(&cb).unwrap();
        let loaded = store.load_circuit_breaker("agent:risky").unwrap().unwrap();
        assert_eq!(loaded.state, "open");
        assert_eq!(loaded.failure_count, 5);

        let all = store.load_all_circuit_breakers().unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_secrets_crud_and_purge() {
        let mut store = InMemoryEngineStore::new();
        let ts = now();
        store.store_secret(&StoredSecret {
            secret_id: "api_key_1".into(),
            agent_pid: "agent:nurse".into(),
            value: "sk-secret123".into(),
            created_at: ts,
            expires_at: Some(ts + 60_000),
            description: "OpenAI key".into(),
        }).unwrap();
        store.store_secret(&StoredSecret {
            secret_id: "permanent".into(),
            agent_pid: "agent:nurse".into(),
            value: "no-expiry".into(),
            created_at: ts,
            expires_at: None,
            description: "Permanent secret".into(),
        }).unwrap();

        assert!(store.load_secret("api_key_1").unwrap().is_some());
        assert_eq!(store.load_secrets_by_agent("agent:nurse").unwrap().len(), 2);

        // Purge expired (move time forward)
        let purged = store.purge_expired_secrets(ts + 120_000).unwrap();
        assert_eq!(purged, 1);
        assert!(store.load_secret("api_key_1").unwrap().is_none());
        assert!(store.load_secret("permanent").unwrap().is_some());

        // Delete
        store.delete_secret("permanent").unwrap();
        assert!(store.load_secret("permanent").unwrap().is_none());
    }

    #[test]
    fn test_escrow_acid() {
        let mut store = InMemoryEngineStore::new();
        let ts = now();
        store.save_escrow(&StoredEscrow {
            escrow_id: "esc_1".into(),
            requester_pid: "agent:buyer".into(),
            provider_pid: "agent:seller".into(),
            amount: 1000,
            state: "locked".into(),
            contract_id: "contract_1".into(),
            invocation_id: None,
            resolution_reason: None,
            created_at: ts,
            expires_at: ts + 86_400_000,
            resolved_at: None,
        }).unwrap();

        let loaded = store.load_escrow("esc_1").unwrap().unwrap();
        assert_eq!(loaded.amount, 1000);
        assert_eq!(loaded.state, "locked");

        let locked = store.load_escrows_by_state("locked").unwrap();
        assert_eq!(locked.len(), 1);

        // Settle
        store.save_settlement(&StoredSettlement {
            escrow_id: "esc_1".into(),
            to_provider: 900,
            to_requester: 100,
            slashed: 0,
            settled_at: ts + 1000,
        }).unwrap();
    }

    #[test]
    fn test_reputation_feedback() {
        let mut store = InMemoryEngineStore::new();
        let ts = now();
        for i in 0..5 {
            store.submit_feedback(&StoredFeedback {
                from_agent: format!("agent:reviewer_{}", i),
                to_agent: "agent:worker".into(),
                score: 0.8 + (i as f64) * 0.02,
                context: None,
                timestamp: ts + i,
            }).unwrap();
        }

        let feedback = store.load_feedback_for("agent:worker", 3).unwrap();
        assert_eq!(feedback.len(), 3);

        let avg = store.compute_avg_reputation("agent:worker").unwrap();
        assert!(avg > 0.7 && avg < 1.0);

        let no_rep = store.compute_avg_reputation("nonexistent").unwrap();
        assert_eq!(no_rep, 0.0);
    }

    #[test]
    fn test_agent_index_search() {
        let mut store = InMemoryEngineStore::new();
        let ts = now();
        store.index_agent(&StoredAgentIndex {
            agent_pid: "agent:search_bot".into(),
            capabilities: "web search, news retrieval, fact checking".into(),
            contract_json: None,
            health_json: None,
            reputation_score: 0.95,
            last_indexed_at: ts,
        }).unwrap();
        store.index_agent(&StoredAgentIndex {
            agent_pid: "agent:code_bot".into(),
            capabilities: "code generation, code review, debugging".into(),
            contract_json: None,
            health_json: None,
            reputation_score: 0.88,
            last_indexed_at: ts,
        }).unwrap();

        let search_results = store.search_agents("code", 10).unwrap();
        assert_eq!(search_results.len(), 1);
        assert_eq!(search_results[0].agent_pid, "agent:code_bot");

        let all = store.search_agents("", 10).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_session_routes_and_purge() {
        let mut store = InMemoryEngineStore::new();
        let ts = now();
        store.save_route(&StoredRoute {
            session_id: "session_1".into(),
            cell_id: "cell_a".into(),
            created_at: ts,
            ttl_ms: 60_000,
            access_count: 0,
        }).unwrap();
        store.save_route(&StoredRoute {
            session_id: "session_2".into(),
            cell_id: "cell_b".into(),
            created_at: ts - 120_000,
            ttl_ms: 60_000,
            access_count: 5,
        }).unwrap();

        assert!(store.load_route("session_1").unwrap().is_some());

        let purged = store.purge_expired_routes(ts + 1).unwrap();
        assert_eq!(purged, 1); // session_2 expired
        assert!(store.load_route("session_1").unwrap().is_some());
        assert!(store.load_route("session_2").unwrap().is_none());
    }

    #[test]
    fn test_tool_defs_crud() {
        let mut store = InMemoryEngineStore::new();
        store.save_tool_def(&StoredToolDef {
            name: "search".into(),
            description: "Search the web".into(),
            params_json: serde_json::json!([{"name": "query", "type": "string"}]),
            rules_json: serde_json::json!({}),
            domain: Some("web".into()),
            created_at: now(),
        }).unwrap();

        let tools = store.load_tool_defs().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "search");

        store.delete_tool_def("search").unwrap();
        assert_eq!(store.load_tool_defs().unwrap().len(), 0);
    }

    #[test]
    fn test_total_objects() {
        let store = InMemoryEngineStore::new();
        assert_eq!(store.total_objects(), 0);
    }

    #[test]
    fn test_pipeline_state() {
        let mut store = InMemoryEngineStore::new();
        let ts = now();
        store.save_pipeline(&StoredPipeline {
            pipeline_id: "pipe_1".into(),
            state: "running".into(),
            steps_json: serde_json::json!([
                {"step_id": "s1", "action": "search", "status": "succeeded"},
                {"step_id": "s2", "action": "summarize", "status": "running"}
            ]),
            created_at: ts,
            updated_at: ts,
        }).unwrap();

        let loaded = store.load_pipeline("pipe_1").unwrap().unwrap();
        assert_eq!(loaded.state, "running");
        assert!(store.load_pipeline("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_negotiation_lifecycle() {
        let mut store = InMemoryEngineStore::new();
        let ts = now();
        store.save_negotiation(&StoredNegotiation {
            negotiation_id: "neg_1".into(),
            requester_pid: "agent:buyer".into(),
            provider_pid: "agent:seller".into(),
            capability_key: "web_search".into(),
            state: "open".into(),
            rounds_json: serde_json::json!([]),
            max_rounds: 5,
            created_at: ts,
            expires_at: ts + 60_000,
            resolved_at: None,
            final_terms_json: None,
        }).unwrap();

        let active = store.load_active_negotiations().unwrap();
        assert_eq!(active.len(), 1);

        let loaded = store.load_negotiation("neg_1").unwrap().unwrap();
        assert_eq!(loaded.state, "open");
    }

    #[test]
    fn test_watchdog_history() {
        let mut store = InMemoryEngineStore::new();
        let ts = now();
        store.append_watchdog_action(&StoredWatchdogAction {
            rule_name: "memory_quota_exceeded".into(),
            condition_json: serde_json::json!({"type": "memory_quota_exceeded", "agent_pid": "agent:greedy"}),
            action_json: serde_json::json!({"type": "evict_to_tier", "target_tier": "cold"}),
            fired_at: ts,
            result: "fired".into(),
        }).unwrap();

        let history = store.load_watchdog_history(10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].rule_name, "memory_quota_exceeded");
    }

    #[test]
    fn test_context_snapshots() {
        let mut store = InMemoryEngineStore::new();
        let ts = now();
        store.save_snapshot(&StoredSnapshot {
            snapshot_cid: "cid_snap_1".into(),
            agent_pid: "agent:thinker".into(),
            data_json: serde_json::json!({"context_tokens": 4096, "step_counter": 7}),
            created_at: ts,
            evicted: false,
        }).unwrap();
        store.save_snapshot(&StoredSnapshot {
            snapshot_cid: "cid_snap_2".into(),
            agent_pid: "agent:thinker".into(),
            data_json: serde_json::json!({"context_tokens": 8192, "step_counter": 15}),
            created_at: ts + 1000,
            evicted: true,
        }).unwrap();

        let loaded = store.load_snapshot("cid_snap_1").unwrap().unwrap();
        assert!(!loaded.evicted);

        let agent_snaps = store.load_snapshots_by_agent("agent:thinker", 10).unwrap();
        assert_eq!(agent_snaps.len(), 2);
        // Should be ordered by created_at DESC
        assert_eq!(agent_snaps[0].snapshot_cid, "cid_snap_2");
    }

    #[test]
    fn test_cross_cell_messages() {
        let mut store = InMemoryEngineStore::new();
        let ts = now();
        store.log_cross_cell_message(&StoredCrossCellMessage {
            message_id: "msg_1".into(),
            source_cell: "cell_a".into(),
            target_cell: "cell_b".into(),
            source_agent: "agent:sender".into(),
            target_agent: "agent:receiver".into(),
            port_id: "port_1".into(),
            payload: Some("hello".into()),
            timestamp: ts,
            delivered: true,
        }).unwrap();

        let msgs = store.load_messages_for_agent("agent:sender", 10).unwrap();
        assert_eq!(msgs.len(), 1);
        let msgs2 = store.load_messages_for_agent("agent:receiver", 10).unwrap();
        assert_eq!(msgs2.len(), 1);
    }

    #[test]
    fn test_policies_crud() {
        let mut store = InMemoryEngineStore::new();
        store.save_policy(&StoredPolicy {
            policy_id: "pol_1".into(),
            name: "deny_external_tools".into(),
            description: "Block external API calls".into(),
            rules_json: serde_json::json!([{"pattern": "tool.external.*", "effect": "deny"}]),
            created_at: now(),
            updated_at: now(),
        }).unwrap();

        let policies = store.load_policies().unwrap();
        assert_eq!(policies.len(), 1);

        store.delete_policy("pol_1").unwrap();
        assert_eq!(store.load_policies().unwrap().len(), 0);
    }

    // ── Custom Folder Tests ──────────────────────────────────────

    #[test]
    fn test_agent_creates_own_folder() {
        let mut store = InMemoryEngineStore::new();
        let owner = FolderOwner::Agent("nurse".into());

        store.create_folder("agent:nurse/scratchpad", &owner, "Nurse working memory").unwrap();
        assert!(store.folder_exists("agent:nurse/scratchpad").unwrap());
        assert!(!store.folder_exists("agent:nurse/nonexistent").unwrap());

        // Put data
        store.folder_put("agent:nurse/scratchpad", "patient_123", &serde_json::json!({
            "name": "John Doe", "age": 45, "bp": "140/90"
        })).unwrap();
        store.folder_put("agent:nurse/scratchpad", "patient_456", &serde_json::json!({
            "name": "Jane Smith", "age": 32
        })).unwrap();

        assert_eq!(store.folder_count("agent:nurse/scratchpad").unwrap(), 2);

        // Get data
        let val = store.folder_get("agent:nurse/scratchpad", "patient_123").unwrap().unwrap();
        assert_eq!(val["name"], "John Doe");

        // Keys
        let keys = store.folder_keys("agent:nurse/scratchpad", None).unwrap();
        assert_eq!(keys.len(), 2);

        // Prefix filter
        let keys = store.folder_keys("agent:nurse/scratchpad", Some("patient_1")).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "patient_123");

        // Delete single key
        store.folder_delete("agent:nurse/scratchpad", "patient_123").unwrap();
        assert_eq!(store.folder_count("agent:nurse/scratchpad").unwrap(), 1);
        assert!(store.folder_get("agent:nurse/scratchpad", "patient_123").unwrap().is_none());
    }

    #[test]
    fn test_tool_creates_own_folder() {
        let mut store = InMemoryEngineStore::new();
        let owner = FolderOwner::Tool("search".into());

        store.create_folder("tool:search/cache", &owner, "Search result cache").unwrap();

        store.folder_put("tool:search/cache", "query:diabetes treatment", &serde_json::json!({
            "results": ["result1", "result2"], "cached_at": 1700000000
        })).unwrap();
        store.folder_put("tool:search/cache", "query:blood pressure", &serde_json::json!({
            "results": ["bp1"], "cached_at": 1700000001
        })).unwrap();

        assert_eq!(store.folder_count("tool:search/cache").unwrap(), 2);

        let val = store.folder_get("tool:search/cache", "query:diabetes treatment").unwrap().unwrap();
        assert_eq!(val["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_folder_isolation_between_agents() {
        let mut store = InMemoryEngineStore::new();

        store.create_folder("agent:nurse/notes", &FolderOwner::Agent("nurse".into()), "Nurse notes").unwrap();
        store.create_folder("agent:doctor/notes", &FolderOwner::Agent("doctor".into()), "Doctor notes").unwrap();

        store.folder_put("agent:nurse/notes", "key1", &serde_json::json!("nurse data")).unwrap();
        store.folder_put("agent:doctor/notes", "key1", &serde_json::json!("doctor data")).unwrap();

        // Same key in different folders — completely isolated
        let nurse_val = store.folder_get("agent:nurse/notes", "key1").unwrap().unwrap();
        let doctor_val = store.folder_get("agent:doctor/notes", "key1").unwrap().unwrap();
        assert_eq!(nurse_val, "nurse data");
        assert_eq!(doctor_val, "doctor data");
    }

    #[test]
    fn test_list_folders_by_owner() {
        let mut store = InMemoryEngineStore::new();

        store.create_folder("agent:nurse/notes", &FolderOwner::Agent("nurse".into()), "Notes").unwrap();
        store.create_folder("agent:nurse/cache", &FolderOwner::Agent("nurse".into()), "Cache").unwrap();
        store.create_folder("tool:search/cache", &FolderOwner::Tool("search".into()), "Search cache").unwrap();
        store.create_folder("system/config", &FolderOwner::System, "System config").unwrap();

        // All folders
        let all = store.list_folders(None).unwrap();
        assert_eq!(all.len(), 4);

        // Agent-specific
        let nurse_folders = store.list_folders(Some(&FolderOwner::Agent("nurse".into()))).unwrap();
        assert_eq!(nurse_folders.len(), 2);

        // Tool-specific
        let tool_folders = store.list_folders(Some(&FolderOwner::Tool("search".into()))).unwrap();
        assert_eq!(tool_folders.len(), 1);

        // System
        let sys_folders = store.list_folders(Some(&FolderOwner::System)).unwrap();
        assert_eq!(sys_folders.len(), 1);
    }

    #[test]
    fn test_delete_folder_removes_all_data() {
        let mut store = InMemoryEngineStore::new();
        store.create_folder("agent:temp/work", &FolderOwner::Agent("temp".into()), "Temp").unwrap();
        store.folder_put("agent:temp/work", "k1", &serde_json::json!("v1")).unwrap();
        store.folder_put("agent:temp/work", "k2", &serde_json::json!("v2")).unwrap();
        assert_eq!(store.folder_count("agent:temp/work").unwrap(), 2);

        // rm -rf
        store.delete_folder("agent:temp/work").unwrap();
        assert!(!store.folder_exists("agent:temp/work").unwrap());
        assert_eq!(store.folder_count("agent:temp/work").unwrap(), 0);
        assert!(store.folder_get("agent:temp/work", "k1").unwrap().is_none());
    }

    #[test]
    fn test_implicit_mkdir_on_put() {
        let mut store = InMemoryEngineStore::new();

        // Put without explicit create_folder — should auto-create
        store.folder_put("auto/created", "key", &serde_json::json!("value")).unwrap();
        assert!(store.folder_exists("auto/created").unwrap());
        assert_eq!(store.folder_count("auto/created").unwrap(), 1);
    }

    #[test]
    fn test_folder_entry_count_in_listing() {
        let mut store = InMemoryEngineStore::new();
        store.create_folder("agent:a/data", &FolderOwner::Agent("a".into()), "Data").unwrap();
        store.folder_put("agent:a/data", "k1", &serde_json::json!(1)).unwrap();
        store.folder_put("agent:a/data", "k2", &serde_json::json!(2)).unwrap();
        store.folder_put("agent:a/data", "k3", &serde_json::json!(3)).unwrap();

        let folders = store.list_folders(Some(&FolderOwner::Agent("a".into()))).unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].entry_count, 3);
    }

    #[test]
    fn test_create_folder_idempotent() {
        let mut store = InMemoryEngineStore::new();
        let owner = FolderOwner::Agent("nurse".into());
        store.create_folder("agent:nurse/x", &owner, "First").unwrap();
        store.folder_put("agent:nurse/x", "k", &serde_json::json!("v")).unwrap();

        // Create again — should NOT wipe data
        store.create_folder("agent:nurse/x", &owner, "Second").unwrap();
        assert_eq!(store.folder_count("agent:nurse/x").unwrap(), 1);
    }
}
