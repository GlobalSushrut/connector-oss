//! # SqliteEngineStore — Production-grade SQLite persistence for Ring 1-4 engine state.
//!
//! WAL mode, single-file, zero-config, ACID, FTS-ready.
//!
//! Production PRAGMAs applied on open:
//! - `journal_mode = WAL` — concurrent reads during writes
//! - `synchronous = NORMAL` — good durability, 10x faster than FULL
//! - `busy_timeout = 5000` — 5s retry on lock contention
//! - `cache_size = -64000` — 64MB page cache
//! - `foreign_keys = ON` — referential integrity
//! - `auto_vacuum = INCREMENTAL` — reclaim space without full vacuum
//! - `temp_store = MEMORY` — temp tables in RAM

use std::path::Path;

use rusqlite::{Connection, params};

use crate::engine_store::*;

// ═══════════════════════════════════════════════════════════════
// Schema — 19 tables
// ═══════════════════════════════════════════════════════════════

const SCHEMA_SQL: &str = r#"
-- Audit & Compliance (append-only)
CREATE TABLE IF NOT EXISTS engine_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,
    category    TEXT NOT NULL,
    agent_pid   TEXT,
    action      TEXT NOT NULL,
    resource    TEXT,
    verdict     TEXT,
    details     TEXT,
    severity    TEXT NOT NULL DEFAULT 'info'
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON engine_audit(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON engine_audit(agent_pid, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_category ON engine_audit(category, timestamp);

-- Agent Behavior
CREATE TABLE IF NOT EXISTS agent_behavior (
    agent_pid       TEXT PRIMARY KEY,
    total_actions   INTEGER DEFAULT 0,
    total_errors    INTEGER DEFAULT 0,
    total_tool_calls INTEGER DEFAULT 0,
    avg_threat_score REAL DEFAULT 0.0,
    scores_json     TEXT DEFAULT '[]',
    last_action_at  INTEGER,
    updated_at      INTEGER NOT NULL
);

-- Circuit Breakers
CREATE TABLE IF NOT EXISTS circuit_breakers (
    agent_pid               TEXT PRIMARY KEY,
    state                   TEXT NOT NULL DEFAULT 'closed',
    failure_count           INTEGER DEFAULT 0,
    failure_threshold       INTEGER DEFAULT 5,
    reset_timeout_ms        INTEGER DEFAULT 60000,
    half_open_max_probes    INTEGER DEFAULT 3,
    half_open_success_count INTEGER DEFAULT 0,
    last_failure_ms         INTEGER DEFAULT 0,
    last_state_change_ms    INTEGER DEFAULT 0
);

-- Adaptive Thresholds
CREATE TABLE IF NOT EXISTS adaptive_thresholds (
    agent_pid       TEXT PRIMARY KEY,
    scores_json     TEXT DEFAULT '[]',
    avg_score       REAL DEFAULT 0.0,
    thresholds_json TEXT,
    updated_at      INTEGER NOT NULL
);

-- Secrets
CREATE TABLE IF NOT EXISTS secrets (
    secret_id   TEXT PRIMARY KEY,
    agent_pid   TEXT NOT NULL,
    value       TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,
    description TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_secrets_agent ON secrets(agent_pid);

-- Escrow Accounts
CREATE TABLE IF NOT EXISTS escrow_accounts (
    escrow_id       TEXT PRIMARY KEY,
    requester_pid   TEXT NOT NULL,
    provider_pid    TEXT NOT NULL,
    amount          INTEGER NOT NULL,
    state           TEXT NOT NULL DEFAULT 'locked',
    contract_id     TEXT NOT NULL,
    invocation_id   TEXT,
    resolution_reason TEXT,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    resolved_at     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_escrow_state ON escrow_accounts(state);

-- Settlements
CREATE TABLE IF NOT EXISTS settlements (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    escrow_id   TEXT NOT NULL,
    to_provider INTEGER NOT NULL,
    to_requester INTEGER NOT NULL,
    slashed     INTEGER DEFAULT 0,
    settled_at  INTEGER NOT NULL
);

-- Reputation Feedback
CREATE TABLE IF NOT EXISTS reputation_feedback (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    from_agent  TEXT NOT NULL,
    to_agent    TEXT NOT NULL,
    score       REAL NOT NULL,
    context     TEXT,
    timestamp   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rep_to ON reputation_feedback(to_agent, timestamp);

-- Reputation Stakes
CREATE TABLE IF NOT EXISTS reputation_stakes (
    agent_pid   TEXT PRIMARY KEY,
    stake       INTEGER NOT NULL DEFAULT 0,
    slash_count INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL
);

-- Agent Index
CREATE TABLE IF NOT EXISTS agent_index (
    agent_pid       TEXT PRIMARY KEY,
    capabilities    TEXT NOT NULL,
    contract_json   TEXT,
    health_json     TEXT,
    reputation_score REAL DEFAULT 0.0,
    last_indexed_at INTEGER NOT NULL
);

-- Negotiations
CREATE TABLE IF NOT EXISTS negotiations (
    negotiation_id  TEXT PRIMARY KEY,
    requester_pid   TEXT NOT NULL,
    provider_pid    TEXT NOT NULL,
    capability_key  TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'open',
    rounds_json     TEXT DEFAULT '[]',
    max_rounds      INTEGER DEFAULT 5,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    resolved_at     INTEGER,
    final_terms_json TEXT
);

-- Pipeline State
CREATE TABLE IF NOT EXISTS pipeline_state (
    pipeline_id TEXT PRIMARY KEY,
    state       TEXT NOT NULL DEFAULT 'running',
    steps_json  TEXT DEFAULT '[]',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

-- Context Snapshots
CREATE TABLE IF NOT EXISTS context_snapshots (
    snapshot_cid TEXT PRIMARY KEY,
    agent_pid   TEXT NOT NULL,
    data_json   TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    evicted     INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ctx_agent ON context_snapshots(agent_pid, created_at);

-- Session Routes
CREATE TABLE IF NOT EXISTS session_routes (
    session_id  TEXT PRIMARY KEY,
    cell_id     TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    ttl_ms      INTEGER NOT NULL,
    access_count INTEGER DEFAULT 0
);

-- Cross-Cell Messages
CREATE TABLE IF NOT EXISTS cross_cell_messages (
    message_id  TEXT PRIMARY KEY,
    source_cell TEXT NOT NULL,
    target_cell TEXT NOT NULL,
    source_agent TEXT NOT NULL,
    target_agent TEXT NOT NULL,
    port_id     TEXT NOT NULL,
    payload     TEXT,
    timestamp   INTEGER NOT NULL,
    delivered   INTEGER DEFAULT 0
);

-- Watchdog History
CREATE TABLE IF NOT EXISTS watchdog_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name   TEXT NOT NULL,
    condition_json TEXT NOT NULL,
    action_json TEXT NOT NULL,
    fired_at    INTEGER NOT NULL,
    result      TEXT DEFAULT 'fired'
);

-- Tool Definitions
CREATE TABLE IF NOT EXISTS tool_definitions (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    params_json TEXT DEFAULT '[]',
    rules_json  TEXT DEFAULT '{}',
    domain      TEXT,
    created_at  INTEGER NOT NULL
);

-- Policies
CREATE TABLE IF NOT EXISTS policies (
    policy_id   TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    rules_json  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

-- Custom Folders (dynamic namespaced KV — like mkdir)
CREATE TABLE IF NOT EXISTS folder_meta (
    namespace   TEXT PRIMARY KEY,
    owner_type  TEXT NOT NULL DEFAULT 'system',
    owner_id    TEXT DEFAULT '',
    description TEXT DEFAULT '',
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS folder_data (
    namespace   TEXT NOT NULL,
    key         TEXT NOT NULL,
    value_json  TEXT NOT NULL,
    PRIMARY KEY (namespace, key)
);
CREATE INDEX IF NOT EXISTS idx_folder_data_ns ON folder_data(namespace);
"#;

// ═══════════════════════════════════════════════════════════════
// SqliteEngineStore
// ═══════════════════════════════════════════════════════════════

/// Production-grade SQLite engine store.
///
/// - **WAL mode**: Concurrent readers + single writer
/// - **ACID**: Full transaction support
/// - **Crash-safe**: WAL + synchronous=NORMAL
/// - **Zero-config**: Single file, auto-create, auto-migrate
pub struct SqliteEngineStore {
    conn: Connection,
}

fn ese(msg: impl std::fmt::Display) -> EngineStoreError {
    EngineStoreError { message: msg.to_string() }
}

impl SqliteEngineStore {
    /// Open or create a SQLite engine store at the given path.
    /// Applies production PRAGMAs and creates schema if needed.
    pub fn open<P: AsRef<Path>>(path: P) -> EngineStoreResult<Self> {
        let conn = Connection::open(path).map_err(|e| ese(format!("SQLite open: {}", e)))?;

        // Production PRAGMAs
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA cache_size = -64000;
             PRAGMA foreign_keys = ON;
             PRAGMA auto_vacuum = INCREMENTAL;
             PRAGMA temp_store = MEMORY;
             PRAGMA wal_autocheckpoint = 1000;"
        ).map_err(|e| ese(format!("PRAGMAs: {}", e)))?;

        // Create schema
        conn.execute_batch(SCHEMA_SQL).map_err(|e| ese(format!("Schema: {}", e)))?;

        Ok(Self { conn })
    }

    /// Open an in-memory SQLite store (for testing with real SQL).
    pub fn in_memory() -> EngineStoreResult<Self> {
        let conn = Connection::open_in_memory().map_err(|e| ese(format!("SQLite open: {}", e)))?;
        conn.execute_batch(SCHEMA_SQL).map_err(|e| ese(format!("Schema: {}", e)))?;
        Ok(Self { conn })
    }
}

impl EngineStore for SqliteEngineStore {
    // ── Audit ────────────────────────────────────────────────────

    fn append_audit(&mut self, entry: &EngineAuditEntry) -> EngineStoreResult<()> {
        let details_str = entry.details.as_ref().map(|d| d.to_string());
        self.conn.execute(
            "INSERT INTO engine_audit (timestamp, category, agent_pid, action, resource, verdict, details, severity)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                entry.timestamp, entry.category, entry.agent_pid,
                entry.action, entry.resource, entry.verdict,
                details_str, entry.severity
            ],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn query_audit(&self, filter: &AuditFilter) -> EngineStoreResult<Vec<EngineAuditEntry>> {
        let mut sql = String::from("SELECT timestamp, category, agent_pid, action, resource, verdict, details, severity FROM engine_audit WHERE 1=1");
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(from) = filter.from_ms {
            sql.push_str(&format!(" AND timestamp >= ?{}", idx));
            param_values.push(Box::new(from));
            idx += 1;
        }
        if let Some(to) = filter.to_ms {
            sql.push_str(&format!(" AND timestamp <= ?{}", idx));
            param_values.push(Box::new(to));
            idx += 1;
        }
        if let Some(ref pid) = filter.agent_pid {
            sql.push_str(&format!(" AND agent_pid = ?{}", idx));
            param_values.push(Box::new(pid.clone()));
            idx += 1;
        }
        if let Some(ref cat) = filter.category {
            sql.push_str(&format!(" AND category = ?{}", idx));
            param_values.push(Box::new(cat.clone()));
            idx += 1;
        }
        if let Some(ref sev) = filter.severity {
            sql.push_str(&format!(" AND severity = ?{}", idx));
            param_values.push(Box::new(sev.clone()));
            let _ = idx; // suppress unused warning
        }

        sql.push_str(" ORDER BY timestamp DESC");
        if let Some(limit) = filter.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }

        let params_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql).map_err(|e| ese(e))?;
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            let details_str: Option<String> = row.get(6)?;
            Ok(EngineAuditEntry {
                timestamp: row.get(0)?,
                category: row.get(1)?,
                agent_pid: row.get(2)?,
                action: row.get(3)?,
                resource: row.get(4)?,
                verdict: row.get(5)?,
                details: details_str.and_then(|s| serde_json::from_str(&s).ok()),
                severity: row.get(7)?,
            })
        }).map_err(|e| ese(e))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| ese(e))?);
        }
        Ok(results)
    }

    fn audit_count(&self) -> EngineStoreResult<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM engine_audit", [], |row| row.get(0)
        ).map_err(|e| ese(e))?;
        Ok(count as usize)
    }

    // ── Agent Behavior ───────────────────────────────────────────

    fn save_behavior(&mut self, profile: &BehaviorProfile) -> EngineStoreResult<()> {
        let scores_json = serde_json::to_string(&profile.recent_scores).unwrap_or_default();
        self.conn.execute(
            "INSERT OR REPLACE INTO agent_behavior (agent_pid, total_actions, total_errors, total_tool_calls, avg_threat_score, scores_json, last_action_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                profile.agent_pid, profile.total_actions as i64, profile.total_errors as i64,
                profile.total_tool_calls as i64, profile.avg_threat_score, scores_json,
                profile.last_action_at, profile.updated_at
            ],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_behavior(&self, agent_pid: &str) -> EngineStoreResult<Option<BehaviorProfile>> {
        let mut stmt = self.conn.prepare(
            "SELECT agent_pid, total_actions, total_errors, total_tool_calls, avg_threat_score, scores_json, last_action_at, updated_at FROM agent_behavior WHERE agent_pid = ?1"
        ).map_err(|e| ese(e))?;
        let mut rows = stmt.query_map(params![agent_pid], |row| {
            let scores_str: String = row.get(5)?;
            Ok(BehaviorProfile {
                agent_pid: row.get(0)?,
                total_actions: row.get::<_, i64>(1)? as u64,
                total_errors: row.get::<_, i64>(2)? as u64,
                total_tool_calls: row.get::<_, i64>(3)? as u64,
                avg_threat_score: row.get(4)?,
                recent_scores: serde_json::from_str(&scores_str).unwrap_or_default(),
                last_action_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        }).map_err(|e| ese(e))?;
        match rows.next() {
            Some(Ok(profile)) => Ok(Some(profile)),
            Some(Err(e)) => Err(ese(e)),
            None => Ok(None),
        }
    }

    // ── Circuit Breakers ─────────────────────────────────────────

    fn save_circuit_breaker(&mut self, cb: &CircuitBreakerState) -> EngineStoreResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO circuit_breakers (agent_pid, state, failure_count, failure_threshold, reset_timeout_ms, half_open_max_probes, half_open_success_count, last_failure_ms, last_state_change_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                cb.agent_pid, cb.state, cb.failure_count, cb.failure_threshold,
                cb.reset_timeout_ms, cb.half_open_max_probes, cb.half_open_success_count,
                cb.last_failure_ms, cb.last_state_change_ms
            ],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_circuit_breaker(&self, agent_pid: &str) -> EngineStoreResult<Option<CircuitBreakerState>> {
        let mut stmt = self.conn.prepare(
            "SELECT agent_pid, state, failure_count, failure_threshold, reset_timeout_ms, half_open_max_probes, half_open_success_count, last_failure_ms, last_state_change_ms FROM circuit_breakers WHERE agent_pid = ?1"
        ).map_err(|e| ese(e))?;
        let mut rows = stmt.query_map(params![agent_pid], |row| {
            Ok(CircuitBreakerState {
                agent_pid: row.get(0)?, state: row.get(1)?,
                failure_count: row.get(2)?, failure_threshold: row.get(3)?,
                reset_timeout_ms: row.get(4)?, half_open_max_probes: row.get(5)?,
                half_open_success_count: row.get(6)?, last_failure_ms: row.get(7)?,
                last_state_change_ms: row.get(8)?,
            })
        }).map_err(|e| ese(e))?;
        match rows.next() {
            Some(Ok(cb)) => Ok(Some(cb)),
            Some(Err(e)) => Err(ese(e)),
            None => Ok(None),
        }
    }

    fn load_all_circuit_breakers(&self) -> EngineStoreResult<Vec<CircuitBreakerState>> {
        let mut stmt = self.conn.prepare(
            "SELECT agent_pid, state, failure_count, failure_threshold, reset_timeout_ms, half_open_max_probes, half_open_success_count, last_failure_ms, last_state_change_ms FROM circuit_breakers"
        ).map_err(|e| ese(e))?;
        let rows = stmt.query_map([], |row| {
            Ok(CircuitBreakerState {
                agent_pid: row.get(0)?, state: row.get(1)?,
                failure_count: row.get(2)?, failure_threshold: row.get(3)?,
                reset_timeout_ms: row.get(4)?, half_open_max_probes: row.get(5)?,
                half_open_success_count: row.get(6)?, last_failure_ms: row.get(7)?,
                last_state_change_ms: row.get(8)?,
            })
        }).map_err(|e| ese(e))?;
        let mut results = Vec::new();
        for row in rows { results.push(row.map_err(|e| ese(e))?); }
        Ok(results)
    }

    // ── Adaptive Thresholds ──────────────────────────────────────

    fn save_threshold(&mut self, baseline: &ThresholdBaseline) -> EngineStoreResult<()> {
        let scores_json = serde_json::to_string(&baseline.scores).unwrap_or_default();
        let thresh_json = baseline.adapted_thresholds.as_ref().map(|t| t.to_string());
        self.conn.execute(
            "INSERT OR REPLACE INTO adaptive_thresholds (agent_pid, scores_json, avg_score, thresholds_json, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![baseline.agent_pid, scores_json, baseline.avg_score, thresh_json, baseline.updated_at],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_threshold(&self, agent_pid: &str) -> EngineStoreResult<Option<ThresholdBaseline>> {
        let mut stmt = self.conn.prepare(
            "SELECT agent_pid, scores_json, avg_score, thresholds_json, updated_at FROM adaptive_thresholds WHERE agent_pid = ?1"
        ).map_err(|e| ese(e))?;
        let mut rows = stmt.query_map(params![agent_pid], |row| {
            let scores_str: String = row.get(1)?;
            let thresh_str: Option<String> = row.get(3)?;
            Ok(ThresholdBaseline {
                agent_pid: row.get(0)?,
                scores: serde_json::from_str(&scores_str).unwrap_or_default(),
                avg_score: row.get(2)?,
                adapted_thresholds: thresh_str.and_then(|s| serde_json::from_str(&s).ok()),
                updated_at: row.get(4)?,
            })
        }).map_err(|e| ese(e))?;
        match rows.next() {
            Some(Ok(b)) => Ok(Some(b)),
            Some(Err(e)) => Err(ese(e)),
            None => Ok(None),
        }
    }

    // ── Secrets ──────────────────────────────────────────────────

    fn store_secret(&mut self, entry: &StoredSecret) -> EngineStoreResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO secrets (secret_id, agent_pid, value, created_at, expires_at, description)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![entry.secret_id, entry.agent_pid, entry.value, entry.created_at, entry.expires_at, entry.description],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_secret(&self, secret_id: &str) -> EngineStoreResult<Option<StoredSecret>> {
        let mut stmt = self.conn.prepare(
            "SELECT secret_id, agent_pid, value, created_at, expires_at, description FROM secrets WHERE secret_id = ?1"
        ).map_err(|e| ese(e))?;
        let mut rows = stmt.query_map(params![secret_id], |row| {
            Ok(StoredSecret {
                secret_id: row.get(0)?, agent_pid: row.get(1)?, value: row.get(2)?,
                created_at: row.get(3)?, expires_at: row.get(4)?, description: row.get(5)?,
            })
        }).map_err(|e| ese(e))?;
        match rows.next() {
            Some(Ok(s)) => Ok(Some(s)),
            Some(Err(e)) => Err(ese(e)),
            None => Ok(None),
        }
    }

    fn delete_secret(&mut self, secret_id: &str) -> EngineStoreResult<()> {
        self.conn.execute("DELETE FROM secrets WHERE secret_id = ?1", params![secret_id]).map_err(|e| ese(e))?;
        Ok(())
    }

    fn purge_expired_secrets(&mut self, now_ms: i64) -> EngineStoreResult<usize> {
        let count = self.conn.execute(
            "DELETE FROM secrets WHERE expires_at IS NOT NULL AND expires_at < ?1",
            params![now_ms],
        ).map_err(|e| ese(e))?;
        Ok(count)
    }

    fn load_secrets_by_agent(&self, agent_pid: &str) -> EngineStoreResult<Vec<StoredSecret>> {
        let mut stmt = self.conn.prepare(
            "SELECT secret_id, agent_pid, value, created_at, expires_at, description FROM secrets WHERE agent_pid = ?1"
        ).map_err(|e| ese(e))?;
        let rows = stmt.query_map(params![agent_pid], |row| {
            Ok(StoredSecret {
                secret_id: row.get(0)?, agent_pid: row.get(1)?, value: row.get(2)?,
                created_at: row.get(3)?, expires_at: row.get(4)?, description: row.get(5)?,
            })
        }).map_err(|e| ese(e))?;
        let mut results = Vec::new();
        for row in rows { results.push(row.map_err(|e| ese(e))?); }
        Ok(results)
    }

    // ── Escrow ───────────────────────────────────────────────────

    fn save_escrow(&mut self, a: &StoredEscrow) -> EngineStoreResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO escrow_accounts (escrow_id, requester_pid, provider_pid, amount, state, contract_id, invocation_id, resolution_reason, created_at, expires_at, resolved_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                a.escrow_id, a.requester_pid, a.provider_pid, a.amount as i64,
                a.state, a.contract_id, a.invocation_id, a.resolution_reason,
                a.created_at, a.expires_at, a.resolved_at
            ],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_escrow(&self, escrow_id: &str) -> EngineStoreResult<Option<StoredEscrow>> {
        let mut stmt = self.conn.prepare(
            "SELECT escrow_id, requester_pid, provider_pid, amount, state, contract_id, invocation_id, resolution_reason, created_at, expires_at, resolved_at FROM escrow_accounts WHERE escrow_id = ?1"
        ).map_err(|e| ese(e))?;
        let mut rows = stmt.query_map(params![escrow_id], |row| {
            Ok(StoredEscrow {
                escrow_id: row.get(0)?, requester_pid: row.get(1)?,
                provider_pid: row.get(2)?, amount: row.get::<_, i64>(3)? as u64,
                state: row.get(4)?, contract_id: row.get(5)?,
                invocation_id: row.get(6)?, resolution_reason: row.get(7)?,
                created_at: row.get(8)?, expires_at: row.get(9)?,
                resolved_at: row.get(10)?,
            })
        }).map_err(|e| ese(e))?;
        match rows.next() {
            Some(Ok(e)) => Ok(Some(e)),
            Some(Err(e)) => Err(ese(e)),
            None => Ok(None),
        }
    }

    fn load_escrows_by_state(&self, state: &str) -> EngineStoreResult<Vec<StoredEscrow>> {
        let mut stmt = self.conn.prepare(
            "SELECT escrow_id, requester_pid, provider_pid, amount, state, contract_id, invocation_id, resolution_reason, created_at, expires_at, resolved_at FROM escrow_accounts WHERE state = ?1"
        ).map_err(|e| ese(e))?;
        let rows = stmt.query_map(params![state], |row| {
            Ok(StoredEscrow {
                escrow_id: row.get(0)?, requester_pid: row.get(1)?,
                provider_pid: row.get(2)?, amount: row.get::<_, i64>(3)? as u64,
                state: row.get(4)?, contract_id: row.get(5)?,
                invocation_id: row.get(6)?, resolution_reason: row.get(7)?,
                created_at: row.get(8)?, expires_at: row.get(9)?,
                resolved_at: row.get(10)?,
            })
        }).map_err(|e| ese(e))?;
        let mut results = Vec::new();
        for row in rows { results.push(row.map_err(|e| ese(e))?); }
        Ok(results)
    }

    fn save_settlement(&mut self, r: &StoredSettlement) -> EngineStoreResult<()> {
        self.conn.execute(
            "INSERT INTO settlements (escrow_id, to_provider, to_requester, slashed, settled_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![r.escrow_id, r.to_provider as i64, r.to_requester as i64, r.slashed as i64, r.settled_at],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    // ── Reputation ───────────────────────────────────────────────

    fn submit_feedback(&mut self, fb: &StoredFeedback) -> EngineStoreResult<()> {
        self.conn.execute(
            "INSERT INTO reputation_feedback (from_agent, to_agent, score, context, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![fb.from_agent, fb.to_agent, fb.score, fb.context, fb.timestamp],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_feedback_for(&self, agent_pid: &str, limit: usize) -> EngineStoreResult<Vec<StoredFeedback>> {
        let mut stmt = self.conn.prepare(
            "SELECT from_agent, to_agent, score, context, timestamp FROM reputation_feedback WHERE to_agent = ?1 ORDER BY timestamp DESC LIMIT ?2"
        ).map_err(|e| ese(e))?;
        let rows = stmt.query_map(params![agent_pid, limit as i64], |row| {
            Ok(StoredFeedback {
                from_agent: row.get(0)?, to_agent: row.get(1)?,
                score: row.get(2)?, context: row.get(3)?, timestamp: row.get(4)?,
            })
        }).map_err(|e| ese(e))?;
        let mut results = Vec::new();
        for row in rows { results.push(row.map_err(|e| ese(e))?); }
        Ok(results)
    }

    fn compute_avg_reputation(&self, agent_pid: &str) -> EngineStoreResult<f64> {
        let avg: f64 = self.conn.query_row(
            "SELECT COALESCE(AVG(score), 0.0) FROM reputation_feedback WHERE to_agent = ?1",
            params![agent_pid],
            |row| row.get(0),
        ).map_err(|e| ese(e))?;
        Ok(avg)
    }

    fn save_stake(&mut self, stake: &StoredStake) -> EngineStoreResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO reputation_stakes (agent_pid, stake, slash_count, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params![stake.agent_pid, stake.stake as i64, stake.slash_count, stake.updated_at],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_stake(&self, agent_pid: &str) -> EngineStoreResult<Option<StoredStake>> {
        let mut stmt = self.conn.prepare(
            "SELECT agent_pid, stake, slash_count, updated_at FROM reputation_stakes WHERE agent_pid = ?1"
        ).map_err(|e| ese(e))?;
        let mut rows = stmt.query_map(params![agent_pid], |row| {
            Ok(StoredStake {
                agent_pid: row.get(0)?, stake: row.get::<_, i64>(1)? as u64,
                slash_count: row.get(2)?, updated_at: row.get(3)?,
            })
        }).map_err(|e| ese(e))?;
        match rows.next() {
            Some(Ok(s)) => Ok(Some(s)),
            Some(Err(e)) => Err(ese(e)),
            None => Ok(None),
        }
    }

    // ── Agent Index ──────────────────────────────────────────────

    fn index_agent(&mut self, entry: &StoredAgentIndex) -> EngineStoreResult<()> {
        let contract = entry.contract_json.as_ref().map(|j| j.to_string());
        let health = entry.health_json.as_ref().map(|j| j.to_string());
        self.conn.execute(
            "INSERT OR REPLACE INTO agent_index (agent_pid, capabilities, contract_json, health_json, reputation_score, last_indexed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![entry.agent_pid, entry.capabilities, contract, health, entry.reputation_score, entry.last_indexed_at],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn search_agents(&self, query: &str, limit: usize) -> EngineStoreResult<Vec<StoredAgentIndex>> {
        let pattern = format!("%{}%", query);
        let mut stmt = self.conn.prepare(
            "SELECT agent_pid, capabilities, contract_json, health_json, reputation_score, last_indexed_at FROM agent_index WHERE capabilities LIKE ?1 OR agent_pid LIKE ?1 LIMIT ?2"
        ).map_err(|e| ese(e))?;
        let rows = stmt.query_map(params![pattern, limit as i64], |row| {
            let contract_str: Option<String> = row.get(2)?;
            let health_str: Option<String> = row.get(3)?;
            Ok(StoredAgentIndex {
                agent_pid: row.get(0)?, capabilities: row.get(1)?,
                contract_json: contract_str.and_then(|s| serde_json::from_str(&s).ok()),
                health_json: health_str.and_then(|s| serde_json::from_str(&s).ok()),
                reputation_score: row.get(4)?, last_indexed_at: row.get(5)?,
            })
        }).map_err(|e| ese(e))?;
        let mut results = Vec::new();
        for row in rows { results.push(row.map_err(|e| ese(e))?); }
        Ok(results)
    }

    fn load_agent_index(&self, agent_pid: &str) -> EngineStoreResult<Option<StoredAgentIndex>> {
        let mut stmt = self.conn.prepare(
            "SELECT agent_pid, capabilities, contract_json, health_json, reputation_score, last_indexed_at FROM agent_index WHERE agent_pid = ?1"
        ).map_err(|e| ese(e))?;
        let mut rows = stmt.query_map(params![agent_pid], |row| {
            let contract_str: Option<String> = row.get(2)?;
            let health_str: Option<String> = row.get(3)?;
            Ok(StoredAgentIndex {
                agent_pid: row.get(0)?, capabilities: row.get(1)?,
                contract_json: contract_str.and_then(|s| serde_json::from_str(&s).ok()),
                health_json: health_str.and_then(|s| serde_json::from_str(&s).ok()),
                reputation_score: row.get(4)?, last_indexed_at: row.get(5)?,
            })
        }).map_err(|e| ese(e))?;
        match rows.next() {
            Some(Ok(e)) => Ok(Some(e)),
            Some(Err(e)) => Err(ese(e)),
            None => Ok(None),
        }
    }

    // ── Negotiations ─────────────────────────────────────────────

    fn save_negotiation(&mut self, neg: &StoredNegotiation) -> EngineStoreResult<()> {
        let rounds = neg.rounds_json.to_string();
        let terms = neg.final_terms_json.as_ref().map(|j| j.to_string());
        self.conn.execute(
            "INSERT OR REPLACE INTO negotiations (negotiation_id, requester_pid, provider_pid, capability_key, state, rounds_json, max_rounds, created_at, expires_at, resolved_at, final_terms_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                neg.negotiation_id, neg.requester_pid, neg.provider_pid,
                neg.capability_key, neg.state, rounds, neg.max_rounds,
                neg.created_at, neg.expires_at, neg.resolved_at, terms
            ],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_negotiation(&self, id: &str) -> EngineStoreResult<Option<StoredNegotiation>> {
        let mut stmt = self.conn.prepare(
            "SELECT negotiation_id, requester_pid, provider_pid, capability_key, state, rounds_json, max_rounds, created_at, expires_at, resolved_at, final_terms_json FROM negotiations WHERE negotiation_id = ?1"
        ).map_err(|e| ese(e))?;
        let mut rows = stmt.query_map(params![id], |row| {
            let rounds_str: String = row.get(5)?;
            let terms_str: Option<String> = row.get(10)?;
            Ok(StoredNegotiation {
                negotiation_id: row.get(0)?, requester_pid: row.get(1)?,
                provider_pid: row.get(2)?, capability_key: row.get(3)?,
                state: row.get(4)?,
                rounds_json: serde_json::from_str(&rounds_str).unwrap_or(serde_json::json!([])),
                max_rounds: row.get(6)?, created_at: row.get(7)?,
                expires_at: row.get(8)?, resolved_at: row.get(9)?,
                final_terms_json: terms_str.and_then(|s| serde_json::from_str(&s).ok()),
            })
        }).map_err(|e| ese(e))?;
        match rows.next() {
            Some(Ok(n)) => Ok(Some(n)),
            Some(Err(e)) => Err(ese(e)),
            None => Ok(None),
        }
    }

    fn load_active_negotiations(&self) -> EngineStoreResult<Vec<StoredNegotiation>> {
        let mut stmt = self.conn.prepare(
            "SELECT negotiation_id, requester_pid, provider_pid, capability_key, state, rounds_json, max_rounds, created_at, expires_at, resolved_at, final_terms_json FROM negotiations WHERE state = 'open'"
        ).map_err(|e| ese(e))?;
        let rows = stmt.query_map([], |row| {
            let rounds_str: String = row.get(5)?;
            let terms_str: Option<String> = row.get(10)?;
            Ok(StoredNegotiation {
                negotiation_id: row.get(0)?, requester_pid: row.get(1)?,
                provider_pid: row.get(2)?, capability_key: row.get(3)?,
                state: row.get(4)?,
                rounds_json: serde_json::from_str(&rounds_str).unwrap_or(serde_json::json!([])),
                max_rounds: row.get(6)?, created_at: row.get(7)?,
                expires_at: row.get(8)?, resolved_at: row.get(9)?,
                final_terms_json: terms_str.and_then(|s| serde_json::from_str(&s).ok()),
            })
        }).map_err(|e| ese(e))?;
        let mut results = Vec::new();
        for row in rows { results.push(row.map_err(|e| ese(e))?); }
        Ok(results)
    }

    // ── Pipeline State ───────────────────────────────────────────

    fn save_pipeline(&mut self, p: &StoredPipeline) -> EngineStoreResult<()> {
        let steps = p.steps_json.to_string();
        self.conn.execute(
            "INSERT OR REPLACE INTO pipeline_state (pipeline_id, state, steps_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![p.pipeline_id, p.state, steps, p.created_at, p.updated_at],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_pipeline(&self, id: &str) -> EngineStoreResult<Option<StoredPipeline>> {
        let mut stmt = self.conn.prepare(
            "SELECT pipeline_id, state, steps_json, created_at, updated_at FROM pipeline_state WHERE pipeline_id = ?1"
        ).map_err(|e| ese(e))?;
        let mut rows = stmt.query_map(params![id], |row| {
            let steps_str: String = row.get(2)?;
            Ok(StoredPipeline {
                pipeline_id: row.get(0)?, state: row.get(1)?,
                steps_json: serde_json::from_str(&steps_str).unwrap_or(serde_json::json!([])),
                created_at: row.get(3)?, updated_at: row.get(4)?,
            })
        }).map_err(|e| ese(e))?;
        match rows.next() {
            Some(Ok(p)) => Ok(Some(p)),
            Some(Err(e)) => Err(ese(e)),
            None => Ok(None),
        }
    }

    // ── Context Snapshots ────────────────────────────────────────

    fn save_snapshot(&mut self, s: &StoredSnapshot) -> EngineStoreResult<()> {
        let data = s.data_json.to_string();
        self.conn.execute(
            "INSERT OR REPLACE INTO context_snapshots (snapshot_cid, agent_pid, data_json, created_at, evicted)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![s.snapshot_cid, s.agent_pid, data, s.created_at, s.evicted as i32],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_snapshot(&self, cid: &str) -> EngineStoreResult<Option<StoredSnapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT snapshot_cid, agent_pid, data_json, created_at, evicted FROM context_snapshots WHERE snapshot_cid = ?1"
        ).map_err(|e| ese(e))?;
        let mut rows = stmt.query_map(params![cid], |row| {
            let data_str: String = row.get(2)?;
            Ok(StoredSnapshot {
                snapshot_cid: row.get(0)?, agent_pid: row.get(1)?,
                data_json: serde_json::from_str(&data_str).unwrap_or(serde_json::json!({})),
                created_at: row.get(3)?, evicted: row.get::<_, i32>(4)? != 0,
            })
        }).map_err(|e| ese(e))?;
        match rows.next() {
            Some(Ok(s)) => Ok(Some(s)),
            Some(Err(e)) => Err(ese(e)),
            None => Ok(None),
        }
    }

    fn load_snapshots_by_agent(&self, agent_pid: &str, limit: usize) -> EngineStoreResult<Vec<StoredSnapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT snapshot_cid, agent_pid, data_json, created_at, evicted FROM context_snapshots WHERE agent_pid = ?1 ORDER BY created_at DESC LIMIT ?2"
        ).map_err(|e| ese(e))?;
        let rows = stmt.query_map(params![agent_pid, limit as i64], |row| {
            let data_str: String = row.get(2)?;
            Ok(StoredSnapshot {
                snapshot_cid: row.get(0)?, agent_pid: row.get(1)?,
                data_json: serde_json::from_str(&data_str).unwrap_or(serde_json::json!({})),
                created_at: row.get(3)?, evicted: row.get::<_, i32>(4)? != 0,
            })
        }).map_err(|e| ese(e))?;
        let mut results = Vec::new();
        for row in rows { results.push(row.map_err(|e| ese(e))?); }
        Ok(results)
    }

    // ── Session Routes ───────────────────────────────────────────

    fn save_route(&mut self, route: &StoredRoute) -> EngineStoreResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO session_routes (session_id, cell_id, created_at, ttl_ms, access_count)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![route.session_id, route.cell_id, route.created_at, route.ttl_ms, route.access_count as i64],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_route(&self, session_id: &str) -> EngineStoreResult<Option<StoredRoute>> {
        let mut stmt = self.conn.prepare(
            "SELECT session_id, cell_id, created_at, ttl_ms, access_count FROM session_routes WHERE session_id = ?1"
        ).map_err(|e| ese(e))?;
        let mut rows = stmt.query_map(params![session_id], |row| {
            Ok(StoredRoute {
                session_id: row.get(0)?, cell_id: row.get(1)?,
                created_at: row.get(2)?, ttl_ms: row.get(3)?,
                access_count: row.get::<_, i64>(4)? as u64,
            })
        }).map_err(|e| ese(e))?;
        match rows.next() {
            Some(Ok(r)) => Ok(Some(r)),
            Some(Err(e)) => Err(ese(e)),
            None => Ok(None),
        }
    }

    fn purge_expired_routes(&mut self, now_ms: i64) -> EngineStoreResult<usize> {
        let count = self.conn.execute(
            "DELETE FROM session_routes WHERE (created_at + ttl_ms) < ?1",
            params![now_ms],
        ).map_err(|e| ese(e))?;
        Ok(count)
    }

    // ── Cross-Cell Messages ──────────────────────────────────────

    fn log_cross_cell_message(&mut self, msg: &StoredCrossCellMessage) -> EngineStoreResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO cross_cell_messages (message_id, source_cell, target_cell, source_agent, target_agent, port_id, payload, timestamp, delivered)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                msg.message_id, msg.source_cell, msg.target_cell,
                msg.source_agent, msg.target_agent, msg.port_id,
                msg.payload, msg.timestamp, msg.delivered as i32
            ],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_messages_for_agent(&self, agent_pid: &str, limit: usize) -> EngineStoreResult<Vec<StoredCrossCellMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT message_id, source_cell, target_cell, source_agent, target_agent, port_id, payload, timestamp, delivered FROM cross_cell_messages WHERE source_agent = ?1 OR target_agent = ?1 ORDER BY timestamp DESC LIMIT ?2"
        ).map_err(|e| ese(e))?;
        let rows = stmt.query_map(params![agent_pid, limit as i64], |row| {
            Ok(StoredCrossCellMessage {
                message_id: row.get(0)?, source_cell: row.get(1)?,
                target_cell: row.get(2)?, source_agent: row.get(3)?,
                target_agent: row.get(4)?, port_id: row.get(5)?,
                payload: row.get(6)?, timestamp: row.get(7)?,
                delivered: row.get::<_, i32>(8)? != 0,
            })
        }).map_err(|e| ese(e))?;
        let mut results = Vec::new();
        for row in rows { results.push(row.map_err(|e| ese(e))?); }
        Ok(results)
    }

    // ── Watchdog ─────────────────────────────────────────────────

    fn append_watchdog_action(&mut self, action: &StoredWatchdogAction) -> EngineStoreResult<()> {
        let cond = action.condition_json.to_string();
        let act = action.action_json.to_string();
        self.conn.execute(
            "INSERT INTO watchdog_history (rule_name, condition_json, action_json, fired_at, result)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![action.rule_name, cond, act, action.fired_at, action.result],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_watchdog_history(&self, limit: usize) -> EngineStoreResult<Vec<StoredWatchdogAction>> {
        let mut stmt = self.conn.prepare(
            "SELECT rule_name, condition_json, action_json, fired_at, result FROM watchdog_history ORDER BY fired_at DESC LIMIT ?1"
        ).map_err(|e| ese(e))?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let cond_str: String = row.get(1)?;
            let act_str: String = row.get(2)?;
            Ok(StoredWatchdogAction {
                rule_name: row.get(0)?,
                condition_json: serde_json::from_str(&cond_str).unwrap_or(serde_json::json!({})),
                action_json: serde_json::from_str(&act_str).unwrap_or(serde_json::json!({})),
                fired_at: row.get(3)?, result: row.get(4)?,
            })
        }).map_err(|e| ese(e))?;
        let mut results = Vec::new();
        for row in rows { results.push(row.map_err(|e| ese(e))?); }
        Ok(results)
    }

    // ── Tool Definitions ─────────────────────────────────────────

    fn save_tool_def(&mut self, tool: &StoredToolDef) -> EngineStoreResult<()> {
        let params_j = tool.params_json.to_string();
        let rules_j = tool.rules_json.to_string();
        self.conn.execute(
            "INSERT OR REPLACE INTO tool_definitions (name, description, params_json, rules_json, domain, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![tool.name, tool.description, params_j, rules_j, tool.domain, tool.created_at],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_tool_defs(&self) -> EngineStoreResult<Vec<StoredToolDef>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, description, params_json, rules_json, domain, created_at FROM tool_definitions"
        ).map_err(|e| ese(e))?;
        let rows = stmt.query_map([], |row| {
            let params_str: String = row.get(2)?;
            let rules_str: String = row.get(3)?;
            Ok(StoredToolDef {
                name: row.get(0)?, description: row.get(1)?,
                params_json: serde_json::from_str(&params_str).unwrap_or(serde_json::json!([])),
                rules_json: serde_json::from_str(&rules_str).unwrap_or(serde_json::json!({})),
                domain: row.get(4)?, created_at: row.get(5)?,
            })
        }).map_err(|e| ese(e))?;
        let mut results = Vec::new();
        for row in rows { results.push(row.map_err(|e| ese(e))?); }
        Ok(results)
    }

    fn delete_tool_def(&mut self, name: &str) -> EngineStoreResult<()> {
        self.conn.execute("DELETE FROM tool_definitions WHERE name = ?1", params![name]).map_err(|e| ese(e))?;
        Ok(())
    }

    // ── Policies ─────────────────────────────────────────────────

    fn save_policy(&mut self, policy: &StoredPolicy) -> EngineStoreResult<()> {
        let rules = policy.rules_json.to_string();
        self.conn.execute(
            "INSERT OR REPLACE INTO policies (policy_id, name, description, rules_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![policy.policy_id, policy.name, policy.description, rules, policy.created_at, policy.updated_at],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn load_policies(&self) -> EngineStoreResult<Vec<StoredPolicy>> {
        let mut stmt = self.conn.prepare(
            "SELECT policy_id, name, description, rules_json, created_at, updated_at FROM policies"
        ).map_err(|e| ese(e))?;
        let rows = stmt.query_map([], |row| {
            let rules_str: String = row.get(3)?;
            Ok(StoredPolicy {
                policy_id: row.get(0)?, name: row.get(1)?, description: row.get(2)?,
                rules_json: serde_json::from_str(&rules_str).unwrap_or(serde_json::json!([])),
                created_at: row.get(4)?, updated_at: row.get(5)?,
            })
        }).map_err(|e| ese(e))?;
        let mut results = Vec::new();
        for row in rows { results.push(row.map_err(|e| ese(e))?); }
        Ok(results)
    }

    fn delete_policy(&mut self, policy_id: &str) -> EngineStoreResult<()> {
        self.conn.execute("DELETE FROM policies WHERE policy_id = ?1", params![policy_id]).map_err(|e| ese(e))?;
        Ok(())
    }

    // ── Custom Folders ───────────────────────────────────────────

    fn create_folder(&mut self, namespace: &str, owner: &FolderOwner, description: &str) -> EngineStoreResult<()> {
        let (owner_type, owner_id) = match owner {
            FolderOwner::Agent(pid) => ("agent", pid.as_str()),
            FolderOwner::Tool(name) => ("tool", name.as_str()),
            FolderOwner::System => ("system", ""),
        };
        self.conn.execute(
            "INSERT OR IGNORE INTO folder_meta (namespace, owner_type, owner_id, description, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![namespace, owner_type, owner_id, description, chrono::Utc::now().timestamp_millis()],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn list_folders(&self, owner_filter: Option<&FolderOwner>) -> EngineStoreResult<Vec<FolderInfo>> {
        let (sql, param_values): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match owner_filter {
            None => (
                "SELECT m.namespace, m.owner_type, m.owner_id, m.description, m.created_at, COUNT(d.key) FROM folder_meta m LEFT JOIN folder_data d ON m.namespace = d.namespace GROUP BY m.namespace".to_string(),
                vec![],
            ),
            Some(owner) => {
                let (otype, oid) = match owner {
                    FolderOwner::Agent(pid) => ("agent", pid.clone()),
                    FolderOwner::Tool(name) => ("tool", name.clone()),
                    FolderOwner::System => ("system", String::new()),
                };
                (
                    "SELECT m.namespace, m.owner_type, m.owner_id, m.description, m.created_at, COUNT(d.key) FROM folder_meta m LEFT JOIN folder_data d ON m.namespace = d.namespace WHERE m.owner_type = ?1 AND m.owner_id = ?2 GROUP BY m.namespace".to_string(),
                    vec![Box::new(otype.to_string()) as Box<dyn rusqlite::types::ToSql>, Box::new(oid)],
                )
            }
        };
        let params_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql).map_err(|e| ese(e))?;
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            let otype: String = row.get(1)?;
            let oid: String = row.get(2)?;
            let owner = match otype.as_str() {
                "agent" => FolderOwner::Agent(oid),
                "tool" => FolderOwner::Tool(oid),
                _ => FolderOwner::System,
            };
            Ok(FolderInfo {
                namespace: row.get(0)?,
                owner,
                description: row.get(3)?,
                created_at: row.get(4)?,
                entry_count: row.get::<_, i64>(5)? as u64,
            })
        }).map_err(|e| ese(e))?;
        let mut results = Vec::new();
        for row in rows { results.push(row.map_err(|e| ese(e))?); }
        Ok(results)
    }

    fn delete_folder(&mut self, namespace: &str) -> EngineStoreResult<()> {
        self.conn.execute("DELETE FROM folder_data WHERE namespace = ?1", params![namespace]).map_err(|e| ese(e))?;
        self.conn.execute("DELETE FROM folder_meta WHERE namespace = ?1", params![namespace]).map_err(|e| ese(e))?;
        Ok(())
    }

    fn folder_put(&mut self, namespace: &str, key: &str, value: &serde_json::Value) -> EngineStoreResult<()> {
        let val_str = value.to_string();
        self.conn.execute(
            "INSERT OR REPLACE INTO folder_data (namespace, key, value_json) VALUES (?1, ?2, ?3)",
            params![namespace, key, val_str],
        ).map_err(|e| ese(e))?;
        // Auto-create folder metadata if missing
        self.conn.execute(
            "INSERT OR IGNORE INTO folder_meta (namespace, owner_type, owner_id, description, created_at)
             VALUES (?1, 'system', '', '', ?2)",
            params![namespace, chrono::Utc::now().timestamp_millis()],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn folder_get(&self, namespace: &str, key: &str) -> EngineStoreResult<Option<serde_json::Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT value_json FROM folder_data WHERE namespace = ?1 AND key = ?2"
        ).map_err(|e| ese(e))?;
        let mut rows = stmt.query_map(params![namespace, key], |row| {
            let s: String = row.get(0)?;
            Ok(s)
        }).map_err(|e| ese(e))?;
        match rows.next() {
            Some(Ok(s)) => Ok(serde_json::from_str(&s).ok()),
            Some(Err(e)) => Err(ese(e)),
            None => Ok(None),
        }
    }

    fn folder_delete(&mut self, namespace: &str, key: &str) -> EngineStoreResult<()> {
        self.conn.execute(
            "DELETE FROM folder_data WHERE namespace = ?1 AND key = ?2",
            params![namespace, key],
        ).map_err(|e| ese(e))?;
        Ok(())
    }

    fn folder_keys(&self, namespace: &str, prefix: Option<&str>) -> EngineStoreResult<Vec<String>> {
        let (sql, param_values): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match prefix {
            None => (
                "SELECT key FROM folder_data WHERE namespace = ?1 ORDER BY key".to_string(),
                vec![Box::new(namespace.to_string()) as Box<dyn rusqlite::types::ToSql>],
            ),
            Some(pfx) => {
                let pattern = format!("{}%", pfx);
                (
                    "SELECT key FROM folder_data WHERE namespace = ?1 AND key LIKE ?2 ORDER BY key".to_string(),
                    vec![Box::new(namespace.to_string()) as Box<dyn rusqlite::types::ToSql>, Box::new(pattern)],
                )
            }
        };
        let params_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql).map_err(|e| ese(e))?;
        let rows = stmt.query_map(params_refs.as_slice(), |row| row.get(0)).map_err(|e| ese(e))?;
        let mut results = Vec::new();
        for row in rows { results.push(row.map_err(|e| ese(e))?); }
        Ok(results)
    }

    fn folder_count(&self, namespace: &str) -> EngineStoreResult<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM folder_data WHERE namespace = ?1",
            params![namespace],
            |row| row.get(0),
        ).map_err(|e| ese(e))?;
        Ok(count as usize)
    }

    fn folder_exists(&self, namespace: &str) -> EngineStoreResult<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM folder_meta WHERE namespace = ?1",
            params![namespace],
            |row| row.get(0),
        ).map_err(|e| ese(e))?;
        Ok(count > 0)
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests — run same scenarios against SqliteEngineStore (in-memory SQLite)
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> i64 { chrono::Utc::now().timestamp_millis() }

    fn store() -> SqliteEngineStore {
        SqliteEngineStore::in_memory().unwrap()
    }

    #[test]
    fn test_sqlite_open_in_memory() {
        let s = store();
        assert_eq!(s.audit_count().unwrap(), 0);
    }

    #[test]
    fn test_sqlite_audit() {
        let mut s = store();
        let ts = now();
        s.append_audit(&EngineAuditEntry {
            timestamp: ts, category: "firewall".into(),
            agent_pid: Some("agent:nurse".into()), action: "tool.call".into(),
            resource: None, verdict: Some("allowed".into()),
            details: Some(serde_json::json!({"tool": "search"})), severity: "info".into(),
        }).unwrap();
        s.append_audit(&EngineAuditEntry {
            timestamp: ts + 1, category: "guard".into(),
            agent_pid: Some("agent:doctor".into()), action: "output.check".into(),
            resource: None, verdict: Some("blocked".into()),
            details: None, severity: "warning".into(),
        }).unwrap();
        assert_eq!(s.audit_count().unwrap(), 2);

        let firewall = s.query_audit(&AuditFilter { category: Some("firewall".into()), ..Default::default() }).unwrap();
        assert_eq!(firewall.len(), 1);

        let limited = s.query_audit(&AuditFilter { limit: Some(1), ..Default::default() }).unwrap();
        assert_eq!(limited.len(), 1);
    }

    #[test]
    fn test_sqlite_behavior() {
        let mut s = store();
        s.save_behavior(&BehaviorProfile {
            agent_pid: "agent:nurse".into(), total_actions: 42, total_errors: 3,
            total_tool_calls: 15, avg_threat_score: 0.12,
            recent_scores: vec![0.1, 0.15], last_action_at: Some(now()), updated_at: now(),
        }).unwrap();
        let loaded = s.load_behavior("agent:nurse").unwrap().unwrap();
        assert_eq!(loaded.total_actions, 42);
        assert_eq!(loaded.recent_scores.len(), 2);
        assert!(s.load_behavior("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_sqlite_circuit_breakers() {
        let mut s = store();
        s.save_circuit_breaker(&CircuitBreakerState {
            agent_pid: "agent:risky".into(), state: "open".into(),
            failure_count: 5, failure_threshold: 5, reset_timeout_ms: 60_000,
            half_open_max_probes: 3, half_open_success_count: 0,
            last_failure_ms: now(), last_state_change_ms: now(),
        }).unwrap();
        let loaded = s.load_circuit_breaker("agent:risky").unwrap().unwrap();
        assert_eq!(loaded.state, "open");
        assert_eq!(s.load_all_circuit_breakers().unwrap().len(), 1);
    }

    #[test]
    fn test_sqlite_secrets() {
        let mut s = store();
        let ts = now();
        s.store_secret(&StoredSecret {
            secret_id: "key_1".into(), agent_pid: "agent:a".into(),
            value: "secret123".into(), created_at: ts,
            expires_at: Some(ts + 60_000), description: "test".into(),
        }).unwrap();
        s.store_secret(&StoredSecret {
            secret_id: "key_2".into(), agent_pid: "agent:a".into(),
            value: "permanent".into(), created_at: ts,
            expires_at: None, description: "permanent".into(),
        }).unwrap();

        assert_eq!(s.load_secrets_by_agent("agent:a").unwrap().len(), 2);
        let purged = s.purge_expired_secrets(ts + 120_000).unwrap();
        assert_eq!(purged, 1);
        assert!(s.load_secret("key_1").unwrap().is_none());
        assert!(s.load_secret("key_2").unwrap().is_some());
    }

    #[test]
    fn test_sqlite_escrow() {
        let mut s = store();
        let ts = now();
        s.save_escrow(&StoredEscrow {
            escrow_id: "esc_1".into(), requester_pid: "buyer".into(),
            provider_pid: "seller".into(), amount: 1000,
            state: "locked".into(), contract_id: "c1".into(),
            invocation_id: None, resolution_reason: None,
            created_at: ts, expires_at: ts + 86_400_000, resolved_at: None,
        }).unwrap();
        let loaded = s.load_escrow("esc_1").unwrap().unwrap();
        assert_eq!(loaded.amount, 1000);
        assert_eq!(s.load_escrows_by_state("locked").unwrap().len(), 1);
    }

    #[test]
    fn test_sqlite_reputation() {
        let mut s = store();
        let ts = now();
        for i in 0..5 {
            s.submit_feedback(&StoredFeedback {
                from_agent: format!("reviewer_{}", i), to_agent: "worker".into(),
                score: 0.8 + (i as f64) * 0.02, context: None, timestamp: ts + i,
            }).unwrap();
        }
        let avg = s.compute_avg_reputation("worker").unwrap();
        assert!(avg > 0.7 && avg < 1.0);

        let fb = s.load_feedback_for("worker", 3).unwrap();
        assert_eq!(fb.len(), 3);
    }

    #[test]
    fn test_sqlite_agent_index_search() {
        let mut s = store();
        let ts = now();
        s.index_agent(&StoredAgentIndex {
            agent_pid: "search_bot".into(), capabilities: "web search, news".into(),
            contract_json: None, health_json: None, reputation_score: 0.95, last_indexed_at: ts,
        }).unwrap();
        s.index_agent(&StoredAgentIndex {
            agent_pid: "code_bot".into(), capabilities: "code generation, debugging".into(),
            contract_json: None, health_json: None, reputation_score: 0.88, last_indexed_at: ts,
        }).unwrap();

        let results = s.search_agents("code", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_pid, "code_bot");
    }

    #[test]
    fn test_sqlite_pipeline_state() {
        let mut s = store();
        let ts = now();
        s.save_pipeline(&StoredPipeline {
            pipeline_id: "pipe_1".into(), state: "running".into(),
            steps_json: serde_json::json!([{"id": "s1"}]),
            created_at: ts, updated_at: ts,
        }).unwrap();
        let loaded = s.load_pipeline("pipe_1").unwrap().unwrap();
        assert_eq!(loaded.state, "running");
    }

    #[test]
    fn test_sqlite_session_routes() {
        let mut s = store();
        let ts = now();
        s.save_route(&StoredRoute {
            session_id: "sess_1".into(), cell_id: "cell_a".into(),
            created_at: ts, ttl_ms: 60_000, access_count: 0,
        }).unwrap();
        s.save_route(&StoredRoute {
            session_id: "sess_2".into(), cell_id: "cell_b".into(),
            created_at: ts - 120_000, ttl_ms: 60_000, access_count: 5,
        }).unwrap();
        let purged = s.purge_expired_routes(ts + 1).unwrap();
        assert_eq!(purged, 1);
        assert!(s.load_route("sess_1").unwrap().is_some());
        assert!(s.load_route("sess_2").unwrap().is_none());
    }

    #[test]
    fn test_sqlite_tool_defs() {
        let mut s = store();
        s.save_tool_def(&StoredToolDef {
            name: "search".into(), description: "Search web".into(),
            params_json: serde_json::json!([]), rules_json: serde_json::json!({}),
            domain: Some("web".into()), created_at: now(),
        }).unwrap();
        assert_eq!(s.load_tool_defs().unwrap().len(), 1);
        s.delete_tool_def("search").unwrap();
        assert_eq!(s.load_tool_defs().unwrap().len(), 0);
    }

    #[test]
    fn test_sqlite_policies() {
        let mut s = store();
        s.save_policy(&StoredPolicy {
            policy_id: "p1".into(), name: "deny_external".into(),
            description: "Block external".into(),
            rules_json: serde_json::json!([{"pattern": "*"}]),
            created_at: now(), updated_at: now(),
        }).unwrap();
        assert_eq!(s.load_policies().unwrap().len(), 1);
        s.delete_policy("p1").unwrap();
        assert_eq!(s.load_policies().unwrap().len(), 0);
    }

    #[test]
    fn test_sqlite_file_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine_test.db");

        // Write data
        {
            let mut s = SqliteEngineStore::open(&path).unwrap();
            s.save_behavior(&BehaviorProfile {
                agent_pid: "agent:persist".into(), total_actions: 99,
                total_errors: 1, total_tool_calls: 50, avg_threat_score: 0.05,
                recent_scores: vec![0.05], last_action_at: Some(now()), updated_at: now(),
            }).unwrap();
        }

        // Reopen and verify
        {
            let s = SqliteEngineStore::open(&path).unwrap();
            let loaded = s.load_behavior("agent:persist").unwrap().unwrap();
            assert_eq!(loaded.total_actions, 99);
        }
    }

    // ── Custom Folder Tests (SQLite) ─────────────────────────────

    #[test]
    fn test_sqlite_agent_folder() {
        let mut s = store();
        let owner = FolderOwner::Agent("nurse".into());
        s.create_folder("agent:nurse/scratchpad", &owner, "Working memory").unwrap();
        assert!(s.folder_exists("agent:nurse/scratchpad").unwrap());

        s.folder_put("agent:nurse/scratchpad", "patient_1", &serde_json::json!({"bp": "140/90"})).unwrap();
        s.folder_put("agent:nurse/scratchpad", "patient_2", &serde_json::json!({"bp": "120/80"})).unwrap();
        assert_eq!(s.folder_count("agent:nurse/scratchpad").unwrap(), 2);

        let val = s.folder_get("agent:nurse/scratchpad", "patient_1").unwrap().unwrap();
        assert_eq!(val["bp"], "140/90");

        let keys = s.folder_keys("agent:nurse/scratchpad", None).unwrap();
        assert_eq!(keys.len(), 2);

        let keys = s.folder_keys("agent:nurse/scratchpad", Some("patient_1")).unwrap();
        assert_eq!(keys.len(), 1);

        s.folder_delete("agent:nurse/scratchpad", "patient_1").unwrap();
        assert_eq!(s.folder_count("agent:nurse/scratchpad").unwrap(), 1);
    }

    #[test]
    fn test_sqlite_tool_folder() {
        let mut s = store();
        let owner = FolderOwner::Tool("search".into());
        s.create_folder("tool:search/cache", &owner, "Search cache").unwrap();
        s.folder_put("tool:search/cache", "q1", &serde_json::json!(["r1", "r2"])).unwrap();
        assert_eq!(s.folder_count("tool:search/cache").unwrap(), 1);
        let v = s.folder_get("tool:search/cache", "q1").unwrap().unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_sqlite_folder_isolation() {
        let mut s = store();
        s.create_folder("agent:a/data", &FolderOwner::Agent("a".into()), "A").unwrap();
        s.create_folder("agent:b/data", &FolderOwner::Agent("b".into()), "B").unwrap();
        s.folder_put("agent:a/data", "key", &serde_json::json!("aaa")).unwrap();
        s.folder_put("agent:b/data", "key", &serde_json::json!("bbb")).unwrap();
        assert_eq!(s.folder_get("agent:a/data", "key").unwrap().unwrap(), "aaa");
        assert_eq!(s.folder_get("agent:b/data", "key").unwrap().unwrap(), "bbb");
    }

    #[test]
    fn test_sqlite_list_folders_by_owner() {
        let mut s = store();
        s.create_folder("agent:n/notes", &FolderOwner::Agent("n".into()), "Notes").unwrap();
        s.create_folder("agent:n/cache", &FolderOwner::Agent("n".into()), "Cache").unwrap();
        s.create_folder("tool:s/cache", &FolderOwner::Tool("s".into()), "Tool cache").unwrap();
        s.create_folder("system/cfg", &FolderOwner::System, "Config").unwrap();

        assert_eq!(s.list_folders(None).unwrap().len(), 4);
        assert_eq!(s.list_folders(Some(&FolderOwner::Agent("n".into()))).unwrap().len(), 2);
        assert_eq!(s.list_folders(Some(&FolderOwner::Tool("s".into()))).unwrap().len(), 1);
        assert_eq!(s.list_folders(Some(&FolderOwner::System)).unwrap().len(), 1);
    }

    #[test]
    fn test_sqlite_delete_folder() {
        let mut s = store();
        s.create_folder("agent:x/tmp", &FolderOwner::Agent("x".into()), "Tmp").unwrap();
        s.folder_put("agent:x/tmp", "k1", &serde_json::json!(1)).unwrap();
        s.folder_put("agent:x/tmp", "k2", &serde_json::json!(2)).unwrap();
        assert_eq!(s.folder_count("agent:x/tmp").unwrap(), 2);

        s.delete_folder("agent:x/tmp").unwrap();
        assert!(!s.folder_exists("agent:x/tmp").unwrap());
        assert_eq!(s.folder_count("agent:x/tmp").unwrap(), 0);
    }

    #[test]
    fn test_sqlite_implicit_mkdir() {
        let mut s = store();
        s.folder_put("auto/ns", "k", &serde_json::json!("v")).unwrap();
        assert!(s.folder_exists("auto/ns").unwrap());
        assert_eq!(s.folder_count("auto/ns").unwrap(), 1);
    }

    #[test]
    fn test_sqlite_folder_entry_count_in_listing() {
        let mut s = store();
        s.create_folder("agent:a/d", &FolderOwner::Agent("a".into()), "D").unwrap();
        s.folder_put("agent:a/d", "k1", &serde_json::json!(1)).unwrap();
        s.folder_put("agent:a/d", "k2", &serde_json::json!(2)).unwrap();
        let folders = s.list_folders(Some(&FolderOwner::Agent("a".into()))).unwrap();
        assert_eq!(folders[0].entry_count, 2);
    }
}
