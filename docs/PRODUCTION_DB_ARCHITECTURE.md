# Production Database Architecture — EngineStore

> Deep research + full 48-component audit — Feb 27, 2026
> Sources: Tiger Data Agentic Postgres, SQLite WAL best practices, redb benchmarks,
> r2d2-sqlite pooling, rusqlite production patterns, FTS5 full-text search

---

## 1. The Problem: ALL Engine State Vanishes on Restart

### Current state

| Layer | Storage | Status | Components |
|-------|---------|--------|------------|
| **Ring 0** (VAC Kernel) | `KernelStore` trait → InMemory / redb / Prolly | ✅ Working | 13 data types: packets, windows, SVs, edges, audit, SCITT, agents, sessions, ports, policies, delegations, WAL |
| **Ring 1-4** (Engine) | In-memory `HashMap` / `Vec` | ❌ LOST ON RESTART | 35+ components: all use HashMaps that vanish |

### What we lose on restart (CRITICAL for production)

| Component | Lost Data | Impact |
|-----------|-----------|--------|
| **SecretStore** | API keys, tokens, credentials | Agents can't call tools |
| **EscrowManager** | Locked funds, settlement state | Financial loss |
| **ReputationEngine** | Trust scores, feedback, stakes | Agent trust reset to zero |
| **CircuitBreaker** | Breaker states | Cascading failures (no protection) |
| **BehaviorAnalyzer** | Per-agent profiles | Adaptive thresholds reset |
| **AdaptiveThreshold** | Score baselines | False positives spike |
| **NegotiationManager** | Active negotiations | Deals lost mid-negotiation |
| **PipelineManager** | Saga state | Can't rollback failed pipelines |
| **SessionRouter** | Sticky routes | Read-your-writes broken |
| **AgentIndex** | Capability graph | Agent discovery broken |
| **Watchdog** | Fired action history | Can't detect flapping |
| **ActionEngine** | Budgets, capabilities | Budget enforcement reset |
| **ToolRegistry** | Tool definitions | Tools must be re-registered |
| **CrossCellPort** | Message log | Audit trail gap |
| **ContextManager** | Snapshots | Can't resume evicted agents |
| **GlobalQuota** | Quota state | Over-provisioning risk |

---

## 2. Complete Component Audit — 48 Components

### Legend
- **P** = Needs persistence (lost on restart is production bug)
- **—** = Stateless or transient (no persistence needed)
- **Access** = R (read-heavy), W (write-heavy), A (append-only), Q (complex queries)

| # | Component | Ring | State Type | Persist? | Access | DB Needs |
|---|-----------|------|-----------|----------|--------|----------|
| 1 | MemoryKernel | 0 | MemPackets, namespaces | P | R/W | KV by CID, prefix query |
| 2 | RangeWindow | 0 | Ordered windows | P | W | Ordered by (ns, sn) |
| 3 | InterferenceEngine | 0 | StateVectors, edges | P | W | Agent-keyed, ordered |
| 4 | KnotEngine | 0 | Merkle graph | — | R | In-memory graph |
| 5 | AuditExport | 0 | Audit entries, SCITT | P | A | Time-range queries, agent filter |
| 6 | AutoDerive | 1 | — | — | — | Stateless |
| 7 | AutoVakya | 1 | — | — | — | Stateless |
| 8 | ActionEngine | 1 | Policies, budgets, caps, actions | P | Q | Complex queries, aggregation |
| 9 | AgentFirewall | 1 | Rules, PII patterns | — | R | Config (loaded once) |
| 10 | BehaviorAnalyzer | 1 | Per-agent profiles | P | W | Agent-keyed time-series |
| 11 | InstructionPlane | 1 | Schema registry | — | R | Config |
| 12 | GuardPipeline | 1 | — | — | — | Stateless per-request |
| 13 | PerceptionEngine | 1 | — | — | — | Stateless |
| 14 | JudgmentEngine | 1 | — | — | — | Stateless |
| 15 | ClaimVerifier | 1 | — | — | — | Stateless |
| 16 | GroundingTable | 1 | Lookup dictionary | — | R | Config (loaded once) |
| 17 | LogicEngine | 1 | Plans, chains | P | W | Plan tracking |
| 18 | KnowledgeEngine | 1 | Documents, compiled KB | P | Q | FTS5 search |
| 19 | BindingEngine | 1 | Cognitive cycles | — | — | Transient |
| 20 | RagEngine | 1 | — | — | R | Stateless (queries kernel) |
| 21 | SecretStore | 1 | Secrets, handles | **P** | R/W | **ENCRYPTED**, TTL |
| 22 | PolicyEngine | 1 | Deny/allow rules | P | R | Pattern matching |
| 23 | ContentGuard | 1 | — | — | — | Stateless |
| 24 | SemanticInjection | 1 | — | — | — | Stateless |
| 25 | FirewallEvents | 1 | Event log | P | A | Append-only, time queries |
| 26 | AdaptiveThreshold | 1 | Per-agent baselines | P | W | Agent-keyed score history |
| 27 | Watchdog | 2 | Rules, fired actions | P | W | Rule storage, action log |
| 28 | CircuitBreaker | 2 | Per-agent circuit state | P | R/W | Fast KV lookup |
| 29 | GlobalQuota | 2 | Namespace limits, cell counts | P | R/W | Distributed counters |
| 30 | ReputationEngine | 3 | Scores, feedback, stakes | P | Q | Aggregate queries |
| 31 | AgentIndex | 3 | Capabilities, health, contracts | P | Q | **FTS5**, graph queries |
| 32 | EscrowManager | 3 | Accounts, settlements | **P** | W | **ACID critical** |
| 33 | DynamicPricer | 3 | Pricing config | P | R | Config |
| 34 | NegotiationManager | 3 | Active negotiations | P | W | Session-like |
| 35 | ServiceContract | 3 | Definitions | P | R | Config |
| 36 | Orchestrator | 3 | DAG tasks | — | — | Transient per-pipeline |
| 37 | ContextManager | 3 | Snapshots | P | W | CID-keyed blobs |
| 38 | SessionRouter | 3 | Sticky routes | P | R | Fast KV |
| 39 | AdaptiveRouter | 3 | Cell metrics | P | W | Time-series |
| 40 | CrossCellPort | 3 | Messages, routing | P | A | Message log |
| 41 | PipelineManager | 3 | Saga state | P | W | Pipeline tracking |
| 42 | NoiseChannel | 3 | Channel state | — | — | In-memory crypto |
| 43 | GatewayBridge | 3 | Request tracking | — | — | Transient |
| 44 | FipsCrypto | 3 | Module registry | — | R | Config |
| 45 | PostQuantum | 3 | Signing keys | P | R | **SECURE** |
| 46 | BftConsensus | 3 | Proposals, votes | P | W | Consensus log |
| 47 | ToolRegistry | 4 | Tool definitions | P | R | Config |
| 48 | ToolDef | 4 | Schemas | — | R | In-memory |

### Summary
- **Stateless** (no DB): 18 components (37%)
- **Config** (read once): 5 components (10%)
- **Needs persistence**: 25 components (52%) — **THIS IS THE GAP**

---

## 3. Why SQLite (Not redb or PostgreSQL)

### Decision Matrix

| Requirement | redb | SQLite (WAL) | PostgreSQL |
|-------------|------|-------------|------------|
| Single-file deployment | ✅ | ✅ | ❌ Server required |
| Zero configuration | ✅ | ✅ | ❌ Setup needed |
| SQL queries | ❌ KV only | ✅ Full SQL | ✅ Full SQL |
| Complex filtering (audit) | ❌ | ✅ WHERE, JOIN | ✅ |
| Aggregate queries (reputation) | ❌ | ✅ GROUP BY, AVG | ✅ |
| Full-text search (agents) | ❌ | ✅ FTS5 | ✅ tsvector |
| JSON column support | ❌ | ✅ JSON1 | ✅ JSONB |
| ACID transactions | ✅ | ✅ | ✅ |
| Concurrent reads | ✅ MVCC | ✅ WAL mode | ✅ |
| Crash safety | ✅ CoW | ✅ WAL | ✅ |
| Write throughput | ~100K/s | ~50K/s WAL | ~30K/s |
| Multi-process access | ❌ | ✅ | ✅ |
| Connection pooling | N/A | ✅ r2d2-sqlite | ✅ deadpool |
| Schema migrations | ❌ | ✅ refinery | ✅ |
| Encryption at rest | ❌ | ✅ SQLCipher | ✅ pgcrypto |
| Rust ecosystem maturity | Good | **Excellent** | Good |
| Production track record | Niche | **Billions of deployments** | Enterprise standard |

### Verdict

| Deployment | Ring 0 (Kernel) | Ring 1-4 (Engine) |
|-----------|-----------------|-------------------|
| **Dev/Test** | InMemoryKernelStore | InMemoryEngineStore |
| **Local prod** | RedbKernelStore | **SqliteEngineStore** |
| **Enterprise** | RedbKernelStore | SqliteEngineStore or PostgresEngineStore |

**redb stays for Ring 0** (simple KV, highest write throughput for packets).
**SQLite takes Ring 1-4** (SQL queries needed for audit, reputation, agent discovery).

---

## 4. SQLite Production Configuration

```sql
-- Applied on every connection open
PRAGMA journal_mode = WAL;          -- Concurrent reads during writes
PRAGMA synchronous = NORMAL;        -- Good durability, 10x faster than FULL
PRAGMA busy_timeout = 5000;         -- 5s retry on lock contention
PRAGMA cache_size = -64000;         -- 64MB page cache
PRAGMA foreign_keys = ON;           -- Referential integrity
PRAGMA auto_vacuum = INCREMENTAL;   -- Reclaim space without full vacuum
PRAGMA wal_autocheckpoint = 1000;   -- Checkpoint every 1000 pages
PRAGMA temp_store = MEMORY;         -- Temp tables in memory
```

### Connection Pattern

```
┌─────────────────────────────────┐
│     SqliteEngineStore           │
│                                 │
│  ┌───────────┐  ┌────────────┐  │
│  │  Writer   │  │  Reader    │  │
│  │  Pool (1) │  │  Pool (4)  │  │
│  └─────┬─────┘  └─────┬──────┘  │
│        │              │         │
│        └──────┬───────┘         │
│               │                 │
│        ┌──────▼──────┐          │
│        │  engine.db  │          │
│        │  (WAL mode) │          │
│        └─────────────┘          │
└─────────────────────────────────┘
```

---

## 5. Schema Design — 19 Tables

### 5A. Audit & Compliance (append-only)

```sql
CREATE TABLE engine_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,       -- epoch ms
    category    TEXT NOT NULL,           -- 'firewall', 'tool', 'guard', 'action', 'secret'
    agent_pid   TEXT,
    action      TEXT NOT NULL,
    resource    TEXT,
    verdict     TEXT,                    -- 'allowed', 'denied', 'blocked', 'error'
    details     TEXT,                    -- JSON blob
    severity    TEXT DEFAULT 'info',     -- 'info', 'warning', 'error', 'critical'
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
);
CREATE INDEX idx_audit_time ON engine_audit(timestamp);
CREATE INDEX idx_audit_agent ON engine_audit(agent_pid, timestamp);
CREATE INDEX idx_audit_category ON engine_audit(category, timestamp);
```

### 5B. Agent State

```sql
CREATE TABLE agent_behavior (
    agent_pid       TEXT PRIMARY KEY,
    total_actions   INTEGER DEFAULT 0,
    total_errors    INTEGER DEFAULT 0,
    total_tool_calls INTEGER DEFAULT 0,
    avg_threat_score REAL DEFAULT 0.0,
    scores_json     TEXT DEFAULT '[]',   -- JSON array of recent scores
    last_action_at  INTEGER,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE circuit_breakers (
    agent_pid               TEXT PRIMARY KEY,
    state                   TEXT NOT NULL DEFAULT 'closed',  -- closed/open/half_open
    failure_count           INTEGER DEFAULT 0,
    failure_threshold       INTEGER DEFAULT 5,
    reset_timeout_ms        INTEGER DEFAULT 60000,
    half_open_max_probes    INTEGER DEFAULT 3,
    half_open_success_count INTEGER DEFAULT 0,
    last_failure_ms         INTEGER DEFAULT 0,
    last_state_change_ms    INTEGER DEFAULT 0
);

CREATE TABLE adaptive_thresholds (
    agent_pid   TEXT PRIMARY KEY,
    scores_json TEXT DEFAULT '[]',       -- JSON array of f64 scores
    avg_score   REAL DEFAULT 0.0,
    thresholds_json TEXT,                -- JSON of adapted VerdictThresholds
    updated_at  INTEGER NOT NULL
);
```

### 5C. Security

```sql
CREATE TABLE secrets (
    secret_id   TEXT PRIMARY KEY,
    agent_pid   TEXT NOT NULL,
    value       BLOB NOT NULL,           -- encrypted at rest
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,                 -- NULL = no expiry
    description TEXT DEFAULT ''
);
CREATE INDEX idx_secrets_agent ON secrets(agent_pid);
CREATE INDEX idx_secrets_expiry ON secrets(expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE secret_handles (
    handle_id   TEXT PRIMARY KEY,
    secret_id   TEXT NOT NULL REFERENCES secrets(secret_id) ON DELETE CASCADE,
    agent_pid   TEXT NOT NULL,
    namespace   TEXT NOT NULL
);

CREATE TABLE policies (
    policy_id   TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    rules_json  TEXT NOT NULL,           -- JSON array of PolicyRule
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
```

### 5D. Economy

```sql
CREATE TABLE escrow_accounts (
    escrow_id       TEXT PRIMARY KEY,
    requester_pid   TEXT NOT NULL,
    provider_pid    TEXT NOT NULL,
    amount          INTEGER NOT NULL,
    state           TEXT NOT NULL DEFAULT 'locked', -- locked/released/slashed/expired/disputed
    contract_id     TEXT NOT NULL,
    invocation_id   TEXT,
    resolution_reason TEXT,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    resolved_at     INTEGER
);
CREATE INDEX idx_escrow_requester ON escrow_accounts(requester_pid, state);
CREATE INDEX idx_escrow_provider ON escrow_accounts(provider_pid, state);

CREATE TABLE settlements (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    escrow_id   TEXT NOT NULL REFERENCES escrow_accounts(escrow_id),
    to_provider INTEGER NOT NULL,
    to_requester INTEGER NOT NULL,
    slashed     INTEGER DEFAULT 0,
    settled_at  INTEGER NOT NULL
);

CREATE TABLE reputation_feedback (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    from_agent  TEXT NOT NULL,
    to_agent    TEXT NOT NULL,
    score       REAL NOT NULL CHECK(score >= 0.0 AND score <= 1.0),
    context     TEXT,
    timestamp   INTEGER NOT NULL
);
CREATE INDEX idx_rep_to ON reputation_feedback(to_agent, timestamp);

CREATE TABLE reputation_stakes (
    agent_pid   TEXT PRIMARY KEY,
    stake       INTEGER NOT NULL DEFAULT 0,
    slash_count INTEGER NOT NULL DEFAULT 0,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE negotiations (
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
```

### 5E. Discovery & Knowledge

```sql
CREATE TABLE agent_index (
    agent_pid       TEXT PRIMARY KEY,
    capabilities    TEXT NOT NULL,       -- searchable text (FTS5 content)
    contract_json   TEXT,
    health_json     TEXT,
    reputation_score REAL DEFAULT 0.0,
    last_indexed_at INTEGER NOT NULL
);

-- FTS5 virtual table for agent discovery
CREATE VIRTUAL TABLE agent_index_fts USING fts5(
    agent_pid, capabilities, content=agent_index, content_rowid=rowid
);

CREATE TABLE knowledge_docs (
    doc_id      TEXT PRIMARY KEY,
    namespace   TEXT NOT NULL,
    content     TEXT NOT NULL,
    metadata_json TEXT,
    created_at  INTEGER NOT NULL
);

CREATE VIRTUAL TABLE knowledge_fts USING fts5(
    doc_id, content, content=knowledge_docs, content_rowid=rowid
);
```

### 5F. Distributed

```sql
CREATE TABLE session_routes (
    session_id  TEXT PRIMARY KEY,
    cell_id     TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    ttl_ms      INTEGER NOT NULL,
    access_count INTEGER DEFAULT 0
);

CREATE TABLE pipeline_state (
    pipeline_id TEXT PRIMARY KEY,
    state       TEXT NOT NULL DEFAULT 'running',
    steps_json  TEXT DEFAULT '[]',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE context_snapshots (
    snapshot_cid TEXT PRIMARY KEY,
    agent_pid   TEXT NOT NULL,
    data_json   TEXT NOT NULL,           -- full ContextSnapshot JSON
    created_at  INTEGER NOT NULL,
    evicted     INTEGER DEFAULT 0
);
CREATE INDEX idx_ctx_agent ON context_snapshots(agent_pid, created_at);

CREATE TABLE cross_cell_messages (
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

CREATE TABLE watchdog_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name   TEXT NOT NULL,
    condition_json TEXT NOT NULL,
    action_json TEXT NOT NULL,
    fired_at    INTEGER NOT NULL,
    result      TEXT DEFAULT 'fired'
);

CREATE TABLE tool_definitions (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    params_json TEXT DEFAULT '[]',
    rules_json  TEXT DEFAULT '{}',
    domain      TEXT,
    created_at  INTEGER NOT NULL
);
```

---

## 6. EngineStore Trait

```rust
pub trait EngineStore: Send {
    // === Audit (append-only) ===
    fn append_audit(&mut self, entry: &EngineAuditEntry) -> StoreResult<()>;
    fn query_audit(&self, filter: &AuditFilter) -> StoreResult<Vec<EngineAuditEntry>>;

    // === Agent Behavior ===
    fn save_behavior(&mut self, pid: &str, profile: &BehaviorProfile) -> StoreResult<()>;
    fn load_behavior(&self, pid: &str) -> StoreResult<Option<BehaviorProfile>>;

    // === Circuit Breakers ===
    fn save_circuit_breaker(&mut self, pid: &str, cb: &CircuitBreakerState) -> StoreResult<()>;
    fn load_circuit_breaker(&self, pid: &str) -> StoreResult<Option<CircuitBreakerState>>;

    // === Adaptive Thresholds ===
    fn save_threshold(&mut self, pid: &str, baseline: &ThresholdBaseline) -> StoreResult<()>;
    fn load_threshold(&self, pid: &str) -> StoreResult<Option<ThresholdBaseline>>;

    // === Secrets (encrypted) ===
    fn store_secret(&mut self, entry: &SecretEntry) -> StoreResult<()>;
    fn load_secret(&self, secret_id: &str) -> StoreResult<Option<SecretEntry>>;
    fn delete_secret(&mut self, secret_id: &str) -> StoreResult<()>;
    fn purge_expired_secrets(&mut self, now_ms: i64) -> StoreResult<usize>;

    // === Escrow (ACID critical) ===
    fn save_escrow(&mut self, account: &EscrowAccount) -> StoreResult<()>;
    fn load_escrow(&self, escrow_id: &str) -> StoreResult<Option<EscrowAccount>>;
    fn save_settlement(&mut self, record: &SettlementRecord) -> StoreResult<()>;

    // === Reputation ===
    fn submit_feedback(&mut self, fb: &ReputationFeedback) -> StoreResult<()>;
    fn compute_reputation(&self, agent_pid: &str) -> StoreResult<f64>;
    fn save_stake(&mut self, pid: &str, stake: u64) -> StoreResult<()>;

    // === Agent Index (FTS5) ===
    fn index_agent(&mut self, entry: &AgentIndexEntry) -> StoreResult<()>;
    fn search_agents(&self, query: &str, limit: usize) -> StoreResult<Vec<AgentIndexEntry>>;

    // === Negotiations ===
    fn save_negotiation(&mut self, neg: &Negotiation) -> StoreResult<()>;
    fn load_negotiation(&self, id: &str) -> StoreResult<Option<Negotiation>>;

    // === Pipeline State ===
    fn save_pipeline(&mut self, pipeline: &ManagedPipeline) -> StoreResult<()>;
    fn load_pipeline(&self, id: &str) -> StoreResult<Option<ManagedPipeline>>;

    // === Context Snapshots ===
    fn save_snapshot(&mut self, snapshot: &ContextSnapshot) -> StoreResult<()>;
    fn load_snapshot(&self, cid: &str) -> StoreResult<Option<ContextSnapshot>>;

    // === Session Routes ===
    fn save_route(&mut self, session_id: &str, cell_id: &str, ttl_ms: i64) -> StoreResult<()>;
    fn load_route(&self, session_id: &str) -> StoreResult<Option<String>>;
    fn purge_expired_routes(&mut self, now_ms: i64) -> StoreResult<usize>;

    // === Tool Definitions ===
    fn save_tool_def(&mut self, tool: &ToolDef) -> StoreResult<()>;
    fn load_tool_defs(&self) -> StoreResult<Vec<ToolDef>>;

    // === Policies ===
    fn save_policy(&mut self, policy: &PolicyRecord) -> StoreResult<()>;
    fn load_policies(&self) -> StoreResult<Vec<PolicyRecord>>;

    // === Watchdog ===
    fn append_watchdog_action(&mut self, action: &WatchdogFiredAction) -> StoreResult<()>;

    // === Cross-Cell Messages ===
    fn log_cross_cell_message(&mut self, msg: &CrossCellMessage) -> StoreResult<()>;
}
```

---

## 7. Implementation Plan

| Phase | Scope | LOC | Tests | Files |
|-------|-------|-----|-------|-------|
| **D1** | EngineStore trait + types | ~150 | 0 | `engine_store.rs` |
| **D2** | SQLite schema + migrations | ~200 | 5 | `sqlite_store.rs` (schema section) |
| **D3** | SqliteEngineStore impl | ~800 | 25 | `sqlite_store.rs` (impl section) |
| **D4** | InMemoryEngineStore | ~200 | 10 | `engine_store.rs` (test backend) |
| **D5** | Wire into DualDispatcher | ~100 | 5 | `dispatcher.rs` |
| **D6** | Wire into ConnectorBuilder | ~50 | 5 | `connector.rs` |
| **Total** | | **~1,500** | **50** | 3 files |

### Dependencies (Cargo.toml additions)
```toml
rusqlite = { version = "0.31", features = ["bundled", "json", "fts5"] }
r2d2 = "0.8"
r2d2_sqlite = "0.24"
```

---

## 8. Competitive Advantage

| Feature | Us | Mem0 | LangChain | CrewAI |
|---------|-----|------|-----------|--------|
| Engine state persists across restarts | ✅ | ❌ | ❌ | ❌ |
| Escrow ACID transactions | ✅ | ❌ | ❌ | ❌ |
| Circuit breaker crash recovery | ✅ | ❌ | ❌ | ❌ |
| FTS5 agent discovery | ✅ | ❌ | ❌ | ❌ |
| Encrypted secrets at rest | ✅ | ❌ | ❌ | ❌ |
| Append-only audit trail | ✅ | ❌ | Partial | ❌ |
| Single-file zero-config production DB | ✅ | ❌ | ❌ | ❌ |
| 4-channel architecture (hot/warm/cold/archive) | ✅ | ❌ | ❌ | ❌ |
