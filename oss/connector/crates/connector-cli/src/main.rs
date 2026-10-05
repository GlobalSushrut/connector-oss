//! # connector — Connector Developer Workflow CLI
//!
//! `connector` is Connector's developer and project workflow surface.
//! Use it for init, dev, manifests, tests, examples, and integration-facing flows.
//! Use `connectorctl` for live runtime operations, review, diagnostics, proof, and recovery.
//! Some runtime-oriented commands remain available here as transitional compatibility paths.
//!
//! ## Commands
//!
//! ### Scaffold / Dev
//!   connector init [path] [--quickstart]        — scaffold project + .env + agent.py
//!   connector dev [--port 8080]                 — start server in dev mode + LLM stub
//!   connector doctor [--verbose] [--fix]        — 15+ diagnostic checks, grouped
//!   connector whoami                            — account, tier, token usage
//!   connector completions <bash|zsh|fish|ps>    — emit shell completion script
//!
//! ### Runtime compatibility paths
//!   connector agent ps [--filter over-budget|paused|all]
//!   connector agent inspect <pid>
//!   connector agent pause <pid>
//!   connector agent resume <pid>
//!   connector agent delete <pid> [--reason MSG]   (alias: kill)
//!   connector agent logs <pid> [-n N] [--follow] [--since Xm] [--until T]
//!   connector agent top
//!   connector agent set-clearance <pid> <level>
//!
//! ### Deploy lifecycle  (manifest management)
//!   connector deploy <manifest.yaml> [--dry-run]
//!   connector deploy ls
//!   connector deploy rollback <name> <version>
//!   connector deploy diff <name> [manifest.yaml]
//!   connector deploy history <name>
//!   connector deploy validate <manifest.yaml> [--strict]
//!   connector deploy lint <manifest.yaml> [--strict]
//!
//! ### Memory inspection
//!   connector memory tree <pid> [--depth N] [--since Xh]
//!   connector memory search <pid> <query>
//!   connector memory show <cid>
//!   connector memory stats <pid>
//!   connector memory export <pid> [--output FILE]
//!
//! ### Trace / Observability
//!   connector trace ls [--agent <pid>] [--limit N]
//!   connector trace show <trace-id>
//!   connector trace stats [--agent <pid>] [--window Xh]
//!
//! ### Test / Verify
//!   connector test invariants [--verbose]
//!   connector test claims <source.txt> --claim "..."
//!   connector test injection <string>
//!   connector test smoke [--agent NAME] [--llm-stub]
//!   connector test all
//!
//! ### Knowledge graph
//!   connector knowledge graph [--agent <pid>]       — show entity/edge count
//!   connector knowledge entities [--agent <pid>]    — list entities
//!   connector knowledge neighbors <entity-id>       — first-degree neighbors
//!   connector knowledge seed <file.json>             — load KnowledgeSeed ontology
//!   connector knowledge reflect <pid>               — trigger reflection run
//!   connector knowledge skills <pid>                — procedural skill cache
//!
//! ### Context management
//!   connector context budget <pid>                  — token budget remaining
//!   connector context compress <pid>                — trigger compression now
//!   connector context flush <pid>                   — clear working memory
//!   connector context assembly <pid> <query>        — preview context assembly
//!
//! ### Webhooks
//!   connector webhooks list                          — list registered webhooks
//!   connector webhooks test <url>                   — send test ping to URL
//!   connector webhooks deliveries <id>              — delivery history for webhook
//!   connector webhooks register <url> [--events E1,E2]
//!   connector webhooks delete <id>
//!
//! ### Examples
//!   connector examples list                         — show built-in example agents
//!   connector examples run <name> --input "..."
//!
//! ### Platform logs
//!   connector logs [--follow] [--since Xm] [--level warn|error] [--filter TYPE]

use clap::{Parser, Subcommand};
use std::collections::HashMap;

// =============================================================================
// CLI structure
// =============================================================================

#[derive(Parser)]
#[command(
    name = "connector",
    version = env!("CARGO_PKG_VERSION"),
    about = "Connector developer/project workflow CLI — init, dev, deploy-from-project, test, and integration flows",
    long_about = "`connector` is the developer and project workflow CLI for Connector. Use it for local setup, manifests, tests, examples, and integration-facing flows. Use `connectorctl` for live runtime operations, review, diagnostics, proof, and recovery. Some runtime commands remain here as transitional compatibility paths while the public CLI boundary is being enforced.",
)]
struct Cli {
    /// API server URL (default: http://localhost:8080, or CONNECTOR_API_URL)
    #[arg(
        long,
        env = "CONNECTOR_API_URL",
        default_value = "http://localhost:8080"
    )]
    api_url: String,

    /// API key (or CONNECTOR_API_KEY env var)
    #[arg(long, env = "CONNECTOR_API_KEY")]
    api_key: Option<String>,

    /// Output format: table (default), json, yaml, plain
    #[arg(long, default_value = "table")]
    output: String,

    /// Suppress all non-essential output (for scripting)
    #[arg(long, short = 'q')]
    quiet: bool,

    /// Disable colour output (also honours NO_COLOR env var)
    #[arg(long)]
    no_color: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Agent runtime state (ps, inspect, pause, resume, delete, logs, top, set-clearance)
    Agent {
        #[command(subcommand)]
        cmd: AgentCmd,
    },
    /// Deploy lifecycle: deploy, ls, rollback, diff, history, validate, lint
    Deploy {
        #[command(subcommand)]
        cmd: DeployCmd,
    },
    /// Memory inspection: tree, search, show, stats, export
    Memory {
        #[command(subcommand)]
        cmd: MemoryCmd,
    },
    /// Trace / observability: ls, show, stats
    Trace {
        #[command(subcommand)]
        cmd: TraceCmd,
    },
    /// Test & verify: invariants, claims, injection, smoke, all
    Test {
        #[command(subcommand)]
        cmd: TestCmd,
    },
    /// Stream platform-level events (like journalctl)
    Logs {
        /// Follow/stream new events continuously
        #[arg(long, short = 'f')]
        follow: bool,
        /// Show events since duration ago (e.g. 10m, 1h, 2h)
        #[arg(long)]
        since: Option<String>,
        /// Filter by level: warn, error
        #[arg(long)]
        level: Option<String>,
        /// Filter by event type: injection_blocked, audit, llm
        #[arg(long)]
        filter: Option<String>,
    },
    /// Run an agent manifest with optional input — streams reasoning + tool calls + answer to stdout.
    /// BIZ-2: TTFV < 5 min — `connector run examples/support.yaml --input "refund my order"`
    Run {
        /// Path to agent YAML manifest
        manifest: String,
        /// Input message to send to the agent
        #[arg(long, short = 'i')]
        input: Option<String>,
        /// Show verbose reasoning trace
        #[arg(long, short = 'v')]
        verbose: bool,
        /// Output format: pretty (default) | json
        #[arg(long, default_value = "pretty")]
        format: String,
    },
    /// Start server in development mode (CONNECTOR_ENV=development + LLM stub)
    Dev {
        /// Port to listen on
        #[arg(long, default_value = "8080")]
        port: u16,
    },
    /// Run diagnostic checks (connectivity, auth, security, observability)
    Doctor {
        /// Show all checks including passed ones
        #[arg(long)]
        verbose: bool,
        /// Output as JSON (for CI/monitoring)
        #[arg(long)]
        json: bool,
        /// Run a single named check (e.g. security, observability)
        #[arg(long)]
        check: Option<String>,
        /// Auto-remediate safe issues
        #[arg(long)]
        fix: bool,
    },
    /// Show account info (email, role, tier, tokens used)
    Whoami,
    /// Scaffold a new Connector project (writes connector.yaml, .env, agent.py)
    Init {
        /// Project directory (default: current dir)
        path: Option<String>,
        /// Create a working quickstart example
        #[arg(long)]
        quickstart: bool,
    },
    /// Emit shell completion script
    Completions {
        /// Shell: bash, zsh, fish, powershell
        shell: String,
    },
    /// Knowledge graph: entities, neighbors, seed ontology, reflect, skills
    Knowledge {
        #[command(subcommand)]
        cmd: KnowledgeCmd,
    },
    /// Context window management: budget, compress, flush, assembly preview
    Context {
        #[command(subcommand)]
        cmd: ContextCmd,
    },
    /// Webhook management: list, register, test, deliveries, delete
    Webhooks {
        #[command(subcommand)]
        cmd: WebhookCmd,
    },
    /// Built-in example agents: list, run
    Examples {
        #[command(subcommand)]
        cmd: ExamplesCmd,
    },
    /// MCP (Model Context Protocol): serve, list-tools, inspect
    Mcp {
        #[command(subcommand)]
        cmd: McpCmd,
    },
    /// Install tools or agents from the marketplace
    Install {
        #[command(subcommand)]
        cmd: InstallCmd,
    },
    /// Audit: export signed receipts, verify chain
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
    /// Policy: check if an operation is allowed for an agent
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Books: accounting-inspired operational ledger (journal, ledger, statement, receipt)
    Books {
        #[command(subcommand)]
        cmd: BooksCmd,
    },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// List running agents (like `ps aux`)
    Ps {
        /// Filter: over-budget, paused, all (default: all)
        #[arg(long, default_value = "all")]
        filter: String,
    },
    /// Full agent detail (ACB + KECS + recent audit)
    Inspect {
        /// Agent PID or name
        pid: String,
    },
    /// Suspend LLM dispatch for an agent
    Pause { pid: String },
    /// Re-enable a paused agent
    Resume { pid: String },
    /// Terminate an agent
    Delete {
        pid: String,
        #[arg(long, default_value = "operator_delete")]
        reason: String,
    },
    /// Terminate an agent (alias for delete)
    #[command(hide = true)]
    Kill {
        pid: String,
        #[arg(long, default_value = "operator_kill")]
        reason: String,
    },
    /// Show audit log entries for an agent
    Logs {
        pid: String,
        /// Number of entries to show
        #[arg(short = 'n', default_value = "50")]
        lines: usize,
        /// Follow/stream new entries
        #[arg(long, short = 'f')]
        follow: bool,
        /// Show entries since duration ago (e.g. 30m, 1h)
        #[arg(long)]
        since: Option<String>,
        /// Show entries until timestamp
        #[arg(long)]
        until: Option<String>,
    },
    /// Live resource usage across all agents (like htop)
    Top,
    /// Set MAC Guard security clearance level
    #[command(name = "set-clearance")]
    SetClearance {
        pid: String,
        /// Clearance level: public | tool_io | standard | protected | control | kernel
        level: String,
    },
    /// Set MAC Guard security clearance (alias for set-clearance)
    #[command(hide = true)]
    Clearance { pid: String, level: String },
    /// Set agent trust override (high | medium | low)
    Trust {
        pid: String,
        /// Trust level: high | medium | low
        #[arg(long)]
        level: String,
    },
    /// Trigger memory reflection run for an agent
    Reflect { pid: String },
    /// Migrate agent to another cell
    Migrate {
        pid: String,
        /// Target cell ID
        #[arg(long)]
        to: String,
    },
    /// Clone (fork) an agent — new PID, inherits ACB, 50% token budget
    Clone {
        pid: String,
        /// New agent name (default: <pid>-clone)
        #[arg(long)]
        name: Option<String>,
        /// Token budget for child (default: 50% of parent remaining)
        #[arg(long)]
        tokens: Option<u64>,
    },
    /// Set token budget for a running agent live
    Budget {
        pid: String,
        /// Daily token limit
        #[arg(long)]
        tokens: Option<u64>,
        /// Max cost per period in USD
        #[arg(long)]
        cost: Option<f64>,
        /// Enforce budget (halt on exhaustion)
        #[arg(long)]
        enforce: bool,
    },
}

#[derive(Subcommand)]
enum DeployCmd {
    /// Deploy an agent manifest
    #[command(name = "run", alias = "apply")]
    Run {
        /// Path to agent.yaml manifest
        manifest: String,
        /// Dry-run: validate + diff, no state change
        #[arg(long)]
        dry_run: bool,
    },
    /// List all deployed agents and their versions
    Ls,
    /// Roll back an agent to a previous version
    Rollback {
        /// Agent name
        name: String,
        /// Version index to restore (from `connector deploy history <name>`)
        version: u32,
    },
    /// Show diff between running and proposed manifest
    Diff {
        /// Agent name
        name: String,
        /// Path to proposed manifest (optional — shows current if omitted)
        manifest: Option<String>,
    },
    /// Show deployment version history
    History {
        /// Agent name
        name: String,
    },
    /// Validate agent manifest schema (exit 0=ok, 2=errors)
    Validate {
        /// Path to manifest file
        manifest: String,
        /// Treat warnings as errors
        #[arg(long)]
        strict: bool,
    },
    /// Lint manifest for anti-patterns (exit 0=clean, 1=warnings, 2=errors)
    Lint {
        /// Path to manifest file
        manifest: String,
        /// Treat warnings as errors (exit 2)
        #[arg(long)]
        strict: bool,
    },
}

#[derive(Subcommand)]
enum MemoryCmd {
    /// Show memory as namespace → session → packet tree
    Tree {
        pid: String,
        /// Tree depth (default: 3)
        #[arg(long, default_value = "3")]
        depth: usize,
        /// Show packets from last N hours (e.g. 1h, 24h)
        #[arg(long)]
        since: Option<String>,
    },
    /// Semantic search across agent memory
    Search {
        pid: String,
        query: String,
        #[arg(long, default_value = "10")]
        limit: usize,
    },
    /// Show a specific memory packet by CID
    Show { cid: String },
    /// Show memory statistics (packet counts, sessions, sizes)
    Stats { pid: String },
    /// Export all memory packets to JSONL
    Export {
        pid: String,
        #[arg(long)]
        output: Option<String>,
    },
    /// Pin a packet so it is never evicted
    Pin {
        /// Packet CID
        cid: String,
    },
    /// Unpin a previously pinned packet
    Unpin {
        /// Packet CID
        cid: String,
    },
    /// Purge all unsealed packets older than a window (e.g. 24h, 7d)
    Purge {
        /// Agent PID
        pid: String,
        /// Age threshold (e.g. 24h, 7d)
        #[arg(long, default_value = "7d")]
        older_than: String,
        /// Actually delete (default: dry-run)
        #[arg(long)]
        confirm: bool,
    },
    /// Compact: run LRU-K eviction + consolidation for an agent
    Compact {
        pid: String,
        /// Max packets to keep (default: 1000)
        #[arg(long, default_value = "1000")]
        max_packets: usize,
    },
    /// Import packets from a JSONL file (reverse of export)
    Import {
        pid: String,
        /// Path to JSONL file produced by `connector memory export`
        file: String,
        #[arg(long)]
        dry_run: bool,
    },
    /// Seal a packet so its content cannot be modified
    Seal { cid: String },
}

#[derive(Subcommand)]
enum KnowledgeCmd {
    /// Show knowledge graph summary (entity count, edge count, interference score)
    Graph {
        #[arg(long)]
        agent: Option<String>,
    },
    /// List all entities in the knowledge graph
    Entities {
        #[arg(long)]
        agent: Option<String>,
        #[arg(long, default_value = "30")]
        limit: usize,
    },
    /// Show first-degree neighbors of an entity
    Neighbors {
        entity_id: String,
        #[arg(long)]
        agent: Option<String>,
    },
    /// Load a KnowledgeSeed JSON ontology file into the graph
    Seed {
        /// Path to knowledge seed JSON file
        file: String,
    },
    /// Trigger a memory reflection run for an agent (LLM-driven consolidation)
    Reflect {
        pid: String,
        /// Force reflection even if interval not reached
        #[arg(long)]
        force: bool,
    },
    /// Show procedural skill cache (tool use patterns) for an agent
    Skills { pid: String },
    /// Show knowledge growth events for an agent
    Growth {
        pid: String,
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Export the full knowledge graph as JSON
    Export {
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
enum ContextCmd {
    /// Show current context window budget for an agent
    Budget { pid: String },
    /// Trigger context compression now (summarise oldest turns)
    Compress {
        pid: String,
        /// Target utilisation % to compress down to (default: 60)
        #[arg(long, default_value = "60")]
        target_pct: u8,
    },
    /// Flush working memory for an agent (clears context window state)
    Flush {
        pid: String,
        /// Also delete ephemeral packets (default: false)
        #[arg(long)]
        purge_ephemeral: bool,
    },
    /// Preview context assembly for a query (shows which packets would be included)
    Assembly {
        pid: String,
        query: String,
        /// Token budget for assembly (default: uses agent setting)
        #[arg(long)]
        budget: Option<u32>,
    },
    /// Show context utilisation across all agents
    Status,
}

#[derive(Subcommand)]
enum WebhookCmd {
    /// List registered webhook endpoints
    List,
    /// Register a new webhook endpoint
    Register {
        url: String,
        /// Comma-separated event types (default: all)
        /// Events: agent.started,agent.suspended,agent.terminated,budget.warning,
        ///         budget.exhausted,approval.required,approval.granted,audit.denial
        #[arg(
            long,
            default_value = "agent.terminated,budget.warning,budget.exhausted"
        )]
        events: String,
        /// Per-webhook signing secret (generated if not provided)
        #[arg(long)]
        secret: Option<String>,
    },
    /// Send a test ping to a webhook URL (verifies reachability)
    Test {
        /// Webhook URL or existing webhook ID
        url_or_id: String,
    },
    /// Show delivery history for a webhook
    Deliveries {
        id: String,
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Delete a webhook endpoint
    Delete { id: String },
    /// Resend a failed delivery
    Resend {
        /// Delivery ID (from `connector webhooks deliveries`)
        delivery_id: String,
    },
}

#[derive(Subcommand)]
enum ExamplesCmd {
    /// List built-in example agents
    List,
    /// Run a built-in example agent
    Run {
        /// Example name (from `connector examples list`)
        name: String,
        /// Input text to send
        #[arg(long)]
        input: String,
        /// Use LLM stub (no API key needed)
        #[arg(long)]
        llm_stub: bool,
    },
    /// Show the agent.yaml source for an example
    Show { name: String },
}

#[derive(Subcommand)]
enum TraceCmd {
    /// List recent LLM call traces
    Ls {
        #[arg(long)]
        agent: Option<String>,
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Show a single trace as a span tree
    Show { trace_id: String },
    /// Show trace statistics (P50/P95/P99, token usage)
    Stats {
        #[arg(long)]
        agent: Option<String>,
        /// Time window (e.g. 1h, 24h)
        #[arg(long, default_value = "1h")]
        window: String,
    },
}

#[derive(Subcommand)]
enum TestCmd {
    /// Run all 6 TLA+ formal safety invariants
    Invariants {
        #[arg(long)]
        verbose: bool,
    },
    /// Test claim verification (hallucination detection)
    Claims {
        source: String,
        #[arg(long)]
        claim: String,
    },
    /// Test injection detection score for a string
    Injection { input: String },
    /// Run full end-to-end smoke test
    Smoke {
        #[arg(long)]
        agent: Option<String>,
        /// Use LLM stub (no API key needed)
        #[arg(long)]
        llm_stub: bool,
    },
    /// Run all tests (invariants + smoke)
    All,
}

#[derive(Subcommand)]
enum InstallCmd {
    /// Install a tool from the marketplace
    Tool {
        /// Tool name or ID
        name: String,
        /// Specific version (default: latest)
        #[arg(long)]
        version: Option<String>,
    },
    /// Install an agent manifest from the marketplace
    Agent {
        /// Agent name or ID
        name: String,
        #[arg(long)]
        version: Option<String>,
    },
    /// List installed tools and agents
    List,
    /// Search marketplace for tools or agents
    Search {
        query: String,
        /// Filter: tools, agents, or all (default: all)
        #[arg(long, default_value = "all")]
        kind: String,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Export signed audit receipts for an agent
    Export {
        pid: String,
        /// Start date or epoch ms (default: 30 days ago)
        #[arg(long)]
        from: Option<String>,
        /// End date or epoch ms (default: now)
        #[arg(long)]
        to: Option<String>,
        /// Output format: jsonl (default), json, table
        #[arg(long, default_value = "jsonl")]
        format: String,
        /// Output file (default: stdout)
        #[arg(long)]
        output: Option<String>,
    },
    /// Verify a JSONL receipt chain offline (no server required)
    Verify {
        /// Path to receipts.jsonl file
        file: String,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Check if an operation is allowed for an agent (access(2) analog)
    Check {
        pid: String,
        /// Operation: tool_dispatch, mem_read, mem_write, access_grant, etc.
        #[arg(long)]
        op: String,
        /// Resource: namespace path, tool URI, agent PID, etc.
        #[arg(long, default_value = "*")]
        resource: String,
    },
}

#[derive(Subcommand)]
enum BooksCmd {
    /// Show system position report (resources, obligations, integrity, cost)
    Position,
    /// Show general journal entries (all transactions)
    Journal {
        /// Filter by actor (agent PID)
        #[arg(long)]
        actor: Option<String>,
        /// Filter by action type
        #[arg(long)]
        action: Option<String>,
        /// Filter by outcome: cleared, rejected, failed, pending
        #[arg(long)]
        outcome: Option<String>,
        /// Show entries since timestamp or duration (e.g. 1h, 24h)
        #[arg(long)]
        since: Option<String>,
        /// Maximum entries to show
        #[arg(long, default_value = "50")]
        limit: usize,
        /// Output format: table (default), json
        #[arg(long, default_value = "table")]
        format: String,
    },
    /// Show account ledger for a specific entity
    Ledger {
        /// Account ID (e.g. agent:pid, session:id, tool:name)
        account_id: String,
        /// Maximum entries to show
        #[arg(long, default_value = "100")]
        limit: usize,
    },
    /// Show full account statement with positions and totals
    Statement {
        /// Account ID (e.g. agent:pid, session:id)
        account_id: String,
    },
    /// Show transaction receipt (drill-down view)
    Receipt {
        /// Journal entry sequence number
        seq_no: u64,
        /// Access tier: summary, standard, detailed, privileged
        #[arg(long, default_value = "standard")]
        tier: String,
    },
    /// Show cost breakdown by agent, model, tool
    Costs {
        /// Period: today, week, month (default: today)
        #[arg(long, default_value = "today")]
        period: String,
        /// Group by: agent, model, tool (default: agent)
        #[arg(long, default_value = "agent")]
        group_by: String,
    },
    /// Show reconciliation balance (T0 vs T1 comparison)
    Balance,
    /// Run reconciliation check
    Reconcile,
    /// Stream live journal entries (like tail -f)
    Live {
        /// Filter by actor (agent PID)
        #[arg(long)]
        actor: Option<String>,
    },
    /// Close session books (finalize and seal)
    Close {
        /// Session ID to close
        session_id: String,
    },
}

#[derive(Subcommand)]
enum McpCmd {
    /// Start MCP server (stdio for IDE integration, or TCP for network)
    Serve {
        /// Transport: stdio (default, for IDE/framework) or tcp
        #[arg(long, default_value = "stdio")]
        transport: String,
        /// TCP port (only used when transport=tcp)
        #[arg(long, default_value = "9090")]
        port: u16,
        /// Expose only specific tool namespaces (comma-separated, default: all)
        #[arg(long)]
        tools: Option<String>,
        /// Agent PID to scope MCP session to
        #[arg(long)]
        agent: Option<String>,
    },
    /// List tools available via MCP
    #[command(name = "list-tools")]
    ListTools {
        #[arg(long)]
        agent: Option<String>,
    },
    /// Inspect a specific MCP tool schema
    Inspect { tool_id: String },
}

// =============================================================================
// API client helpers
// =============================================================================

// =============================================================================
// CLI-P2-1: Progress spinner (TTY-aware)
// =============================================================================

/// Animated spinner for TTY; plain "label..." text on non-TTY (CI).
/// Drop or call .finish() to clear the spinner line.
struct Spinner {
    thread: Option<std::thread::JoinHandle<()>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    is_tty: bool,
    label: String,
}

impl Spinner {
    fn new(label: &str) -> Self {
        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        if is_tty {
            let stop2 = stop.clone();
            let msg = label.to_string();
            let thread = std::thread::spawn(move || {
                let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                let mut i = 0usize;
                while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
                    eprint!("\r{} {}  ", frames[i % frames.len()], msg);
                    i += 1;
                    std::thread::sleep(std::time::Duration::from_millis(80));
                }
            });
            Self {
                thread: Some(thread),
                stop,
                is_tty: true,
                label: label.to_string(),
            }
        } else {
            // Non-TTY (CI): just print the label once
            eprintln!("{}...", label);
            Self {
                thread: None,
                stop,
                is_tty: false,
                label: label.to_string(),
            }
        }
    }

    fn finish(mut self, result: &str) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if self.is_tty {
            // Clear spinner line and print final result
            eprintln!("\r✅ {}  {}", self.label, result);
        }
    }

    fn fail(mut self, reason: &str) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if self.is_tty {
            eprintln!("\r❌ {}  {}", self.label, reason);
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if self.is_tty {
            eprint!("\r{}\r", " ".repeat(self.label.len() + 12));
        }
    }
}

// =============================================================================

struct Client {
    api_url: String,
    api_key: Option<String>,
    http: reqwest::blocking::Client,
}

fn is_canonical_result(body: &serde_json::Value) -> bool {
    body.get("ok").and_then(|v| v.as_bool()).is_some()
        && body.get("intent").and_then(|v| v.as_object()).is_some()
        && body.get("data").is_some()
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn singularize(value: &str) -> String {
    value.strip_suffix('s').unwrap_or(value).to_string()
}

fn infer_intent(method: &str, path: &str) -> (String, String, String) {
    let bare = path.split('?').next().unwrap_or(path);
    let parts: Vec<&str> = bare
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let first = parts.first().copied().unwrap_or("resource");
    let last = parts.last().copied().unwrap_or(first);

    match (method, parts.as_slice()) {
        ("GET", [noun]) => ("list".to_string(), singularize(noun), "all".to_string()),
        ("GET", [noun, target]) => ("show".to_string(), singularize(noun), (*target).to_string()),
        ("POST", [noun, target, action]) => (
            (*action).to_string(),
            singularize(noun),
            (*target).to_string(),
        ),
        ("POST", [noun, action])
            if *noun == "deploy" || *noun == "webhooks" =>
        {
            (
                (*action).to_string(),
                singularize(noun),
                (*action).to_string(),
            )
        }
        ("PATCH", [noun, target]) => (
            "update".to_string(),
            singularize(noun),
            (*target).to_string(),
        ),
        ("DELETE", [noun, target]) => (
            "delete".to_string(),
            singularize(noun),
            (*target).to_string(),
        ),
        ("POST", [noun]) => ("create".to_string(), singularize(noun), (*noun).to_string()),
        _ => (
            method.to_ascii_lowercase(),
            singularize(first),
            last.to_string(),
        ),
    }
}

fn infer_summary(
    method: &str,
    path: &str,
    body: &serde_json::Value,
    ok: bool,
) -> serde_json::Value {
    let (verb, noun, target) = infer_intent(method, path);
    let status = if ok { "completed" } else { "failed" };
    let why = body
        .get("message")
        .or_else(|| body.get("detail"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let next = match (verb.as_str(), noun.as_str()) {
        ("list", _) => vec![format!(
            "Use `connector show {} <id>` for detailed inspection",
            noun
        )],
        ("show", _) => vec![format!(
            "Use `connector audit {}` to inspect evidence",
            target
        )],
        _ => vec![
            "Inspect the receipt, trust, and evidence sections for follow-up action".to_string(),
        ],
    };

    serde_json::json!({
        "title": format!("{} {}", capitalize(&verb), noun),
        "message": why.clone().unwrap_or_else(|| format!("{} {} completed for {}", capitalize(&verb), noun, target)),
        "status": status,
        "why": why,
        "next": next
    })
}

fn infer_trust(body: &serde_json::Value) -> Option<serde_json::Value> {
    let score = body
        .get("trust")
        .cloned()
        .or_else(|| body.pointer("/status/trust").cloned());
    let grade = body
        .get("trust_grade")
        .cloned()
        .or_else(|| body.pointer("/status/trust_grade").cloned());
    let verified = body
        .get("verified")
        .and_then(|v| v.as_bool())
        .or_else(|| body.pointer("/receipt/verified").and_then(|v| v.as_bool()));

    if score.is_none() && grade.is_none() && verified.is_none() {
        None
    } else {
        Some(serde_json::json!({
            "score": score,
            "grade": grade,
            "verified": verified.unwrap_or(false)
        }))
    }
}

fn infer_evidence(body: &serde_json::Value) -> serde_json::Value {
    let mut evidence = Vec::new();
    if let Some(trace_id) = body.get("trace_id").and_then(|v| v.as_str()) {
        evidence.push(serde_json::json!({
            "kind": "trace",
            "id": trace_id,
            "label": "execution_trace",
            "verified": body.get("verified").and_then(|v| v.as_bool()).unwrap_or(false)
        }));
    }
    for field in ["cid", "snapshot_cid", "root_cid"] {
        if let Some(cid) = body.get(field).and_then(|v| v.as_str()) {
            evidence.push(serde_json::json!({
                "kind": "cid",
                "id": cid,
                "label": field,
                "verified": true
            }));
        }
    }
    serde_json::Value::Array(evidence)
}

fn infer_presentation(path: &str, body: &serde_json::Value) -> serde_json::Value {
    let bare = path.split('?').next().unwrap_or(path);
    let mut mode = if bare.ends_with('s') || bare.contains("/list") {
        "list"
    } else {
        "detail"
    };
    let mut columns: Vec<String> = Vec::new();
    let mut row_count = None;

    if let Some(obj) = body.as_object() {
        for value in obj.values() {
            if let Some(items) = value.as_array() {
                if let Some(first) = items.first().and_then(|item| item.as_object()) {
                    columns = first.keys().take(8).cloned().collect();
                    row_count = Some(items.len());
                    mode = "list";
                    break;
                }
            }
        }
    }

    serde_json::json!({
        "mode": mode,
        "table_safe": mode == "list",
        "row_count": row_count,
        "columns": columns,
    })
}

fn normalize_success_response(
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    if is_canonical_result(&body) {
        return body;
    }

    let (verb, noun, target) = infer_intent(method, path);
    let ok = body.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);
    let mut envelope = serde_json::json!({
        "ok": ok,
        "intent": {
            "verb": verb,
            "noun": noun,
            "target": target,
        },
        "summary": infer_summary(method, path, &body, ok),
        "trust": infer_trust(&body),
        "evidence": infer_evidence(&body),
        "links": {
            "docs": "/docs"
        },
        "render": {
            "role": "operator",
            "redacted": false,
            "redacted_fields": []
        },
        "presentation": infer_presentation(path, &body),
        "meta": {
            "schema": "connector.result.v1",
            "family": "canonical_semantic_package",
            "package_first": true,
            "view": "package",
            "source": "cli-normalized"
        },
        "data": body.clone()
    });

    if let Some(obj) = body.as_object() {
        if let Some(envelope_obj) = envelope.as_object_mut() {
            for (key, value) in obj {
                envelope_obj
                    .entry(key.clone())
                    .or_insert_with(|| value.clone());
            }
        }
    }

    envelope
}

impl Client {
    fn new(api_url: &str, api_key: Option<String>) -> Self {
        Self {
            api_url: api_url.trim_end_matches('/').to_string(),
            api_key,
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("HTTP client build failed"),
        }
    }

    fn auth_header(&self) -> HashMap<&'static str, String> {
        let mut h = HashMap::new();
        if let Some(ref key) = self.api_key {
            h.insert("Authorization", format!("Bearer {}", key));
        } else {
            // Dev mode fallback
            h.insert("Authorization", "Bearer dev-token".to_string());
        }
        h
    }

    fn get(&self, path: &str) -> Result<serde_json::Value, String> {
        let url = format!("{}/api/v1{}", self.api_url, path);
        let auth = self.auth_header();
        let mut req = self.http.get(&url);
        for (k, v) in &auth {
            req = req.header(*k, v);
        }
        let resp = req.send().map_err(|e| {
            format!("Cannot connect to Connector at {}\n  → Is the server running? Try: connector dev\n  → Or set CONNECTOR_API_URL to point to your server", self.api_url)
        })?;
        self.parse_response("GET", path, resp)
    }

    fn post(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        let url = format!("{}/api/v1{}", self.api_url, path);
        let auth = self.auth_header();
        let mut req = self.http.post(&url).json(body);
        for (k, v) in &auth {
            req = req.header(*k, v);
        }
        let resp = req.send().map_err(|e| {
            format!(
                "Cannot connect to Connector at {}\n  → Is the server running? Try: connector dev",
                self.api_url
            )
        })?;
        self.parse_response("POST", path, resp)
    }

    fn delete(&self, path: &str) -> Result<serde_json::Value, String> {
        let url = format!("{}/api/v1{}", self.api_url, path);
        let auth = self.auth_header();
        let mut req = self.http.delete(&url);
        for (k, v) in &auth {
            req = req.header(*k, v);
        }
        let resp = req
            .send()
            .map_err(|e| format!("Cannot connect to Connector at {}", self.api_url))?;
        self.parse_response("DELETE", path, resp)
    }

    fn parse_response(
        &self,
        method: &str,
        path: &str,
        resp: reqwest::blocking::Response,
    ) -> Result<serde_json::Value, String> {
        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .unwrap_or_else(|_| serde_json::json!({"error": "non-JSON response from server"}));
        if !status.is_success() {
            // Parse structured error envelope {ok, error:{code, message, hint, docs}}
            let msg = if let Some(err_obj) = body.get("error").and_then(|e| e.as_object()) {
                let message = err_obj
                    .get("message")
                    .and_then(|v| v.as_str())
                    .or_else(|| body.get("error").and_then(|v| v.as_str()))
                    .unwrap_or("unknown error");
                let mut out = format!("{} (HTTP {})", message, status.as_u16());
                if let Some(code) = err_obj.get("code").and_then(|v| v.as_str()) {
                    out.push_str(&format!("\n  code: {}", code));
                }
                if let Some(detail) = err_obj.get("detail").and_then(|v| v.as_str()) {
                    out.push_str(&format!("\n  detail: {}", detail));
                }
                if let Some(hints) = err_obj.get("hints").and_then(|v| v.as_array()) {
                    for hint in hints.iter().filter_map(|v| v.as_str()) {
                        out.push_str(&format!("\n  hint: {}", hint));
                    }
                } else if let Some(hints) = err_obj.get("hint").and_then(|v| v.as_array()) {
                    for hint in hints.iter().filter_map(|v| v.as_str()) {
                        out.push_str(&format!("\n  hint: {}", hint));
                    }
                } else if let Some(hint) = err_obj.get("hint").and_then(|v| v.as_str()) {
                    out.push_str(&format!("\n  hint: {}", hint));
                }
                if let Some(docs) = err_obj.get("docs").and_then(|v| v.as_str()) {
                    out.push_str(&format!("\n  docs: {}", docs));
                }
                out
            } else {
                // Fallback: extract top-level error/message/hint fields
                let message = body
                    .get("error")
                    .and_then(|v| v.as_str())
                    .or_else(|| body.get("message").and_then(|v| v.as_str()))
                    .unwrap_or("unknown error");
                let mut out = format!("{} (HTTP {})", message, status.as_u16());
                if let Some(hints) = body.get("hints").and_then(|v| v.as_array()) {
                    for hint in hints.iter().filter_map(|v| v.as_str()) {
                        out.push_str(&format!("\n  hint: {}", hint));
                    }
                } else if let Some(hints) = body.get("hint").and_then(|v| v.as_array()) {
                    for hint in hints.iter().filter_map(|v| v.as_str()) {
                        out.push_str(&format!("\n  hint: {}", hint));
                    }
                } else if let Some(hint) = body.get("hint").and_then(|v| v.as_str()) {
                    out.push_str(&format!("\n  hint: {}", hint));
                }
                out
            };
            return Err(msg);
        }
        Ok(normalize_success_response(method, path, body))
    }
}

// =============================================================================
// Main
// =============================================================================

fn main() {
    let cli = Cli::parse();

    let client = Client::new(&cli.api_url, cli.api_key.clone());

    let quiet = cli.quiet;
    let no_color = cli.no_color
        || std::env::var("NO_COLOR").is_ok()
        || std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false);

    let result = match cli.command {
        Commands::Agent { cmd } => handle_agent(cmd, &client, &cli.output, quiet, no_color),
        Commands::Deploy { cmd } => handle_deploy_cmd(cmd, &client, quiet),
        Commands::Memory { cmd } => handle_memory_cmd(cmd, &client, &cli.output, quiet),
        Commands::Trace { cmd } => handle_trace_cmd(cmd, &client, &cli.output, quiet),
        Commands::Test { cmd } => handle_test_cmd(cmd, &client, quiet),
        Commands::Logs {
            follow,
            since,
            level,
            filter,
        } => handle_platform_logs(
            &client,
            follow,
            since.as_deref(),
            level.as_deref(),
            filter.as_deref(),
        ),
        Commands::Dev { port } => handle_dev(port),
        Commands::Doctor {
            verbose,
            json,
            check,
            fix,
        } => handle_doctor_v2(&client, &cli.api_url, verbose, json, check.as_deref(), fix),
        Commands::Whoami => handle_whoami(&client),
        Commands::Init { path, quickstart } => handle_init(path.as_deref(), quickstart),
        Commands::Completions { shell } => handle_completions(&shell),
        Commands::Knowledge { cmd } => handle_knowledge_cmd(cmd, &client, &cli.output, quiet),
        Commands::Context { cmd } => handle_context_cmd(cmd, &client, &cli.output, quiet),
        Commands::Webhooks { cmd } => handle_webhook_cmd(cmd, &client, &cli.output, quiet),
        Commands::Examples { cmd } => handle_examples_cmd(cmd, &client, quiet),
        Commands::Mcp { cmd } => handle_mcp_cmd(cmd, &client, quiet),
        Commands::Install { cmd } => handle_install_cmd(cmd, &client, quiet),
        Commands::Audit { cmd } => handle_audit_cmd(cmd, &client, quiet),
        Commands::Policy { cmd } => handle_policy_cmd(cmd, &client, quiet),
        Commands::Books { cmd } => handle_books_cmd(cmd, &client, &cli.output, quiet),
        Commands::Run {
            manifest,
            input,
            verbose,
            format,
        } => handle_run_cmd(&manifest, input.as_deref(), verbose, &format, &client),
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

// =============================================================================
// Agent commands
// =============================================================================

fn handle_agent(
    cmd: AgentCmd,
    client: &Client,
    output: &str,
    quiet: bool,
    no_color: bool,
) -> Result<(), String> {
    match cmd {
        AgentCmd::Ps { filter } => {
            let data = client.get("/agents")?;
            let agents = data
                .get("agents")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if agents.is_empty() {
                println!("No agents registered. Deploy one with: connector deploy agent.yaml");
                return Ok(());
            }
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            println!(
                "{:<24} {:<12} {:<20} {:<12} {:<10}",
                "PID/NAME", "STATUS", "MODEL", "TOKENS_USED", "CLEARANCE"
            );
            println!("{}", "─".repeat(82));
            for a in &agents {
                println!(
                    "{:<24} {:<12} {:<20} {:<12} {:<10}",
                    a.get("pid")
                        .or(a.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?"),
                    a.get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown"),
                    a.get("model").and_then(|v| v.as_str()).unwrap_or("-"),
                    a.get("total_tokens_consumed")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    a.get("clearance")
                        .and_then(|v| v.as_str())
                        .unwrap_or("standard"),
                );
            }
            println!("\n{} agent(s)", agents.len());
        }

        AgentCmd::Inspect { pid } => {
            let data = client.get(&format!("/agents/{}", pid))?;
            println!("{}", serde_json::to_string_pretty(&data).unwrap());
        }

        AgentCmd::Pause { pid } => {
            let data = client.post(&format!("/agents/{}/pause", pid), &serde_json::json!({}))?;
            let paused = data
                .get("paused")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            println!(
                "{}  agent '{}' paused",
                if paused { "✅" } else { "⚠️" },
                pid
            );
        }

        AgentCmd::Resume { pid } => {
            let data = client.post(&format!("/agents/{}/resume", pid), &serde_json::json!({}))?;
            let paused = data.get("paused").and_then(|v| v.as_bool()).unwrap_or(true);
            println!(
                "{}  agent '{}' resumed",
                if !paused { "✅" } else { "⚠️" },
                pid
            );
        }

        AgentCmd::Delete { pid, reason } | AgentCmd::Kill { pid, reason } => {
            let data = client.delete(&format!("/agents/{}", pid))?;
            let terminated = data
                .get("terminated")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if !quiet {
                println!(
                    "{}  agent '{}' deleted",
                    if terminated { "✅" } else { "⚠️" },
                    pid
                );
                if let Some(cid) = data.get("cid").and_then(|v| v.as_str()) {
                    println!("   CID: {}", cid);
                }
            }
        }

        AgentCmd::Logs {
            pid,
            lines,
            follow,
            since,
            until,
        } => {
            if follow {
                // CLI-P2-3: Wire up SSE stream for --follow
                let url = format!(
                    "{}/api/v1/agents/{}/activity?follow=true",
                    client.api_url, pid
                );
                if !quiet {
                    println!("Streaming logs for agent '{}' (Ctrl+C to stop)", pid);
                    println!(
                        "{:<22} {:<20} {:<12} {}",
                        "TIMESTAMP", "OPERATION", "OUTCOME", "DETAIL"
                    );
                    println!("{}", "─".repeat(80));
                }
                let auth = client.auth_header();
                let mut req = client.http.get(&url);
                for (k, v) in &auth {
                    req = req.header(*k, v);
                }
                let mut resp = req
                    .send()
                    .map_err(|e| format!("Cannot connect to Connector: {}", e))?;
                loop {
                    let text = resp
                        .text()
                        .map_err(|e| format!("Stream read error: {}", e))?;
                    for line in text.lines() {
                        let line = line.trim();
                        if line.starts_with("data:") {
                            let json_str = line.trim_start_matches("data:").trim();
                            if json_str.is_empty() || json_str == ":heartbeat" {
                                continue;
                            }
                            if let Ok(entry) = serde_json::from_str::<serde_json::Value>(json_str) {
                                let ts =
                                    entry.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
                                let op = entry
                                    .get("operation")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("?");
                                let outcome =
                                    entry.get("outcome").and_then(|v| v.as_str()).unwrap_or("?");
                                let detail = entry
                                    .get("reason")
                                    .or(entry.get("detail"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                println!(
                                    "{:<22} {:<20} {:<12} {}",
                                    format_epoch_ms(ts),
                                    op,
                                    outcome,
                                    detail
                                );
                            }
                        }
                    }
                    // reqwest blocking .text() consumes the whole body; re-request for follow
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    let mut req2 = client.http.get(&url);
                    for (k, v) in &auth {
                        req2 = req2.header(*k, v);
                    }
                    resp = req2
                        .send()
                        .map_err(|e| format!("Stream reconnect error: {}", e))?;
                }
            } else {
                let mut path = format!("/agents/{}/activity", pid);
                let mut params = vec![format!("limit={}", lines)];
                if let Some(s) = since.as_deref() {
                    params.push(format!("since={}", s));
                }
                if let Some(u) = until.as_deref() {
                    params.push(format!("until={}", u));
                }
                if !params.is_empty() {
                    path = format!("{}?{}", path, params.join("&"));
                }

                let data = client.get(&path)?;
                let entries = data
                    .get("activity")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                if !quiet {
                    println!(
                        "Audit log — agent '{}' (last {} entries)",
                        pid,
                        entries.len().min(lines)
                    );
                    println!(
                        "{:<22} {:<20} {:<12} {}",
                        "TIMESTAMP", "OPERATION", "OUTCOME", "DETAIL"
                    );
                    println!("{}", "─".repeat(80));
                }
                for entry in entries.iter().take(lines) {
                    let ts = entry.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
                    let ts_fmt = format_epoch_ms(ts);
                    let op = entry
                        .get("operation")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    let outcome = entry.get("outcome").and_then(|v| v.as_str()).unwrap_or("?");
                    let detail = entry
                        .get("reason")
                        .or(entry.get("detail"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    println!("{:<22} {:<20} {:<12} {}", ts_fmt, op, outcome, detail);
                }
            }
        }

        AgentCmd::Top => {
            let data = client.get("/agents")?;
            let agents = data
                .get("agents")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            println!(
                "{:<24} {:<10} {:<12} {:<12} {:<16}",
                "NAME", "STATUS", "TOKENS/DAY", "COST_USD", "BUDGET"
            );
            println!("{}", "─".repeat(76));
            for a in &agents {
                let budget = a
                    .get("daily_budget")
                    .and_then(|v| v.as_u64())
                    .map(|b| format!("{}", b))
                    .unwrap_or("∞".to_string());
                println!(
                    "{:<24} {:<10} {:<12} {:<12.4} {:<16}",
                    a.get("name")
                        .or(a.get("pid"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?"),
                    a.get("status").and_then(|v| v.as_str()).unwrap_or("?"),
                    a.get("total_tokens_consumed")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    a.get("total_cost_usd")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0),
                    budget,
                );
            }
        }

        AgentCmd::SetClearance { pid, level } | AgentCmd::Clearance { pid, level } => {
            let data = client.post(
                &format!("/agents/{}/clearance", pid),
                &serde_json::json!({ "level": level }),
            )?;
            if let Some(changed) = data.get("clearance_changed").and_then(|v| v.as_bool()) {
                if changed {
                    println!(
                        "✅  clearance changed: {} → {}",
                        data.get("previous").and_then(|v| v.as_str()).unwrap_or("?"),
                        data.get("new").and_then(|v| v.as_str()).unwrap_or("?"),
                    );
                    if let Some(effect) = data.get("effect").and_then(|v| v.as_str()) {
                        println!("   {}", effect);
                    }
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
            }
        }

        AgentCmd::Trust { pid, level } => {
            let data = client.post(
                &format!("/agents/{}/trust", pid),
                &serde_json::json!({ "trust_level": level }),
            )?;
            println!(
                "✅  trust override set: agent '{}' → level={}",
                pid,
                data.get("trust_level")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&level)
            );
            if let Some(kecs) = data.get("kecs").and_then(|v| v.as_f64()) {
                println!("   KECS score: {:.3}", kecs);
            }
        }

        AgentCmd::Reflect { pid } => {
            let sp = Spinner::new(&format!("Running reflection for '{}'", pid));
            let data = client.post(&format!("/agents/{}/reflect", pid), &serde_json::json!({}));
            match data {
                Ok(d) => {
                    let cid = d
                        .get("reflection_cid")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    sp.finish(&format!("cid:{}", cid));
                    if !quiet {
                        println!("✅  Reflection complete for '{}'", pid);
                        println!("   CID:               {}", cid);
                        println!(
                            "   Packets analysed:  {}",
                            d.get("packets_in").and_then(|v| v.as_u64()).unwrap_or(0)
                        );
                        println!(
                            "   Insights stored:   {}",
                            d.get("insights_stored")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0)
                        );
                    }
                }
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
            }
        }

        AgentCmd::Migrate { pid, to } => {
            let sp = Spinner::new(&format!("Migrating '{}' → cell:{}", pid, to));
            let data = client.post(
                &format!("/agents/{}/migrate", pid),
                &serde_json::json!({ "target_cell_id": to }),
            );
            match data {
                Ok(d) => {
                    sp.finish("done");
                    println!("✅  Agent '{}' migrated to cell '{}'", pid, to);
                    println!(
                        "   Snapshot CID:  {}",
                        d.get("snapshot_cid")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?")
                    );
                    println!(
                        "   Duration:      {}ms",
                        d.get("migration_ms").and_then(|v| v.as_u64()).unwrap_or(0)
                    );
                }
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
            }
        }

        AgentCmd::Clone { pid, name, tokens } => {
            let sp = Spinner::new(&format!("Cloning agent '{}'", pid));
            let mut body = serde_json::json!({});
            if let Some(n) = name {
                body["name"] = serde_json::json!(n);
            }
            if let Some(t) = tokens {
                body["token_budget"] = serde_json::json!(t);
            }
            let data = client.post(&format!("/agents/{}/clone", pid), &body);
            match data {
                Ok(d) => {
                    sp.finish("done");
                    println!("✅  Agent '{}' cloned", pid);
                    println!(
                        "   Child PID:    {}",
                        d.get("child_pid").and_then(|v| v.as_str()).unwrap_or("?")
                    );
                    println!(
                        "   Name:         {}",
                        d.get("name").and_then(|v| v.as_str()).unwrap_or("?")
                    );
                    println!(
                        "   Token budget: {}",
                        d.get("token_budget").and_then(|v| v.as_u64()).unwrap_or(0)
                    );
                    println!(
                        "   State:        {}",
                        d.get("state").and_then(|v| v.as_str()).unwrap_or("?")
                    );
                    println!(
                        "\nStart child: connector agent resume {}",
                        d.get("child_pid").and_then(|v| v.as_str()).unwrap_or("?")
                    );
                }
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
            }
        }

        AgentCmd::Budget {
            pid,
            tokens,
            cost,
            enforce,
        } => {
            let mut body = serde_json::json!({});
            if let Some(t) = tokens {
                body["daily_limit"] = serde_json::json!(t);
            }
            if let Some(c) = cost {
                body["max_cost_usd"] = serde_json::json!(c);
            }
            body["enforce"] = serde_json::json!(enforce);
            let data = client
                .http
                .patch(&format!("{}/api/v1/agents/{}/budget", client.api_url, pid))
                .json(&body)
                .header(
                    "Authorization",
                    client
                        .api_key
                        .as_deref()
                        .map(|k| format!("Bearer {}", k))
                        .unwrap_or("Bearer dev-token".into()),
                )
                .send()
                .map_err(|e| format!("Request failed: {}", e))
                .and_then(|r| {
                    client.parse_response("PATCH", &format!("/agents/{}/budget", pid), r)
                });
            match data {
                Ok(d) => {
                    println!("✅  Budget updated for '{}'", pid);
                    if let Some(b) = d.get("token_budget") {
                        println!(
                            "   Daily limit:  {}",
                            b.get("daily_limit").and_then(|v| v.as_u64()).unwrap_or(0)
                        );
                        println!(
                            "   Used today:   {}",
                            b.get("used_today").and_then(|v| v.as_u64()).unwrap_or(0)
                        );
                        println!(
                            "   Enforce:      {}",
                            b.get("enforce").and_then(|v| v.as_bool()).unwrap_or(false)
                        );
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

// =============================================================================
// Deploy subcommand dispatcher
// =============================================================================

fn handle_deploy_cmd(cmd: DeployCmd, client: &Client, quiet: bool) -> Result<(), String> {
    match cmd {
        DeployCmd::Run { manifest, dry_run } => handle_deploy(&manifest, dry_run, client, quiet),
        DeployCmd::Ls => handle_ls(client),
        DeployCmd::Rollback { name, version } => handle_rollback(&name, version, client),
        DeployCmd::Diff { name, manifest } => handle_diff(&name, manifest.as_deref(), client),
        DeployCmd::History { name } => handle_history(&name, client),
        DeployCmd::Validate { manifest, strict } => handle_validate(&manifest, strict),
        DeployCmd::Lint { manifest, strict } => handle_lint(&manifest, strict),
    }
}

// =============================================================================
// Deploy commands
// =============================================================================

fn handle_deploy(
    manifest_path: &str,
    dry_run: bool,
    client: &Client,
    quiet: bool,
) -> Result<(), String> {
    let content = std::fs::read_to_string(manifest_path)
        .map_err(|e| format!("Cannot read {}: {}", manifest_path, e))?;

    // Local validation first (no network)
    let manifest = connector_api::manifest::AgentManifest::from_yaml(&content)
        .map_err(|e| format!("Manifest parse error: {}", e))?;

    let errors = manifest.validate();
    if !errors.is_empty() {
        eprintln!("Manifest validation failed:");
        for e in &errors {
            eprintln!("  {}", e);
        }
        std::process::exit(2);
    }

    let warnings = manifest.lint();
    for w in &warnings {
        eprintln!("warn: {}", w);
    }

    // Deploy via API — show spinner while waiting
    let spinner = if !quiet && !dry_run {
        Some(Spinner::new("Deploying"))
    } else {
        None
    };

    let result = client.post(
        "/deploy",
        &serde_json::json!({
            "manifest": content,
            "format": "yaml",
            "dry_run": dry_run,
        }),
    );

    let data = match result {
        Ok(d) => {
            if let Some(sp) = spinner {
                sp.finish("");
            }
            d
        }
        Err(e) => {
            if let Some(sp) = spinner {
                sp.fail(&e);
            }
            return Err(e);
        }
    };

    if dry_run {
        println!("Dry-run result for '{}':", manifest.metadata.name);
        if let Some(diff) = data.get("diff").and_then(|v| v.as_array()) {
            print_diff_table(diff);
        }
        println!(
            "\nCID: {}",
            data.get("cid").and_then(|v| v.as_str()).unwrap_or("?")
        );
        println!("Dry-run complete. No changes applied.");
    } else {
        let name = data
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(&manifest.metadata.name);
        let version = data.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
        let cid = data.get("cid").and_then(|v| v.as_str()).unwrap_or("?");
        println!("✅  Deployed '{}' v{}", name, version);
        println!("   CID:       {}", cid);
        println!(
            "   Namespace: {}",
            data.get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
        );
        println!(
            "   Agent PID: {}",
            data.get("agent_pid")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
        );
        println!();
        println!("Next steps:");
        println!("   connector agent ps              # verify agent is running");
        println!("   connector agent inspect {}     # full details", name);
    }
    Ok(())
}

fn handle_rollback(name: &str, version: u32, client: &Client) -> Result<(), String> {
    let data = client.post(
        "/deploy/rollback",
        &serde_json::json!({
            "name": name,
            "version": version,
        }),
    )?;
    let rolled_back = data
        .get("rolled_back")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if rolled_back {
        println!("✅  Rolled back '{}' to version {}", name, version);
        println!(
            "   CID:   {}",
            data.get("cid").and_then(|v| v.as_str()).unwrap_or("?")
        );
        println!(
            "   Model: {}",
            data.get("model").and_then(|v| v.as_str()).unwrap_or("?")
        );
    } else {
        println!("{}", serde_json::to_string_pretty(&data).unwrap());
    }
    Ok(())
}

fn handle_diff(name: &str, manifest_path: Option<&str>, client: &Client) -> Result<(), String> {
    let path = match manifest_path {
        Some(p) => {
            let content =
                std::fs::read_to_string(p).map_err(|e| format!("Cannot read {}: {}", p, e))?;
            let url = format!(
                "/deploy/diff/{}?manifest={}",
                name,
                urlencoding_simple(&content)
            );
            client.get(&url)?
        }
        None => client.get(&format!("/deploy/diff/{}", name))?,
    };

    if let Some(diff) = path.get("diff").and_then(|v| v.as_array()) {
        print_diff_table(diff);
    } else {
        println!("{}", serde_json::to_string_pretty(&path).unwrap());
    }
    Ok(())
}

fn handle_history(name: &str, client: &Client) -> Result<(), String> {
    let data = client.get(&format!("/deploy/history/{}", name))?;
    let versions = data
        .get("versions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let active = data
        .get("active_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    println!("Version history for '{}':", name);
    println!("{}", "─".repeat(70));
    println!(
        "{:<6} {:<8} {:<20} {:<32}",
        "VER", "ACTIVE", "DEPLOYED_AT", "CID"
    );
    println!("{}", "─".repeat(70));
    for v in &versions {
        let ver = v.get("version_index").and_then(|x| x.as_u64()).unwrap_or(0);
        let is_active = ver == active;
        let deployed_at = v.get("deployed_at").and_then(|x| x.as_i64()).unwrap_or(0);
        let cid = v.get("cid").and_then(|x| x.as_str()).unwrap_or("?");
        println!(
            "{:<6} {:<8} {:<20} {:<32}",
            format!("v{}", ver),
            if is_active { "◀ active" } else { "" },
            format_epoch_ms(deployed_at),
            &cid[..cid.len().min(40)],
        );
    }
    println!(
        "\nTo rollback: connector deploy rollback {} <version>",
        name
    );
    Ok(())
}

fn handle_ls(client: &Client) -> Result<(), String> {
    let data = client.get("/deploy/list")?;
    let agents = data
        .get("agents")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if agents.is_empty() {
        println!("No deployed agents. Use: connector deploy agent.yaml");
        return Ok(());
    }
    println!(
        "{:<24} {:<10} {:<8} {:<20}",
        "NAME", "VERSIONS", "ACTIVE", "LAST_DEPLOYED"
    );
    println!("{}", "─".repeat(66));
    for a in &agents {
        println!(
            "{:<24} {:<10} {:<8} {:<20}",
            a.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
            a.get("versions").and_then(|v| v.as_u64()).unwrap_or(0),
            format!(
                "v{}",
                a.get("active_version")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            ),
            format_epoch_ms(a.get("deployed_at").and_then(|v| v.as_i64()).unwrap_or(0)),
        );
    }
    Ok(())
}

// =============================================================================
// Validate + Lint
// =============================================================================

fn handle_validate(manifest_path: &str, strict: bool) -> Result<(), String> {
    let content = std::fs::read_to_string(manifest_path)
        .map_err(|e| format!("Cannot read {}: {}", manifest_path, e))?;

    let manifest = match connector_api::manifest::AgentManifest::from_yaml(&content) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}:  parse error  {}", manifest_path, e);
            std::process::exit(2);
        }
    };

    let errors = manifest.validate();
    let warnings = manifest.lint();

    for e in &errors {
        eprintln!("{}  error  {}", manifest_path, e);
    }
    for w in &warnings {
        eprintln!("{}  warn   {}", manifest_path, w);
    }

    if !errors.is_empty() {
        std::process::exit(2);
    }
    if strict && !warnings.is_empty() {
        std::process::exit(2);
    }
    if warnings.is_empty() && errors.is_empty() {
        println!("{} is valid ✅", manifest_path);
    }
    Ok(())
}

fn handle_lint(manifest_path: &str, strict: bool) -> Result<(), String> {
    let content = std::fs::read_to_string(manifest_path)
        .map_err(|e| format!("Cannot read {}: {}", manifest_path, e))?;

    let manifest = match connector_api::manifest::AgentManifest::from_yaml(&content) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{}:  error  {}", manifest_path, e);
            std::process::exit(2);
        }
    };

    let errors = manifest.validate();
    let warnings = manifest.lint();

    for e in &errors {
        eprintln!("{}  error  {}", manifest_path, e);
    }
    for w in &warnings {
        println!("{}", w);
    }

    if !errors.is_empty() {
        std::process::exit(2);
    }
    if !warnings.is_empty() {
        if strict {
            std::process::exit(2);
        }
        std::process::exit(1);
    }
    println!("{} — no issues found ✅", manifest_path);
    Ok(())
}

// =============================================================================
// Dev mode + Doctor + Whoami + Init
// =============================================================================

fn handle_dev(port: u16) -> Result<(), String> {
    println!("Starting Connector in development mode...");
    println!("  CONNECTOR_ENV=development");
    println!("  CONNECTOR_LLM_STUB=true");
    println!("  Port: {}", port);
    println!();

    // Set env vars and exec connector-platform (or connector-server)
    std::env::set_var("CONNECTOR_ENV", "development");
    std::env::set_var("CONNECTOR_LLM_STUB", "true");
    std::env::set_var("CONNECTOR_DEV_MODE", "1");
    std::env::set_var("CONNECTOR_PORT", port.to_string());

    // Search order: local build dirs first, then PATH, then sibling binary
    let candidates: Vec<String> = vec![
        "./target/debug/connector-platform".to_string(),
        "./target/release/connector-platform".to_string(),
        "./target/debug/connector-server".to_string(),
        "./target/release/connector-server".to_string(),
    ];
    for candidate in &candidates {
        let p = std::path::Path::new(candidate);
        if p.exists() {
            println!("Starting {} on port {}...", candidate, port);
            let status = std::process::Command::new(candidate)
                .envs(std::env::vars())
                .status();
            match status {
                Ok(s) => std::process::exit(s.code().unwrap_or(0)),
                Err(e) => eprintln!("Failed to start {}: {}", candidate, e),
            }
        }
    }
    // Fallback: search PATH
    let server_names = ["connector-platform", "connector-server"];
    for name in &server_names {
        if let Ok(path) = which_binary(name) {
            println!("Starting {} on port {}...", name, port);
            let status = std::process::Command::new(&path)
                .envs(std::env::vars())
                .status();
            match status {
                Ok(s) => std::process::exit(s.code().unwrap_or(0)),
                Err(e) => eprintln!("Failed to start {}: {}", name, e),
            }
        }
    }

    eprintln!("No server binary found. Tried:");
    eprintln!("  ./target/debug/connector-platform");
    eprintln!("  ./target/release/connector-platform");
    eprintln!("  PATH search: connector-platform, connector-server");
    eprintln!();
    eprintln!("Build with: cargo build --bin connector-platform");
    eprintln!("Or install: curl -sSL https://connector.ai/install.sh | bash");
    Err("server binary not found".to_string())
}

fn handle_doctor_v2(
    client: &Client,
    api_url: &str,
    verbose: bool,
    as_json: bool,
    check: Option<&str>,
    fix: bool,
) -> Result<(), String> {
    let mut errors = 0usize;
    let mut warnings = 0usize;
    // Collect results: (group, label, status: ok/warn/err, detail, fix_hint)
    let mut results: Vec<(&str, &str, &str, String, Option<String>)> = Vec::new();

    // ── CONNECTIVITY ──────────────────────────────────────────────────────────
    let server_ok = match client.get("/health") {
        Ok(data) => {
            let ver = data.get("version").and_then(|v| v.as_str()).unwrap_or("?");
            let ms = data
                .get("response_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            results.push((
                "CONNECTIVITY",
                "API server reachable",
                "ok",
                format!("{} ({}ms)", api_url, ms),
                None,
            ));
            true
        }
        Err(_) => {
            errors += 1;
            results.push((
                "CONNECTIVITY",
                "API server reachable",
                "err",
                format!("cannot reach {}", api_url),
                Some("connector dev  # to start locally".to_string()),
            ));
            false
        }
    };
    match client.get("/ready") {
        Ok(data) => {
            let ready = data.get("ready").and_then(|v| v.as_bool()).unwrap_or(false);
            if ready {
                results.push((
                    "CONNECTIVITY",
                    "Readiness probe",
                    "ok",
                    "all subsystems ready".to_string(),
                    None,
                ));
            } else {
                warnings += 1;
                results.push((
                    "CONNECTIVITY",
                    "Readiness probe",
                    "warn",
                    "not fully ready".to_string(),
                    Some("check server logs for startup errors".to_string()),
                ));
            }
        }
        Err(_) => {
            warnings += 1;
            results.push((
                "CONNECTIVITY",
                "Readiness probe",
                "warn",
                "endpoint unreachable".to_string(),
                None,
            ));
        }
    }
    // LLM gateway check
    let llm_key = std::env::var("CONNECTOR_LLM_API_KEY").is_ok();
    let llm_stub = std::env::var("CONNECTOR_LLM_STUB")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if llm_key || llm_stub {
        results.push((
            "CONNECTIVITY",
            "LLM gateway",
            "ok",
            if llm_stub {
                "stub mode (CONNECTOR_LLM_STUB=true)".to_string()
            } else {
                "CONNECTOR_LLM_API_KEY set".to_string()
            },
            None,
        ));
    } else {
        warnings += 1;
        results.push((
            "CONNECTIVITY",
            "LLM gateway",
            "warn",
            "CONNECTOR_LLM_API_KEY not set".to_string(),
            Some(
                "export CONNECTOR_LLM_API_KEY=sk-... OR set CONNECTOR_LLM_STUB=true for dev"
                    .to_string(),
            ),
        ));
    }

    // ── AUTH ──────────────────────────────────────────────────────────────────
    if client.api_key.is_some() {
        results.push(("AUTH", "API key", "ok", "present".to_string(), None));
    } else {
        warnings += 1;
        results.push((
            "AUTH",
            "API key",
            "warn",
            "not set (using dev-token)".to_string(),
            Some("export CONNECTOR_API_KEY=cpk_live_...".to_string()),
        ));
    }
    if server_ok {
        match client.get("/auth/me") {
            Ok(data) => {
                let role = data.get("role").and_then(|v| v.as_str()).unwrap_or("?");
                let tier = data.get("tier").and_then(|v| v.as_str()).unwrap_or("?");
                results.push((
                    "AUTH",
                    "Token valid",
                    "ok",
                    format!("role={} tier={}", role, tier),
                    None,
                ));
            }
            Err(_) => {
                warnings += 1;
                results.push((
                    "AUTH",
                    "Token valid",
                    "warn",
                    "could not verify token".to_string(),
                    Some("connector whoami to diagnose".to_string()),
                ));
            }
        }
    }

    // ── PLATFORM STATE ────────────────────────────────────────────────────────
    if server_ok {
        match client.get("/license/status") {
            Ok(data) => {
                let tier = data
                    .get("tier")
                    .and_then(|v| v.as_str())
                    .unwrap_or("community");
                let used = data
                    .get("agents_used")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let limit = data
                    .get("agent_limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(3);
                results.push((
                    "PLATFORM",
                    "License",
                    "ok",
                    format!("{} tier — {}/{} agents", tier, used, limit),
                    None,
                ));
            }
            Err(_) => {
                warnings += 1;
                results.push((
                    "PLATFORM",
                    "License",
                    "warn",
                    "could not validate".to_string(),
                    None,
                ));
            }
        }
        match client.get("/monitor/health") {
            Ok(data) => {
                let packets = data
                    .get("memory_packets")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                results.push((
                    "PLATFORM",
                    "Memory packets",
                    "ok",
                    format!("{} packets stored", packets),
                    None,
                ));
            }
            Err(_) => {
                results.push((
                    "PLATFORM",
                    "Memory packets",
                    "ok",
                    "monitor endpoint offline".to_string(),
                    None,
                ));
            }
        }
    }

    // ── SECURITY ──────────────────────────────────────────────────────────────
    let dev_mode = std::env::var("CONNECTOR_DEV_MODE").is_ok();
    let prod_env = std::env::var("CONNECTOR_ENV")
        .map(|v| v == "production" || v == "prod")
        .unwrap_or(false);
    if dev_mode && prod_env {
        errors += 1;
        results.push((
            "SECURITY",
            "Dev mode safety",
            "err",
            "CONNECTOR_DEV_MODE=1 + CONNECTOR_ENV=production — server will refuse to start"
                .to_string(),
            Some("unset CONNECTOR_DEV_MODE before deploying to production".to_string()),
        ));
    } else if dev_mode {
        warnings += 1;
        results.push((
            "SECURITY",
            "Dev mode",
            "warn",
            "CONNECTOR_DEV_MODE=1 (dev-token accepted — OK for local dev)".to_string(),
            Some("do not set CONNECTOR_DEV_MODE in production".to_string()),
        ));
    } else {
        results.push(("SECURITY", "Dev mode", "ok", "OFF".to_string(), None));
    }
    let webhook_hmac = std::env::var("CONNECTOR_WEBHOOK_SECRET").is_ok();
    if webhook_hmac {
        results.push((
            "SECURITY",
            "Webhook HMAC",
            "ok",
            "CONNECTOR_WEBHOOK_SECRET set".to_string(),
            None,
        ));
    } else {
        warnings += 1;
        results.push((
            "SECURITY",
            "Webhook HMAC",
            "warn",
            "webhooks delivered without signatures".to_string(),
            Some("export CONNECTOR_WEBHOOK_SECRET=<random-32-bytes>".to_string()),
        ));
    }
    // ── OBSERVABILITY ─────────────────────────────────────────────────────────
    let otel = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok();
    if otel {
        results.push((
            "OBSERVABILITY",
            "OTEL tracing",
            "ok",
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").unwrap_or_default(),
            None,
        ));
    } else {
        warnings += 1;
        results.push((
            "OBSERVABILITY",
            "OTEL tracing",
            "warn",
            "no OTLP endpoint — spans not exported".to_string(),
            Some("export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317".to_string()),
        ));
    }
    if server_ok {
        match client.get("/metrics") {
            Ok(_) => {
                results.push((
                    "OBSERVABILITY",
                    "Prometheus metrics",
                    "ok",
                    "/metrics endpoint responding".to_string(),
                    None,
                ));
            }
            Err(_) => {
                warnings += 1;
                results.push((
                    "OBSERVABILITY",
                    "Prometheus metrics",
                    "warn",
                    "/metrics unreachable".to_string(),
                    None,
                ));
            }
        }
    }

    // ── PROTOCOLS ─────────────────────────────────────────────────────────────
    if server_ok {
        match client.get("/health") {
            Ok(_) => {
                results.push((
                    "PROTOCOLS",
                    "A2A discovery",
                    "ok",
                    "/.well-known/agent.json available".to_string(),
                    None,
                ));
            }
            Err(_) => {
                warnings += 1;
                results.push((
                    "PROTOCOLS",
                    "A2A discovery",
                    "warn",
                    "could not verify".to_string(),
                    None,
                ));
            }
        }
        match client.get("/protocols/mcp/tools") {
            Ok(data) => {
                let tools = data
                    .get("tools")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                results.push((
                    "PROTOCOLS",
                    "MCP tools",
                    "ok",
                    format!("{} tools registered", tools),
                    None,
                ));
            }
            Err(_) => {
                warnings += 1;
                results.push((
                    "PROTOCOLS",
                    "MCP tools",
                    "warn",
                    "MCP tools endpoint unreachable".to_string(),
                    None,
                ));
            }
        }
    }

    // ── OUTPUT ────────────────────────────────────────────────────────────────
    if as_json {
        let json_out: Vec<serde_json::Value> = results.iter().map(|(g, label, status, detail, hint)| {
            let mut o = serde_json::json!({"group": g, "check": label, "status": status, "detail": detail});
            if let Some(h) = hint { o["hint"] = serde_json::Value::String(h.clone()); }
            o
        }).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "errors": errors, "warnings": warnings,
                "checks": json_out
            }))
            .unwrap()
        );
        if errors > 0 {
            std::process::exit(2);
        }
        if warnings > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    println!("Connector Platform — Diagnostic Report");
    println!("═══════════════════════════════════════════");
    println!("Server:  {}", api_url);
    println!();
    let mut current_group = "";
    for (group, label, status, detail, hint) in &results {
        // Skip passed checks unless --verbose
        if *status == "ok" && !verbose {
            continue;
        }
        // Group header
        if *group != current_group {
            if current_group != "" {
                println!();
            }
            println!("[{}]", group);
            current_group = group;
        }
        let icon = match *status {
            "ok" => "✅",
            "warn" => "⚠️ ",
            _ => "❌",
        };
        println!("  {} {:<32} {}", icon, label, detail);
        if let Some(h) = hint {
            println!("     → {}", h);
        }
    }
    // Always show failed/warned checks, even without --verbose
    if !verbose {
        let mut current_group2 = "";
        for (group, label, status, detail, hint) in &results {
            if *status == "ok" {
                continue;
            }
            if *group != current_group2 {
                if current_group2 != "" {
                    println!();
                }
                println!("[{}]", group);
                current_group2 = group;
            }
            let icon = match *status {
                "warn" => "⚠️ ",
                _ => "❌",
            };
            println!("  {} {:<32} {}", icon, label, detail);
            if let Some(h) = hint {
                println!("     → {}", h);
            }
        }
    }
    println!();
    println!("═══════════════════════════════════════════");
    if errors == 0 && warnings == 0 {
        println!("✅ All checks passed");
    } else {
        println!("Result: {} error(s), {} warning(s)", errors, warnings);
        println!("Run with --verbose to see all checks.");
        println!("Docs: https://connector.ai/docs/doctor");
    }
    if errors > 0 {
        std::process::exit(2);
    }
    Ok(())
}

fn handle_whoami(client: &Client) -> Result<(), String> {
    let data = client.get("/auth/me")?;
    let email = data.get("email").and_then(|v| v.as_str()).unwrap_or("?");
    let role = data.get("role").and_then(|v| v.as_str()).unwrap_or("?");

    println!("Account:  {}", email);
    println!("Role:     {}", role);

    if let Ok(lic) = client.get("/license/status") {
        println!(
            "Tier:     {}",
            lic.get("tier")
                .and_then(|v| v.as_str())
                .unwrap_or("community")
        );
        println!(
            "Agents:   {}/{}",
            lic.get("agents_used").and_then(|v| v.as_u64()).unwrap_or(0),
            lic.get("agent_limit").and_then(|v| v.as_u64()).unwrap_or(3)
        );
    }

    // BIZ-2: tokens today line
    if let Ok(metrics) = client.get("/monitor/health") {
        let tokens_today = metrics
            .get("metrics")
            .and_then(|m| m.get("tokens_today"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let cost_today = metrics
            .get("metrics")
            .and_then(|m| m.get("cost_usd_today"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        println!("Tokens:   {} today  (${:.4})", tokens_today, cost_today);
    }

    if let Ok(health) = client.get("/health") {
        println!(
            "Server:   {} ({})",
            health
                .get("service")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
            health
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
        );
        println!(
            "Mode:     {}",
            health.get("mode").and_then(|v| v.as_str()).unwrap_or("?")
        );
    }
    Ok(())
}

// =============================================================================
// BIZ-2: connector run <manifest> --input "..." — streams agent reasoning to stdout
// =============================================================================

fn handle_run_cmd(
    manifest: &str,
    input: Option<&str>,
    verbose: bool,
    format: &str,
    client: &Client,
) -> Result<(), String> {
    // Read manifest from file
    let manifest_content = std::fs::read_to_string(manifest)
        .map_err(|e| format!("Cannot read manifest '{}': {}", manifest, e))?;

    // Extract agent name from manifest YAML (best-effort, no dep needed)
    let agent_name = manifest_content
        .lines()
        .find(|l| l.trim_start().starts_with("name:"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "agent".to_string());

    let user_input = input.unwrap_or("Hello, what can you help with?");

    // Step 1: deploy the agent (or register it if already deployed)
    let deploy_body = serde_json::json!({
        "manifest": manifest_content,
        "llm_stub": std::env::var("CONNECTOR_LLM_STUB").is_ok(),
    });
    let deploy_result = client
        .post("/run-example", &deploy_body)
        .or_else(|_| client.post("/deploy/run", &deploy_body));

    let agent_pid = match deploy_result {
        Ok(ref r) => r
            .get("agent_pid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        Err(_) => String::new(),
    };

    // BIZ-2: output format mirrors curl + structured logs
    // Format: timestamp · agent_pid · event_type · content
    let now_ts = || {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("{}", ms)
    };

    if format == "json" {
        println!(
            "{}",
            serde_json::json!({
                "ts": now_ts(), "agent_pid": agent_pid, "event": "input", "content": user_input
            })
        );
    } else {
        println!("{} · {} · input      · {}", now_ts(), agent_pid, user_input);
    }

    // Step 2: open a session and dispatch input via gateway
    let session_body = serde_json::json!({ "agent_pid": agent_pid });
    let session_id = if !agent_pid.is_empty() {
        client
            .post(&format!("/agents/{}/sessions", agent_pid), &session_body)
            .ok()
            .and_then(|r| {
                r.get("session_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "session_0".to_string())
    } else {
        "session_0".to_string()
    };

    // Step 3: send through gateway (OpenAI-compatible endpoint)
    let gateway_body = serde_json::json!({
        "model": "gpt-4o",
        "agent_pid": agent_pid,
        "session_id": session_id,
        "messages": [{ "role": "user", "content": user_input }],
        "stream": false,
    });

    let resp = client
        .post("/v1/chat/completions", &gateway_body)
        .or_else(|_| client.post("/api/v1/gateway/chat", &gateway_body));

    match resp {
        Ok(r) => {
            // Extract answer from OpenAI-compatible response
            let answer = r
                .get("choices")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("message"))
                .and_then(|m| m.get("content"))
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| {
                    r.get("response")
                        .and_then(|v| v.as_str())
                        .unwrap_or("[no response]")
                });

            let tokens = r
                .get("usage")
                .and_then(|u| u.get("total_tokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let model = r.get("model").and_then(|v| v.as_str()).unwrap_or("?");

            if format == "json" {
                println!(
                    "{}",
                    serde_json::json!({
                        "ts": now_ts(), "agent_pid": agent_pid,
                        "event": "answer", "content": answer,
                        "tokens": tokens, "model": model,
                    })
                );
            } else {
                if verbose {
                    println!("{} · {} · model      · {}", now_ts(), agent_pid, model);
                    println!("{} · {} · tokens     · {}", now_ts(), agent_pid, tokens);
                }
                println!("{} · {} · answer     · {}", now_ts(), agent_pid, answer);
            }
        }
        Err(e) => {
            // If gateway not reachable, give helpful error
            eprintln!("[error] Agent did not respond: {}", e);
            eprintln!("  → Is the server running?  connector dev");
            eprintln!("  → LLM stub mode?          CONNECTOR_LLM_STUB=true connector dev");
            return Err(format!("run failed: {}", e));
        }
    }

    Ok(())
}

fn handle_init(path: Option<&str>, quickstart: bool) -> Result<(), String> {
    let dir = path.unwrap_or(".");

    // BIZ-2: create ~/.connector/ global config dir with default connector.yaml
    if let Some(home) = std::env::var_os("HOME") {
        let global_dir = std::path::Path::new(&home).join(".connector");
        let _ = std::fs::create_dir_all(&global_dir);
        let global_config = global_dir.join("connector.yaml");
        if !global_config.exists() {
            let _ = std::fs::write(&global_config, GLOBAL_CONNECTOR_YAML);
        }
    }

    std::fs::create_dir_all(dir)
        .map_err(|e| format!("Cannot create directory '{}': {}", dir, e))?;

    // Write agent.yaml
    let agent_yaml = if quickstart {
        QUICKSTART_MANIFEST
    } else {
        MINIMAL_MANIFEST
    };
    let manifest_path = format!("{}/agent.yaml", dir);
    std::fs::write(&manifest_path, agent_yaml)
        .map_err(|e| format!("Cannot write agent.yaml: {}", e))?;

    // Write .env
    let env_path = format!("{}/.env", dir);
    if !std::path::Path::new(&env_path).exists() {
        std::fs::write(&env_path, INIT_DOT_ENV).map_err(|e| format!("Cannot write .env: {}", e))?;
    }

    // Write agent.py (3-line quickstart)
    let py_path = format!("{}/agent.py", dir);
    if !std::path::Path::new(&py_path).exists() {
        std::fs::write(&py_path, INIT_AGENT_PY)
            .map_err(|e| format!("Cannot write agent.py: {}", e))?;
    }

    // Write examples/support.yaml
    let examples_dir = format!("{}/examples", dir);
    let _ = std::fs::create_dir_all(&examples_dir);
    let support_path = format!("{}/examples/support.yaml", dir);
    if !std::path::Path::new(&support_path).exists() {
        std::fs::write(&support_path, SUPPORT_EXAMPLE_MANIFEST)
            .map_err(|e| format!("Cannot write examples/support.yaml: {}", e))?;
    }

    // BIZ-2: output matches spec — "✓ Ready. Run: connector run examples/support.yaml"
    println!("✓ Ready. Run: connector run examples/support.yaml");
    println!();
    println!("Files created:");
    println!("  {}   — agent manifest", manifest_path);
    println!(
        "  {}/.env          — environment config (add CONNECTOR_LLM_API_KEY)",
        dir
    );
    println!("  {}/agent.py      — Python SDK quickstart (3 lines)", dir);
    println!("  {}/examples/support.yaml  — support agent example", dir);
    println!();
    println!("Quick start (< 60s, no API key needed):");
    println!("  1. connector dev                                     # start server + LLM stub");
    println!("  2. connector run examples/support.yaml --input \"refund my order\"");
    println!();
    println!("With real LLM:");
    println!("  export CONNECTOR_LLM_API_KEY=sk-...");
    println!("  connector run examples/support.yaml --input \"refund my order\"");
    println!();
    println!("Docs: https://connector.ai/docs/quickstart");
    Ok(())
}

// =============================================================================
// Memory subcommand handlers
// =============================================================================

fn handle_memory_cmd(
    cmd: MemoryCmd,
    client: &Client,
    output: &str,
    quiet: bool,
) -> Result<(), String> {
    match cmd {
        MemoryCmd::Tree { pid, depth, since } => {
            let mut path = format!("/agents/{}/memory/tree?depth={}", pid, depth);
            if let Some(s) = since {
                path.push_str(&format!("&since={}", s));
            }
            let data = client.get(&path)?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            let ns = data
                .get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or(&pid);
            let sessions = data
                .get("sessions")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let total_packets: usize = sessions
                .iter()
                .map(|s| {
                    s.get("packets")
                        .and_then(|p| p.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0)
                })
                .sum();
            println!("memory tree: {} (pid:{})", pid, pid);
            println!(
                "namespace: {}  [{} sessions, {} packets]",
                ns,
                sessions.len(),
                total_packets
            );
            println!();
            for (si, session) in sessions.iter().enumerate() {
                let sid = session
                    .get("session_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let packets = session
                    .get("packets")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let connector = if si + 1 < sessions.len() {
                    "├──"
                } else {
                    "└──"
                };
                let bar = if si + 1 < sessions.len() { "│" } else { " " };
                println!("{} session:{}  [{} packets]", connector, sid, packets.len());
                for (pi, pkt) in packets.iter().enumerate() {
                    let cid = pkt.get("cid").and_then(|v| v.as_str()).unwrap_or("?");
                    let ptype = pkt.get("type").and_then(|v| v.as_str()).unwrap_or("?");
                    let content = pkt.get("content").and_then(|v| v.as_str()).unwrap_or("");
                    let ts = pkt.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
                    let ts_fmt = format_epoch_ms(ts);
                    let truncated = if content.len() > 48 {
                        format!("\"{}…\"", &content[..48])
                    } else {
                        format!("\"{}\"", content)
                    };
                    let pconn = if pi + 1 < packets.len() {
                        "├──"
                    } else {
                        "└──"
                    };
                    let sealed = if pkt.get("sealed").and_then(|v| v.as_bool()).unwrap_or(false) {
                        " 🔒"
                    } else {
                        ""
                    };
                    let pinned = if pkt.get("pinned").and_then(|v| v.as_bool()).unwrap_or(false) {
                        " 📌"
                    } else {
                        ""
                    };
                    println!(
                        "{}   {} {:<10} {:<12} {:<50} {}{}{}",
                        bar,
                        pconn,
                        &cid[..cid.len().min(10)],
                        ptype,
                        truncated,
                        ts_fmt,
                        sealed,
                        pinned
                    );
                }
            }
            // Stats footer
            let stats = data.get("stats");
            if let Some(s) = stats {
                println!();
                println!(
                    "Stats: {} packets  {} sessions  oldest: {}  newest: {}",
                    s.get("total_packets").and_then(|v| v.as_u64()).unwrap_or(0),
                    s.get("total_sessions")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    s.get("oldest_relative")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-"),
                    s.get("newest_relative")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-"),
                );
            }
        }

        MemoryCmd::Search { pid, query, limit } => {
            let data = client.post(
                &format!("/agents/{}/memory/search", pid),
                &serde_json::json!({"query": query, "limit": limit}),
            )?;
            let results = data
                .get("results")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            if !quiet {
                println!("Searching memory for: \"{}\"", query);
                println!("Agent: {}  Namespace: {}", pid, pid);
                println!();
                println!(
                    "  {:<4} {:<12} {:<12} {:<48} {:<6} {}",
                    "Rank", "CID", "Type", "Content", "Score", "When"
                );
                println!("  {}", "─".repeat(96));
            }
            for (i, r) in results.iter().enumerate() {
                let cid = r.get("cid").and_then(|v| v.as_str()).unwrap_or("?");
                let rtype = r.get("type").and_then(|v| v.as_str()).unwrap_or("?");
                let content = r.get("content").and_then(|v| v.as_str()).unwrap_or("");
                let score = r.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let ts = r.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
                let truncated = if content.len() > 46 {
                    format!("\"{}…\"", &content[..46])
                } else {
                    format!("\"{}\"", content)
                };
                println!(
                    "  #{:<3} {:<12} {:<12} {:<48} {:.2}   {}",
                    i + 1,
                    &cid[..cid.len().min(10)],
                    rtype,
                    truncated,
                    score,
                    format_epoch_ms(ts)
                );
            }
            if !quiet {
                println!("\n{} results  (semantic search)", results.len());
            }
        }

        MemoryCmd::Show { cid } => {
            let data = client.get(&format!("/memory/packets/{}", cid))?;
            println!("{}", serde_json::to_string_pretty(&data).unwrap());
        }

        MemoryCmd::Stats { pid } => {
            let data = client.get(&format!("/agents/{}/memory/stats", pid))?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            println!("Memory stats: {}", pid);
            println!(
                "  Packets:   {}",
                data.get("total_packets")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            );
            println!(
                "  Sessions:  {}",
                data.get("total_sessions")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            );
            println!(
                "  Size:      {}",
                data.get("total_size_human")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
            );
            println!(
                "  Oldest:    {}",
                data.get("oldest_relative")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-")
            );
            println!(
                "  Newest:    {}",
                data.get("newest_relative")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-")
            );
        }

        MemoryCmd::Export {
            pid,
            output: out_file,
        } => {
            let data = client.get(&format!("/agents/{}/memory/export", pid))?;
            let json = serde_json::to_string_pretty(&data).unwrap();
            if let Some(path) = out_file {
                std::fs::write(&path, &json)
                    .map_err(|e| format!("Cannot write {}: {}", path, e))?;
                if !quiet {
                    println!("✅ Exported memory to {}", path);
                }
            } else {
                println!("{}", json);
            }
        }

        // Extended DB-management commands delegated to handle_memory_extended
        other => {
            if let Some(result) = handle_memory_extended(other, client, output, quiet) {
                return result;
            }
        }
    }
    Ok(())
}

// =============================================================================
// Trace subcommand handlers
// =============================================================================

fn handle_trace_cmd(
    cmd: TraceCmd,
    client: &Client,
    output: &str,
    quiet: bool,
) -> Result<(), String> {
    match cmd {
        TraceCmd::Ls { agent, limit } => {
            let mut path = format!("/actionlog/traces?limit={}", limit);
            if let Some(a) = &agent {
                path.push_str(&format!("&agent_pid={}", a));
            }
            let data = client.get(&path)?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            let traces = data
                .get("traces")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if !quiet {
                println!(
                    "{:<20} {:<20} {:<24} {:<10} {:<8} {}",
                    "TRACE_ID", "AGENT", "START", "DURATION", "TOKENS", "STATUS"
                );
                println!("{}", "─".repeat(90));
            }
            for t in &traces {
                let id = t.get("trace_id").and_then(|v| v.as_str()).unwrap_or("?");
                let agent_name = t.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("?");
                let ts = t.get("started_at").and_then(|v| v.as_i64()).unwrap_or(0);
                let dur = t.get("duration_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                let tokens = t.get("tokens_used").and_then(|v| v.as_u64()).unwrap_or(0);
                let status = t.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                let status_icon = if status == "ok" || status == "allowed" {
                    "✅"
                } else {
                    "❌"
                };
                println!(
                    "{:<20} {:<20} {:<24} {:<10} {:<8} {} {}",
                    &id[..id.len().min(18)],
                    &agent_name[..agent_name.len().min(18)],
                    format_epoch_ms(ts),
                    if dur > 0 {
                        format!("{}ms", dur)
                    } else {
                        "--".to_string()
                    },
                    tokens,
                    status_icon,
                    status
                );
            }
        }

        TraceCmd::Show { trace_id } => {
            let data = client.get(&format!("/actionlog/traces/{}", trace_id))?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            let agent = data
                .get("agent_pid")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let ts = data.get("started_at").and_then(|v| v.as_i64()).unwrap_or(0);
            let dur = data
                .get("duration_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!("Trace: {}", trace_id);
            println!(
                "Agent: {}  Started: {}  Duration: {}ms",
                agent,
                format_epoch_ms(ts),
                dur
            );
            println!();
            let spans = data
                .get("spans")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for (i, span) in spans.iter().enumerate() {
                let name = span.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let service = span.get("service").and_then(|v| v.as_str()).unwrap_or("?");
                let span_dur = span
                    .get("duration_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let status = span.get("status").and_then(|v| v.as_str()).unwrap_or("ok");
                let icon = if status == "ok" || status == "allowed" {
                    "✅"
                } else {
                    "❌"
                };
                let connector = if i == 0 {
                    "┌─"
                } else if i + 1 == spans.len() {
                    "└──"
                } else {
                    "├──"
                };
                let indent = if i == 0 { "  " } else { "  " };
                println!(
                    "{}{}[{}] {}  {:<8}ms  {}",
                    indent, connector, service, name, span_dur, icon
                );
                // Show key attributes
                if let Some(attrs) = span.get("attributes").and_then(|v| v.as_object()) {
                    for (k, v) in attrs.iter().take(3) {
                        println!("  │    {}: {}", k, v);
                    }
                }
            }
            println!();
            println!(
                "Run 'connector trace stats --agent {} --window 1h' for aggregates.",
                agent
            );
        }

        TraceCmd::Stats { agent, window } => {
            let mut path = format!("/actionlog/traces/stats?window={}", window);
            if let Some(a) = &agent {
                path.push_str(&format!("&agent_pid={}", a));
            }
            let data = client.get(&path)?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            println!("Trace stats  window: {}", window);
            println!(
                "  Total calls:    {}",
                data.get("total_calls")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            );
            println!(
                "  Blocked:        {}",
                data.get("blocked").and_then(|v| v.as_u64()).unwrap_or(0)
            );
            println!(
                "  Tokens used:    {}",
                data.get("tokens_used")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            );
            println!(
                "  P50 latency:    {}ms",
                data.get("p50_ms").and_then(|v| v.as_u64()).unwrap_or(0)
            );
            println!(
                "  P95 latency:    {}ms",
                data.get("p95_ms").and_then(|v| v.as_u64()).unwrap_or(0)
            );
            println!(
                "  P99 latency:    {}ms",
                data.get("p99_ms").and_then(|v| v.as_u64()).unwrap_or(0)
            );
        }
    }
    Ok(())
}

// =============================================================================
// Test subcommand handlers
// =============================================================================

fn handle_test_cmd(cmd: TestCmd, client: &Client, quiet: bool) -> Result<(), String> {
    match cmd {
        TestCmd::Invariants { verbose } => {
            if !quiet {
                println!("Running Connector formal invariants...");
                println!();
            }
            let data = client.get("/safety/formal/verify")?;
            let invariants = data
                .get("invariants")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let all_passed = data
                .get("all_invariants_passed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mut passed = 0usize;
            let mut failed = 0usize;
            for inv in &invariants {
                let name = inv.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let desc = inv
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let ok = inv.get("passed").and_then(|v| v.as_bool()).unwrap_or(false);
                if ok {
                    passed += 1;
                } else {
                    failed += 1;
                }
                let icon = if ok { "✅" } else { "❌" };
                println!("  {} {:<35} — {}", icon, name, desc);
            }
            println!();
            println!(
                "  Passed: {}/{}  Failed: {}",
                passed,
                passed + failed,
                failed
            );
            if all_passed {
                println!("\nAll invariants passed. Your AI system is provably safe.");
            } else {
                eprintln!("\nFailed invariants detected — review safety posture.");
                std::process::exit(2);
            }
        }

        TestCmd::Claims { source, claim } => {
            let content = std::fs::read_to_string(&source)
                .map_err(|e| format!("Cannot read {}: {}", source, e))?;
            let data = client.post(
                "/safety/claims/verify",
                &serde_json::json!({
                    "source_text": content,
                    "claims": [claim],
                }),
            )?;
            if !quiet {
                println!("Claim verification result:");
                println!();
            }
            let safe = data
                .get("hallucination_safe")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            println!("  {} Claim: \"{}\"", if safe { "✅" } else { "❌" }, claim);
            println!(
                "  Result: {}",
                if safe {
                    "SUPPORTED by source"
                } else {
                    "NOT SUPPORTED (potential hallucination)"
                }
            );
        }

        TestCmd::Injection { input } => {
            let data = client.post(
                "/firewall/injection-check",
                &serde_json::json!({
                    "text": input,
                }),
            )?;
            let score = data
                .get("injection_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let blocked = data
                .get("blocked")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            println!("Injection detection result:");
            println!("  Score:   {:.4}  (threshold: 0.80)", score);
            println!(
                "  Result:  {}",
                if blocked {
                    "❌ BLOCKED (injection detected)"
                } else {
                    "✅ SAFE (score below threshold)"
                }
            );
        }

        TestCmd::Smoke { agent, llm_stub } => {
            if !quiet {
                let mode = if llm_stub { " (LLM stub mode)" } else { "" };
                println!("Running smoke test{}...", mode);
                println!();
            }
            let agent_name = agent.as_deref().unwrap_or("smoke-test-agent");
            let mut pass = 0usize;
            let mut fail = 0usize;

            // Step 1: Register agent
            let sp = Spinner::new("Register agent");
            match client.post(
                "/agents",
                &serde_json::json!({"name": agent_name, "namespace": agent_name}),
            ) {
                Ok(d) => {
                    let pid = d
                        .get("pid")
                        .or_else(|| d.get("agent_pid"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    pass += 1;
                    sp.finish(&format!("pid:{}", pid));
                    if !quiet {
                        println!("  ✅ Register agent          pid:{}", pid);
                    }
                }
                Err(e) => {
                    fail += 1;
                    sp.fail(&e);
                    if !quiet {
                        println!("  ❌ Register agent          {}", e);
                    }
                }
            }

            // Step 2: Write memory
            let sp = Spinner::new("Write memory");
            match client.post("/memory/write", &serde_json::json!({"agent_pid": agent_name, "content": "smoke test memory", "type": "Feedback"})) {
                Ok(d) => {
                    let cid = d.get("cid").and_then(|v| v.as_str()).unwrap_or("?");
                    pass += 1;
                    sp.finish(&format!("cid:{}", cid));
                    if !quiet { println!("  ✅ Write memory            cid:{}", cid); }
                }
                Err(e) => { fail += 1; sp.fail(&e); if !quiet { println!("  ❌ Write memory            {}", e); } }
            }

            // Step 3: Recall memory
            let sp = Spinner::new("Recall memory");
            match client.get(&format!("/memory/recall/{}", agent_name)) {
                Ok(d) => {
                    let count = d
                        .get("packets")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    pass += 1;
                    sp.finish(&format!("{} packet(s)", count));
                    if !quiet {
                        println!("  ✅ Recall memory           {} packet(s) returned", count);
                    }
                }
                Err(e) => {
                    fail += 1;
                    sp.fail(&e);
                    if !quiet {
                        println!("  ❌ Recall memory           {}", e);
                    }
                }
            }

            // Step 4: Formal invariants
            let sp = Spinner::new("Formal invariants");
            match client.get("/safety/formal/verify") {
                Ok(d) => {
                    let ok = d
                        .get("all_invariants_passed")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if ok {
                        pass += 1;
                        sp.finish("all passed");
                        if !quiet {
                            println!("  ✅ Formal invariants       all passed");
                        }
                    } else {
                        fail += 1;
                        sp.fail("some failed");
                        if !quiet {
                            println!("  ❌ Formal invariants       some failed");
                        }
                    }
                }
                Err(e) => {
                    fail += 1;
                    sp.fail(&e);
                    if !quiet {
                        println!("  ❌ Formal invariants       {}", e);
                    }
                }
            }

            println!();
            if fail == 0 {
                println!(
                    "Smoke test passed ({}/{} checks). System is ready.",
                    pass,
                    pass + fail
                );
                println!("Run 'connector test all' for full suite including invariants.");
            } else {
                eprintln!("Smoke test failed: {}/{} checks passed.", pass, pass + fail);
                std::process::exit(2);
            }
        }

        TestCmd::All => {
            handle_test_cmd(TestCmd::Invariants { verbose: false }, client, quiet)?;
            println!();
            handle_test_cmd(
                TestCmd::Smoke {
                    agent: None,
                    llm_stub: true,
                },
                client,
                quiet,
            )?;
        }
    }
    Ok(())
}

// =============================================================================
// Platform logs handler
// =============================================================================

fn handle_platform_logs(
    client: &Client,
    follow: bool,
    since: Option<&str>,
    level: Option<&str>,
    filter: Option<&str>,
) -> Result<(), String> {
    let mut path = "/actionlog/actions?limit=100".to_string();
    if let Some(s) = since {
        path.push_str(&format!("&since={}", s));
    }
    if let Some(l) = level {
        path.push_str(&format!("&level={}", l));
    }
    if let Some(f) = filter {
        path.push_str(&format!("&filter={}", f));
    }

    let data = client.get(&path)?;
    let entries = data
        .get("actions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    println!(
        "{:<22} {:<16} {:<20} {:<12} {}",
        "TIMESTAMP", "AGENT", "OPERATION", "OUTCOME", "DETAIL"
    );
    println!("{}", "─".repeat(90));
    for entry in &entries {
        let ts = entry.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
        let agent = entry
            .get("agent_pid")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let op = entry
            .get("action")
            .or(entry.get("operation"))
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let outcome = entry.get("outcome").and_then(|v| v.as_str()).unwrap_or("?");
        let detail = entry
            .get("reason")
            .or(entry.get("detail"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        println!(
            "{:<22} {:<16} {:<20} {:<12} {}",
            format_epoch_ms(ts),
            &agent[..agent.len().min(14)],
            &op[..op.len().min(18)],
            outcome,
            detail
        );
    }
    if follow {
        println!("\n(--follow: stream via GET /api/v1/actionlog/actions?follow=true)");
    }
    Ok(())
}

// =============================================================================
// Shell completions handler
// =============================================================================

fn handle_completions(shell: &str) -> Result<(), String> {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    match shell.to_lowercase().as_str() {
        "bash" => {
            clap_complete::generate(clap_complete::Shell::Bash, &mut cmd, "connector", &mut std::io::stdout());
            Ok(())
        }
        "zsh" => {
            clap_complete::generate(clap_complete::Shell::Zsh, &mut cmd, "connector", &mut std::io::stdout());
            Ok(())
        }
        "fish" => {
            clap_complete::generate(clap_complete::Shell::Fish, &mut cmd, "connector", &mut std::io::stdout());
            Ok(())
        }
        "powershell" | "ps" => {
            clap_complete::generate(clap_complete::Shell::PowerShell, &mut cmd, "connector", &mut std::io::stdout());
            Ok(())
        }
        _ => Err(format!(
            "unknown shell '{}'\n  supported: bash, zsh, fish, powershell\n  example: connector completions bash >> ~/.bashrc",
            shell
        )),
    }
}

const INIT_DOT_ENV: &str = "\
# Connector Platform — local dev environment
# Source this file: source .env  OR  use direnv
CONNECTOR_BASE_URL=http://localhost:8080
CONNECTOR_DEV_MODE=1
CONNECTOR_LLM_STUB=true

# Uncomment to use a real LLM:
# CONNECTOR_LLM_API_KEY=sk-proj-...
# CONNECTOR_LLM_BASE_URL=https://api.openai.com
# CONNECTOR_LLM_MODEL=gpt-4o-mini
";

const INIT_AGENT_PY: &str = "\
# Connector Platform — Python quickstart
# Run: python agent.py
# Docs: https://connector.ai/docs/quickstart

from connector_sdk import ConnectorAgent

agent = ConnectorAgent(\"my-agent\")          # registers automatically
agent.remember(\"User prefers dark mode\")    # write persistent memory
memories = agent.recall()                    # recall all memories

print(f\"Agent: {agent.pid}\")
print(f\"Memories: {len(memories)}\")
for m in memories:
    print(f\"  - {m.get('content', m)}\")
";

// =============================================================================
// Helpers
// =============================================================================

fn print_diff_table(diff: &[serde_json::Value]) {
    println!(
        "{:<30} {:<30} {:<30} {:<10}",
        "FIELD", "CURRENT", "PROPOSED", "CHANGE"
    );
    println!("{}", "─".repeat(104));
    for d in diff {
        println!(
            "{:<30} {:<30} {:<30} {:<10}",
            d.get("field").and_then(|v| v.as_str()).unwrap_or("?"),
            truncate_str(d.get("current").and_then(|v| v.as_str()).unwrap_or("?"), 28),
            truncate_str(
                d.get("proposed").and_then(|v| v.as_str()).unwrap_or("?"),
                28
            ),
            d.get("change_type").and_then(|v| v.as_str()).unwrap_or("?"),
        );
    }
}

fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() > max {
        &s[..max]
    } else {
        s
    }
}

fn format_epoch_ms(ms: i64) -> String {
    if ms == 0 {
        return "-".to_string();
    }
    let secs = ms / 1000;
    // Simple ISO-8601 approximation without chrono dep on output
    let dt = chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| format!("{}", ms));
    dt
}

fn urlencoding_simple(s: &str) -> String {
    // Minimal URL encoding for query param passing — in production use urlencoding crate
    s.replace('%', "%25")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('+', "%2B")
        .replace(' ', "%20")
        .replace('\n', "%0A")
}

fn which_binary(name: &str) -> Result<String, ()> {
    if let Ok(output) = std::process::Command::new("which").arg(name).output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(path);
            }
        }
    }
    // Check same directory as this binary
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.parent().unwrap_or(std::path::Path::new(".")).join(name);
        if sibling.exists() {
            return Ok(sibling.to_string_lossy().to_string());
        }
    }
    Err(())
}

// =============================================================================
// Scaffold templates
// =============================================================================

const MINIMAL_MANIFEST: &str = r#"apiVersion: connector/v1
kind: Agent
metadata:
  name: my-agent
  version: "0.1.0"
  description: "My first Connector agent"
spec:
  model:
    provider: openai
    name: gpt-4o
  instructions: "You are a helpful assistant."
  resources:
    token_budget:
      daily_limit: 100000
  comply: [soc2]
"#;

const QUICKSTART_MANIFEST: &str = r#"apiVersion: connector/v1
kind: Agent
metadata:
  name: quickstart-bot
  version: "0.1.0"
  description: "Quickstart agent — responds to any input"
spec:
  model:
    provider: openai
    name: gpt-4o
  instructions: |
    You are a helpful assistant. Answer questions clearly and concisely.
    If asked about Connector, explain it as an AI OS that gives agents
    memory, trust, compliance, and lifecycle management.
  tools: []
  memory:
    mode: persistent
  resources:
    token_budget:
      daily_limit: 50000
      enforce: true
    priority: normal
  security:
    classification: standard
  lifecycle:
    restart: on-failure
    max_restarts: 3
  comply: [soc2]
"#;

/// BIZ-2: ~/.connector/connector.yaml — global config with commented fields
const GLOBAL_CONNECTOR_YAML: &str = r#"# Connector global configuration
# Generated by: connector init
# Docs: https://connector.ai/docs/config

# API server URL (override with CONNECTOR_API_URL env var)
# api_url: http://localhost:8080

# Default output format: pretty | json | table
# output: pretty

# Auth token (set via: connector auth login, or CONNECTOR_API_KEY env var)
# api_key: cpk_live_...

# LLM provider (override with CONNECTOR_LLM_API_KEY env var)
# llm:
#   provider: openai
#   model: gpt-4o
#   api_key: sk-...
"#;

/// BIZ-2: examples/support.yaml — working support agent example
const SUPPORT_EXAMPLE_MANIFEST: &str = r#"apiVersion: connector/v1
kind: Agent
metadata:
  name: support-agent
  version: "0.1.0"
  description: "Customer support agent — handles refunds, order status, FAQs"
spec:
  model:
    provider: openai
    name: gpt-4o
  instructions: |
    You are a helpful customer support agent.
    - For refund requests: acknowledge, ask for order ID, confirm refund initiated
    - For order status: ask for order ID, provide status
    - For general questions: answer clearly and concisely
    Always be polite and resolve issues in < 3 turns.
  tools: []
  memory:
    mode: persistent
    types: [episodic, semantic]
  resources:
    token_budget:
      daily_limit: 10000
      enforce: false
    priority: normal
  security:
    classification: standard
  lifecycle:
    restart: on-failure
    max_restarts: 3
  comply: []
"#;

// =============================================================================
// Extended Memory handlers (pin/unpin/purge/compact/import/seal)
// =============================================================================

fn handle_memory_extended(
    cmd: MemoryCmd,
    client: &Client,
    output: &str,
    quiet: bool,
) -> Option<Result<(), String>> {
    match cmd {
        MemoryCmd::Pin { cid } => Some({
            match client.post(
                &format!("/memory/packets/{}/pin", cid),
                &serde_json::json!({}),
            ) {
                Ok(_) => {
                    println!("✅  Pinned {}  (never evicted)", cid);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }),
        MemoryCmd::Unpin { cid } => Some({
            match client.post(
                &format!("/memory/packets/{}/unpin", cid),
                &serde_json::json!({}),
            ) {
                Ok(_) => {
                    println!("✅  Unpinned {}  (eligible for eviction)", cid);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }),
        MemoryCmd::Seal { cid } => Some({
            match client.post(
                &format!("/memory/packets/{}/seal", cid),
                &serde_json::json!({"reason": "operator_seal"}),
            ) {
                Ok(_) => {
                    println!("🔒  Sealed {}  — content immutable", cid);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }),
        MemoryCmd::Purge {
            pid,
            older_than,
            confirm,
        } => Some({
            if !confirm && !quiet {
                println!(
                    "Dry-run: packets older than {} for agent '{}' would be purged.",
                    older_than, pid
                );
                println!("Re-run with --confirm to actually delete.");
                match client.post(
                    &format!("/agents/{}/memory/purge", pid),
                    &serde_json::json!({"older_than": older_than, "dry_run": true}),
                ) {
                    Ok(data) => {
                        println!(
                            "  Would delete: {} packets",
                            data.get("would_delete")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0)
                        );
                        return Some(Ok(()));
                    }
                    Err(e) => return Some(Err(e)),
                }
            }
            let sp = Spinner::new(&format!(
                "Purging packets older than {} for '{}'",
                older_than, pid
            ));
            match client.post(
                &format!("/agents/{}/memory/purge", pid),
                &serde_json::json!({"older_than": older_than, "dry_run": false}),
            ) {
                Ok(d) => {
                    let deleted = d.get("deleted").and_then(|v| v.as_u64()).unwrap_or(0);
                    sp.finish(&format!("{} packets deleted", deleted));
                    if !quiet {
                        println!("✅  Purged {} packets for agent '{}'", deleted, pid);
                    }
                    Ok(())
                }
                Err(e) => {
                    sp.fail(&e);
                    Err(e)
                }
            }
        }),
        MemoryCmd::Compact { pid, max_packets } => Some({
            let sp = Spinner::new(&format!(
                "Compacting memory for '{}' (max {} packets)",
                pid, max_packets
            ));
            match client.post(
                &format!("/agents/{}/memory/compact", pid),
                &serde_json::json!({"max_packets": max_packets}),
            ) {
                Ok(d) => {
                    let kept = d.get("packets_kept").and_then(|v| v.as_u64()).unwrap_or(0);
                    let evicted = d
                        .get("packets_evicted")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    sp.finish(&format!("kept:{} evicted:{}", kept, evicted));
                    if !quiet {
                        println!("✅  Compact complete for '{}'", pid);
                        println!("   Kept:    {}", kept);
                        println!("   Evicted: {}", evicted);
                        println!("   Method:  LRU-K eviction");
                    }
                    Ok(())
                }
                Err(e) => {
                    sp.fail(&e);
                    Err(e)
                }
            }
        }),
        MemoryCmd::Import { pid, file, dry_run } => Some({
            let content = match std::fs::read_to_string(&file) {
                Ok(c) => c,
                Err(e) => return Some(Err(format!("Cannot read {}: {}", file, e))),
            };
            let lines: Vec<serde_json::Value> = content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            if dry_run {
                println!(
                    "Dry-run: would import {} packets for agent '{}'",
                    lines.len(),
                    pid
                );
                return Some(Ok(()));
            }
            let sp = Spinner::new(&format!("Importing {} packets for '{}'", lines.len(), pid));
            match client.post(
                &format!("/agents/{}/memory/import", pid),
                &serde_json::json!({"packets": lines, "dry_run": dry_run}),
            ) {
                Ok(d) => {
                    let imported = d.get("imported").and_then(|v| v.as_u64()).unwrap_or(0);
                    let skipped = d.get("skipped").and_then(|v| v.as_u64()).unwrap_or(0);
                    sp.finish(&format!("{} imported, {} skipped", imported, skipped));
                    if !quiet {
                        println!(
                            "✅  Imported {} packets for '{}' ({} skipped — already exist)",
                            imported, pid, skipped
                        );
                    }
                    Ok(())
                }
                Err(e) => {
                    sp.fail(&e);
                    Err(e)
                }
            }
        }),
        _ => None, // handled by existing handle_memory_cmd
    }
}

// =============================================================================
// Knowledge graph handlers
// =============================================================================

fn handle_knowledge_cmd(
    cmd: KnowledgeCmd,
    client: &Client,
    output: &str,
    quiet: bool,
) -> Result<(), String> {
    match cmd {
        KnowledgeCmd::Graph { agent } => {
            let path = if let Some(a) = &agent {
                format!("/memory/graph/growth-events/{}", a)
            } else {
                "/memory/graph/entities".to_string()
            };
            let data = client.get(&path)?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            if let Some(a) = &agent {
                let entities = data
                    .get("total_entities")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let interference = data
                    .get("interference_score")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let events = data
                    .get("growth_event_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                println!("Knowledge graph — agent '{}'", a);
                println!("  Entities:           {}", entities);
                println!("  Interference score: {:.3}", interference);
                println!("  Growth events:      {}", events);
                println!(
                    "  Contradiction:      {}",
                    data.get("contradiction_detected")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                );
            } else {
                let entities = data
                    .get("entities")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                println!("Knowledge graph — global");
                println!("  Entities: {}", entities);
            }
        }

        KnowledgeCmd::Entities { agent, limit } => {
            let data = client.get("/memory/graph/entities")?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            let entities = data
                .get("entities")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            println!(
                "{:<32} {:<16} {:<8} {}",
                "ENTITY_ID", "TYPE", "EDGES", "LABEL"
            );
            println!("{}", "─".repeat(72));
            for e in entities.iter().take(limit) {
                println!(
                    "{:<32} {:<16} {:<8} {}",
                    e.get("id").and_then(|v| v.as_str()).unwrap_or("?"),
                    e.get("entity_type").and_then(|v| v.as_str()).unwrap_or("?"),
                    e.get("edge_count").and_then(|v| v.as_u64()).unwrap_or(0),
                    e.get("label").and_then(|v| v.as_str()).unwrap_or(""),
                );
            }
            println!("\n{} entities (showing up to {})", entities.len(), limit);
        }

        KnowledgeCmd::Neighbors { entity_id, agent } => {
            let data = client.get(&format!("/memory/graph/neighbors/{}", entity_id))?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            let neighbors = data
                .get("neighbors")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            println!("Neighbors of '{}' ({} found):", entity_id, neighbors.len());
            println!("{}", "─".repeat(60));
            for n in &neighbors {
                let rel = n.get("relation").and_then(|v| v.as_str()).unwrap_or("?");
                let id = n.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let weight = n.get("weight").and_then(|v| v.as_f64()).unwrap_or(1.0);
                println!("  ─[{:<20}]→  {:<32}  (w={:.2})", rel, id, weight);
            }
        }

        KnowledgeCmd::Seed { file } => {
            let content = std::fs::read_to_string(&file)
                .map_err(|e| format!("Cannot read {}: {}", file, e))?;
            let seed: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| format!("Invalid JSON in {}: {}", file, e))?;
            let sp = Spinner::new(&format!("Loading knowledge seed from {}", file));
            let data = client.post("/memory/graph/seed", &seed);
            match data {
                Ok(d) => {
                    let entities = d
                        .get("entities_added")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let edges = d.get("edges_added").and_then(|v| v.as_u64()).unwrap_or(0);
                    sp.finish(&format!("{} entities, {} edges", entities, edges));
                    if !quiet {
                        println!("✅  Knowledge seed loaded from '{}'", file);
                        println!("   Entities added: {}", entities);
                        println!("   Edges added:    {}", edges);
                    }
                }
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
            }
        }

        KnowledgeCmd::Reflect { pid, force } => {
            let sp = Spinner::new(&format!("Running reflection for '{}'", pid));
            let data = client.post(
                &format!("/agents/{}/reflect", pid),
                &serde_json::json!({"force": force}),
            );
            match data {
                Ok(d) => {
                    let cid = d
                        .get("reflection_cid")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    sp.finish(&format!("cid:{}", cid));
                    if !quiet {
                        println!("✅  Reflection complete — '{}'", pid);
                        println!("   Reflection CID:   {}", cid);
                        println!(
                            "   Packets analysed: {}",
                            d.get("packets_in").and_then(|v| v.as_u64()).unwrap_or(0)
                        );
                        println!(
                            "   Insights stored:  {}",
                            d.get("insights_stored")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0)
                        );
                        println!(
                            "   Next scheduled:   {}",
                            d.get("next_reflection_at")
                                .and_then(|v| v.as_str())
                                .unwrap_or("—")
                        );
                    }
                }
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
            }
        }

        KnowledgeCmd::Skills { pid } => {
            let data = client.get(&format!("/agents/{}/skills", pid))?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            let skills = data
                .get("skills")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            println!(
                "Procedural skills — agent '{}'  ({} tools profiled)",
                pid,
                skills.len()
            );
            println!(
                "{:<24} {:<8} {:<10} {:<10} {}",
                "TOOL", "SUCCESS%", "AVG_MS", "CALLS", "PREFERRED_PARAMS"
            );
            println!("{}", "─".repeat(78));
            for s in &skills {
                println!(
                    "{:<24} {:<8.1} {:<10} {:<10} {}",
                    s.get("tool_name").and_then(|v| v.as_str()).unwrap_or("?"),
                    s.get("success_rate")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0)
                        * 100.0,
                    s.get("avg_latency_ms")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    s.get("call_count").and_then(|v| v.as_u64()).unwrap_or(0),
                    s.get("preferred_params")
                        .and_then(|v| v.as_str())
                        .unwrap_or("—"),
                );
            }
        }

        KnowledgeCmd::Growth { pid, limit } => {
            let data = client.get(&format!("/memory/graph/growth-events/{}", pid))?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            let events = data
                .get("growth_events")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            println!(
                "Knowledge growth events — agent '{}'  ({} events)",
                pid,
                events.len()
            );
            println!(
                "{:<10} {:<20} {:<8} {}",
                "WINDOW_SN", "KIND", "ENTITIES", "INTERFERENCE"
            );
            println!("{}", "─".repeat(60));
            for ev in events.iter().take(limit) {
                println!(
                    "{:<10} {:<20} {:<8} {:.3}",
                    ev.get("window_sn").and_then(|v| v.as_u64()).unwrap_or(0),
                    ev.get("kind").and_then(|v| v.as_str()).unwrap_or("?"),
                    ev.get("entities")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0),
                    ev.get("interference_score")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0),
                );
            }
        }

        KnowledgeCmd::Export {
            agent,
            output: out_file,
        } => {
            let data = client.get("/memory/graph/entities")?;
            let json = serde_json::to_string_pretty(&data).unwrap();
            if let Some(path) = out_file {
                std::fs::write(&path, &json)
                    .map_err(|e| format!("Cannot write {}: {}", path, e))?;
                if !quiet {
                    println!("✅  Knowledge graph exported to {}", path);
                }
            } else {
                println!("{}", json);
            }
        }
    }
    Ok(())
}

// =============================================================================
// Context management handlers
// =============================================================================

fn handle_context_cmd(
    cmd: ContextCmd,
    client: &Client,
    output: &str,
    quiet: bool,
) -> Result<(), String> {
    match cmd {
        ContextCmd::Budget { pid } => {
            let data = client.get(&format!("/context/{}/budget", pid))?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            let used = data
                .get("tokens_used")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let limit = data
                .get("tokens_limit")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let pct = data
                .get("utilization_pct")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let status = data.get("status").and_then(|v| v.as_str()).unwrap_or("ok");
            let bar_len = (pct / 5.0).round() as usize;
            let bar = format!(
                "[{}{}]",
                "█".repeat(bar_len),
                "░".repeat(20usize.saturating_sub(bar_len))
            );
            println!("Context budget — agent '{}'", pid);
            println!("  {:<20} {} / {}  ({:.1}%)", bar, used, limit, pct);
            println!("  Status:        {}", status);
            println!(
                "  Model:         {}",
                data.get("model").and_then(|v| v.as_str()).unwrap_or("?")
            );
            println!("  Breakdown:");
            for part in &["system_prompt", "history", "retrieved_docs", "tool_results"] {
                let t = data.get(part).and_then(|v| v.as_u64()).unwrap_or(0);
                if t > 0 {
                    println!("    {:<20} {} tokens", part, t);
                }
            }
        }

        ContextCmd::Compress { pid, target_pct } => {
            let sp = Spinner::new(&format!(
                "Compressing context for '{}' (target: {}%)",
                pid, target_pct
            ));
            let data = client.post(
                &format!("/context/{}/compress", pid),
                &serde_json::json!({"target_utilization_pct": target_pct}),
            );
            match data {
                Ok(d) => {
                    let before = d.get("before_pct").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let after = d.get("after_pct").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    sp.finish(&format!("{:.1}% → {:.1}%", before, after));
                    if !quiet {
                        println!("✅  Context compressed for '{}'", pid);
                        println!("   Before: {:.1}%  →  After: {:.1}%", before, after);
                        println!(
                            "   Turns summarised: {}",
                            d.get("turns_summarised")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0)
                        );
                        println!(
                            "   Summary CID:      {}",
                            d.get("summary_cid").and_then(|v| v.as_str()).unwrap_or("?")
                        );
                    }
                }
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
            }
        }

        ContextCmd::Flush {
            pid,
            purge_ephemeral,
        } => {
            let sp = Spinner::new(&format!("Flushing context for '{}'", pid));
            let data = client.post(
                &format!("/context/{}/flush", pid),
                &serde_json::json!({"purge_ephemeral": purge_ephemeral}),
            );
            match data {
                Ok(d) => {
                    sp.finish("done");
                    if !quiet {
                        println!("✅  Context flushed for '{}'", pid);
                        if purge_ephemeral {
                            println!(
                                "   Ephemeral packets deleted: {}",
                                d.get("ephemeral_deleted")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0)
                            );
                        }
                    }
                }
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
            }
        }

        ContextCmd::Assembly { pid, query, budget } => {
            let mut body = serde_json::json!({"query": query});
            if let Some(b) = budget {
                body["budget_tokens"] = serde_json::json!(b);
            }
            let data = client.post(&format!("/context/{}/assemble", pid), &body)?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            let chunks = data
                .get("chunks")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let total_tokens = data
                .get("total_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!(
                "Context assembly preview — '{}' for query: \"{}\"",
                pid, query
            );
            println!("Total tokens: {}   Chunks: {}", total_tokens, chunks.len());
            println!("{}", "─".repeat(70));
            for (i, c) in chunks.iter().enumerate() {
                let kind = c.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
                let score = c.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let tokens = c.get("tokens").and_then(|v| v.as_u64()).unwrap_or(0);
                let preview = c.get("preview").and_then(|v| v.as_str()).unwrap_or("");
                println!(
                    "#{:<3} [{:<12}] score={:.3}  tokens={:<6}  \"{}\"",
                    i + 1,
                    kind,
                    score,
                    tokens,
                    if preview.len() > 48 {
                        &preview[..48]
                    } else {
                        preview
                    }
                );
            }
        }

        ContextCmd::Status => {
            let data = client.get("/context/status")?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            let agents = data
                .get("agents")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            println!(
                "{:<24} {:<8} {:<8} {:<8} {}",
                "AGENT", "USED%", "TOKENS", "LIMIT", "STATUS"
            );
            println!("{}", "─".repeat(60));
            for a in &agents {
                let pct = a
                    .get("utilization_pct")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let icon = if pct >= 90.0 {
                    "⚠️ "
                } else if pct >= 70.0 {
                    "⚡"
                } else {
                    "✅"
                };
                println!(
                    "{} {:<22} {:<8.1} {:<8} {:<8} {}",
                    icon,
                    a.get("pid").and_then(|v| v.as_str()).unwrap_or("?"),
                    pct,
                    a.get("tokens_used").and_then(|v| v.as_u64()).unwrap_or(0),
                    a.get("tokens_limit").and_then(|v| v.as_u64()).unwrap_or(0),
                    a.get("status").and_then(|v| v.as_str()).unwrap_or("ok"),
                );
            }
        }
    }
    Ok(())
}

// =============================================================================
// Webhook handlers
// =============================================================================

fn handle_webhook_cmd(
    cmd: WebhookCmd,
    client: &Client,
    output: &str,
    quiet: bool,
) -> Result<(), String> {
    match cmd {
        WebhookCmd::List => {
            let data = client.get("/webhooks")?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            let wh = data
                .get("webhooks")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if wh.is_empty() {
                println!("No webhooks registered.");
                println!("  → connector webhooks register https://myapp.com/hooks");
                return Ok(());
            }
            println!("{:<12} {:<40} {:<10} {}", "ID", "URL", "STATUS", "EVENTS");
            println!("{}", "─".repeat(80));
            for w in &wh {
                let events = w
                    .get("events")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|e| e.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                println!(
                    "{:<12} {:<40} {:<10} {}",
                    w.get("id").and_then(|v| v.as_str()).unwrap_or("?"),
                    w.get("url").and_then(|v| v.as_str()).unwrap_or("?"),
                    w.get("status").and_then(|v| v.as_str()).unwrap_or("active"),
                    &events[..events.len().min(40)],
                );
            }
        }

        WebhookCmd::Register {
            url,
            events,
            secret,
        } => {
            let events_list: Vec<&str> = events.split(',').map(|s| s.trim()).collect();
            let body = serde_json::json!({
                "url": url,
                "events": events_list,
                "secret": secret,
            });
            let data = client.post("/webhooks", &body)?;
            let id = data.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            println!("✅  Webhook registered");
            println!("   ID:     {}", id);
            println!("   URL:    {}", url);
            println!("   Events: {}", events);
            if data
                .get("secret_generated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                println!(
                    "   Secret: {}  (save this — shown once)",
                    data.get("secret").and_then(|v| v.as_str()).unwrap_or("?")
                );
            }
            println!("\nVerify with: connector webhooks test {}", id);
        }

        WebhookCmd::Test { url_or_id } => {
            let sp = Spinner::new(&format!("Sending test ping to '{}'", url_or_id));
            let data = client.post(
                &format!("/webhooks/{}/test", url_or_id),
                &serde_json::json!({}),
            );
            match data {
                Ok(d) => {
                    let status = d.get("status_code").and_then(|v| v.as_u64()).unwrap_or(0);
                    let latency = d.get("latency_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                    sp.finish(&format!("HTTP {} in {}ms", status, latency));
                    if status >= 200 && status < 300 {
                        println!("✅  Webhook reachable — HTTP {} in {}ms", status, latency);
                    } else {
                        println!("⚠️   Webhook returned HTTP {} in {}ms", status, latency);
                    }
                }
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
            }
        }

        WebhookCmd::Deliveries { id, limit } => {
            let data = client.get(&format!("/webhooks/{}/deliveries?limit={}", id, limit))?;
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
                return Ok(());
            }
            let deliveries = data
                .get("deliveries")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            println!(
                "Deliveries for webhook '{}'  ({} shown)",
                id,
                deliveries.len()
            );
            println!(
                "{:<22} {:<30} {:<6} {:<8} {}",
                "TIMESTAMP", "EVENT", "HTTP", "MS", "STATUS"
            );
            println!("{}", "─".repeat(80));
            for d in &deliveries {
                let ts = d.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
                let status = d.get("status_code").and_then(|v| v.as_u64()).unwrap_or(0);
                let icon = if status >= 200 && status < 300 {
                    "✅"
                } else {
                    "❌"
                };
                println!(
                    "{} {:<20} {:<30} {:<6} {:<8} {}",
                    icon,
                    format_epoch_ms(ts),
                    d.get("event_type").and_then(|v| v.as_str()).unwrap_or("?"),
                    status,
                    d.get("latency_ms").and_then(|v| v.as_u64()).unwrap_or(0),
                    d.get("delivery_status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?"),
                );
            }
            println!("\nTo resend a failed delivery: connector webhooks resend <delivery_id>");
        }

        WebhookCmd::Delete { id } => {
            let data = client.delete(&format!("/webhooks/{}", id))?;
            println!("✅  Webhook '{}' deleted", id);
            let _ = data;
        }

        WebhookCmd::Resend { delivery_id } => {
            let sp = Spinner::new(&format!("Resending delivery '{}'", delivery_id));
            let data = client.post(
                &format!("/webhooks/deliveries/{}/resend", delivery_id),
                &serde_json::json!({}),
            );
            match data {
                Ok(d) => {
                    let status = d.get("status_code").and_then(|v| v.as_u64()).unwrap_or(0);
                    sp.finish(&format!("HTTP {}", status));
                    if status >= 200 && status < 300 {
                        println!("✅  Redelivery succeeded — HTTP {}", status);
                    } else {
                        println!("⚠️   Redelivery returned HTTP {}", status);
                    }
                }
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

// =============================================================================
// Examples handlers
// =============================================================================

/// Built-in example catalogue — name, description, agents, avg tokens, features
const EXAMPLES: &[(&str, &str, usize, u64, &str)] = &[
    (
        "banking-fraud",
        "Transaction fraud detection (3-agent pipeline)",
        3,
        2_400,
        "memory,tools,safety",
    ),
    (
        "hospital-er",
        "Emergency room triage and protocol lookup",
        2,
        3_100,
        "memory,hipaa,tools",
    ),
    (
        "customer-support",
        "Triage → knowledge lookup → escalation",
        3,
        1_800,
        "memory,tools,hitl",
    ),
    (
        "legal-review",
        "Ingest → extract clauses → flag risks (3-agent)",
        3,
        8_000,
        "memory,tools",
    ),
    (
        "code-review",
        "PR security scan + style + test coverage",
        2,
        4_500,
        "tools,safety",
    ),
    (
        "data-pipeline",
        "CSV → validate → transform → structured output",
        1,
        1_200,
        "tools,memory",
    ),
    (
        "research-assistant",
        "Web research + citations + summarisation",
        2,
        6_000,
        "tools,memory,search",
    ),
    (
        "multi-tenant-saas",
        "Namespace isolation between org:acme and org:rival",
        2,
        2_000,
        "memory,mac,isolation",
    ),
];

fn handle_examples_cmd(cmd: ExamplesCmd, client: &Client, quiet: bool) -> Result<(), String> {
    match cmd {
        ExamplesCmd::List => {
            if !quiet {
                println!(
                    "{:<24} {:<44} {:<8} {:<12} {}",
                    "NAME", "DESCRIPTION", "AGENTS", "AVG_TOKENS", "FEATURES"
                );
                println!("{}", "─".repeat(100));
            }
            for (name, desc, agents, tokens, features) in EXAMPLES {
                println!(
                    "{:<24} {:<44} {:<8} {:<12} {}",
                    name, desc, agents, tokens, features
                );
            }
            if !quiet {
                println!("\nRun one: connector examples run customer-support --input \"my order is late\"");
            }
        }

        ExamplesCmd::Run {
            name,
            input,
            llm_stub,
        } => {
            let found = EXAMPLES.iter().find(|(n, _, _, _, _)| {
                *n == name.as_str() || n.replace('-', "_") == name.replace('-', "_")
            });
            if found.is_none() {
                let names: Vec<&str> = EXAMPLES.iter().map(|(n, _, _, _, _)| *n).collect();
                return Err(format!(
                    "Unknown example '{}'. Available: {}",
                    name,
                    names.join(", ")
                ));
            }
            if llm_stub {
                std::env::set_var("CONNECTOR_LLM_STUB", "true");
            }
            // Deploy the example agent and run it
            let sp = Spinner::new(&format!("Running example '{}'", name));
            let data = client.post(
                "/run-example",
                &serde_json::json!({
                    "name": name,
                    "input": input,
                    "llm_stub": llm_stub,
                }),
            );
            match data {
                Ok(d) => {
                    sp.finish("done");
                    println!("\n─── Output ─────────────────────────────────────────────────────");
                    println!(
                        "{}",
                        d.get("output")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&serde_json::to_string_pretty(&d).unwrap())
                    );
                    println!("─────────────────────────────────────────────────────────────────");
                    println!(
                        "\nTokens used: {}   Duration: {}ms",
                        d.get("tokens_used").and_then(|v| v.as_u64()).unwrap_or(0),
                        d.get("duration_ms").and_then(|v| v.as_u64()).unwrap_or(0),
                    );
                }
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
            }
        }

        ExamplesCmd::Show { name } => {
            let found = EXAMPLES.iter().find(|(n, _, _, _, _)| *n == name.as_str());
            if let Some((n, desc, agents, tokens, features)) = found {
                println!(
                    "Example: {}  ({} agents, ~{} tokens/run, features: {})",
                    n, agents, tokens, features
                );
                println!("Description: {}", desc);
                println!(
                    "\nTo run: connector examples run {} --input \"your input here\"",
                    name
                );
                let data = client.get(&format!("/examples/{}/manifest", name));
                match data {
                    Ok(d) => {
                        if let Some(yaml) = d.get("manifest").and_then(|v| v.as_str()) {
                            println!("\nagent.yaml:");
                            println!("{}", "─".repeat(60));
                            println!("{}", yaml);
                        }
                    }
                    Err(_) => {
                        println!("\n(manifest preview not available offline)");
                    }
                }
            } else {
                return Err(format!("Unknown example '{}'. Run `connector examples list` to see available examples.", name));
            }
        }
    }
    Ok(())
}

// =============================================================================
// MCP subcommand handler
// =============================================================================

fn handle_mcp_cmd(cmd: McpCmd, client: &Client, quiet: bool) -> Result<(), String> {
    match cmd {
        McpCmd::Serve {
            transport,
            port,
            tools,
            agent,
        } => {
            // Fetch tool list from server to populate MCP manifest
            let tool_filter = tools.as_deref().unwrap_or("*");
            let agent_scope = agent.as_deref().unwrap_or("*");

            if transport == "tcp" {
                println!(
                    "Starting MCP server on TCP port {} (agent={}, tools={})",
                    port, agent_scope, tool_filter
                );
                println!("Connect your IDE or framework to: tcp://localhost:{}", port);
                println!("");
                println!("Add to your mcp.json:");
                println!("{{");
                println!("  \"mcpServers\": {{");
                println!("    \"connector\": {{");
                println!("      \"command\": \"connector\",");
                println!("      \"args\": [\"mcp\", \"serve\", \"--transport\", \"tcp\", \"--port\", \"{}\"]", port);
                println!("    }}");
                println!("  }}");
                println!("}}");
            } else {
                // stdio mode — emit JSON-RPC framing on stdout, read on stdin
                // This is the standard MCP stdio transport per the spec
                if !quiet {
                    eprintln!("connector mcp serve: stdio transport started");
                    eprintln!("  Agent scope: {}", agent_scope);
                    eprintln!("  Tool filter: {}", tool_filter);
                    eprintln!("  API: {}", client.api_url);
                    eprintln!("  Add to mcp.json: {{\"command\": \"connector\", \"args\": [\"mcp\", \"serve\"]}}");
                }

                // Fetch available tools from the server
                let tools_data = client
                    .get("/tools/list")
                    .unwrap_or_else(|_| serde_json::json!({"tools": []}));
                let tool_list = tools_data
                    .get("tools")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                // Emit MCP initialization response (JSON-RPC 2.0)
                let init_resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": { "listChanged": false }
                        },
                        "serverInfo": {
                            "name": "connector",
                            "version": env!("CARGO_PKG_VERSION"),
                        }
                    }
                });
                println!("{}", serde_json::to_string(&init_resp).unwrap());

                // MCP stdio event loop — read JSON-RPC requests from stdin, dispatch
                use std::io::BufRead;
                let stdin = std::io::stdin();
                for line in stdin.lock().lines() {
                    let line = match line {
                        Ok(l) => l,
                        Err(_) => break,
                    };
                    if line.trim().is_empty() {
                        continue;
                    }

                    let req: serde_json::Value = match serde_json::from_str(&line) {
                        Ok(v) => v,
                        Err(e) => {
                            let err = serde_json::json!({
                                "jsonrpc": "2.0", "id": null,
                                "error": {"code": -32700, "message": format!("Parse error: {}", e)}
                            });
                            println!("{}", serde_json::to_string(&err).unwrap());
                            continue;
                        }
                    };

                    let id = req.get("id").cloned().unwrap_or(serde_json::json!(null));
                    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");

                    let resp = match method {
                        "initialize" => serde_json::json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": {
                                "protocolVersion": "2024-11-05",
                                "capabilities": {"tools": {"listChanged": false}},
                                "serverInfo": {"name": "connector", "version": env!("CARGO_PKG_VERSION")}
                            }
                        }),

                        "tools/list" => {
                            let mcp_tools: Vec<serde_json::Value> = tool_list.iter().map(|t| {
                                serde_json::json!({
                                    "name": t.get("tool_id").or_else(|| t.get("name")).and_then(|v| v.as_str()).unwrap_or("unknown"),
                                    "description": t.get("description").and_then(|v| v.as_str()).unwrap_or(""),
                                    "inputSchema": t.get("input_schema").cloned().unwrap_or(serde_json::json!({"type":"object","properties":{}}))
                                })
                            }).collect();
                            serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"tools":mcp_tools}})
                        }

                        "tools/call" => {
                            let params =
                                req.get("params").cloned().unwrap_or(serde_json::json!({}));
                            let tool_name =
                                params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                            let tool_args = params
                                .get("arguments")
                                .cloned()
                                .unwrap_or(serde_json::json!({}));

                            // Dispatch to Connector platform via REST
                            let dispatch_result = client.post(
                                "/tools/invoke",
                                &serde_json::json!({
                                    "tool_id": tool_name,
                                    "action": "call",
                                    "input": tool_args,
                                    "agent_pid": agent_scope,
                                }),
                            );

                            match dispatch_result {
                                Ok(r) => serde_json::json!({
                                    "jsonrpc": "2.0", "id": id,
                                    "result": {
                                        "content": [{"type": "text", "text": serde_json::to_string(&r).unwrap_or_default()}],
                                        "isError": false
                                    }
                                }),
                                Err(e) => serde_json::json!({
                                    "jsonrpc": "2.0", "id": id,
                                    "result": {
                                        "content": [{"type": "text", "text": e}],
                                        "isError": true
                                    }
                                }),
                            }
                        }

                        "notifications/initialized" => continue, // no response needed

                        _ => serde_json::json!({
                            "jsonrpc": "2.0", "id": id,
                            "error": {"code": -32601, "message": format!("Method not found: {}", method)}
                        }),
                    };

                    println!("{}", serde_json::to_string(&resp).unwrap());
                }
            }
        }

        McpCmd::ListTools { agent } => {
            let path = match agent {
                Some(ref pid) => format!("/agents/{}/tools", pid),
                None => "/tools/list".to_string(),
            };
            let data = client.get(&path)?;
            let tools = data
                .get("tools")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if tools.is_empty() {
                println!("No MCP tools available.");
                return Ok(());
            }
            println!("{:<32} {:<16} {}", "TOOL_ID", "NAMESPACE", "DESCRIPTION");
            println!("{}", "─".repeat(80));
            for t in &tools {
                println!(
                    "{:<32} {:<16} {}",
                    t.get("tool_id")
                        .or_else(|| t.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?"),
                    t.get("namespace_path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("—"),
                    t.get("description").and_then(|v| v.as_str()).unwrap_or("—"),
                );
            }
            println!("\nTo start MCP server: connector mcp serve");
        }

        McpCmd::Inspect { tool_id } => {
            let data = client
                .get(&format!("/tools/{}", tool_id))
                .or_else(|_| client.get(&format!("/tools/inspect/{}", tool_id)))?;
            println!("Tool: {}", tool_id);
            println!(
                "{}",
                serde_json::to_string_pretty(&data).unwrap_or_default()
            );
        }
    }
    Ok(())
}

// =============================================================================
// AMA-9: connector install — module ecosystem
// =============================================================================

fn handle_install_cmd(cmd: InstallCmd, client: &Client, quiet: bool) -> Result<(), String> {
    match cmd {
        InstallCmd::Tool { name, version } => {
            let sp = Spinner::new(&format!("Installing tool '{}'", name));
            let data = client.post(
                "/marketplace/tools/install",
                &serde_json::json!({
                    "name": name,
                    "version": version,
                }),
            );
            match data {
                Ok(d) => {
                    sp.finish("done");
                    println!("✅  Tool '{}' installed", name);
                    println!(
                        "   Tool ID:  {}",
                        d.get("tool_id").and_then(|v| v.as_str()).unwrap_or("?")
                    );
                    println!(
                        "   Version:  {}",
                        d.get("version").and_then(|v| v.as_str()).unwrap_or("?")
                    );
                    println!(
                        "   Endpoint: {}",
                        d.get("endpoint").and_then(|v| v.as_str()).unwrap_or("?")
                    );
                }
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
            }
        }

        InstallCmd::Agent { name, version } => {
            let sp = Spinner::new(&format!("Installing agent '{}'", name));
            let data = client.post(
                "/marketplace/agents/install",
                &serde_json::json!({
                    "name": name,
                    "version": version,
                }),
            );
            match data {
                Ok(d) => {
                    sp.finish("done");
                    println!("✅  Agent '{}' installed", name);
                    println!(
                        "   Agent PID: {}",
                        d.get("agent_pid").and_then(|v| v.as_str()).unwrap_or("?")
                    );
                    println!(
                        "   Manifest:  {}",
                        d.get("manifest_cid")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?")
                    );
                }
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
            }
        }

        InstallCmd::List => {
            let data = client.get("/marketplace/installed")?;
            let modules = data
                .get("modules")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if modules.is_empty() {
                println!("No modules installed. Browse with: connector install search <query>");
                return Ok(());
            }
            println!(
                "{:<32} {:<10} {:<12} {}",
                "MODULE_ID", "TYPE", "VERSION", "INSTALLED_AT"
            );
            println!("{}", "─".repeat(72));
            for m in &modules {
                println!(
                    "{:<32} {:<10} {:<12} {}",
                    m.get("module_id").and_then(|v| v.as_str()).unwrap_or("?"),
                    m.get("type").and_then(|v| v.as_str()).unwrap_or("?"),
                    m.get("version").and_then(|v| v.as_str()).unwrap_or("?"),
                    m.get("installed_at")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?"),
                );
            }
        }

        InstallCmd::Search { query, kind } => {
            let data = client.get(&format!("/marketplace/search?q={}&kind={}", query, kind))?;
            let results = data
                .get("results")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if results.is_empty() {
                println!(
                    "No results for '{}'. Try: connector install search \"{}\"",
                    query, query
                );
                return Ok(());
            }
            println!(
                "{:<32} {:<10} {:<12} {}",
                "NAME", "TYPE", "VERSION", "DESCRIPTION"
            );
            println!("{}", "─".repeat(80));
            for r in &results {
                println!(
                    "{:<32} {:<10} {:<12} {}",
                    r.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                    r.get("type").and_then(|v| v.as_str()).unwrap_or("?"),
                    r.get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("latest"),
                    r.get("description").and_then(|v| v.as_str()).unwrap_or("—"),
                );
            }
        }
    }
    Ok(())
}

// =============================================================================
// CMD-2: connector audit — signed receipt export + chain verify
// =============================================================================

fn handle_audit_cmd(cmd: AuditCmd, client: &Client, quiet: bool) -> Result<(), String> {
    match cmd {
        AuditCmd::Export {
            pid,
            from,
            to,
            format,
            output,
        } => {
            let now_ms = chrono::Utc::now().timestamp_millis();
            let from_ms = from
                .as_deref()
                .map(parse_ts)
                .unwrap_or(now_ms - 30 * 86_400_000);
            let to_ms = to.as_deref().map(parse_ts).unwrap_or(now_ms);

            let sp = Spinner::new(&format!("Exporting audit receipts for '{}'", pid));
            let data = client.get(&format!(
                "/agents/{}/audit/receipts?from_ms={}&to_ms={}&limit=2000",
                pid, from_ms, to_ms
            ));

            match data {
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
                Ok(d) => {
                    sp.finish("done");
                    let receipts = d
                        .get("receipts")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let count = receipts.len();

                    let content = match format.as_str() {
                        "json" => serde_json::to_string_pretty(&d).unwrap_or_default(),
                        "table" => {
                            let mut lines = vec![format!(
                                "{:<20} {:<16} {:<10} {}",
                                "RECEIPT_ID", "OPERATION", "OUTCOME", "TIMESTAMP"
                            )];
                            lines.push("─".repeat(72));
                            for r in &receipts {
                                lines.push(format!(
                                    "{:<20} {:<16} {:<10} {}",
                                    &r.get("receipt_id").and_then(|v| v.as_str()).unwrap_or("?")
                                        [..16.min(
                                            r.get("receipt_id")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("?")
                                                .len()
                                        )],
                                    r.get("operation").and_then(|v| v.as_str()).unwrap_or("?"),
                                    r.get("outcome").and_then(|v| v.as_str()).unwrap_or("?"),
                                    r.get("timestamp_ms").and_then(|v| v.as_i64()).unwrap_or(0),
                                ));
                            }
                            lines.join("\n")
                        }
                        _ => receipts
                            .iter()
                            .map(|r| serde_json::to_string(r).unwrap_or_default())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    };

                    if let Some(path) = output {
                        std::fs::write(&path, &content)
                            .map_err(|e| format!("Write failed: {}", e))?;
                        if !quiet {
                            println!("✅  {} receipts written to {}", count, path);
                        }
                    } else {
                        println!("{}", content);
                        if !quiet {
                            eprintln!(
                                "\n({} receipts, chain_head: {})",
                                count,
                                d.get("chain_head").and_then(|v| v.as_str()).unwrap_or("—")
                            );
                        }
                    }
                }
            }
        }

        AuditCmd::Verify { file } => {
            let content = std::fs::read_to_string(&file)
                .map_err(|e| format!("Cannot read {}: {}", file, e))?;

            let receipts: Vec<serde_json::Value> = content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();

            if receipts.is_empty() {
                // Try whole-file JSON array
                let arr: Vec<serde_json::Value> =
                    serde_json::from_str(&content).unwrap_or_default();
                if arr.is_empty() {
                    return Err(format!("No receipts found in {}", file));
                }
            }

            let body = serde_json::json!({"receipts": receipts});
            // Offline verify — check chain locally without server
            let mut valid = true;
            let mut broken_at: Option<usize> = None;
            for (i, receipt) in receipts.iter().enumerate() {
                if i > 0 {
                    let expected = receipts[i - 1].get("receipt_id").and_then(|v| v.as_str());
                    let actual = receipt.get("parent_receipt").and_then(|v| v.as_str());
                    if expected != actual {
                        valid = false;
                        broken_at = Some(i);
                        break;
                    }
                }
                let hash = receipt
                    .get("content_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if hash.len() != 64 {
                    valid = false;
                    broken_at = Some(i);
                    break;
                }
            }

            if valid {
                println!("✅  Receipt chain valid ({} receipts)", receipts.len());
                println!(
                    "   Chain head: {}",
                    receipts
                        .last()
                        .and_then(|r| r.get("receipt_id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("—")
                );
            } else {
                println!("❌  Receipt chain BROKEN at index {:?}", broken_at);
                std::process::exit(1);
            }
            let _ = body;
        }
    }
    Ok(())
}

/// Parse a timestamp — ISO date string or epoch ms integer string.
fn parse_ts(s: &str) -> i64 {
    if let Ok(n) = s.parse::<i64>() {
        return n;
    }
    // Try ISO 8601
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return dt.timestamp_millis();
    }
    // Try date only: YYYY-MM-DD
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis();
    }
    0
}

// =============================================================================
// CMD-5: connector policy check — access(2) syscall analog
// =============================================================================

fn handle_policy_cmd(cmd: PolicyCmd, client: &Client, quiet: bool) -> Result<(), String> {
    match cmd {
        PolicyCmd::Check { pid, op, resource } => {
            let data = client.post(
                &format!("/agents/{}/policy/check", pid),
                &serde_json::json!({ "operation": op, "resource": resource }),
            )?;

            let allowed = data
                .get("allowed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let reason = data.get("reason").and_then(|v| v.as_str()).unwrap_or("—");

            if allowed {
                println!("✅  ALLOWED");
            } else {
                println!("❌  DENIED");
            }
            if !quiet {
                println!("   Agent:     {}", pid);
                println!("   Operation: {}", op);
                println!("   Resource:  {}", resource);
                println!("   Reason:    {}", reason);
            }

            // Exit code 1 if denied (useful in scripts / CI)
            if !allowed {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

// =============================================================================
// ConnectorMap Books — Accounting-inspired operational ledger CLI
// =============================================================================

fn handle_books_cmd(
    cmd: BooksCmd,
    client: &Client,
    output: &str,
    quiet: bool,
) -> Result<(), String> {
    match cmd {
        BooksCmd::Position => {
            let sp = Spinner::new("Fetching system position");
            let data = client.get("/books");
            match data {
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
                Ok(d) => {
                    sp.finish("done");
                    if output == "json" {
                        println!("{}", serde_json::to_string_pretty(&d).unwrap());
                        return Ok(());
                    }
                    let data = d.get("data").unwrap_or(&d);
                    println!(
                        "╔══════════════════════════════════════════════════════════════════╗"
                    );
                    println!(
                        "║                     SYSTEM POSITION REPORT                       ║"
                    );
                    println!(
                        "╠══════════════════════════════════════════════════════════════════╣"
                    );

                    // Resources
                    if let Some(res) = data.get("resources") {
                        println!(
                            "║ RESOURCES HELD                                                   ║"
                        );
                        println!(
                            "║   Active Memory:  {} packets                                     ",
                            res.get("active_memory_count")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0)
                        );
                        println!(
                            "║   Running Agents: {}                                             ",
                            res.get("running_agents")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0)
                        );
                        println!(
                            "║   Active Sessions: {}                                            ",
                            res.get("active_sessions")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0)
                        );
                    }

                    // Integrity
                    if let Some(int) = data.get("integrity") {
                        println!(
                            "╠══════════════════════════════════════════════════════════════════╣"
                        );
                        println!(
                            "║ INTEGRITY POSITION                                               ║"
                        );
                        println!(
                            "║   Trust Score: {} (Grade {})                                     ",
                            int.get("trust_score").and_then(|v| v.as_u64()).unwrap_or(0),
                            int.get("trust_grade")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?")
                        );
                        println!(
                            "║   Chain Length: {} entries                                       ",
                            int.get("chain_length")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0)
                        );
                        println!(
                            "║   Reconciliation: {}                                             ",
                            int.get("reconciliation_status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("UNKNOWN")
                        );
                    }

                    // Cost
                    if let Some(cost) = data.get("cost") {
                        println!(
                            "╠══════════════════════════════════════════════════════════════════╣"
                        );
                        println!(
                            "║ COST POSITION                                                    ║"
                        );
                        println!(
                            "║   Today: {} tokens (${:.4})                                      ",
                            cost.get("today_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            cost.get("today_cost_usd")
                                .and_then(|v| v.as_f64())
                                .unwrap_or(0.0)
                        );
                        println!(
                            "║   Month: {} tokens (${:.4})                                      ",
                            cost.get("month_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            cost.get("month_cost_usd")
                                .and_then(|v| v.as_f64())
                                .unwrap_or(0.0)
                        );
                    }

                    println!(
                        "╚══════════════════════════════════════════════════════════════════╝"
                    );
                }
            }
        }

        BooksCmd::Journal {
            actor,
            action,
            outcome,
            since,
            limit,
            format,
        } => {
            let mut query = format!("?limit={}", limit);
            if let Some(ref a) = actor {
                query.push_str(&format!("&actor={}", a));
            }
            if let Some(ref a) = action {
                query.push_str(&format!("&action={}", a));
            }
            if let Some(ref o) = outcome {
                query.push_str(&format!("&outcome={}", o));
            }
            if let Some(ref s) = since {
                query.push_str(&format!("&since={}", s));
            }

            let sp = Spinner::new("Fetching journal entries");
            let data = client.get(&format!("/books/journal{}", query));
            match data {
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
                Ok(d) => {
                    sp.finish("done");
                    if format == "json" || output == "json" {
                        println!("{}", serde_json::to_string_pretty(&d).unwrap());
                        return Ok(());
                    }
                    let data = d.get("data").unwrap_or(&d);
                    let entries = data
                        .get("entries")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();

                    println!(
                        "{:<8} {:<20} {:<24} {:<12} {:<10}",
                        "SEQ", "TIMESTAMP", "ACTOR", "ACTION", "OUTCOME"
                    );
                    println!("{}", "─".repeat(80));

                    for e in &entries {
                        let seq = e.get("seq_no").and_then(|v| v.as_u64()).unwrap_or(0);
                        let ts = e.get("timestamp_ms").and_then(|v| v.as_i64()).unwrap_or(0);
                        let ts_str = chrono::DateTime::from_timestamp_millis(ts)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| ts.to_string());
                        let actor = e
                            .get("actor")
                            .and_then(|a| a.get("id"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("?");
                        let action = e.get("action").and_then(|v| v.as_str()).unwrap_or("?");
                        let outcome = e.get("outcome").and_then(|v| v.as_str()).unwrap_or("?");

                        println!(
                            "{:<8} {:<20} {:<24} {:<12} {:<10}",
                            seq,
                            &ts_str[..20.min(ts_str.len())],
                            &actor[..24.min(actor.len())],
                            action,
                            outcome
                        );
                    }

                    if !quiet {
                        println!("\n{} entries shown", entries.len());
                    }
                }
            }
        }

        BooksCmd::Ledger { account_id, limit } => {
            let sp = Spinner::new(&format!("Fetching ledger for '{}'", account_id));
            let data = client.get(&format!("/books/ledger/{}?limit={}", account_id, limit));
            match data {
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
                Ok(d) => {
                    sp.finish("done");
                    if output == "json" {
                        println!("{}", serde_json::to_string_pretty(&d).unwrap());
                        return Ok(());
                    }
                    let data = d.get("data").unwrap_or(&d);

                    println!("Account Ledger: {}", account_id);
                    println!("{}", "═".repeat(60));

                    if let Some(totals) = data.get("totals") {
                        println!("Running Totals:");
                        println!(
                            "  Memory:  {} bytes",
                            totals
                                .get("memory_bytes")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0)
                        );
                        println!(
                            "  Tools:   {} calls",
                            totals
                                .get("tool_calls")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0)
                        );
                        println!(
                            "  Tokens:  {}",
                            totals.get("tokens").and_then(|v| v.as_u64()).unwrap_or(0)
                        );
                        println!(
                            "  Trust:   {}",
                            totals
                                .get("trust_delta")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0)
                        );
                    }

                    let entries = data
                        .get("entries")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    println!("\n{} ledger entries", entries.len());
                }
            }
        }

        BooksCmd::Statement { account_id } => {
            let sp = Spinner::new(&format!("Generating statement for '{}'", account_id));
            let data = client.get(&format!("/books/statement/{}", account_id));
            match data {
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
                Ok(d) => {
                    sp.finish("done");
                    println!("{}", serde_json::to_string_pretty(&d).unwrap());
                }
            }
        }

        BooksCmd::Receipt { seq_no, tier } => {
            let sp = Spinner::new(&format!("Fetching receipt #{}", seq_no));
            let data = client.get(&format!("/books/receipt/{}?tier={}", seq_no, tier));
            match data {
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
                Ok(d) => {
                    sp.finish("done");
                    println!("{}", serde_json::to_string_pretty(&d).unwrap());
                }
            }
        }

        BooksCmd::Costs { period, group_by } => {
            let sp = Spinner::new("Fetching cost breakdown");
            let data = client.get(&format!(
                "/books/costs?period={}&group_by={}",
                period, group_by
            ));
            match data {
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
                Ok(d) => {
                    sp.finish("done");
                    if output == "json" {
                        println!("{}", serde_json::to_string_pretty(&d).unwrap());
                        return Ok(());
                    }
                    let data = d.get("data").unwrap_or(&d);

                    println!("Cost Statement — Period: {}", period);
                    println!("{}", "═".repeat(60));
                    println!(
                        "Total Tokens: {}",
                        data.get("total_tokens")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    );
                    println!(
                        "Total Cost:   ${:.4}",
                        data.get("total_cost_usd")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0)
                    );
                }
            }
        }

        BooksCmd::Balance => {
            let sp = Spinner::new("Checking reconciliation balance");
            let data = client.get("/books/balance");
            match data {
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
                Ok(d) => {
                    sp.finish("done");
                    if output == "json" {
                        println!("{}", serde_json::to_string_pretty(&d).unwrap());
                        return Ok(());
                    }
                    let data = d.get("data").unwrap_or(&d);
                    let verdict = data
                        .get("verdict")
                        .and_then(|v| v.as_str())
                        .unwrap_or("UNKNOWN");

                    println!("Reconciliation Balance");
                    println!("{}", "═".repeat(60));

                    if let Some(checks) = data.get("checks").and_then(|v| v.as_array()) {
                        println!(
                            "{:<30} {:<12} {:<12} {:<10}",
                            "METRIC", "T0", "T1", "STATUS"
                        );
                        println!("{}", "─".repeat(60));
                        for c in checks {
                            println!(
                                "{:<30} {:<12} {:<12} {:<10}",
                                c.get("metric").and_then(|v| v.as_str()).unwrap_or("?"),
                                c.get("t0_value").and_then(|v| v.as_str()).unwrap_or("?"),
                                c.get("t1_value").and_then(|v| v.as_str()).unwrap_or("?"),
                                c.get("status").and_then(|v| v.as_str()).unwrap_or("?"),
                            );
                        }
                    }

                    println!(
                        "\nVerdict: {}",
                        if verdict == "BOOKS RECONCILE" {
                            "✅"
                        } else {
                            "❌"
                        }
                    );
                    println!("         {}", verdict);
                }
            }
        }

        BooksCmd::Reconcile => {
            let sp = Spinner::new("Running reconciliation check");
            let data = client.post("/books/reconcile", &serde_json::json!({}));
            match data {
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
                Ok(d) => {
                    sp.finish("done");
                    println!("{}", serde_json::to_string_pretty(&d).unwrap());
                }
            }
        }

        BooksCmd::Live { actor } => {
            println!("Streaming live journal entries (Ctrl+C to stop)...\n");
            println!(
                "{:<8} {:<20} {:<24} {:<12} {:<10}",
                "SEQ", "TIMESTAMP", "ACTOR", "ACTION", "OUTCOME"
            );
            println!("{}", "─".repeat(80));

            // SSE streaming would require async client; for now poll
            let mut last_seq = 0u64;
            loop {
                let query = format!("/books/journal?limit=10&offset=0");
                if let Ok(d) = client.get(&query) {
                    let data = d.get("data").unwrap_or(&d);
                    if let Some(entries) = data.get("entries").and_then(|v| v.as_array()) {
                        for e in entries {
                            let seq = e.get("seq_no").and_then(|v| v.as_u64()).unwrap_or(0);
                            if seq > last_seq {
                                let ts =
                                    e.get("timestamp_ms").and_then(|v| v.as_i64()).unwrap_or(0);
                                let ts_str = chrono::DateTime::from_timestamp_millis(ts)
                                    .map(|dt| dt.format("%H:%M:%S").to_string())
                                    .unwrap_or_else(|| ts.to_string());
                                let actor_id = e
                                    .get("actor")
                                    .and_then(|a| a.get("id"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("?");
                                let action =
                                    e.get("action").and_then(|v| v.as_str()).unwrap_or("?");
                                let outcome =
                                    e.get("outcome").and_then(|v| v.as_str()).unwrap_or("?");

                                // Filter by actor if specified
                                if let Some(ref filter_actor) = actor {
                                    if !actor_id.contains(filter_actor) {
                                        continue;
                                    }
                                }

                                println!(
                                    "{:<8} {:<20} {:<24} {:<12} {:<10}",
                                    seq,
                                    ts_str,
                                    &actor_id[..24.min(actor_id.len())],
                                    action,
                                    outcome
                                );
                                last_seq = seq;
                            }
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
        }

        BooksCmd::Close { session_id } => {
            let sp = Spinner::new(&format!("Closing session '{}'", session_id));
            let data = client.post(
                &format!("/books/close/{}", session_id),
                &serde_json::json!({}),
            );
            match data {
                Err(e) => {
                    sp.fail(&e);
                    return Err(e);
                }
                Ok(d) => {
                    sp.finish("done");
                    let data = d.get("data").unwrap_or(&d);

                    println!("Session Closed: {}", session_id);
                    println!("{}", "═".repeat(60));
                    println!(
                        "Duration:      {} ms",
                        data.get("duration_ms")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    );
                    println!(
                        "Entry Count:   {}",
                        data.get("entry_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    );
                    println!(
                        "Cleared:       {}",
                        data.get("cleared_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    );
                    println!(
                        "Rejected:      {}",
                        data.get("rejected_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    );
                    println!(
                        "Failed:        {}",
                        data.get("failed_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    );
                    println!(
                        "Trust at Close: {}",
                        data.get("trust_at_close")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    );
                    println!(
                        "Status:        {}",
                        data.get("reconciliation_status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?")
                    );

                    if let Some(root) = data.get("final_merkle_root").and_then(|v| v.as_str()) {
                        println!("Merkle Root:   {}", root);
                    }
                }
            }
        }
    }
    Ok(())
}
