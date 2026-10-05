//! `/console` — System Console.
//!
//! Every operator-reachable backend family that used to live only in `curl`
//! is declared once as an [`Op`] (method, path template, fields) and rendered
//! as a control card. Path fields substitute into `{...}` placeholders; query
//! fields append to the URL; the rest become the JSON body. Every response is
//! shown verbatim — no invented success states.
//!
//! `/api/v2` is on the V2 tab. Handlers that have no engine return HTTP 501
//! with `ok: false` — the card still exists so the operator sees the refusal.
//! Portal/payment/SCIM stay off this surface.

use leptos::prelude::*;
use serde_json::{json, Map, Value};
use wasm_bindgen_futures::spawn_local;

use crate::api;
use crate::auth::AuthState;
use crate::components::operator::primitives::{OpText, OpTextVariant};
use crate::ui_state::open_agent_explain;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Agent,
    Memory,
    Kernel,
    Infra,
    Safety,
    Economy,
    Intel,
    Comply,
    Lab,
    V2,
    Work,
    Mesh,
}

impl Tab {
    fn label(self) -> &'static str {
        match self {
            Tab::Agent => "Agent",
            Tab::Memory => "Memory",
            Tab::Kernel => "Kernel",
            Tab::Infra => "Infra",
            Tab::Safety => "Safety",
            Tab::Economy => "Economy",
            Tab::Intel => "Intel",
            Tab::Comply => "Comply",
            Tab::Lab => "Lab",
            Tab::V2 => "V2",
            Tab::Work => "Work",
            Tab::Mesh => "Mesh",
        }
    }
    fn code(self) -> &'static str {
        match self {
            Tab::Agent => "AGT",
            Tab::Memory => "MEM",
            Tab::Kernel => "KRN",
            Tab::Infra => "INF",
            Tab::Safety => "SAF",
            Tab::Economy => "ECO",
            Tab::Intel => "INT",
            Tab::Comply => "CMP",
            Tab::Lab => "LAB",
            Tab::V2 => "V2",
            Tab::Work => "WRK",
            Tab::Mesh => "MSH",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Where {
    /// Substitutes into a `{...}` placeholder in the path template.
    Path,
    /// Appended as a query string — the only form a GET can carry.
    Query,
    /// Goes into the JSON body.
    Body,
}

#[derive(Clone)]
struct Field {
    key: &'static str,
    label: &'static str,
    placeholder: &'static str,
    at: Where,
}

impl Field {
    const fn path(key: &'static str, label: &'static str, placeholder: &'static str) -> Self {
        Self { key, label, placeholder, at: Where::Path }
    }
    const fn query(key: &'static str, label: &'static str, placeholder: &'static str) -> Self {
        Self { key, label, placeholder, at: Where::Query }
    }
    const fn body(key: &'static str, label: &'static str, placeholder: &'static str) -> Self {
        Self { key, label, placeholder, at: Where::Body }
    }
}

#[derive(Clone)]
struct Op {
    method: &'static str,
    path: &'static str,
    label: &'static str,
    desc: &'static str,
    fields: Vec<Field>,
}

fn op(
    method: &'static str,
    path: &'static str,
    label: &'static str,
    desc: &'static str,
    fields: Vec<Field>,
) -> Op {
    Op { method, path, label, desc, fields }
}

const PID: Field = Field::path("pid", "Agent pid", "agent-pid");
const AGENT: Field = Field::path("agent_pid", "Agent pid", "agent-pid");
const ID: Field = Field::path("id", "Id", "id");
const PLUGIN: Field = Field::path("plugin_id", "Plugin id", "plugin-id");
const PROOF: Field = Field::path("proof_id", "Proof id", "prf-id");

fn agent_ops() -> Vec<Op> {
    vec![
        op("GET", "/agents/{pid}/verify", "Verify", "Integrity check for the agent.", vec![PID]),
        op("GET", "/agents/{pid}/cost", "Cost", "Accrued spend for this agent.", vec![PID]),
        op("GET", "/agents/{pid}/logs", "Logs", "Recent agent log lines.", vec![PID]),
        op("GET", "/agents/{pid}/events", "Events", "Kernel event stream slice.", vec![PID]),
        op("GET", "/agents/{pid}/skills", "Skills", "Registered skills.", vec![PID]),
        op("GET", "/agents/{pid}/residency", "Residency", "Where this agent is placed.", vec![PID]),
        op("GET", "/agents/{pid}/progeny", "Progeny", "Agents spawned by this one.", vec![PID]),
        op("GET", "/agents/progeny/tree", "Progeny tree", "Full lineage across the fleet.", vec![]),
        op("GET", "/agents/lifecycle/standard", "Lifecycle spec", "Canonical lifecycle states.", vec![]),
        op("POST", "/agents/{pid}/start", "Start", "Goes through the lifecycle gate.", vec![PID]),
        op("POST", "/agents/{pid}/resume", "Resume", "Blocked while quarantined.", vec![PID]),
        op("POST", "/agents/{pid}/freeze", "Freeze", "Suspend and hold state.", vec![PID]),
        op("POST", "/agents/{pid}/thaw", "Thaw", "Blocked while quarantined.", vec![PID]),
        op("POST", "/agents/{pid}/kill", "Kill", "Terminate the agent process.", vec![PID]),
        op(
            "POST",
            "/agents/{pid}/reset",
            "Reset",
            "Stops the agent and frees its slot. Refused if the lifecycle gate denies the stop.",
            vec![PID],
        ),
        op(
            "POST",
            "/agents/{pid}/quarantine",
            "Quarantine",
            "Isolates the agent. Start/resume/thaw all refuse afterwards.",
            vec![PID, Field::body("reason", "Reason", "why you are quarantining")],
        ),
        op(
            "POST",
            "/agents/{pid}/unquarantine",
            "Unquarantine",
            "Needs a linked HITL approval, or admin force with a reason.",
            vec![
                PID,
                Field::body("reason", "Reason", "justification"),
                Field::body("force", "Force (true/false)", "false"),
            ],
        ),
        op(
            "POST",
            "/agents/{pid}/signal",
            "Signal",
            "suspend · resume · terminate — routed through the lifecycle gate.",
            vec![PID, Field::body("signal", "Signal", "suspend")],
        ),
        op(
            "POST",
            "/agents/{pid}/clone",
            "Clone",
            "Fork this agent into a new pid.",
            vec![PID, Field::body("name", "New name", "clone-of-x")],
        ),
        op(
            "POST",
            "/agents/{pid}/migrate",
            "Migrate",
            "Move the agent to another cell.",
            vec![PID, Field::body("target_cell", "Target cell", "cell-id")],
        ),
        op(
            "PATCH",
            "/agents/{pid}/budget",
            "Set budget",
            "Adjust the spend ceiling.",
            vec![PID, Field::body("limit_usd", "Limit USD", "25.0")],
        ),
        op("POST", "/agents/{pid}/reset-budget", "Reset budget", "Zero the accrued spend.", vec![PID]),
        op(
            "POST",
            "/agents/{pid}/clearance",
            "Set clearance",
            "Change the agent's clearance band.",
            vec![PID, Field::body("clearance", "Clearance", "standard")],
        ),
        op(
            "POST",
            "/agents/{pid}/trust",
            "Set trust",
            "Adjust the trust score input.",
            vec![PID, Field::body("score", "Score", "0.8")],
        ),
        op(
            "POST",
            "/agents/{pid}/policy/check",
            "Policy check",
            "Dry-run a policy decision for this agent.",
            vec![PID, Field::body("operation", "Operation", "llm.chat")],
        ),
        op("GET", "/agents/{pid}/episodes", "Episodes", "Episode history.", vec![PID]),
        op(
            "POST",
            "/agents/{pid}/episodes",
            "Open episode",
            "Start a new episode.",
            vec![PID, Field::body("title", "Title", "episode title")],
        ),
        op(
            "POST",
            "/agents/{pid}/episodes/{episode_id}/close",
            "Close episode",
            "Seal an open episode.",
            vec![PID, Field::path("episode_id", "Episode id", "ep-id")],
        ),
        op("POST", "/agents/{pid}/reflect", "Reflect", "Trigger a reflection pass.", vec![PID]),
        op("GET", "/agents/{pid}/audit/receipts", "Audit receipts", "Receipt chain.", vec![PID]),
        op("POST", "/agents/{pid}/audit/receipts/verify", "Verify receipts", "Recompute the chain.", vec![PID]),
        op("GET", "/agents/{pid}/memory/stats", "Memory stats", "Packet + token counters.", vec![PID]),
        op("GET", "/agents/{pid}/memory/tree", "Memory tree", "Hierarchical memory view.", vec![PID]),
        op(
            "POST",
            "/agents/{pid}/memory/search",
            "Memory search",
            "Search this agent's memory.",
            vec![PID, Field::body("query", "Query", "search terms")],
        ),
        op("POST", "/agents/{pid}/memory/compact", "Compact memory", "Compact the agent's store.", vec![PID]),
        op(
            "POST",
            "/agents/{pid}/memory/purge",
            "Purge memory",
            "Destructive. Removes packets for this agent.",
            vec![PID, Field::body("confirm", "Confirm (true)", "true")],
        ),
        op(
            "DELETE",
            "/agents/{pid}/data",
            "Delete agent data",
            "Destructive. Right-to-erasure path.",
            vec![PID],
        ),
        op(
            "POST",
            "/agents/{pid}/kill-switch",
            "Kill-switch",
            "Interrupt generation and kill the agent. Timed.",
            vec![PID],
        ),
        op(
            "POST",
            "/agents/{pid}/cease",
            "SpendCease",
            "Fence generation + void ctx_tok + reap workers. Model desire irrelevant; cancel tax may remain.",
            vec![PID],
        ),
        op(
            "GET",
            "/agents/{pid}/expometer",
            "Expometer",
            "Authority (cease/quarantine/pause) + world grants + LLM mode/inflight — one operator snapshot.",
            vec![PID],
        ),
        op("GET", "/spend/burn/{pid}", "Spend burn meter", "Live remaining usd/tokens/hops + inflight LLM (admit ledger ≠ invoice).", vec![PID]),
        op("GET", "/spend/ceiling/{pid}", "Spend ceiling", "Current generation SpendCeiling snapshot.", vec![PID]),
        op("GET", "/spend/cease/latest/{pid}", "Latest CeaseReceipt", "Pointer to the latest SpendCease receipt for this agent.", vec![PID]),
        op("GET", "/aipsprt/schema", "AiPassport schema", "AiPassport + SpendCease schema honesty.", vec![]),
        op("GET", "/aipsprt/{passport_id}", "AiPassport get", "Public leave-behind passport (no private map).", vec![Field::path("passport_id", "Passport id", "aipsprt_…")]),
        op(
            "GET",
            "/aipsprt/private/{passport_id}",
            "AiPassport private",
            "Tenant forensic map (operator auth).",
            vec![Field::path("passport_id", "Passport id", "aipsprt_…")],
        ),
        op(
            "GET",
            "/aipsprt/index/digest/{digest}",
            "AiPassport digest index",
            "Auth-only postings list — not a public existence oracle.",
            vec![Field::path("digest", "Payload digest hex", "sha256hex")],
        ),
        op(
            "GET",
            "/aipsprt/{passport_id}/c2pa-map",
            "AiPassport C2PA map",
            "Thin Content Credentials export sketch (not an embedded manifest).",
            vec![Field::path("passport_id", "Passport id", "aipsprt_…")],
        ),
        op(
            "POST",
            "/aipsprt/verify",
            "AiPassport verify",
            "Federated Ed25519 verify against this node pubkey.",
            vec![
                Field::body("passport", "Passport JSON", "{}"),
                Field::body("payload_digest", "Payload digest (optional)", ""),
            ],
        ),
        op("GET", "/agents/{pid}/memory", "Memory list", "Packets currently held by this agent.", vec![PID]),
        op("GET", "/agents/{pid}/memory/os", "Memory OS", "OS-plane memory view for this agent.", vec![PID]),
        op("GET", "/agents/{pid}/contract", "Contract", "Identity contract currently bound.", vec![PID]),
        op("GET", "/agents/{pid}/compliance-contract", "Compliance contract", "Compliance contract for this agent.", vec![PID]),
        op("GET", "/agents/{pid}/identity-envelope", "Identity envelope", "Activation + identity envelope.", vec![PID]),
        op("POST", "/agents/{pid}/activate", "Activate", "Activate a provisioned agent.", vec![PID]),
        op("GET", "/agents/{pid}/capabilities", "Capabilities", "Declared capabilities.", vec![PID]),
        op("GET", "/agents/{pid}/grants", "Grants", "Capability grants on this agent.", vec![PID]),
        op("GET", "/agents/{pid}/knot/summary", "Knot summary", "Identity knot rollup.", vec![PID]),
        op("GET", "/agents/{pid}/forensic/universal", "Forensic universal", "Universal forensic snapshot.", vec![PID]),
        op("GET", "/agents/{pid}/edge", "Agent edge", "Edge binding for this agent.", vec![PID]),
        op("GET", "/agents/{pid}/chat/threads", "Chat threads", "Operator chat threads.", vec![PID]),
        op("GET", "/agents/{pid}/setup", "Setup record", "Identity setup currently stored.", vec![PID]),
        op("GET", "/agents", "List agents", "Kernel agent inventory.", vec![]),
        op("GET", "/agents/{pid}/audit/pdf", "Agent isolation PDF", "Per-agent FS/net/VM/broker proof PDF.", vec![PID]),
        op("GET", "/agents/{pid}/audit/isolation", "Agent isolation JSON", "Same isolation packet as JSON.", vec![PID]),
        op("GET", "/compliance/brief/pdf", "Compliance brief PDF", "System data-boundary brief PDF.", vec![]),
        op("GET", "/compliance/report/pdf", "Compliance report PDF", "Full TSC/NIST workpaper PDF.", vec![]),
        op("POST", "/agents/{pid}/quarantine", "Quarantine agent brain", "LLM broker / brain quarantine (≠ TraceTramp).", vec![PID]),
        op("POST", "/agents/{pid}/unquarantine", "Unquarantine agent", "Resume Talk on new broker epoch (200).", vec![PID]),
        op("GET", "/substrate/status", "Substrate status", "Linux bar + LLM governance posture.", vec![]),
        op("GET", "/runtime/enforcement", "Runtime enforcement", "Effect exclusivity / sandbox refuse.", vec![]),
        op("GET", "/agents/sot-status", "SoT status", "Source-of-truth agent table.", vec![]),
        op("POST", "/agents/{pid}/pause", "Pause", "Pause the agent.", vec![PID]),
        op("GET", "/agents/{pid}/activity", "Activity", "Recent activity for this agent.", vec![PID]),
        op("GET", "/agents/{pid}/traces", "Traces", "Trace ids for this agent.", vec![PID]),
        op("GET", "/agents/{pid}/hitl/pending", "HITL pending", "Human-in-the-loop queue.", vec![PID]),
        op(
            "POST",
            "/agents/{pid}/hitl/{id}/approve",
            "HITL approve",
            "Approve a pending HITL item.",
            vec![PID, Field::path("id", "HITL id", "hitl-id")],
        ),
        op(
            "POST",
            "/agents/{pid}/hitl/{id}/deny",
            "HITL deny",
            "Deny a pending HITL item.",
            vec![PID, Field::path("id", "HITL id", "hitl-id")],
        ),
    ]
}

fn memory_ops() -> Vec<Op> {
    vec![
        op("GET", "/context/status", "Context fleet", "Every tracked agent, worst context pressure first.", vec![]),
        op(
            "GET",
            "/context/{pid}/budget",
            "Context budget",
            "Tokens used vs ceiling for one agent.",
            vec![PID],
        ),
        op(
            "POST",
            "/context/{pid}/compress",
            "Compress context",
            "Give a target utilisation % or an absolute token count to free.",
            vec![
                PID,
                Field::body("target_utilization_pct", "Target utilisation %", "60"),
                Field::body("target_tokens", "or tokens to free", ""),
            ],
        ),
        op(
            "POST",
            "/context/{pid}/flush",
            "Flush context",
            "Clears the window. Snapshots first unless you purge ephemeral state.",
            vec![
                PID,
                Field::body("purge_ephemeral", "Purge ephemeral (true/false)", "false"),
            ],
        ),
        op("POST", "/context/{pid}/snapshot", "Snapshot context", "Persist a context snapshot.", vec![PID]),
        op("GET", "/context/{pid}/snapshots", "Context snapshots", "Stored snapshots.", vec![PID]),
        op(
            "POST",
            "/context/{pid}/restore/{snapshot_id}",
            "Restore snapshot",
            "Restore a named snapshot.",
            vec![PID, Field::path("snapshot_id", "Snapshot id", "snap-id")],
        ),
        op("POST", "/context/{pid}/resume", "Resume context", "Resume after snapshot.", vec![PID]),
        op("GET", "/context/{pid}/pressure", "Context pressure", "Pressure reading.", vec![PID]),
        op("POST", "/context/{pid}/evict", "Evict context", "Evict window contents.", vec![PID]),
        op("GET", "/memory/agents", "Memory agents", "Agents with memory rows.", vec![]),
        op(
            "GET",
            "/memory/search",
            "Memory search (GET)",
            "Query-string search across packets.",
            vec![Field::query("q", "Query", "search terms")],
        ),
        op("GET", "/memory/objects", "Memory objects", "Object-fabric listing.", vec![]),
        op(
            "POST",
            "/context/{pid}/assemble",
            "Assembly preview",
            "Scores the agent's real context window against a query, best-first within budget.",
            vec![
                PID,
                Field::body("query", "Query", "what would be retrieved"),
                Field::body("budget_tokens", "Budget tokens", "8000"),
            ],
        ),
        op("GET", "/memory/plane/overview", "Plane overview", "Whole memory plane at a glance.", vec![]),
        op("GET", "/memory/plane/context-efficiency", "Context efficiency", "How well context is used.", vec![]),
        op("GET", "/memory/stale-analysis", "Stale analysis", "Fleet-wide staleness.", vec![]),
        op(
            "GET",
            "/memory/stale/{agent_pid}",
            "Stale (agent)",
            "Stale packets for one agent.",
            vec![Field::path("agent_pid", "Agent pid", "agent-pid")],
        ),
        op(
            "GET",
            "/memory/context-pressure/{agent_pid}",
            "Context pressure",
            "How close to the context ceiling.",
            vec![Field::path("agent_pid", "Agent pid", "agent-pid")],
        ),
        op(
            "GET",
            "/memory/interference/{agent_pid}",
            "Interference",
            "Cross-memory interference signal.",
            vec![Field::path("agent_pid", "Agent pid", "agent-pid")],
        ),
        op(
            "POST",
            "/memory/consolidate/{agent_pid}",
            "Consolidate",
            "Merge related packets.",
            vec![Field::path("agent_pid", "Agent pid", "agent-pid")],
        ),
        op(
            "POST",
            "/memory/enrich/{agent_pid}",
            "Enrich",
            "Run enrichment over the agent's memory.",
            vec![Field::path("agent_pid", "Agent pid", "agent-pid")],
        ),
        op(
            "POST",
            "/memory/optimize-context/{agent_pid}",
            "Optimize context",
            "Recompute the working context.",
            vec![Field::path("agent_pid", "Agent pid", "agent-pid")],
        ),
        op(
            "GET",
            "/memory/region/{agent_pid}",
            "Region",
            "Memory region for an agent.",
            vec![Field::path("agent_pid", "Agent pid", "agent-pid")],
        ),
        op(
            "POST",
            "/memory/region/configure",
            "Configure region",
            "Resize / retune a region.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("size_mb", "Size MB", "256"),
            ],
        ),
        op(
            "POST",
            "/memory/eviction-policy",
            "Eviction policy",
            "Set how memory is evicted under pressure.",
            vec![Field::body("policy", "Policy", "lru")],
        ),
        op(
            "GET",
            "/memory/tier/distribution/{agent_pid}",
            "Tier distribution",
            "Hot / warm / cold split.",
            vec![Field::path("agent_pid", "Agent pid", "agent-pid")],
        ),
        op(
            "POST",
            "/memory/tier/change",
            "Change tier",
            "Move a packet between tiers.",
            vec![
                Field::body("cid", "Packet CID", "cid"),
                Field::body("tier", "Tier", "warm"),
            ],
        ),
        op(
            "GET",
            "/memory/packets/{cid}",
            "Packet",
            "Read one memory packet.",
            vec![Field::path("cid", "Packet CID", "cid")],
        ),
        op(
            "POST",
            "/memory/packets/{cid}/pin",
            "Pin packet",
            "Protect from eviction.",
            vec![Field::path("cid", "Packet CID", "cid")],
        ),
        op(
            "POST",
            "/memory/packets/{cid}/unpin",
            "Unpin packet",
            "Allow eviction again.",
            vec![Field::path("cid", "Packet CID", "cid")],
        ),
        op(
            "POST",
            "/memory/packets/{cid}/seal",
            "Seal packet",
            "Make immutable.",
            vec![Field::path("cid", "Packet CID", "cid")],
        ),
        op("GET", "/memory/graph/entities", "Graph entities", "Knowledge-graph entities.", vec![]),
        op(
            "POST",
            "/memory/graph/entity",
            "Add entity",
            "Create a graph entity.",
            vec![
                Field::body("name", "Name", "entity name"),
                Field::body("kind", "Kind", "person"),
            ],
        ),
        op(
            "POST",
            "/memory/graph/edge",
            "Add edge",
            "Relate two entities. This is how the address relation graph pillar gets satisfied.",
            vec![
                Field::body("from", "From", "entity or agent id"),
                Field::body("to", "To", "entity or address"),
                Field::body("relation", "Relation", "uses"),
            ],
        ),
        op(
            "GET",
            "/memory/graph/neighbors/{entity_id}",
            "Neighbors",
            "Adjacent graph nodes.",
            vec![Field::path("entity_id", "Entity id", "entity-id")],
        ),
        op(
            "POST",
            "/memory/graph/seed",
            "Seed graph",
            "Bootstrap graph structure.",
            vec![Field::body("agent_pid", "Agent pid", "agent-pid")],
        ),
        op(
            "POST",
            "/memory/knowledge/ingest",
            "Ingest knowledge",
            "Add source material to the knowledge plane.",
            vec![
                Field::body("source", "Source", "url or label"),
                Field::body("content", "Content", "text"),
            ],
        ),
        op(
            "POST",
            "/memory/knowledge/query",
            "Query knowledge",
            "Ask the knowledge plane.",
            vec![Field::body("query", "Query", "question")],
        ),
        op("POST", "/memory/knowledge/compile", "Compile knowledge", "Rebuild derived knowledge.", vec![]),
        op("GET", "/memory/sessions/list", "Sessions", "Open memory sessions.", vec![]),
        op(
            "POST",
            "/memory/sessions",
            "Open session",
            "Start a memory session.",
            vec![Field::body("agent_pid", "Agent pid", "agent-pid")],
        ),
        op(
            "POST",
            "/memory/sessions/{session_id}/close",
            "Close session",
            "Seal a memory session.",
            vec![Field::path("session_id", "Session id", "session-id")],
        ),
        op(
            "POST",
            "/memory/share",
            "Share memory",
            "Grant another agent access.",
            vec![
                Field::body("from_agent", "From agent", "agent-pid"),
                Field::body("to_agent", "To agent", "agent-pid"),
            ],
        ),
        op(
            "POST",
            "/memory/access/revoke",
            "Revoke access",
            "Withdraw a memory share.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("target", "Target", "agent-pid"),
            ],
        ),
        op("GET", "/memory/vector-box", "Vector box", "Vector index status.", vec![]),
        op("GET", "/memory/semantic-search", "Semantic search", "Vector search across memory.", vec![]),
    ]
}

fn kernel_ops() -> Vec<Op> {
    vec![
        op("GET", "/kernel/status", "Kernel status", "Core kernel posture.", vec![]),
        op("GET", "/health", "Health rollup", "Kernel plus every enabled plugin, worst status wins.", vec![]),
        op("GET", "/kernel/profiles", "Profiles", "Kernel profiles in use.", vec![]),
        op(
            "GET",
            "/plugins/tier-scheduler",
            "Tier scheduler",
            "Plugin-side scheduler view: cgroup v2 scan and the guest idle-suspend hint.",
            vec![],
        ),
        op("GET", "/kernel/cage-manifest", "Cage manifest", "Isolation manifest.", vec![]),
        op("GET", "/kernel/supervisor/inventory", "Supervisor inventory", "What the supervisor owns.", vec![]),
        op(
            "GET",
            "/kernel/agents/{pid}/status",
            "Agent kernel status",
            "Kernel-side view of one agent.",
            vec![PID],
        ),
        op(
            "POST",
            "/kernel/agents/{pid}/attach",
            "Attach",
            "Attach the agent to a kernel slot.",
            vec![PID],
        ),
        op(
            "POST",
            "/kernel/agents/{pid}/release",
            "Release",
            "Release the kernel slot.",
            vec![PID],
        ),
        op("GET", "/kernel/microvm/cells", "MicroVM cells", "Cell inventory.", vec![]),
        op("GET", "/kernel/microvm/shards", "MicroVM shards", "Shard layout.", vec![]),
        op("GET", "/kernel/microvm/topology", "MicroVM topology", "Placement topology.", vec![]),
        op("GET", "/kernel/microvm/rollup", "MicroVM rollup", "Aggregate usage.", vec![]),
        op("GET", "/kernel/microvm/carpenter-plan", "Carpenter plan", "Planned placement changes.", vec![]),
        op(
            "GET",
            "/kernel/microvm/agents/{pid}/usage",
            "MicroVM usage",
            "Per-agent cell usage.",
            vec![PID],
        ),
        op(
            "POST",
            "/kernel/microvm/agents/{pid}/schedule",
            "Schedule",
            "Place the agent on a cell.",
            vec![PID, Field::body("cell", "Cell", "cell-id")],
        ),
        op("GET", "/kernel/plugin-condos", "Plugin condos", "Shared plugin hosts.", vec![]),
        op("GET", "/kernel/plugin-condos/placement", "Condo placement", "Current placement.", vec![]),
        op("GET", "/kernel/plugin-condos/placement-plan", "Condo plan", "Proposed placement.", vec![]),
        op(
            "POST",
            "/kernel/plugin-condos/create",
            "Create condo",
            "Provision a plugin condo.",
            vec![Field::body("name", "Name", "condo name")],
        ),
        op(
            "POST",
            "/kernel/plugin-condos/assign",
            "Assign condo",
            "Move a plugin into a condo.",
            vec![
                Field::body("plugin_id", "Plugin id", "devguard"),
                Field::body("condo", "Condo", "condo-id"),
            ],
        ),
        op("GET", "/kernel/plugin-crash-recovery/status", "Crash recovery", "Plugin crash state.", vec![]),
        op(
            "GET",
            "/kernel/plugin-crash-recovery/{plugin_id}/status",
            "Crash state (plugin)",
            "One plugin's crash history.",
            vec![Field::path("plugin_id", "Plugin id", "devguard")],
        ),
        op(
            "POST",
            "/kernel/plugin-crash-recovery/unquarantine",
            "Unquarantine plugin",
            "Release a crash-quarantined plugin.",
            vec![Field::body("plugin_id", "Plugin id", "devguard")],
        ),
        op(
            "POST",
            "/kernel/plugin-crash-recovery/clear",
            "Clear crash record",
            "Reset the crash counter.",
            vec![Field::body("plugin_id", "Plugin id", "devguard")],
        ),
        op("GET", "/kernel/plugin-tier-scheduler", "Tier scheduler", "Plugin tier scheduling.", vec![]),
        op("GET", "/kernel/aios/fleet", "AIOS fleet", "Fleet view.", vec![]),
        op("GET", "/kernel/aios/modules", "AIOS modules", "Loaded modules.", vec![]),
        op("GET", "/kernel/aios/infra", "AIOS infra", "Infrastructure view.", vec![]),
        op("GET", "/kernel/aios/crossings", "AIOS crossings", "Boundary crossings.", vec![]),
        op("GET", "/kernel/aios/claim-readiness", "Claim readiness", "What the node can honestly claim.", vec![]),
        op("GET", "/kernel/aios/absorb", "AIOS absorb", "Absorb/readiness surface.", vec![]),
        op(
            "POST",
            "/kernel/aios/operate",
            "AIOS operate",
            "interrupt · retrieve · compensate. Stop stays kill-switch.",
            vec![
                Field::body("op", "Op", "interrupt"),
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("args", "Args JSON (optional)", "{}"),
            ],
        ),
        op("GET", "/kernel/address-dac", "Address DAC index", "Per-address rules + HITL preview.", vec![Field::query("address", "Address (optional)", "")]),
        op(
            "GET",
            "/kernel/address-dac/contract",
            "Address DAC contract",
            "Rules and HITL contracts for one address.",
            vec![Field::query("address", "Address", "local:host")],
        ),
        op(
            "PUT",
            "/kernel/address-dac/rules",
            "Put address rules",
            "Capability allow/block for an address. Admin.",
            vec![
                Field::body("address", "Address", "local:host"),
                Field::body("default_effect", "Default effect (optional)", "allow"),
                Field::body("allowed_tools", "Allowed tools JSON", "[]"),
                Field::body("denied_tools", "Denied tools JSON", "[]"),
            ],
        ),
        op(
            "PUT",
            "/kernel/address-dac/hitl",
            "Put address HITL",
            "Human gate none/ask/root/block. Admin.",
            vec![
                Field::body("address", "Address", "local:host"),
                Field::body("default_policy", "Default policy (optional)", "ask"),
                Field::body("tools", "Tools JSON (optional)", "[]"),
            ],
        ),
        op(
            "POST",
            "/kernel/address-dac/simulate",
            "Simulate address DAC",
            "Dry-run preview. Does not persist a seal.",
            vec![
                Field::body("address", "Address", "local:host"),
                Field::body("tools", "Tools JSON (optional)", "[]"),
            ],
        ),
        op(
            "POST",
            "/kernel/address-dac/unseal",
            "Unseal address DAC",
            "Requires kernel root passcode.",
            vec![
                Field::body("address", "Address", "local:host"),
                Field::body("tool", "Tool", "tool-id"),
                Field::body("root_passcode", "Root passcode", ""),
            ],
        ),
        op("GET", "/adaptive/status", "Adaptive status", "Adaptive scheduler posture.", vec![]),
        op("GET", "/adaptive/decisions", "Adaptive decisions", "Recent adaptive decisions.", vec![]),
        op("GET", "/adaptive/agents/{pid}/config", "Adaptive config", "Per-agent adaptive config.", vec![PID]),
        op(
            "PUT",
            "/adaptive/agents/{pid}/config",
            "Set adaptive config",
            "Write per-agent adaptive config.",
            vec![PID, Field::body("config", "Config JSON", "{}")],
        ),
        op(
            "GET",
            "/kernel/aios/cell/{pid}",
            "AIOS cell",
            "Cell detail for an agent.",
            vec![PID],
        ),
        op("GET", "/substrate/admission/matrix", "Admission matrix", "Every admission layer at once.", vec![]),
    ]
}

fn infra_ops() -> Vec<Op> {
    vec![
        // ── Native observability ──
        op("GET", "/monitor/native", "Native telemetry", "In-process ring buffer: RPS, p95, error rate, microVM rollup.", vec![]),
        op("GET", "/monitor/native/charts", "Chart presets", "Available native charts and which are pinned.", vec![]),
        op(
            "POST",
            "/monitor/native/charts/pins",
            "Pin chart",
            "Pin or unpin a native chart for the monitor page.",
            vec![
                Field::body("chart_id", "Chart id", "rps_1m"),
                Field::body("pinned", "Pinned (true/false)", "true"),
            ],
        ),
        op("GET", "/monitor/alerts", "Alert rules", "Config + dynamic alert rules.", vec![]),
        op(
            "POST",
            "/monitor/alert-rules",
            "Create alert rule",
            "Persist a dynamic rule. Admin+.",
            vec![
                Field::body("name", "Name", "high-error"),
                Field::body("condition", "Condition", "error_rate > 0.05"),
                Field::body("channels", "Channels JSON (optional)", "[]"),
                Field::body("cooldown_secs", "Cooldown secs (optional)", "300"),
            ],
        ),
        op(
            "PUT",
            "/monitor/alert-rules/{rule_id}",
            "Update alert rule",
            "Patch a dynamic rule. Admin+.",
            vec![
                Field::path("rule_id", "Rule id", "rule_…"),
                Field::body("name", "Name (optional)", ""),
                Field::body("condition", "Condition (optional)", ""),
                Field::body("cooldown_secs", "Cooldown secs (optional)", ""),
            ],
        ),
        op(
            "DELETE",
            "/monitor/alert-rules/{rule_id}",
            "Delete alert rule",
            "Remove a dynamic rule. Admin+.",
            vec![Field::path("rule_id", "Rule id", "rule_…")],
        ),
        // ── Hub mirrors ──
        op("GET", "/settings/hub-mirrors", "Hub mirrors", "Persisted mirror list and the effective URLs in use.", vec![]),
        op(
            "POST",
            "/settings/hub-mirrors",
            "Set hub mirrors",
            "Order is priority. Admin only.",
            vec![Field::body("urls", "URLs (JSON array)", "[\"https://hub.example\"]")],
        ),
        // ── Plugin supply chain ──
        op(
            "GET",
            "/plugins/marketplace",
            "Marketplace entry",
            "Published versions, manifests and readme for one plugin.",
            vec![Field::query("plugin_id", "Plugin id", "vendor/slug")],
        ),
        op(
            "GET",
            "/plugins/egress-allowlist",
            "Egress allowlist",
            "Outbound hosts the active version's manifest permits.",
            vec![Field::query("plugin_id", "Plugin id", "vendor/slug")],
        ),
        op(
            "GET",
            "/plugins/tracetramp/admin/quarantine/all",
            "Quarantine (all)",
            "Every tracetramp quarantine, not just the active page.",
            vec![],
        ),
        // ── Author portal ──
        op("GET", "/authoring/stats", "Author stats", "Publish events, tokens and namespace claims.", vec![]),
        op("GET", "/authoring/tokens", "Author tokens", "Minted publish tokens (hashes only).", vec![]),
        op(
            "POST",
            "/authoring/tokens",
            "Mint author token",
            "Returned once and never again — copy it immediately.",
            vec![
                Field::body("label", "Label", "ci-publisher"),
                Field::body("vendor", "Vendor", "vendor"),
            ],
        ),
        op(
            "DELETE",
            "/authoring/tokens/{token_id}",
            "Revoke token",
            "Revokes a publish token.",
            vec![Field::path("token_id", "Token id", "token-id")],
        ),
        op("GET", "/authoring/namespaces", "Namespace claims", "Claimed vendor namespaces.", vec![]),
        op(
            "POST",
            "/authoring/namespaces",
            "Claim namespace",
            "Reserve a vendor namespace for publishing.",
            vec![Field::body("vendor", "Vendor", "vendor")],
        ),
        // ── Compliance ──
        op(
            "GET",
            "/compliance/eu_ai_act/transparency_report",
            "EU AI Act transparency",
            "Audit-log-backed transparency record over a period. Developer+.",
            vec![],
        ),
        op("GET", "/infra/cells/status", "Cells status", "Cell health.", vec![]),
        op(
            "POST",
            "/infra/cells/route",
            "Route to cell",
            "Force a routing decision.",
            vec![Field::body("target", "Target", "cell-id")],
        ),
        op("GET", "/infra/router/cells", "Router cells", "Router's cell table.", vec![]),
        op(
            "POST",
            "/infra/router/route",
            "Router route",
            "Ask the router to place a request.",
            vec![Field::body("key", "Key", "routing key")],
        ),
        op("GET", "/infra/quota", "Quotas", "All namespace quotas.", vec![]),
        op(
            "GET",
            "/infra/quota/{namespace}",
            "Quota (namespace)",
            "One namespace's quota.",
            vec![Field::path("namespace", "Namespace", "default")],
        ),
        op(
            "POST",
            "/infra/quota/set",
            "Set quota",
            "Change a namespace quota.",
            vec![
                Field::body("namespace", "Namespace", "default"),
                Field::body("limit", "Limit", "1000"),
            ],
        ),
        op("GET", "/infra/consensus/status", "Consensus status", "Quorum health.", vec![]),
        op(
            "POST",
            "/infra/consensus/propose",
            "Propose",
            "Submit a consensus proposal.",
            vec![Field::body("proposal", "Proposal", "payload")],
        ),
        op(
            "POST",
            "/infra/consensus/vote",
            "Vote",
            "Vote on a proposal.",
            vec![
                Field::body("proposal_id", "Proposal id", "id"),
                Field::body("vote", "Vote", "yes"),
            ],
        ),
        op("GET", "/infra/reputation/scores", "Reputation scores", "Fleet reputation.", vec![]),
        op(
            "POST",
            "/infra/reputation/feedback",
            "Reputation feedback",
            "Record an outcome.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("outcome", "Outcome", "good"),
            ],
        ),
        op(
            "POST",
            "/infra/reputation/slash",
            "Slash",
            "Penalise a misbehaving participant.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("reason", "Reason", "why"),
            ],
        ),
        op("GET", "/infra/orchestrator/sagas", "Sagas", "Long-running sagas.", vec![]),
        op(
            "GET",
            "/infra/orchestrator/sagas/{id}",
            "Saga",
            "One saga's state.",
            vec![Field::path("id", "Saga id", "saga-id")],
        ),
        op(
            "POST",
            "/infra/orchestrator/sagas/{id}/rollback",
            "Rollback saga",
            "Compensate a failed saga.",
            vec![Field::path("id", "Saga id", "saga-id")],
        ),
        op(
            "POST",
            "/infra/orchestrator/submit",
            "Submit job",
            "Hand work to the orchestrator.",
            vec![Field::body("job", "Job", "payload")],
        ),
        op(
            "POST",
            "/infra/context/snapshot",
            "Context snapshot",
            "Capture context state.",
            vec![Field::body("agent_pid", "Agent pid", "agent-pid")],
        ),
        op(
            "POST",
            "/infra/context/restore",
            "Context restore",
            "Restore a snapshot.",
            vec![Field::body("snapshot_id", "Snapshot id", "snap-id")],
        ),
        op(
            "POST",
            "/infra/context/evict",
            "Context evict",
            "Drop context under pressure.",
            vec![Field::body("agent_pid", "Agent pid", "agent-pid")],
        ),
        op("GET", "/infra/tc/crypto-modules", "Crypto modules", "Available crypto modules.", vec![]),
        op(
            "POST",
            "/infra/tc/issue",
            "Issue credential",
            "Mint a threshold credential.",
            vec![Field::body("subject", "Subject", "agent-pid")],
        ),
        op(
            "POST",
            "/infra/tc/rotate",
            "Rotate",
            "Rotate threshold keys.",
            vec![Field::body("key_id", "Key id", "key-id")],
        ),
        op(
            "POST",
            "/infra/tc/revoke",
            "Revoke",
            "Revoke a credential.",
            vec![Field::body("credential_id", "Credential id", "cred-id")],
        ),
        op("GET", "/infra/vault/status", "Vault status", "Secret vault posture.", vec![]),
        op(
            "POST",
            "/infra/vault/resolve",
            "Vault resolve",
            "Resolve a secret reference.",
            vec![Field::body("ref", "Reference", "vault://path")],
        ),
        op(
            "POST",
            "/infra/vault/redact",
            "Vault redact",
            "Redact a stored value.",
            vec![Field::body("ref", "Reference", "vault://path")],
        ),
        op("GET", "/infra/orchestrator", "Orchestrator jobs", "Canonical orchestrator inventory.", vec![]),
        op(
            "GET",
            "/infra/orchestrator/{orch_id}",
            "Orchestrator job",
            "One orchestrator job.",
            vec![Field::path("orch_id", "Orch id", "orch-id")],
        ),
        op("GET", "/aapi/capabilities", "AAPI capabilities", "Delegated capability tokens.", vec![]),
        op(
            "POST",
            "/aapi/capabilities/issue",
            "Issue capability",
            "Mint a UCAN-style capability token.",
            vec![
                Field::body("issuer", "Issuer", "root"),
                Field::body("subject", "Subject", "agent-pid"),
                Field::body("actions", "Actions JSON", "[\"tool.dispatch\"]"),
                Field::body("resources", "Resources JSON", "[\"*\"]"),
                Field::body("ttl_hours", "TTL hours (optional)", "24"),
            ],
        ),
        op(
            "POST",
            "/aapi/capabilities/delegate",
            "Delegate capability",
            "Attenuated child token. Cannot grant more than the parent.",
            vec![
                Field::body("parent_token_id", "Parent token", "tok-id"),
                Field::body("new_subject", "New subject", "agent-pid"),
                Field::body("remove_actions", "Remove actions JSON (optional)", "[]"),
            ],
        ),
        op(
            "DELETE",
            "/aapi/capabilities/{token_id}",
            "Revoke capability",
            "Revoke one token.",
            vec![Field::path("token_id", "Token id", "tok-id")],
        ),
        op(
            "GET",
            "/aapi/capabilities/{token_id}/verify",
            "Verify capability",
            "Check whether a token is still valid.",
            vec![Field::path("token_id", "Token id", "tok-id")],
        ),
        op(
            "POST",
            "/aapi/budgets",
            "Create budget",
            "Per-agent resource budget.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("resource", "Resource", "tokens"),
                Field::body("limit", "Limit", "1000"),
            ],
        ),
        op(
            "POST",
            "/aapi/budgets/consume",
            "Consume budget",
            "Debit a budget. Denied when exhausted.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("resource", "Resource", "tokens"),
                Field::body("amount", "Amount", "1"),
            ],
        ),
        op(
            "GET",
            "/aapi/budgets/{agent_pid}/{resource}",
            "Get budget",
            "Remaining budget for one resource.",
            vec![
                Field::path("agent_pid", "Agent pid", "agent-pid"),
                Field::path("resource", "Resource", "tokens"),
            ],
        ),
        op(
            "POST",
            "/aapi/policies",
            "Add AAPI policy",
            "Dynamic policy with a JSON rules array.",
            vec![
                Field::body("id", "Policy id", "pol-1"),
                Field::body("name", "Name", "guard"),
                Field::body("rules", "Rules JSON", "[{\"effect\":\"allow\",\"action_pattern\":\"*\",\"priority\":0}]"),
            ],
        ),
        op(
            "DELETE",
            "/aapi/policies/{id}",
            "Remove AAPI policy",
            "Drop a dynamic policy.",
            vec![ID],
        ),
        op(
            "POST",
            "/aapi/policies/evaluate",
            "Evaluate AAPI policy",
            "Ask the action engine.",
            vec![
                Field::body("action", "Action", "tool.dispatch"),
                Field::body("resource", "Resource", "*"),
                Field::body("role", "Role (optional)", "developer"),
            ],
        ),
        op("POST", "/aapi/policies/hipaa", "Apply HIPAA policy", "Idempotent HIPAA guard template.", vec![]),
        op("POST", "/aapi/policies/financial", "Apply financial policy", "Idempotent financial guard template.", vec![]),
        op(
            "POST",
            "/aapi/tools/authorize",
            "Authorize tool",
            "AAPI decision for one agent × action × resource.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("action", "Action", "tool.dispatch"),
                Field::body("resource", "Resource", "tool://echo"),
                Field::body("role", "Role (optional)", ""),
            ],
        ),
        op(
            "POST",
            "/aapi/tools/register",
            "Register AAPI tool",
            "Register a tool name on the action plane.",
            vec![
                Field::body("name", "Name", "echo"),
                Field::body("description", "Description (optional)", ""),
            ],
        ),
        op(
            "GET",
            "/aapi/interactions",
            "AAPI interactions",
            "Interaction log. Optional agent filter.",
            vec![Field::query("agent_pid", "Agent pid (optional)", "")],
        ),
        op(
            "POST",
            "/aapi/interactions",
            "Log AAPI interaction",
            "Append one interaction row.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("itype", "Type", "tool"),
                Field::body("target", "Target", "echo"),
                Field::body("operation", "Operation", "invoke"),
                Field::body("status", "Status", "ok"),
            ],
        ),
        op(
            "POST",
            "/aapi/compliance",
            "Set AAPI compliance",
            "Regulations JSON + retention.",
            vec![
                Field::body("regulations", "Regulations JSON", "[\"hipaa\"]"),
                Field::body("data_classification", "Classification (optional)", ""),
                Field::body("retention_days", "Retention days (optional)", "90"),
                Field::body("requires_human_review", "Human review (true/false)", "false"),
            ],
        ),
        op(
            "POST",
            "/tools/mcp/invoke",
            "MCP invoke",
            "Live MCP dispatch through the kernel. Same executor as v2 invoke.",
            vec![
                Field::body("bridge_id", "Bridge id", "default"),
                Field::body("tool", "Tool", "echo"),
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("input", "Input JSON", "{}"),
            ],
        ),
        op("GET", "/tools/approvals/pending", "Tool approvals", "Kernel-skipped tool dispatches awaiting a human.", vec![]),
        op(
            "POST",
            "/tools/approvals/{audit_id}",
            "Approve tool",
            "Re-execute a pending tool call.",
            vec![
                Field::path("audit_id", "Audit id", "audit-id"),
                Field::body("approved_by", "Approved by (optional)", "admin"),
            ],
        ),
        op("GET", "/tools/mcp/bridges", "MCP bridges", "Registered MCP bridges.", vec![]),
        op(
            "POST",
            "/tools/mcp/register",
            "Register MCP bridge",
            "Also on Connect. Registers a live bridge URL.",
            vec![
                Field::body("bridge_id", "Bridge id", "default"),
                Field::body("url", "URL", "http://127.0.0.1:3000"),
                Field::body("agent_pid", "Agent pid (optional)", ""),
                Field::body("tools", "Tools JSON (optional)", "[]"),
            ],
        ),
        op(
            "DELETE",
            "/tools/mcp/bridges/{bridge_id}",
            "Unregister MCP bridge",
            "Drops the store row and circuit-breaker config.",
            vec![Field::path("bridge_id", "Bridge id", "default")],
        ),
        op(
            "POST",
            "/tools/mcp/invoke-scoped",
            "MCP invoke scoped",
            "Same dispatch with tool_scope + circuit breaker.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("tool_id", "Tool id", "default:echo"),
                Field::body("input", "Input JSON", "{}"),
                Field::body("operation", "Operation (optional)", ""),
                Field::body("path", "Path (optional)", ""),
            ],
        ),
        op("GET", "/tools/mcp/collision-check", "MCP collision check", "Name collisions across bridges.", vec![]),
        op("GET", "/license/status", "License status", "Active license.", vec![]),
        op("GET", "/license/machine", "License machine", "Machine identity for licensing.", vec![]),
        op("GET", "/license/heartbeat", "License heartbeat", "Last check-in.", vec![]),
        op("GET", "/license/usage", "License usage", "Usage counters.", vec![]),
        op("GET", "/license/tiers", "License tiers", "Known tiers.", vec![]),
        op("GET", "/license/features/{feature}", "License feature", "Whether a feature is entitled.", vec![Field::path("feature", "Feature", "agents")]),
        op(
            "POST",
            "/license/activate",
            "Activate license",
            "Admin+. Requires license_key.",
            vec![Field::body("license_key", "License key", "")],
        ),
        op("GET", "/notifications", "Notifications", "Active reminders.", vec![]),
        op("GET", "/notifications/history", "Notification history", "Delivered log.", vec![]),
        op("GET", "/notifications/templates", "Notification templates", "Template list.", vec![]),
        op("GET", "/notifications/{id}", "Notification", "One notification.", vec![ID]),
        op(
            "POST",
            "/notifications/schedule",
            "Schedule notification",
            "Create a reminder.",
            vec![
                Field::body("notification_type", "Type", "TRUST_DEGRADED"),
                Field::body("title", "Title", "title"),
                Field::body("message", "Message", "body"),
            ],
        ),
        op("POST", "/notifications/scan", "Scan notifications", "Emit any due notifications now.", vec![]),
        op(
            "PATCH",
            "/notifications/{id}/acknowledge",
            "Acknowledge notification",
            "acknowledge or snooze.",
            vec![
                ID,
                Field::body("action", "Action", "acknowledge"),
                Field::body("snooze_mins", "Snooze mins (optional)", ""),
            ],
        ),
        op("DELETE", "/notifications/{id}", "Cancel notification", "Cancel a scheduled reminder.", vec![ID]),
        op("GET", "/operator/pulse", "Operator pulse", "Operator pulse snapshot.", vec![]),
        op("GET", "/operator/capabilities", "Operator capabilities", "What this role may call.", vec![]),
        op("GET", "/monitor/health", "Monitor health", "Process health + uptime.", vec![]),
        op("GET", "/monitor/trust", "Monitor trust", "Live trust.", vec![]),
        op("GET", "/monitor/integrity", "Monitor integrity", "Integrity check.", vec![]),
        op("GET", "/monitor/slos", "Monitor SLOs", "SLO table.", vec![]),
        op("GET", "/monitor/storage/layout", "Storage layout", "Zone layout.", vec![]),
        op("GET", "/monitor/anomalies", "Anomalies", "Detected anomalies.", vec![]),
        op("GET", "/monitor/signals", "Monitor signals", "Signal bus.", vec![]),
        op(
            "POST",
            "/deploy",
            "Deploy manifest",
            "Parse AgentManifest, register, start. Tenant required. Not Kubernetes.",
            vec![
                Field::body("manifest", "Manifest YAML/JSON", "name: my-agent"),
                Field::body("format", "Format (optional)", "yaml"),
                Field::body("dry_run", "Dry run (true/false)", "false"),
            ],
        ),
        op("POST", "/deploy/validate", "Validate deploy", "Validate + diff, no mutation.", vec![Field::body("manifest", "Manifest", "name: my-agent")]),
        op("GET", "/deploy/list", "Deploy list", "Deployed AgentRegistry names.", vec![]),
        op("GET", "/deploy/history/{name}", "Deploy history", "Version history.", vec![Field::path("name", "Name", "my-agent")]),
        op("GET", "/deploy/diff/{name}", "Deploy diff", "Running vs uploaded.", vec![Field::path("name", "Name", "my-agent")]),
        op(
            "POST",
            "/deploy/rollback",
            "Deploy rollback",
            "Registry rollback to a version.",
            vec![Field::body("name", "Name", "my-agent"), Field::body("version", "Version", "1")],
        ),
        op("GET", "/runtime/mesh/ping", "Mesh ping", "Runtime mesh reachability.", vec![]),
        op("GET", "/plugins/lifecycle", "Plugin lifecycle", "Lifecycle state of every known plugin.", vec![]),
        op("GET", "/plugins/header-health", "Plugin header health", "Whether plugin headers are reachable.", vec![]),
        op("GET", "/plugins/service-map", "Plugin service map", "Hub-proxied service map.", vec![]),
        op(
            "GET",
            "/plugins/{plugin_id}/lifecycle",
            "Plugin lifecycle detail",
            "Current lifecycle row for one plugin.",
            vec![PLUGIN],
        ),
        op(
            "POST",
            "/plugins/{plugin_id}/lifecycle",
            "Apply plugin lifecycle",
            "install · enable · disable · upgrade · uninstall.",
            vec![
                PLUGIN,
                Field::body("action", "Action", "enable"),
                Field::body("target_version", "Target version (optional)", ""),
            ],
        ),
        op(
            "GET",
            "/plugins/{plugin_id}/lifecycle/history",
            "Plugin lifecycle history",
            "Transition history for one plugin.",
            vec![PLUGIN],
        ),
        op(
            "GET",
            "/plugins/{plugin_id}/configure/schema",
            "Plugin settings schema",
            "JSON schema for plugin settings.",
            vec![PLUGIN],
        ),
        op(
            "GET",
            "/plugins/{plugin_id}/configure",
            "Plugin settings",
            "Current settings values.",
            vec![PLUGIN],
        ),
        op(
            "POST",
            "/plugins/{plugin_id}/configure",
            "Set plugin settings",
            "Body is the `values` object from the schema.",
            vec![PLUGIN, Field::body("values", "Values JSON", "{}")],
        ),
        op("GET", "/runtime/docklock/status", "Docklock status", "Docklock enforcement posture.", vec![]),
        op(
            "POST",
            "/runtime/docklock/probe",
            "Docklock probe",
            "Ask whether a bypass kind is denied for an agent.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("bypass_kind", "Bypass kind", "network"),
            ],
        ),
        op("GET", "/runtime/enforcement", "Runtime enforcement", "Sandbox enforcement rollup.", vec![]),
        op(
            "GET",
            "/runtime/enforcement/{sandbox_id}",
            "Enforcement detail",
            "One sandbox's enforcement record.",
            vec![Field::path("sandbox_id", "Sandbox id", "sandbox-id")],
        ),
        op("GET", "/runtime/plugin-inventory", "Plugin inventory", "Runtime plugin inventory.", vec![]),
        op("GET", "/runtime/lifecycle/summary", "Workload lifecycle", "Workload lifecycle summary.", vec![]),
        op("GET", "/runtime/egress/status", "Egress status", "Runtime egress posture.", vec![]),
        op("GET", "/infra/reputation/scores", "Reputation scores", "Canonical reputation table.", vec![]),
        op(
            "POST",
            "/infra/reputation/stake",
            "Reputation stake",
            "Register a reputation stake.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("stake", "Stake", "100"),
            ],
        ),
        op(
            "POST",
            "/infra/reputation/slash",
            "Reputation slash",
            "Slash a staked agent.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("slash_amount", "Slash amount", "10"),
                Field::body("reason", "Reason", "sla-violation"),
            ],
        ),
    ]
}

fn safety_ops() -> Vec<Op> {
    vec![
        op("GET", "/safety/formal/verify", "Formal verify", "Run every mounted invariant.", vec![]),
        op("GET", "/safety/formal/invariants", "Formal invariants", "Invariant catalog.", vec![]),
        op("GET", "/safety/formal/report", "Formal report", "Latest verification report.", vec![]),
        op("GET", "/safety/formal/violations", "Formal violations", "Open invariant violations.", vec![]),
        op("GET", "/safety/formal/snapshot", "Formal snapshot", "Last verification snapshot.", vec![]),
        op("GET", "/safety/grounding/categories", "Grounding categories", "Anti-hallucination tables loaded.", vec![]),
        op(
            "POST",
            "/safety/grounding/lookup",
            "Grounding lookup",
            "Resolve a term against a grounding category.",
            vec![
                Field::body("category", "Category", "icd10"),
                Field::body("term", "Term", "diabetes"),
                Field::body("fuzzy", "Fuzzy (true/false)", "false"),
            ],
        ),
        op(
            "POST",
            "/safety/grounding/verify",
            "Grounding verify",
            "Check LLM output against a grounding category.",
            vec![
                Field::body("category", "Category", "icd10"),
                Field::body("text", "Text", "patient has diabetes"),
                Field::body("terms", "Terms JSON (optional)", "[]"),
            ],
        ),
        op(
            "POST",
            "/safety/grounding/add",
            "Grounding add",
            "Add an entry to the grounding table.",
            vec![
                Field::body("category", "Category", "icd10"),
                Field::body("term", "Term", "term"),
                Field::body("code", "Code", "E11"),
                Field::body("description", "Description", "desc"),
                Field::body("system", "System", "ICD-10"),
            ],
        ),
        op("GET", "/grounding/stats", "Grounding stats", "Table size and hit counters.", vec![]),
        op(
            "POST",
            "/grounding/claims/verify",
            "Verify claim",
            "Verify one claim against source text.",
            vec![
                Field::body("item", "Claim", "the patient has diabetes"),
                Field::body("category", "Category", "icd10"),
                Field::body("source_text", "Source text", "source"),
                Field::body("source_cid", "Source CID (optional)", ""),
            ],
        ),
        op(
            "POST",
            "/grounding/claims/verify-batch",
            "Verify claims batch",
            "Verify many claims. Body is a JSON array of the same shape as verify.",
            vec![
                Field::body(
                    "claims",
                    "Claims JSON",
                    "[{\"item\":\"the patient has diabetes\",\"category\":\"icd10\",\"source_text\":\"source\"}]",
                ),
            ],
        ),
        op(
            "POST",
            "/grounding/claims/ground-and-verify",
            "Ground and verify",
            "Look up a term then verify the claim against source text.",
            vec![
                Field::body("item", "Claim", "the patient has diabetes"),
                Field::body("category", "Category", "icd10"),
                Field::body("source_text", "Source text", "source"),
                Field::body("source_cid", "Source CID (optional)", ""),
            ],
        ),
        op("GET", "/actionlog/actions", "Action log", "Recorded actions.", vec![Field::query("agent_pid", "Agent pid (optional)", ""), Field::query("limit", "Limit (optional)", "50")]),
        op("GET", "/actionlog/denied", "Denied actions", "Denied operations.", vec![]),
        op("GET", "/actionlog/interactions", "Action interactions", "Interaction slice.", vec![]),
        op("GET", "/actionlog/access-matrix", "Access matrix", "Who may do what.", vec![]),
        op("GET", "/actionlog/tool-audit", "Tool audit", "Tool dispatch audit.", vec![]),
        op("GET", "/actionlog/compliance-gaps", "Compliance gaps", "Gaps from the action log.", vec![]),
        op("GET", "/actionlog/pii-scan", "PII scan", "PII scan of the log.", vec![]),
        op("GET", "/actionlog/chargeback-report", "Chargeback report", "Cost tags from actions.", vec![]),
        op("GET", "/actionlog/subject-access", "Subject access", "Subject-access export.", vec![]),
        op("GET", "/actionlog/dependency-map", "Dependency map", "Action dependencies.", vec![]),
        op("GET", "/actionlog/traces", "Traces", "Trace index.", vec![]),
        op("GET", "/actionlog/traces/stats", "Trace stats", "Trace counters.", vec![]),
        op("GET", "/actionlog/traces/{id}", "Trace", "One trace.", vec![ID]),
        op("GET", "/actionlog/regulation-report/{framework}", "Regulation report", "Framework report from the log.", vec![Field::path("framework", "Framework", "gdpr")]),
        op(
            "POST",
            "/actionlog/record",
            "Record action",
            "Append an action-log row.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("intent", "Intent", "tool.dispatch"),
                Field::body("action", "Action", "invoke"),
            ],
        ),
        op("GET", "/forensics/status", "Forensics status", "Forensic plane.", vec![]),
        op("GET", "/forensics/chain", "Forensics chain", "Receipt chain.", vec![]),
        op("GET", "/forensics/package", "Forensics package", "Export package.", vec![]),
        op("GET", "/forensics/court-readiness", "Court readiness", "Court-defensible posture.", vec![]),
        op("GET", "/forensics/witnessctl-join", "WitnessCtl join", "Join record.", vec![]),
        op("GET", "/forensics/universal/{pid}", "Forensics universal", "Universal snapshot for an agent.", vec![PID]),
        op("GET", "/forensics/rollups/{agent}", "Forensics rollups", "Rollups for an agent.", vec![Field::path("agent", "Agent", "agent-pid")]),
        op("GET", "/disputes/decisions", "Dispute decisions", "Recorded decisions.", vec![]),
        op(
            "POST",
            "/disputes/record",
            "Record decision",
            "Write a signed dispute decision.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("action", "Action", "allow"),
                Field::body("target", "Target", "resource"),
                Field::body("outcome", "Outcome", "allowed"),
            ],
        ),
        op("POST", "/disputes/judgment", "Dispute judgment", "Run judgment.", vec![Field::body("agent_pid", "Agent pid", "agent-pid")]),
        op("POST", "/disputes/risk-check", "Dispute risk check", "Risk check a decision.", vec![Field::body("agent_pid", "Agent pid", "agent-pid")]),
        op("GET", "/disputes/{decision_id}/report", "Dispute report", "One decision report.", vec![Field::path("decision_id", "Decision id", "dec_…")]),
        op("GET", "/disputes/{decision_id}/defense-package", "Defense package", "Defense pack.", vec![Field::path("decision_id", "Decision id", "dec_…")]),
        op("GET", "/disputes/provenance/{cid}", "Dispute provenance", "Provenance chain for a CID.", vec![Field::path("cid", "CID", "cid")]),
        op("GET", "/disputes/regulation-template/{framework}", "Regulation template", "Template for a framework.", vec![Field::path("framework", "Framework", "gdpr")]),
        op(
            "POST",
            "/cognitive/observe",
            "Cognitive observe",
            "PerceptionEngine observe.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("input", "Input", "text"),
                Field::body("user", "User", "operator"),
            ],
        ),
        op("GET", "/cognitive/context/{agent_pid}", "Cognitive context", "Perceived context.", vec![AGENT]),
        op("GET", "/cognitive/report/{agent_pid}", "Cognitive report", "Cycle report.", vec![AGENT]),
        op(
            "POST",
            "/cognitive/plan",
            "Cognitive plan",
            "CID-backed plan.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("goal", "Goal", "goal"),
                Field::body("steps", "Steps JSON", "[\"step-1\"]"),
            ],
        ),
        op(
            "POST",
            "/cognitive/judgment",
            "Cognitive judgment",
            "8-dimension quality judgment.",
            vec![Field::body("agent_pid", "Agent pid", "agent-pid"), Field::body("profile", "Profile (optional)", "default")],
        ),
        op(
            "POST",
            "/cognitive/cycle",
            "Cognitive cycle",
            "Perceive → retrieve → reason → reflect → act.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("input", "Input", "text"),
                Field::body("user", "User", "operator"),
                Field::body("goal", "Goal", "goal"),
                Field::body("steps", "Steps JSON (optional)", "[]"),
            ],
        ),
        op("GET", "/firewall/status", "Firewall status", "Fleet firewall posture.", vec![]),
        op("GET", "/firewall/status/{pid}", "Firewall status (agent)", "Firewall for one agent.", vec![PID]),
        op("GET", "/firewall/baselines", "Firewall baselines", "Detector baselines.", vec![]),
        op("GET", "/firewall/adjustments", "Firewall adjustments", "Live threshold adjustments.", vec![]),
        op(
            "GET",
            "/firewall/thresholds/{pid}",
            "Firewall thresholds",
            "Per-agent detector thresholds.",
            vec![PID],
        ),
        op(
            "GET",
            "/firewall/false-positives/{pid}",
            "False positives",
            "Recorded false positives for an agent.",
            vec![PID],
        ),
        op(
            "POST",
            "/firewall/inspect",
            "Firewall inspect",
            "Run content through the detector chain.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("content", "Content", "text to inspect"),
                Field::body("namespace", "Namespace", ""),
            ],
        ),
        op(
            "POST",
            "/firewall/rules",
            "Put firewall rule",
            "Write a graph rule.",
            vec![
                Field::body("rule_id", "Rule id", "rule-1"),
                Field::body("action", "Action", "deny"),
                Field::body("operation", "Operation (optional)", ""),
                Field::body("namespace_prefix", "Namespace prefix (optional)", ""),
                Field::body("reason", "Reason (optional)", ""),
            ],
        ),
        op("GET", "/proof/list", "Proofs", "Issued work proofs.", vec![]),
        op("GET", "/proof/public-key", "Proof public key", "Certificate signing public key.", vec![]),
        op(
            "POST",
            "/proof/generate",
            "Generate proof",
            "Mint a work proof from the audit chain.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("session_id", "Session id (optional)", ""),
                Field::body("title", "Title (optional)", ""),
            ],
        ),
        op(
            "GET",
            "/proof/{proof_id}/certificate",
            "Proof certificate",
            "Certificate JSON for a proof.",
            vec![PROOF],
        ),
        op(
            "GET",
            "/proof/{proof_id}/verify",
            "Verify proof",
            "Re-verify a stored proof.",
            vec![PROOF],
        ),
        op(
            "GET",
            "/proof/trust-trend/{pid}",
            "Trust trend",
            "Trust score history for an agent.",
            vec![PID],
        ),
        op(
            "POST",
            "/proof/vc/{agent_pid}",
            "Issue verifiable credential",
            "Issue a VC for this agent.",
            vec![AGENT],
        ),
        op("GET", "/protocol/conp/info", "CONP info", "Machine-control protocol info.", vec![]),
        op("GET", "/protocol/conp/capabilities", "CONP capabilities", "Advertised CONP capabilities.", vec![]),
        op("GET", "/protocol/world", "World connect", "World/protocol connect surface.", vec![]),
        op(
            "POST",
            "/protocol/conp/command",
            "CONP command",
            "Digest-bound machine command. Developer+. Package pin required outside lab.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("capability_id", "Capability", "halt"),
                Field::body("entity_id", "Entity id", "entity-id"),
                Field::body("parameters", "Parameters JSON", "{}"),
                Field::body("message_type", "MessageType (Command/CapabilityGrant/…)", "Command"),
                Field::body("lab_echo_hal", "Lab echo HAL (true/false)", "true"),
                Field::body("package", "Package pin JSON (required outside lab)", ""),
            ],
        ),
        op(
            "POST",
            "/protocol/conp/message",
            "CONP message",
            "Same admit path as command for grants/contracts. Developer+.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("capability_id", "Capability", "machine.move_axis"),
                Field::body("entity_id", "Entity id", "machine:arm-1"),
                Field::body("message_type", "MessageType", "CapabilityGrant"),
                Field::body("parameters", "Parameters JSON", "{}"),
                Field::body("package", "Package pin JSON (required outside lab)", ""),
            ],
        ),
        op(
            "POST",
            "/protocol/conp/safety/estop",
            "CONP estop",
            "Emergency stop on the CONP plane. Operator+.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("entity_id", "Entity id (optional)", ""),
                Field::body("reason", "Reason", "operator estop"),
            ],
        ),
        op("GET", "/protocols/a2a/card", "A2A agent card", "Agent-to-agent card.", vec![]),
        op(
            "POST",
            "/protocols/a2a/tasks",
            "A2A send task",
            "Send a task over A2A.",
            vec![
                Field::body("message", "Message", "hello"),
                Field::body("sender_pid", "Sender pid (optional)", ""),
                Field::body("package", "Package pin JSON (required outside lab)", ""),
            ],
        ),
        op(
            "GET",
            "/protocols/a2a/tasks/{task_id}",
            "A2A get task",
            "Fetch an A2A task.",
            vec![Field::path("task_id", "Task id", "task-id")],
        ),
        op(
            "POST",
            "/protocols/a2a/tasks/{task_id}/cancel",
            "A2A cancel task",
            "Cancel an A2A task.",
            vec![Field::path("task_id", "Task id", "task-id")],
        ),
        op("GET", "/protocols/anp/dids", "ANP DIDs", "Registered ANP DIDs.", vec![]),
        op(
            "POST",
            "/protocols/anp/dids",
            "Register ANP DID",
            "Register a DID on ANP.",
            vec![
                Field::body("did", "DID", "did:example:123"),
                Field::body("service_endpoint", "Service endpoint", "https://example"),
                Field::body("description", "Description (optional)", ""),
            ],
        ),
        op(
            "GET",
            "/protocols/anp/dids/{did}",
            "Resolve ANP DID",
            "Resolve a DID.",
            vec![Field::path("did", "DID", "did:example:123")],
        ),
    ]
}

fn economy_ops() -> Vec<Op> {
    vec![
        op("GET", "/spend/burn/{pid}", "Spend burn meter", "Live remaining usd/tokens/hops + inflight LLM.", vec![PID]),
        op("GET", "/spend/ceiling/{pid}", "Spend ceiling", "Current generation SpendCeiling.", vec![PID]),
        op("GET", "/spend/cease/latest/{pid}", "Latest CeaseReceipt", "Latest SpendCease receipt pointer.", vec![PID]),
        op(
            "GET",
            "/agents/{pid}/expometer",
            "Expometer",
            "Authority + world grants + LLM mode — one operator snapshot.",
            vec![PID],
        ),
        op(
            "POST",
            "/agents/{pid}/cease",
            "SpendCease",
            "Hard stop: fence generation, void ctx_tok, reap. Not model obedience.",
            vec![PID],
        ),
        op(
            "POST",
            "/economy/escrow/lock",
            "Escrow lock",
            "Lock funds against a contract.",
            vec![
                Field::body("requester_pid", "Requester pid", "agent-a"),
                Field::body("provider_pid", "Provider pid", "agent-b"),
                Field::body("amount", "Amount", "100"),
                Field::body("contract_id", "Contract id", "ctr-id"),
                Field::body("ttl_ms", "TTL ms (optional)", "3600000"),
            ],
        ),
        op("GET", "/economy/escrow/{id}", "Escrow status", "One escrow record.", vec![ID]),
        op("POST", "/economy/escrow/{id}/release", "Escrow release", "Release locked funds to the provider.", vec![ID]),
        op("POST", "/economy/escrow/{id}/slash", "Escrow slash", "Slash locked funds on SLA breach.", vec![ID]),
        op("POST", "/economy/escrow/{id}/dispute", "Escrow dispute", "Open a dispute on this escrow.", vec![ID]),
        op("GET", "/economy/settlements", "Settlements", "Completed escrow settlements.", vec![]),
        op("GET", "/economy/negotiate", "Negotiations", "Open and closed negotiations.", vec![]),
        op(
            "POST",
            "/economy/negotiate/propose",
            "Propose terms",
            "Open a capability negotiation.",
            vec![
                Field::body("requester_pid", "Requester pid", "agent-a"),
                Field::body("provider_pid", "Provider pid", "agent-b"),
                Field::body("capability_key", "Capability", "llm.chat"),
                Field::body("max_latency_ms", "Max latency ms", "800"),
                Field::body("availability_pct", "Availability %", "99.0"),
                Field::body("cost_per_call", "Cost per call", "1"),
                Field::body("stake_amount", "Stake", "10"),
            ],
        ),
        op("GET", "/economy/negotiate/{id}", "Negotiation status", "One negotiation.", vec![ID]),
        op(
            "POST",
            "/economy/negotiate/{id}/counter",
            "Counter-propose",
            "Provider counters with new terms.",
            vec![
                ID,
                Field::body("requester_pid", "Requester pid", "agent-a"),
                Field::body("provider_pid", "Provider pid", "agent-b"),
                Field::body("capability_key", "Capability", "llm.chat"),
                Field::body("max_latency_ms", "Max latency ms", "1200"),
                Field::body("availability_pct", "Availability %", "99.5"),
                Field::body("cost_per_call", "Cost per call", "2"),
                Field::body("stake_amount", "Stake", "20"),
            ],
        ),
        op("POST", "/economy/negotiate/{id}/accept", "Accept terms", "Accept the current offer.", vec![ID]),
        op("POST", "/economy/negotiate/{id}/reject", "Reject terms", "Reject the current offer.", vec![ID]),
        op("GET", "/marketplace/contracts", "Marketplace contracts", "Published contracts.", vec![]),
        op(
            "GET",
            "/marketplace/contracts/{pid}",
            "Marketplace contract",
            "One published contract.",
            vec![PID],
        ),
        op("GET", "/marketplace/index", "Marketplace index", "Agent capability index.", vec![]),
        op(
            "GET",
            "/marketplace/index/{pid}",
            "Agent capabilities (index)",
            "Indexed capabilities for one agent.",
            vec![PID],
        ),
        op("GET", "/marketplace/rankings", "Rankings", "Marketplace rankings.", vec![]),
        op("GET", "/marketplace/agents", "Marketplace agents", "Agents listed on the marketplace.", vec![]),
        op("GET", "/marketplace/tools", "Marketplace tools", "Registered tools.", vec![]),
        op("GET", "/marketplace/modules", "Marketplace modules", "Installable modules.", vec![]),
        op(
            "POST",
            "/marketplace/discover",
            "Discover",
            "Find providers matching an intent.",
            vec![
                Field::body("domain", "Domain", "llm"),
                Field::body("action", "Action", "chat"),
                Field::body("max_latency_ms", "Max latency ms (optional)", ""),
                Field::body("min_trust_score", "Min trust (optional)", ""),
            ],
        ),
        op(
            "POST",
            "/marketplace/contracts",
            "Publish contract",
            "Publish a marketplace contract.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("capabilities", "Capabilities JSON", "[{\"domain\":\"llm\",\"action\":\"chat\"}]"),
                Field::body("max_latency_ms", "Max latency ms", "800"),
                Field::body("availability_pct", "Availability %", "99.0"),
                Field::body("pricing_type", "Pricing type", "per_call"),
                Field::body("cost_per_call", "Cost per call (optional)", "1"),
            ],
        ),
        op(
            "POST",
            "/marketplace/modules/install",
            "Install module",
            "Install a marketplace module.",
            vec![Field::body("module_id", "Module id", "module-id")],
        ),
        op(
            "DELETE",
            "/marketplace/modules/{module_id}",
            "Uninstall module",
            "Remove an installed module.",
            vec![Field::path("module_id", "Module id", "module-id")],
        ),
        op("GET", "/economy/reputation/scores", "Reputation (deprecated path)", "Same table as /infra/reputation/scores. Sunset header on the wire.", vec![]),
        op(
            "GET",
            "/economy/reputation/scores/{pid}",
            "Reputation score (deprecated path)",
            "One agent's score on the sunset path.",
            vec![PID],
        ),
        op(
            "POST",
            "/economy/deposit",
            "Deposit",
            "Credit escrow balance for an agent.",
            vec![Field::body("agent_pid", "Agent pid", "agent-pid"), Field::body("amount", "Amount", "10")],
        ),
        op("GET", "/economy/balance/{pid}", "Balance", "Escrow balance.", vec![PID]),
        op(
            "POST",
            "/economy/quote",
            "Price quote",
            "Dynamic quote between requester and provider.",
            vec![
                Field::body("requester_pid", "Requester", "agent-a"),
                Field::body("provider_pid", "Provider", "agent-b"),
                Field::body("base_cost", "Base cost", "1"),
            ],
        ),
        op(
            "POST",
            "/economy/budget-gate",
            "Set budget gate",
            "Max spend in a window.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("max_spend", "Max spend", "100"),
                Field::body("window_duration_ms", "Window ms (optional)", "86400000"),
            ],
        ),
        op("GET", "/economy/budget-gate/{pid}", "Budget gate", "Gate status. Null if unset.", vec![PID]),
    ]
}

fn intel_ops() -> Vec<Op> {
    vec![
        op("GET", "/intelligence/council", "Councils", "Minted councils this operator can see.", vec![]),
        op("GET", "/intelligence/council/inbox", "Council inbox", "Inbound council traffic.", vec![]),
        op(
            "POST",
            "/intelligence/council",
            "Mint council",
            "Root-gated. Members is a JSON array of pids.",
            vec![
                Field::body("name", "Name", "council name"),
                Field::body("members", "Members JSON", "[\"agent-a\",\"agent-b\"]"),
                Field::body("justification", "Justification", "why this council"),
                Field::body("root_passcode", "Root passcode", ""),
            ],
        ),
        op("GET", "/intelligence/council/{id}", "Council", "One council record.", vec![ID]),
        op("GET", "/intelligence/council/{id}/floor", "Council floor", "Who-said-what floor.", vec![ID]),
        op("GET", "/intelligence/council/{id}/tasks", "Council tasks", "Tasks on this council.", vec![ID]),
        op(
            "POST",
            "/intelligence/council/{id}/speak",
            "Council speak",
            "Speak as the I in X-Connector-Agent-Pid. from_I must match.",
            vec![
                ID,
                Field::body("from_I", "From I", "agent-pid"),
                Field::body("body", "Body", "statement"),
                Field::body("kind", "Kind (optional)", "motion"),
            ],
        ),
        op(
            "POST",
            "/intelligence/council/{id}/members",
            "Add council member",
            "Root-gated add of one I.",
            vec![
                ID,
                Field::body("I", "I (pid)", "agent-pid"),
                Field::body("root_passcode", "Root passcode", ""),
            ],
        ),
        op(
            "POST",
            "/intelligence/council/{id}/close",
            "Close council",
            "Root-gated. Floor stays as evidence.",
            vec![ID, Field::body("root_passcode", "Root passcode", "")],
        ),
        op("GET", "/intelligence/spec-schema", "Intelligence spec schema", "Apply-schema for IntelligenceSpec.", vec![]),
        op(
            "GET",
            "/intelligence/{pid}/pack",
            "Intelligence pack",
            "Quick pack for one agent.",
            vec![PID],
        ),
        op("GET", "/history/agents", "History agents", "Agents with recorded history.", vec![]),
        op("GET", "/history/agents/archive", "Agent archive", "Archived agent records.", vec![]),
        op(
            "GET",
            "/history/agents/{agent_pid}/timeline",
            "Agent timeline",
            "Session timeline.",
            vec![AGENT],
        ),
        op(
            "GET",
            "/history/agents/{agent_pid}/sessions",
            "Agent sessions",
            "Session list.",
            vec![AGENT],
        ),
        op(
            "GET",
            "/history/agents/{agent_pid}/sessions-range",
            "Sessions range",
            "Sessions in a window.",
            vec![AGENT],
        ),
        op(
            "GET",
            "/history/agents/{agent_pid}/cost-timeline",
            "Cost timeline",
            "Spend over time.",
            vec![AGENT],
        ),
        op(
            "GET",
            "/history/agents/{agent_pid}/drift",
            "Behaviour drift",
            "Behaviour drift detector.",
            vec![AGENT],
        ),
        op(
            "GET",
            "/history/agents/{agent_pid}/regression",
            "Regression detect",
            "Regression against prior sessions.",
            vec![AGENT],
        ),
        op(
            "GET",
            "/history/agents/{agent_pid}/diff",
            "Agent diff",
            "Diff against a prior snapshot.",
            vec![AGENT],
        ),
        op(
            "POST",
            "/history/agents/{agent_pid}/terminate",
            "Terminate (history)",
            "Terminate via the history plane.",
            vec![AGENT],
        ),
        op("GET", "/insights/fleet", "Fleet insights", "Fleet-wide insight rollup.", vec![]),
        op("GET", "/insights/self-heal-candidates", "Self-heal candidates", "Suggested self-heal fixes.", vec![]),
        op(
            "GET",
            "/insights/agents/{agent_pid}/optimize",
            "Optimize agent",
            "Optimization hints for one agent.",
            vec![AGENT],
        ),
        op(
            "GET",
            "/insights/model-recommendation/{pid}",
            "Model recommendation",
            "Recommended model for this agent.",
            vec![PID],
        ),
        op(
            "GET",
            "/insights/causal-analysis/{pid}",
            "Causal analysis",
            "Causal analysis for this agent.",
            vec![PID],
        ),
        op(
            "GET",
            "/insights/budget-forecast/{pid}",
            "Budget forecast",
            "Spend forecast for this agent.",
            vec![PID],
        ),
        op(
            "POST",
            "/insights/apply-fix/{pid}/{fix_id}",
            "Apply insight fix",
            "Apply a named self-heal fix.",
            vec![PID, Field::path("fix_id", "Fix id", "fix-id")],
        ),
        op(
            "GET",
            "/fabric/tasks",
            "Fabric tasks",
            "Tasks in a context. context_id is required.",
            vec![Field::query("context_id", "Context id", "ctx-id")],
        ),
        op(
            "GET",
            "/fabric/tasks/{task_id}",
            "Fabric task",
            "One fabric task.",
            vec![Field::path("task_id", "Task id", "task-id")],
        ),
        op(
            "POST",
            "/fabric/tasks/{task_id}/transition",
            "Transition fabric task",
            "Advance a fabric task.",
            vec![
                Field::path("task_id", "Task id", "task-id"),
                Field::body("state", "To state", "WORKING"),
                Field::body("reason", "Reason (optional)", ""),
            ],
        ),
        op(
            "POST",
            "/fabric/tasks/{task_id}/resume",
            "Resume fabric task",
            "Resume a paused fabric task.",
            vec![Field::path("task_id", "Task id", "task-id")],
        ),
        op(
            "POST",
            "/fabric/tasks/{task_id}/cancel",
            "Cancel fabric task",
            "Cancel a fabric task.",
            vec![Field::path("task_id", "Task id", "task-id")],
        ),
        op(
            "POST",
            "/missions",
            "Create mission",
            "Open a mission journal.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("label", "Label (optional)", "mission label"),
            ],
        ),
        op("GET", "/missions/{id}", "Mission", "One mission journal.", vec![ID]),
        op("POST", "/missions/{id}/resume", "Resume mission", "Resume a paused mission.", vec![ID]),
        op("POST", "/missions/{id}/complete", "Complete mission", "Seal a mission.", vec![ID]),
        op("GET", "/command-center/snapshot", "Command center", "Operator command-center snapshot.", vec![]),
        op("GET", "/reports/center", "Report center", "Stored report receipts.", vec![]),
        op("GET", "/knowledge-graph", "Knowledge graph", "Agent knowledge-transfer graph.", vec![]),
        op("GET", "/knowledge-graph/agents/{pid}", "Knowledge node", "One agent's node.", vec![PID]),
        op("GET", "/knowledge-graph/transfers", "Knowledge transfers", "Transfer edges.", vec![]),
        op(
            "POST",
            "/knowledge-graph/transfer",
            "Trigger transfer",
            "Record a manual transfer.",
            vec![
                Field::body("from_pid", "From pid", "agent-a"),
                Field::body("to_pid", "To pid", "agent-b"),
                Field::body("content_summary", "Summary", "what moved"),
                Field::body("tokens", "Tokens (optional)", "0"),
            ],
        ),
    ]
}

fn comply_ops() -> Vec<Op> {
    vec![
        op("GET", "/compliance/scorecard", "Scorecard", "Live compliance scorecard.", vec![]),
        op("GET", "/compliance/frameworks", "Frameworks", "Mounted compliance frameworks.", vec![]),
        op("GET", "/compliance/findings", "Findings", "Open and closed findings.", vec![]),
        op("GET", "/compliance/findings/{id}", "Finding", "One finding.", vec![ID]),
        op(
            "PATCH",
            "/compliance/findings/{id}",
            "Update finding",
            "Patch status / owner / notes. Operator+.",
            vec![
                ID,
                Field::body("status", "Status", "open"),
                Field::body("owner", "Owner", ""),
                Field::body("notes", "Notes", ""),
            ],
        ),
        op("GET", "/compliance/policy-violations", "Policy violations", "Recorded policy violations.", vec![]),
        op("GET", "/compliance/data-boundary", "Data boundary", "Data-residency boundary.", vec![]),
        op("GET", "/compliance/access-report", "Access report", "Access audit report.", vec![]),
        op("GET", "/compliance/drift", "Compliance drift", "Drift vs last evidence pack.", vec![]),
        op("GET", "/compliance/iso42001", "ISO 42001", "ISO 42001 report.", vec![]),
        op(
            "POST",
            "/compliance/evidence-pack",
            "Evidence pack",
            "Admin+. Builds a pack for a framework over a period.",
            vec![
                Field::query("framework", "Framework", "SOC2_TYPE2"),
                Field::query("period_days", "Period days", "90"),
            ],
        ),
        op("GET", "/compliance/gdpr/data-subjects", "GDPR data subjects", "Tracked data subjects.", vec![]),
        op("GET", "/compliance/gdpr/erasure-log", "GDPR erasure log", "Right-to-erasure log.", vec![]),
        op(
            "POST",
            "/compliance/gdpr/forget/{pid}",
            "GDPR forget",
            "Right-to-erasure for one pid.",
            vec![PID],
        ),
        op("GET", "/compliance/eu_ai_act/assessment", "EU AI Act assessment", "Current assessment.", vec![]),
        op(
            "GET",
            "/compliance/eu_ai_act/transparency_report",
            "EU AI Act transparency",
            "Audit-log-backed transparency record.",
            vec![],
        ),
        op(
            "POST",
            "/compliance/eu_ai_act/risk_classification",
            "EU AI Act risk class",
            "Classify a system. Developer+.",
            vec![
                Field::body("system_name", "System name", "AI System"),
                Field::body("domain", "Domain", "general"),
                Field::body("affects_individuals", "Affects individuals", "false"),
                Field::body("automated_decision", "Automated decision", "false"),
                Field::body("human_oversight", "Human oversight", "true"),
                Field::body("safety_critical", "Safety critical", "false"),
            ],
        ),
        op(
            "POST",
            "/compliance/eu_ai_act/log_incident",
            "Log EU AI Act incident",
            "Record an incident against the Act. Operator+.",
            vec![
                Field::body("summary", "Summary", "what happened"),
                Field::body("severity", "Severity", "low"),
            ],
        ),
        op("GET", "/compliance/agreements", "Agreements", "Legal agreements on file.", vec![]),
        op("GET", "/compliance/shared-responsibility", "Shared responsibility", "Shared-responsibility matrix.", vec![]),
        op("GET", "/compliance/hipaa/evidence-pack", "HIPAA evidence pack", "HIPAA evidence.", vec![]),
        op("GET", "/compliance/hipaa/phi-scan", "HIPAA PHI scan", "PHI scan.", vec![]),
        op("GET", "/compliance/soc2/controls", "SOC2 controls", "Control catalogue.", vec![]),
        op("GET", "/compliance/eu-ai-act/inventory", "EU AI Act inventory", "System inventory.", vec![]),
        op("GET", "/compliance/eu-ai-act/risk-classification", "EU AI Act risk GET", "Stored classifications.", vec![]),
        op("GET", "/compliance/report", "Compliance report", "Generated report.", vec![]),
    ]
}

fn lab_ops() -> Vec<Op> {
    vec![
        op("GET", "/prompts", "Prompts", "Prompt registry.", vec![]),
        op(
            "POST",
            "/prompts",
            "Create prompt",
            "Register a prompt.",
            vec![
                Field::body("name", "Name", "prompt name"),
                Field::body("system_prompt", "System prompt", "You are…"),
                Field::body("description", "Description (optional)", ""),
            ],
        ),
        op("GET", "/prompts/{id}", "Prompt", "One prompt.", vec![ID]),
        op("DELETE", "/prompts/{id}", "Delete prompt", "Remove a prompt.", vec![ID]),
        op("GET", "/prompts/{id}/versions", "Prompt versions", "Version list.", vec![ID]),
        op("GET", "/prompts/{id}/resolve", "Resolve prompt", "Active version body.", vec![ID]),
        op("GET", "/prompts/{id}/analytics", "Prompt analytics", "Usage analytics.", vec![ID]),
        op("POST", "/prompts/{id}/lint", "Lint prompt", "Lint the current body.", vec![ID]),
        op(
            "POST",
            "/prompts/{id}/activate",
            "Activate prompt version",
            "Activate a version.",
            vec![ID, Field::body("version", "Version", "1")],
        ),
        op("GET", "/experiments", "Experiments", "Experiment tracker.", vec![]),
        op(
            "POST",
            "/experiments/create",
            "Create experiment",
            "Open an experiment.",
            vec![
                Field::body("name", "Name", "exp name"),
                Field::body("agent_name", "Agent name", "agent"),
                Field::body("description", "Description", ""),
            ],
        ),
        op(
            "POST",
            "/experiments/run",
            "Run experiment",
            "Execute one variant.",
            vec![
                Field::body("experiment_id", "Experiment id", "exp_…"),
                Field::body("input", "Input", "prompt"),
                Field::body("user", "User", "operator"),
                Field::body("variant", "Variant (optional)", ""),
            ],
        ),
        op(
            "GET",
            "/experiments/{experiment_id}/runs",
            "Experiment runs",
            "Runs for one experiment.",
            vec![Field::path("experiment_id", "Experiment id", "exp_…")],
        ),
        op(
            "GET",
            "/experiments/{experiment_id}/winner",
            "Experiment winner",
            "Current winner.",
            vec![Field::path("experiment_id", "Experiment id", "exp_…")],
        ),
        op(
            "GET",
            "/experiments/{experiment_id}/significance",
            "Significance",
            "Significance vs control.",
            vec![Field::path("experiment_id", "Experiment id", "exp_…")],
        ),
        op(
            "GET",
            "/experiments/{experiment_id}/suggest",
            "Suggest next",
            "Suggested next variant.",
            vec![Field::path("experiment_id", "Experiment id", "exp_…")],
        ),
        op(
            "GET",
            "/experiments/{experiment_id}/eval-summary",
            "Eval summary",
            "Judge eval summary.",
            vec![Field::path("experiment_id", "Experiment id", "exp_…")],
        ),
        op("GET", "/experiments/datasets", "Datasets", "Golden datasets.", vec![]),
        op("GET", "/pipeline/definitions", "Pipeline definitions", "Stored pipeline definitions.", vec![]),
        op("GET", "/pipeline/gate-policies", "Gate policies", "Pipeline gate policies.", vec![]),
        op("GET", "/cls/packages", "CLS packages", "Registered CLS packages.", vec![]),
        op(
            "GET",
            "/pipeline/{pipeline_id}/gate",
            "Pipeline gate",
            "Gate state for one pipeline.",
            vec![Field::path("pipeline_id", "Pipeline id", "pipe-id")],
        ),
        op(
            "GET",
            "/pipeline/{pipeline_id}/integrity",
            "Pipeline integrity",
            "Integrity check.",
            vec![Field::path("pipeline_id", "Pipeline id", "pipe-id")],
        ),
        op(
            "POST",
            "/pipeline/kecs-suspend-sweep",
            "KECS suspend sweep",
            "Run the auto-suspend sweep.",
            vec![],
        ),
        op(
            "POST",
            "/cls/packages",
            "Register CLS package",
            "Register a CLS package id + version.",
            vec![
                Field::body("package_id", "Package id", "pkg-id"),
                Field::body("version", "Version", "1.0.0"),
            ],
        ),
        op(
            "GET",
            "/cls/packages/{id}",
            "CLS package",
            "One CLS package record.",
            vec![ID],
        ),
        op("POST", "/cls/packages/{id}/install", "Install CLS package", "Install a registered package.", vec![ID]),
        op(
            "POST",
            "/cls/packages/{id}/bind",
            "Bind CLS package",
            "Bind a package to an agent or node.",
            vec![
                ID,
                Field::body("agent", "Agent (optional)", "agent-pid"),
                Field::body("node", "Node (optional)", ""),
            ],
        ),
        op(
            "POST",
            "/cls/packages/{id}/lifecycle",
            "CLS lifecycle",
            "start · stop · pause · resume.",
            vec![ID, Field::body("action", "Action", "start")],
        ),
        op("GET", "/cls/packages/{id}/execution", "CLS execution", "Execution surface for a package.", vec![ID]),
        op(
            "POST",
            "/cls/compile",
            "CLS compile",
            "Compile a CLS source blob.",
            vec![Field::body("source", "Source", "")],
        ),
        op(
            "POST",
            "/plugins/cpkg/preflight",
            "CPKG preflight",
            "Validate a connector package before install. Admin/dev.",
            vec![
                Field::body("url", "URL (optional)", ""),
                Field::body("cpkg_base64", "Package base64 (optional)", ""),
            ],
        ),
        op(
            "POST",
            "/plugins/cpkg/install",
            "CPKG install",
            "Install a connector package. Admin/dev.",
            vec![
                Field::body("url", "URL (optional)", ""),
                Field::body("cpkg_base64", "Package base64 (optional)", ""),
            ],
        ),
    ]
}

fn v2_ops() -> Vec<Op> {
    vec![
        op("GET", "/api/v2/health", "V2 health", "Simplified health envelope.", vec![]),
        op("GET", "/api/v2/health/maturity", "V2 maturity", "Maturity scores.", vec![]),
        op("GET", "/api/v2/health/agents", "V2 agents health", "Per-agent health from kernel.", vec![]),
        op("GET", "/api/v2/agents", "V2 list agents", "Simplified agent list.", vec![]),
        op(
            "POST",
            "/api/v2/agents",
            "V2 create agent",
            "Create via the v2 envelope.",
            vec![
                Field::body("name", "Name", "agent-name"),
                Field::body("namespace", "Namespace (optional)", ""),
                Field::body("model", "Model (optional)", ""),
            ],
        ),
        op("GET", "/api/v2/agents/{id}", "V2 get agent", "One agent.", vec![ID]),
        op("POST", "/api/v2/agents/{id}/start", "V2 start agent", "Start.", vec![ID]),
        op("POST", "/api/v2/agents/{id}/stop", "V2 stop agent", "Stop.", vec![ID]),
        op("GET", "/api/v2/memory", "V2 list memory", "List/search. Optional agent_id query.", vec![Field::query("agent_id", "Agent id (optional)", "")]),
        op(
            "POST",
            "/api/v2/memory",
            "V2 write memory",
            "Write a packet.",
            vec![
                Field::body("agent_id", "Agent id", "agent-pid"),
                Field::body("content", "Content JSON", "{\"text\":\"hello\"}"),
            ],
        ),
        op("GET", "/api/v2/memory/{cid}", "V2 get memory", "By CID.", vec![Field::path("cid", "CID", "cid")]),
        op("DELETE", "/api/v2/memory/{cid}", "V2 delete memory", "Delete by CID.", vec![Field::path("cid", "CID", "cid")]),
        op("GET", "/api/v2/tools", "V2 tools", "Tool registry.", vec![]),
        op("GET", "/api/v2/tools/{id}", "V2 get tool", "One tool.", vec![ID]),
        op(
            "POST",
            "/api/v2/tools/{id}/invoke",
            "V2 invoke tool",
            "Same MCP dispatch as POST /tools/mcp/invoke. id is bridge:tool.",
            vec![
                ID,
                Field::body("agent_id", "Agent id", "agent-pid"),
                Field::body("parameters", "Parameters JSON", "{}"),
            ],
        ),
        op("GET", "/api/v2/sessions", "V2 sessions", "Session list.", vec![]),
        op(
            "POST",
            "/api/v2/sessions",
            "V2 create session",
            "Open a session.",
            vec![Field::body("agent_id", "Agent id", "agent-pid")],
        ),
        op("GET", "/api/v2/sessions/{id}", "V2 get session", "One session.", vec![ID]),
        op("DELETE", "/api/v2/sessions/{id}", "V2 close session", "Close.", vec![ID]),
        op("GET", "/api/v2/audit", "V2 audit", "Audit list.", vec![]),
        op("GET", "/api/v2/audit/export", "V2 audit export", "OCSF export.", vec![]),
        op("GET", "/api/v2/audit/{id}", "V2 audit entry", "One entry.", vec![ID]),
        op("GET", "/api/v2/exec/list", "V2 exec list", "Stored executions.", vec![]),
        op(
            "POST",
            "/api/v2/exec/run",
            "V2 exec run",
            "Queues on the orchestrator. Status starts as queued.",
            vec![Field::body("task", "Task", "echo hello")],
        ),
        op(
            "POST",
            "/api/v2/exec/queue",
            "V2 exec queue",
            "Persist a queued execution record.",
            vec![Field::body("task", "Task", "echo hello")],
        ),
        op(
            "POST",
            "/api/v2/exec/schedule",
            "V2 exec schedule",
            "Persist a schedule record. Cron next-run is not computed from the expression.",
            vec![
                Field::body("task", "Task", "echo hello"),
                Field::body("schedule", "Schedule JSON", "{\"interval_seconds\":3600}"),
            ],
        ),
        op("GET", "/api/v2/exec/{id}/status", "V2 exec status", "Stored status.", vec![ID]),
        op("GET", "/api/v2/exec/{id}/logs", "V2 exec logs", "Stored logs.", vec![ID]),
        op("POST", "/api/v2/exec/{id}/abort", "V2 exec abort", "Abort.", vec![ID]),
        op("POST", "/api/v2/exec/{id}/retry", "V2 exec retry", "Retry.", vec![ID]),
        op("GET", "/api/v2/exec/{id}/cost", "V2 exec cost", "Cost if recorded.", vec![ID]),
        op("GET", "/api/v2/exec/{id}/resources", "V2 exec resources", "Resource record.", vec![ID]),
        op("GET", "/api/v2/exec/{task}/deps", "V2 exec deps", "Declared deps.", vec![Field::path("task", "Task", "task")]),
        op("POST", "/api/v2/exec/dry-run", "V2 exec dry-run", "Dry-run a task.", vec![Field::body("task", "Task", "echo hello")]),
        op("POST", "/api/v2/exec/validate", "V2 exec validate", "Validate a task spec.", vec![Field::body("task", "Task", "echo hello")]),
        op("POST", "/api/v2/exec/benchmark", "V2 exec benchmark", "Benchmark a task.", vec![Field::body("task", "Task", "echo hello")]),
        op(
            "POST",
            "/api/v2/deploy/create",
            "V2 deploy create",
            "Registers an AgentManifest. Not a container rollout.",
            vec![
                Field::body("name", "Name", "my-agent"),
                Field::body("image", "Image", "unused"),
            ],
        ),
        op("POST", "/api/v2/deploy/plan", "V2 deploy plan", "Diff against current registry names.", vec![Field::body("spec", "Spec JSON", "{}")]),
        op("POST", "/api/v2/deploy/apply", "V2 deploy apply", "501 — no rollout engine.", vec![Field::body("plan_id", "Plan id", "plan_…")]),
        op("GET", "/api/v2/deploy/list", "V2 deploy list", "AgentRegistry names.", vec![]),
        op("GET", "/api/v2/deploy/{name}/status", "V2 deploy status", "Registry version state.", vec![Field::path("name", "Name", "my-agent")]),
        op("POST", "/api/v2/deploy/{name}/rollback", "V2 deploy rollback", "Registry rollback.", vec![Field::path("name", "Name", "my-agent"), Field::body("to_version", "To version", "1")]),
        op("POST", "/api/v2/deploy/{name}/scale", "V2 deploy scale", "501 — no replica dimension.", vec![Field::path("name", "Name", "my-agent"), Field::body("replicas", "Replicas", "3")]),
        op("GET", "/api/v2/deploy/{name}/logs", "V2 deploy logs", "Store-backed only. Empty if none.", vec![Field::path("name", "Name", "my-agent")]),
        op("GET", "/api/v2/deploy/{name}/metrics", "V2 deploy metrics", "Process counters. Host CPU/mem are null.", vec![Field::path("name", "Name", "my-agent")]),
        op("GET", "/api/v2/system/info", "V2 system info", "Build + kernel counts. Uptime from boot clock.", vec![]),
        op("GET", "/api/v2/system/health", "V2 system health", "Kernel/store checks only.", vec![]),
        op("GET", "/api/v2/system/metrics", "V2 system metrics", "Linux /proc CPU/mem + data_dir disk. Network stays null.", vec![]),
        op("GET", "/api/v2/system/logs", "V2 system logs", "Store-backed. Empty if none.", vec![]),
        op("POST", "/api/v2/system/backup", "V2 backup", "Gzip tar of data_dir. Local path + sha256. No download route.", vec![]),
        op("GET", "/api/v2/system/upgrade", "V2 upgrade", "Current crate version only. latest is null.", vec![]),
        op("GET", "/api/v2/registry/list", "V2 registry", "AgentRegistry items.", vec![]),
        op("GET", "/api/v2/registry/{id}", "V2 registry item", "One item.", vec![ID]),
        op("DELETE", "/api/v2/registry/{id}", "V2 registry delete", "Delete.", vec![ID]),
        op("POST", "/api/v2/registry/{id}/pull", "V2 registry pull", "Pull.", vec![ID]),
        op(
            "POST",
            "/api/v2/registry/push",
            "V2 registry push",
            "Push a name into the registry.",
            vec![Field::body("name", "Name", "agent"), Field::body("image", "Image", "unused")],
        ),
        op("GET", "/api/v2/storage/list", "V2 storage list", "Local storage zones + dir sizes.", vec![]),
        op("GET", "/api/v2/storage/{name}", "V2 storage zone", "audit · agent-behavior · secrets.", vec![Field::path("name", "Zone", "audit")]),
        op(
            "POST",
            "/api/v2/storage/sync",
            "V2 storage sync",
            "Copies files. Byte total unmeasured.",
            vec![Field::body("source", "Source", "/tmp/a"), Field::body("destination", "Destination", "/tmp/b")],
        ),
        op("POST", "/api/v2/storage/cleanup", "V2 storage cleanup", "Deletes {data_dir}/tmp files older than 24h only.", vec![]),
        op("GET", "/api/v2/network/list", "V2 networks", "Kernel namespaces. Not VPCs.", vec![]),
        op("GET", "/api/v2/network/{name}", "V2 network inspect", "Agents in a namespace.", vec![Field::path("name", "Name", "default")]),
        op(
            "POST",
            "/api/v2/network/test",
            "V2 network test",
            "Real TCP connect with timeout.",
            vec![Field::body("target", "Target", "example.com"), Field::body("port", "Port", "443")],
        ),
        op("GET", "/api/v2/dns/resolve", "V2 DNS resolve", "System resolver. TTL unmeasured.", vec![Field::query("domain", "Domain", "example.com")]),
        op("GET", "/api/v2/dns/lookup", "V2 reverse DNS", "libc getnameinfo PTR. Empty means none.", vec![Field::query("ip", "IP", "1.1.1.1")]),
        op("GET", "/api/v2/dns/records", "V2 DNS records", "Store-backed. Empty if none.", vec![Field::query("zone", "Zone (optional)", "")]),
        op(
            "GET",
            "/api/v2/dns/propagation",
            "V2 DNS propagation",
            "UDP A query per nameserver. Empty nameservers uses /etc/resolv.conf.",
            vec![
                Field::query("domain", "Domain", "example.com"),
                Field::query("nameservers", "Nameservers (optional)", "8.8.8.8,1.1.1.1"),
            ],
        ),
        op(
            "GET",
            "/api/v2/tls/check",
            "V2 TLS check",
            "Real rustls handshake. trusted is webpki-roots only.",
            vec![
                Field::query("domain", "Domain", "example.com"),
                Field::query("port", "Port (optional)", "443"),
            ],
        ),
        op(
            "GET",
            "/api/v2/tls/cert-info",
            "V2 cert info",
            "Handshake + x509 parse of the peer leaf. Fingerprint is SHA-256 of DER.",
            vec![
                Field::query("domain", "Domain", "example.com"),
                Field::query("port", "Port (optional)", "443"),
            ],
        ),
        op("GET", "/api/v2/tls/certificates", "V2 certificates", "Store-backed. Empty if none issued here.", vec![]),
        op("POST", "/api/v2/tls/request", "V2 request cert", "501 — no ACME issuer.", vec![Field::body("domain", "Domain", "example.com")]),
    ]
}

fn work_ops() -> Vec<Op> {
    vec![
        op("GET", "/workflows", "List workflows", "Registered CLS workflows.", vec![]),
        op(
            "POST",
            "/workflows",
            "Register workflow",
            "POST CLS source.",
            vec![
                Field::body("id", "Workflow id", "wf-id"),
                Field::body("cls_source", "CLS source", ""),
            ],
        ),
        op("GET", "/workflows/reference-templates", "Reference templates", "Shipped templates.", vec![]),
        op("GET", "/workflows/catalog", "Workflow catalog", "Catalog sync status.", vec![]),
        op("POST", "/workflows/catalog/sync", "Sync catalog", "Pull catalog.", vec![]),
        op("GET", "/workflows/surfaces", "Workflow surfaces", "Operator surfaces.", vec![]),
        op("GET", "/plugins/workflow-contracts", "Plugin workflow contracts", "Contracts per plugin.", vec![]),
        op(
            "POST",
            "/workflows/bootstrap",
            "Bootstrap workflow",
            "reference:<id> or cls_source.",
            vec![
                Field::body("source", "Source", "reference:hello"),
                Field::body("enable", "Enable", "true"),
            ],
        ),
        op(
            "POST",
            "/workflows/reference/{id}/install",
            "Install reference",
            "One-click install.",
            vec![ID],
        ),
        op(
            "POST",
            "/workflows/reference/{id}/sample-run",
            "Sample run",
            "Run the sample for a reference template.",
            vec![ID],
        ),
        op("GET", "/workflows/{id}", "Workflow detail", "One workflow.", vec![ID]),
        op("GET", "/workflows/{id}/builder-round-trip", "Builder round-trip", "Round-trip status.", vec![ID]),
        op("GET", "/workflows/{id}/surface", "Workflow surface", "Operator surface doc.", vec![ID]),
        op("GET", "/workflows/{id}/capabilities", "Workflow capabilities", "Declared capabilities.", vec![ID]),
        op("GET", "/workflows/{id}/edge", "Workflow edge", "Edge binding.", vec![ID]),
        op("GET", "/workflows/{id}/versions", "Workflow versions", "Version list.", vec![ID]),
        op("GET", "/workflows/{id}/runs", "Workflow runs", "Runner history.", vec![ID]),
        op("GET", "/workflows/{id}/dry-runs", "Dry-runs", "Dry-run index.", vec![ID]),
        op(
            "POST",
            "/workflows/{id}/lifecycle",
            "Lifecycle",
            "compile · stage · enable · pause · archive.",
            vec![ID, Field::body("state", "State", "ENABLED")],
        ),
        op("POST", "/workflows/{id}/dry-run", "Dry-run", "Execute a dry-run.", vec![ID]),
        op("POST", "/workflows/{id}/rollback", "Rollback workflow", "Roll back a version.", vec![ID]),
        op(
            "POST",
            "/workflows/{id}/runs/{run_id}/cancel",
            "Cancel run",
            "Cancel a live run.",
            vec![ID, Field::path("run_id", "Run id", "run-id")],
        ),
        op(
            "GET",
            "/workflows/{id}/dry-runs/{run_id}",
            "Dry-run report",
            "One dry-run report.",
            vec![ID, Field::path("run_id", "Run id", "run-id")],
        ),
        op("POST", "/hub/workflows/publish", "Hub publish", "Publish to hub if implemented.", vec![Field::body("workflow_id", "Workflow id", "wf-id")]),
    ]
}

fn mesh_ops() -> Vec<Op> {
    vec![
        op("GET", "/substrate/status", "Substrate status", "Durability, isolation, concurrency honesty.", vec![]),
        op("GET", "/substrate/admission/matrix", "Admission matrix", "Who may enter which plane.", vec![]),
        op("GET", "/runtime/mesh", "Runtime mesh", "Single-node mesh vocabulary.", vec![]),
        op("GET", "/runtime/mesh/ping", "Mesh ping", "Reachability.", vec![]),
        op("GET", "/runtime/cells", "Runtime cells", "Cell table.", vec![]),
        op("GET", "/runtime/ha-federation", "HA federation", "Federation posture.", vec![]),
        op("GET", "/runtime/mesh/join-token", "Join token", "Lab join token if enabled.", vec![]),
        op("POST", "/runtime/mesh/join-token", "Mint join token", "Process-local. Clears on restart.", vec![]),
        op(
            "POST",
            "/runtime/mesh/channel/send",
            "Channel send",
            "HMAC envelope to a peer inbox. Needs CONNECTOR_MESH_CHANNEL_SECRET.",
            vec![
                Field::body("peer_url", "Peer URL", "http://127.0.0.1:18081"),
                Field::body("payload", "Payload JSON", "{}"),
            ],
        ),
        op("GET", "/runtime/mesh/channel/inbox", "Channel inbox list", "Local inbox.", vec![]),
        op(
            "POST",
            "/runtime/mesh/channel/inbox",
            "Channel inbox receive",
            "Peer delivery path. Signed body required.",
            vec![Field::body("kind", "Kind", "cnp_mesh_channel.v1")],
        ),
        op("GET", "/cnp/overview", "CNP overview", "Native protocol layers.", vec![]),
        op("GET", "/runtime/pores", "Landlock pores", "iptables-like world-address table. Default DROP. Vendor LLM dests exclusive to cage when a tool is connected.", vec![Field::query("agent_pid", "Agent pid (optional)", "")]),
        op("GET", "/runtime/llm-vendor-cut", "LLM vendor cut", "Host DROP of Anthropic/OpenAI/etc except the Landlock LLM cage mark.", vec![]),
        op("GET", "/cnp/wire", "CNP wire", "L2 wire status.", vec![]),
        op("GET", "/cnp/inbox", "CNP inbox", "Inbound CNP.", vec![]),
        op(
            "POST",
            "/cnp/send",
            "CNP send",
            "Serialize a cognitive message onto L2. Package pin required outside lab.",
            vec![
                Field::body("dest_cell", "Dest cell", "cell_local"),
                Field::body("text", "Text", "hello"),
                Field::body("agent_pid", "Agent pid (optional)", ""),
                Field::body("package", "Package pin JSON (required outside lab)", ""),
            ],
        ),
        op(
            "POST",
            "/cnp/actuation",
            "CNP actuation",
            "Admit connector.cnp.actuation.v1 (SetPosition, Gripper, …). Not SIL/ROS.",
            vec![
                Field::body("from_agent", "From agent", "agent-pid"),
                Field::body("to_agent", "To agent / cell", "agent_machine_proxy"),
                Field::body("command", "Command", "set_position"),
                Field::body("parameters", "Parameters JSON", "{\"joint_positions\":[0.1]}"),
                Field::body("package", "Package pin JSON (required outside lab)", ""),
            ],
        ),
        op(
            "POST",
            "/cnp/messages",
            "CNP messages",
            "Alias of /cnp/actuation (plan surface).",
            vec![
                Field::body("from_agent", "From agent", "agent-pid"),
                Field::body("to_agent", "To agent / cell", "agent_machine_proxy"),
                Field::body("command", "Command", "emergency_stop"),
                Field::body("parameters", "Parameters JSON", "{}"),
            ],
        ),
        op("GET", "/distribution/releases", "Distribution releases", "Known release channels.", vec![]),
        op(
            "POST",
            "/distribution/download-link",
            "Download link",
            "GitHub release URL for a platform/arch.",
            vec![
                Field::body("platform", "Platform", "linux"),
                Field::body("arch", "Arch", "amd64"),
                Field::body("version", "Version", "latest"),
            ],
        ),
        op(
            "POST",
            "/distribution/verify",
            "Verify binary",
            "License instance match + hash present. Does not hash a file on disk.",
            vec![
                Field::body("sha256", "SHA-256", ""),
                Field::body("instance_id", "Instance id", ""),
            ],
        ),
        op("GET", "/memory/tier/distribution/{agent_pid}", "Memory tier distribution", "Hot/warm/cold for one agent.", vec![AGENT]),
        op("GET", "/intelligence/spec-schema", "Intelligence spec schema", "Apply schema.", vec![]),
        op(
            "POST",
            "/intelligence/apply",
            "Apply intelligence",
            "Create + charter + activate. Developer+.",
            vec![
                Field::body("kind", "Kind", "Intelligence"),
                Field::body("metadata", "Metadata JSON", "{\"name\":\"my-i\"}"),
                Field::body("spec", "Spec JSON", "{\"purpose\":\"…\"}"),
            ],
        ),
        op("GET", "/intelligence/gateway/status", "Gateway status", "Intelligence gateway.", vec![]),
        op("GET", "/intelligence/gateway/addresses", "Gateway addresses", "Bound addresses.", vec![]),
        op("GET", "/intelligence/gateway/grants", "Gateway grants", "Active grants.", vec![]),
        op(
            "POST",
            "/intelligence/gateway/root",
            "Gateway root",
            "Init or rotate the kernel root passcode. Admin+.",
            vec![
                Field::body("root_passcode", "Root passcode", ""),
                Field::body("new_root_passcode", "New passcode (optional)", ""),
            ],
        ),
        op(
            "POST",
            "/intelligence/gateway/address",
            "Put gateway address",
            "Register a world address. Owner + root.",
            vec![
                Field::body("address", "Address", "local:host"),
                Field::body("type", "Type", "host"),
                Field::body("root_passcode", "Root passcode", ""),
                Field::body("label", "Label (optional)", ""),
            ],
        ),
        op(
            "POST",
            "/intelligence/gateway/grant",
            "Put gateway grant",
            "Per (agent × address). Default Cone Ask. App Allow is human+root only.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("address", "Address", "local:host"),
                Field::body("root_passcode", "Root passcode", ""),
                Field::body("effect", "Effect (optional)", "ask"),
                Field::body("access", "Access JSON (optional)", "[]"),
            ],
        ),
        op(
            "POST",
            "/intelligence/gateway/grant/revoke",
            "Revoke gateway grant",
            "Human operator only. Compensating undo.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("address", "Address", "local:host"),
                Field::body("root_passcode", "Root passcode", ""),
            ],
        ),
        op("GET", "/world/browser", "Browser world", "Connector-native web explorer posture. Document GET, not Chromium computer-use.", vec![]),
        op(
            "POST",
            "/world/browser/navigate",
            "Browser navigate",
            "Governed one-hop GET. Owner must grant the origin (type browser). Redirects are not followed.",
            vec![
                Field::body("agent_pid", "Agent pid", "agent-pid"),
                Field::body("url", "URL", "https://example.com"),
                Field::body("session_id", "Session id (optional)", ""),
            ],
        ),
        op("GET", "/world/browser/sessions", "Browser sessions", "Recorded exploration sessions.", vec![Field::query("agent_pid", "Agent pid (optional)", "")]),
        op("GET", "/multiagent/intelligence/standard", "Multiagent standard", "Pipeline spec.", vec![]),
        op("GET", "/multiagent/map", "Cross-agent map", "Who talks to whom.", vec![]),
        op("GET", "/multiagent/ports", "Multiagent ports", "Open ports.", vec![]),
        op("GET", "/multiagent/mesh/knowledge-plane", "Knowledge plane", "Shared knowledge mesh.", vec![]),
        op(
            "POST",
            "/multiagent/pipeline",
            "Run pipeline",
            "Parallel groups on agents[].parallel_group. Tenant required.",
            vec![
                Field::body("name", "Name", "pipe"),
                Field::body("user", "User", "operator"),
                Field::body("input", "Input", "hello"),
                Field::body("agents", "Agents JSON", "[{\"name\":\"a\"},{\"name\":\"b\",\"parallel_group\":\"g1\"}]"),
            ],
        ),
        op(
            "GET",
            "/multiagent/trace/{pipe_name}",
            "Pipeline trace",
            "Trace a named pipeline.",
            vec![Field::path("pipe_name", "Pipe name", "pipe")],
        ),
        op(
            "POST",
            "/multiagent/tasks/dispatch",
            "Dispatch task",
            "Dispatch across agents.",
            vec![Field::body("task", "Task", "classify")],
        ),
        op("GET", "/runtime/mode", "Runtime mode", "Lab / defense-strict.", vec![]),
        op("GET", "/runtime/activation", "Activation", "Node activation.", vec![]),
        op("GET", "/runtime/self", "Runtime self", "This node's identity.", vec![]),
        op("GET", "/runtime/contract", "Runtime contract", "Bound contract.", vec![]),
        op("GET", "/runtime/hardware", "Runtime hardware", "Hardware placement.", vec![]),
        op("GET", "/runtime/matrix", "Runtime matrix", "Matrix isolation.", vec![]),
        op("GET", "/runtime/isolation", "Isolation runtime", "Node isolation posture.", vec![]),
        op(
            "POST",
            "/runtime/isolation",
            "Set isolation runtime",
            "Write isolation posture.",
            vec![Field::body("tier", "Tier", "standard")],
        ),
        op("GET", "/runtime/isolation/{agent_pid}", "Agent isolation", "Isolation tier for one agent.", vec![AGENT]),
        op("GET", "/runtime/policy", "Runtime policy", "Bound runtime policy.", vec![]),
        op("GET", "/runtime/permissions", "Runtime permissions", "Permission table.", vec![]),
        op(
            "POST",
            "/multiagent/grant",
            "Multiagent grant",
            "AccessGrant between agents. Isolated by default — grantee required.",
            vec![
                Field::body("grantor_pid", "Grantor", "agent-a"),
                Field::body("grantee_pid", "Grantee", "agent-b"),
                Field::body("namespace", "Namespace", "default"),
                Field::body("justification", "Justification", "why"),
                Field::body("permissions", "Permissions JSON (optional)", "[\"read\"]"),
            ],
        ),
        op(
            "POST",
            "/multiagent/revoke",
            "Multiagent revoke",
            "Revoke an AccessGrant.",
            vec![
                Field::body("grantor_pid", "Grantor", "agent-a"),
                Field::body("grantee_pid", "Grantee", "agent-b"),
                Field::body("namespace", "Namespace", "default"),
            ],
        ),
    ]
}

#[component]
pub fn ConsoleCanvas(auth: ReadSignal<AuthState>) -> impl IntoView {
    let _ = auth;
    crate::components::page_title::use_page_title("System Console");
    let tab = RwSignal::new(Tab::Agent);
    let (filter, set_filter) = signal(String::new());
    let (quick_pid, set_quick_pid) = signal(String::new());

    let tabs = [
        Tab::Agent,
        Tab::Memory,
        Tab::Kernel,
        Tab::Infra,
        Tab::Safety,
        Tab::Economy,
        Tab::Intel,
        Tab::Comply,
        Tab::Lab,
        Tab::V2,
        Tab::Work,
        Tab::Mesh,
    ];

    view! {
        <div class="w-full px-4 py-4 sm:px-6 pb-10 fcs-install">
            <div class="fcs-bezel">
                <div class="fcs-titlebar">
                    <div class="fcs-titlebar-mark">
                        <span class="fcs-win-controls" aria-hidden="true">
                            <span class="fcs-win-btn close"></span>
                            <span class="fcs-win-btn"></span>
                            <span class="fcs-win-btn"></span>
                        </span>
                        <span class="truncate">"CONNECTOR OS  ·  SYSTEM CONSOLE"</span>
                    </div>
                    <div class="fcs-lights">
                        <span class="fcs-light pwr"><span class="dot"></span>"BUS"</span>
                        <span class="fcs-light pwr"><span class="dot"></span>"DECK"</span>
                    </div>
                </div>

                <div class="fcs-body space-y-4">
                    <div>
                        <OpText text="SYSTEM CONSOLE".to_string() variant=OpTextVariant::Title />
                        <p class="mt-1 text-sm text-stone-400 leading-relaxed">
                            "API catalog for this node — every card is a real endpoint. An empty agent list does not clear these cards; they are not a live inbox of agent work."
                        </p>
                    </div>

                    <div class="fcs-pad flex flex-wrap items-end gap-2">
                        <label class="flex flex-col gap-1 flex-1 min-w-[12rem]">
                            <span class="text-[10px] uppercase tracking-wider text-stone-500">"Inspect an agent live"</span>
                            <input
                                class="fcs-input"
                                placeholder="agent-pid"
                                prop:value=move || quick_pid.get()
                                on:input=move |ev| set_quick_pid.set(event_target_value(&ev))
                            />
                        </label>
                        <button
                            type="button"
                            class="fcs-btn amber"
                            on:click=move |_| {
                                let p = quick_pid.get();
                                if !p.trim().is_empty() {
                                    open_agent_explain(p.trim().to_string());
                                }
                            }
                        >
                            "OPEN MONITOR"
                        </button>
                    </div>

                    <div class="flex flex-wrap items-center gap-2">
                        {tabs.into_iter().map(|t| {
                            let is_active = move || tab.get() == t;
                            view! {
                                <button
                                    type="button"
                                    class=move || if is_active() { "fcs-btn go" } else { "fcs-btn" }
                                    on:click=move |_| tab.set(t)
                                >
                                    {format!("{} · {}", t.code(), t.label())}
                                </button>
                            }
                        }).collect_view()}
                        <input
                            class="fcs-input ml-auto max-w-[16rem]"
                            placeholder="filter operations…"
                            prop:value=move || filter.get()
                            on:input=move |ev| set_filter.set(event_target_value(&ev))
                        />
                    </div>

                    {move || {
                        let needle = filter.get().to_lowercase();
                        let ops = match tab.get() {
                            Tab::Agent => agent_ops(),
                            Tab::Memory => memory_ops(),
                            Tab::Kernel => kernel_ops(),
                            Tab::Infra => infra_ops(),
                            Tab::Safety => safety_ops(),
                            Tab::Economy => economy_ops(),
                            Tab::Intel => intel_ops(),
                            Tab::Comply => comply_ops(),
                            Tab::Lab => lab_ops(),
                            Tab::V2 => v2_ops(),
                            Tab::Work => work_ops(),
                            Tab::Mesh => mesh_ops(),
                        };
                        let shown: Vec<Op> = ops
                            .into_iter()
                            .filter(|o| {
                                needle.is_empty()
                                    || o.label.to_lowercase().contains(&needle)
                                    || o.path.to_lowercase().contains(&needle)
                            })
                            .collect();
                        view! {
                            <div class="fcs-ops-grid">
                                {shown.into_iter().map(|o| view! { <OpCard op=o /> }).collect_view()}
                            </div>
                        }
                    }}
                </div>

                <div class="fcs-statusbar">
                    <span>"LIVE ENDPOINTS  ·  RESPONSES VERBATIM"</span>
                    <span>"SYSTEM CONSOLE"</span>
                </div>
            </div>
        </div>
    }
}

#[component]
fn OpCard(op: Op) -> impl IntoView {
    let fields = op.fields.clone();
    let values: Vec<RwSignal<String>> = fields.iter().map(|_| RwSignal::new(String::new())).collect();
    let (out, set_out) = signal(String::new());
    let (busy, set_busy) = signal(false);

    let method = op.method;
    let path_tpl = op.path;
    let fields_run = fields.clone();
    let values_run = values.clone();

    let run = move |_| {
        let mut path = path_tpl.to_string();
        let mut body = Map::new();
        let mut missing: Vec<&str> = Vec::new();

        let mut query: Vec<String> = Vec::new();
        for (f, v) in fields_run.iter().zip(values_run.iter()) {
            let raw = v.get();
            let val = raw.trim();
            match f.at {
                Where::Path => {
                    if val.is_empty() {
                        missing.push(f.label);
                    } else {
                        path = path.replace(&format!("{{{}}}", f.key), val);
                    }
                }
                Where::Query => {
                    if !val.is_empty() {
                        query.push(format!(
                            "{}={}",
                            f.key,
                            js_sys::encode_uri_component(val)
                        ));
                    }
                }
                Where::Body => {
                    if !val.is_empty() {
                        // Keep booleans, numbers and JSON literals typed so the
                        // server sees real JSON rather than a quoted string.
                        let parsed = match val {
                            "true" => json!(true),
                            "false" => json!(false),
                            other if other.starts_with('[') || other.starts_with('{') => {
                                serde_json::from_str::<Value>(other)
                                    .unwrap_or_else(|_| json!(other))
                            }
                            other => other
                                .parse::<f64>()
                                .map(|n| json!(n))
                                .unwrap_or_else(|_| json!(other)),
                        };
                        body.insert(f.key.to_string(), parsed);
                    }
                }
            }
        }

        if !missing.is_empty() {
            set_out.set(format!("Required: {}", missing.join(", ")));
            return;
        }

        if !query.is_empty() {
            path = format!("{path}?{}", query.join("&"));
        }

        set_busy.set(true);
        set_out.set(String::new());
        spawn_local(async move {
            let payload = Value::Object(body);
            let res = match method {
                "GET" => api::get_value(&path).await,
                "POST" => api::post_value(&path, payload).await,
                "PUT" => api::put_value(&path, payload).await,
                "PATCH" => api::patch_value(&path, payload).await,
                "DELETE" => api::delete_value(&path).await,
                _ => api::get_value(&path).await,
            };
            match res {
                Ok(v) => set_out.set(serde_json::to_string_pretty(&v).unwrap_or_default()),
                Err(e) => set_out.set(format!("{e}")),
            }
            set_busy.set(false);
        });
    };

    let destructive = matches!(op.method, "DELETE")
        || op.label.contains("Purge")
        || op.label.contains("Kill")
        || op.label.contains("Slash")
        || op.label.contains("Forget")
        || op.label.contains("Estop")
        || op.label.contains("Terminate")
        || op.label.contains("Close council")
        || op.label.contains("Quarantine") && !op.label.contains("Un");

    let btn_class = if destructive { "fcs-btn amber" } else { "fcs-btn go" };

    view! {
        <article class=move || {
            if out.get().is_empty() {
                "fcs-pad space-y-2 min-w-0"
            } else {
                "fcs-pad space-y-2 min-w-0 is-open"
            }
        }>
            <div class="flex items-start justify-between gap-2">
                <div class="min-w-0">
                    <p class="fcs-pad-id">{format!("{} {}", op.method, op.path)}</p>
                    <h4 class="text-xs font-semibold text-stone-100 mt-0.5">{op.label}</h4>
                </div>
            </div>
            <p class="text-[11px] text-stone-400">{op.desc}</p>

            {(!fields.is_empty()).then(|| {
                let pairs: Vec<(Field, RwSignal<String>)> =
                    fields.iter().cloned().zip(values.iter().copied()).collect();
                view! {
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                        {pairs.into_iter().map(|(f, sig)| view! {
                            <label class="flex flex-col gap-1">
                                <span class="text-[9px] uppercase tracking-wider text-stone-500">{f.label}</span>
                                <input
                                    class="fcs-input"
                                    placeholder=f.placeholder
                                    prop:value=move || sig.get()
                                    on:input=move |ev| sig.set(event_target_value(&ev))
                                />
                            </label>
                        }).collect_view()}
                    </div>
                }
            })}

            <button
                type="button"
                class=btn_class
                prop:disabled=move || busy.get()
                on:click=run
            >
                {move || if busy.get() { "RUNNING…" } else { "RUN" }}
            </button>

            {move || {
                let o = out.get();
                (!o.is_empty()).then(|| view! {
                    <pre class="fcs-pre max-h-56 overflow-auto">{o}</pre>
                })
            }}
        </article>
    }
}
