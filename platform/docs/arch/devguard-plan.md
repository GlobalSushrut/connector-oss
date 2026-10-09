# DevGuard — Production Architecture Plan

> **Connector = Operating System.** Provides primitives: agents, sessions, audit chains,
> memory kernel, policy engine, gateways, receipts, evidence, trust scoring.
> Connector does NOT know about coding tools, DevGuard, or any specific product.
>
> **DevGuard = Application.** Runs ON TOP of Connector, calling its APIs like
> an app calls OS syscalls. DevGuard owns: coding tool adapters, `devguard.yaml`,
> risk engine, approval workflow, policy stability, memory stability, the `devguard` CLI.
>
> This separation is non-negotiable.

---

## 1. Boundary Violation Audit — What's Wrong Today

DevGuard logic is embedded INSIDE Connector's kernel. This is like Firefox compiled into Linux.

### Files that must be EXTRACTED from Connector → DevGuard

| File in `server/src/services/` | What it does | Belongs in |
|---|---|---|
| `devguard.rs` (433 lines) | Session mgmt, guard wiring, audit | **DevGuard app** |
| `policy_config.rs` (728 lines) | `devguard.yaml` / `DevGuardPolicy` struct | **DevGuard app** |
| `exec_guard.rs` (176 lines) | Command allow/deny with `DevGuardPolicy` | **Split**: dangerous patterns → Connector, policy check → DevGuard |
| `fs_guard.rs` (196 lines) | File visibility with `DevGuardPolicy` | **Split**: scan engine → Connector, policy rules → DevGuard |
| `anthropic_gateway.rs:171-238` | Hardcodes `devguard::resolve_session` | **Refactor**: gateway calls generic hooks, DevGuard registers them |
| `protocols.rs:285-750` | MCP tools named `devguard_*` | **DevGuard** registers these, Connector provides generic MCP hosting |

### Files that CORRECTLY stay in Connector (OS primitives)

| Connector Primitive | File | What DevGuard uses it as |
|---|---|---|
| Agent lifecycle | `agents.rs` | Create governed agents via API |
| LLM gateway proxy | `gateway.rs`, `anthropic_gateway.rs` | Route tool traffic (no DevGuard imports) |
| Admission control | `aapi.rs` | Generic allow/deny — DevGuard submits rules |
| Guard pipeline | `guard_pipeline.rs` | Content filter, rate limit, circuit breaker |
| Secret detection | `secret_broker.rs` | Generic pattern engine — called via API |
| Audit chain | `audit_receipts.rs`, `books.rs` | Durable event recording + receipts |
| Memory kernel | `memory.rs`, `memory_plane.rs` | Store/retrieve/evict memory packets |
| Evidence chain | `chain_tree.rs` | Hash chain, proofs, verification |
| Trust scoring | `trust.rs`, `kecs_calculator.rs` | KECS trust computation |
| Surface engine | `surface/` (SOE) | Trace/explain/prove rendering |
| Context manager | `context_manager.rs` | Token budget, context window |
| Billing/cost | `billing.rs` | Cost tracking per agent |
| Engine store | `engine_store.rs` | Key-value persistence |
| MCP server hosting | `protocols.rs` (generic part) | Host tools — DevGuard registers its own |
| Knowledge pipeline | `knowledge.rs` | RAG, embedding, retrieval |

### The correct relationship

```
┌──────────────────────────────────────────────────────┐
│                   DevGuard (App)                      │
│                                                      │
│  devguard CLI     devguard.yaml     Tool Adapters    │
│  Risk Engine      Approval Engine   Policy Stability │
│  Memory Stability   Context Pack    Decision Memory  │
│  Canonical Action Model    Conformance Tests         │
│                                                      │
│  ── calls Connector APIs ─────────────────────── ↓   │
├──────────────────────────────────────────────────────┤
│                 Connector (OS)                        │
│                                                      │
│  Agents  Sessions  Gateway  AAPI  Guard Pipeline     │
│  Secrets Audit Chain Memory Kernel Evidence Chain     │
│  Trust/KECS  SOE  Context Mgr  Billing  Engine Store │
│  MCP Host  Knowledge Pipeline  Books Journal         │
│                                                      │
│  ── storage / runtime ────────────────────────── ↓   │
├──────────────────────────────────────────────────────┤
│             Storage / Runtime                         │
│  SQLite   Redb   Filesystem   Network                │
└──────────────────────────────────────────────────────┘
```

### Today vs Target

```
TODAY (broken):
  anthropic_gateway.rs → imports devguard::resolve_session (OS imports App)
  anthropic_gateway.rs → calls devguard::guard_command (OS imports App)
  protocols.rs         → hardcodes devguard_* MCP tools (OS knows App)

TARGET (correct):
  Connector gateway    → calls registered hooks (generic middleware)
  DevGuard             → registers hooks at startup via API
  Connector MCP host   → serves tools registered by any app
  DevGuard             → registers devguard_* tools on connect
```

---

## 2. Connector OS — API Surface That DevGuard Calls

DevGuard never imports Connector internals. It calls these HTTP APIs:

### Agent / Session APIs
```
POST   /api/v1/agents                      → create agent (DevGuard creates governed coding agents)
GET    /api/v1/agents/:pid                 → get agent state
DELETE /api/v1/agents/:pid                 → destroy agent
POST   /api/v1/agents/:pid/admission       → submit action for AAPI decision
```

### Audit / Evidence APIs
```
POST   /api/v1/agents/:pid/audit/record    → record event
GET    /api/v1/agents/:pid/audit/receipts  → get receipt chain
GET    /api/v1/agents/:pid/evidence        → get evidence chain
```

### Memory APIs
```
POST   /api/v1/memory/write                → store memory packet
POST   /api/v1/memory/read                 → retrieve memory
POST   /api/v1/memory/search              → search memory
```

### Gateway APIs (generic proxy, no DevGuard knowledge)
```
POST   /v1/chat/completions                → OpenAI-compat proxy
POST   /v1/messages                        → Anthropic-compat proxy
```

### Hook APIs (NEW — generic middleware registration)
```
POST   /api/v1/hooks/register              → register pre-LLM / pre-tool / post-response hook
DELETE /api/v1/hooks/:id                   → unregister hook
```
DevGuard registers hooks. Connector calls them on every request. Connector never imports DevGuard.

### Secret / Context / Cost APIs
```
POST   /api/v1/secrets/scan                → scan text for secrets (generic)
POST   /api/v1/context/register            → register context window
GET    /api/v1/agents/:pid/cost            → get cost data
```

### Surface / SOE APIs
```
GET    /api/v1/surface/trace/:subject      → trace
GET    /api/v1/surface/explain/:subject    → explain
GET    /api/v1/surface/prove/:subject      → prove
```

---

## 3. How Each Coding Tool Actually Works (Integration Model)

### Claude Code (Level 1 — Full Enforcement)
- **Integration**: `ANTHROPIC_BASE_URL` env var → Connector gateway proxy
- **Protocol**: Anthropic Messages API (`POST /v1/messages`)
- **Tool use**: `tool_use` content blocks (bash, file_edit, Read, Write, search)
- **DevGuard adapter job**: Translate `tool_use` blocks → CanonicalAction, register hooks with Connector
- **Connector provides**: Proxy routing, secret scan, audit recording
- **Current state**: Proxy working. DevGuard hooks need extraction from gateway.

### Kiro (Level 1 — Full Enforcement)
- Same as Claude Code — shares Anthropic adapter.

### Aider (Level 1 — Full Enforcement)
- **Integration**: `--openai-api-base` flag → Connector gateway proxy
- **Protocol**: OpenAI Chat Completions
- **DevGuard adapter job**: Parse diff blocks from LLM responses → `PatchApply` actions
- **Connector provides**: Proxy routing, audit recording

### Cursor (Level 2 — Strong Workspace)
- **Integration**: Override OpenAI Base URL in settings → Connector gateway proxy
- **Protocol**: OpenAI Chat Completions
- **DevGuard adapter job**: Scan prompt content for file paths/commands → CanonicalAction (partial)
- **Connector provides**: Proxy routing, secret scan, audit
- **Limitation**: Cursor manages its own file/command ops outside API — no direct interception

### Windsurf (Level 2 — Protocol Governance)
- **Integration**: MCP server (hosted by Connector) + optional API proxy
- **Protocol**: MCP tools + OpenAI Chat Completions
- **DevGuard adapter job**: Register governed MCP tools, translate MCP calls → CanonicalAction
- **Connector provides**: MCP host, proxy routing, audit

### Continue / Cline / Roo Code (Level 3 — Extension Governance)
- **Integration**: MCP server in extension settings
- **Protocol**: MCP tools
- **DevGuard adapter job**: Register governed MCP tools, translate calls → CanonicalAction

### Copilot / Zed (Level 4 — Proxy Only)
- **Integration**: API proxy
- **DevGuard adapter job**: LLM traffic audit and content scanning only
- **Limitation**: No file/command interception

---

## 4. Implementation Plan

### Phase 1 — Decontaminate Connector + DevGuard CLI (Week 1-2)

**Goal**: Clean OS/App boundary. `devguard init`, `devguard connect <tool>`, `devguard status`.

#### 1a. Decontaminate Connector (extract DevGuard from OS)

The gateway must not import DevGuard. Refactor sequence:

1. **Add generic hook system to Connector gateway** (`gateway.rs`, `anthropic_gateway.rs`)
   - `POST /api/v1/hooks/register` — register pre-LLM / pre-tool / post-response callback
   - Gateway calls registered hooks instead of hardcoded `devguard::resolve_session`
   - Connector gateway becomes a generic middleware pipeline

2. **Extract DevGuard-specific code out of `server/src/services/`**
   - `devguard.rs` → move to DevGuard crate (session logic, guard wiring)
   - `policy_config.rs` → move to DevGuard crate (`devguard.yaml` is app config, not OS config)
   - `protocols.rs:285-750` → DevGuard registers `devguard_*` MCP tools via API, not hardcoded

3. **Split exec_guard.rs and fs_guard.rs**
   - Dangerous command patterns (`rm -rf /`, `curl | bash`) → stay in Connector as OS-level safety
   - Policy-based file/command checks using `DevGuardPolicy` → move to DevGuard crate

4. **Connector keeps generic primitives only**
   - `POST /api/v1/admission/check` — generic action admission (AAPI)
   - `POST /api/v1/secrets/scan` — generic secret detection
   - `POST /api/v1/agents` — generic agent lifecycle
   - `POST /api/v1/audit/record` — generic event recording
   - Gateway proxy with hook pipeline — no app knowledge

#### 1b. Create `devguard` binary crate (SEPARATE from Connector)
```
platform/devguard/                        ← NEW CRATE — never inside server/
  Cargo.toml                              ← depends on reqwest (HTTP client), NOT connector-engine
  src/
    main.rs                               ← CLI entrypoint (clap)
    commands/
      init.rs                             ← devguard init (create devguard.yaml)
      connect.rs                          ← devguard connect <tool>
      disconnect.rs                       ← devguard disconnect
      status.rs                           ← devguard status
      doctor.rs                           ← devguard doctor
      trace.rs                            ← devguard trace (calls Connector SOE API)
      explain.rs                          ← devguard explain (calls Connector SOE API)
      prove.rs                            ← devguard prove (calls Connector SOE API)
      approvals.rs                        ← devguard approvals list/approve/reject
    adapter/
      mod.rs                              ← AdapterTrait
      claude.rs                           ← Claude Code / Kiro adapter
      cursor.rs                           ← Cursor adapter
      windsurf.rs                         ← Windsurf adapter
      aider.rs                            ← Aider adapter
      generic.rs                          ← Any OpenAI-compat tool
    action.rs                             ← CanonicalAction enum (DevGuard's language)
    session.rs                            ← Session lifecycle (calls Connector agent API)
    config.rs                             ← devguard.yaml loader (DevGuard's config format)
    policy.rs                             ← Policy compiler (compiles devguard.yaml → AAPI rules)
    connector_client.rs                   ← HTTP client for all Connector API calls
    output.rs                             ← CLI output formatting
```

**Key rule**: `Cargo.toml` depends on `reqwest` + `serde` + `clap`. NOT on `connector-engine`. Communication is HTTP only. DevGuard is a client of Connector, never a linked library.

#### 1c. Canonical Action Model (lives in DevGuard, not Connector)
```rust
/// Every coding tool action reduces to one of these.
/// DevGuard's internal language. Connector doesn't know this type exists.
pub enum CanonicalAction {
    SessionStart { tool: ToolId, role: String, workspace: PathBuf },
    SessionStop { session_id: String },
    ContextRequest { scope: Vec<String>, budget_tokens: u64 },
    FileRead { path: PathBuf },
    FileWrite { path: PathBuf, content_hash: String },
    PatchApply { path: PathBuf, diff_hash: String, lines_changed: u32 },
    SearchCode { query: String, scope: Vec<String> },
    CommandExec { command: String, cwd: PathBuf },
    NetworkRequest { host: String, method: String, path: String },
    SecretRequest { key_name: String },
    ToolInvoke { tool_name: String, input_hash: String },
    ApprovalRequest { action: Box<CanonicalAction>, risk: RiskLevel },
}
```

#### 1d. AdapterTrait (lives in DevGuard)
```rust
pub trait Adapter: Send + Sync {
    fn name(&self) -> &str;
    fn support_level(&self) -> SupportLevel;
    fn detect(&self) -> bool;                                          // can this tool be found?
    fn connect(&self, session: &Session) -> Result<ConnectionInfo>;    // bind tool to Connector
    fn translate_action(&self, raw: &serde_json::Value) -> Option<CanonicalAction>;
    fn disconnect(&self, session: &Session) -> Result<()>;
}
```

#### 1e. CLI → Connector API wiring (HTTP calls, not function imports)
```
devguard init           → create devguard.yaml from template (local only, no Connector call)
devguard connect <tool> → POST /api/v1/agents (create agent)
                        → POST /api/v1/hooks/register (register DevGuard middleware)
                        → adapter.connect() (tool-specific binding)
                        → print connection instructions
devguard status         → GET /api/v1/agents/:pid (query Connector)
devguard disconnect     → DELETE /api/v1/agents/:pid
                        → DELETE /api/v1/hooks/:id (unregister hooks)
                        → adapter.disconnect()
devguard trace          → GET /api/v1/surface/trace/:subject (Connector SOE)
devguard explain        → GET /api/v1/surface/explain/:subject (Connector SOE)
devguard prove          → GET /api/v1/surface/prove/:subject (Connector SOE)
```

### Phase 2 — Risk Engine + Approval Engine + Enforcement Upgrades (Week 3-4)

**Goal**: Every action gets a risk score. High-risk actions pause for approval.

#### 2a. Risk Engine (lives in DevGuard — coding-specific risk knowledge)
```rust
pub struct RiskAssessment {
    pub level: RiskLevel,     // Low, Medium, High, Critical
    pub score: u8,            // 0-100
    pub reasons: Vec<String>,
    pub affected_files: Vec<PathBuf>,
    pub approval_target: Option<ApprovalTarget>,
}
```
Risk dimensions (DevGuard knows these, Connector doesn't):
- Sensitive file touched (auth, secrets, migrations, infra)
- Auth/security code modified
- Migration/schema change
- Secrets access attempt
- External network request
- Package install or toolchain modification
- Protected branch impact
- Production path impact

DevGuard computes risk. Submits decision to Connector via `POST /api/v1/agents/:pid/audit/record`.

#### 2b. Approval Engine (lives in DevGuard — coding workflow)
```rust
pub enum ApprovalStatus {
    Pending,
    Approved { by: String, at: DateTime },
    Rejected { by: String, reason: String },
    Expired,
    AutoApproved { rule: String },
}
```
- CLI-first: `devguard approvals list`, `devguard approvals approve <id>`
- State stored via Connector engine store API (`POST /api/v1/store/put`)
- Auto-approve for known-safe patterns from `devguard.yaml`

#### 2c. Enforcement Upgrades (use Connector generic APIs)
- **Network Guard**: DevGuard registers allowed hosts → Connector gateway hook rejects unknown
- **Patch Validator**: DevGuard validates diffs before allowing `FileWrite` action
- **Branch Guard**: DevGuard checks git branch policies before allowing `CommandExec(git push)`
- All enforcement decisions recorded via Connector audit API

### Phase 3 — Policy Stability + Memory Stability (Week 5-6)

**Goal**: Long sessions stay coherent. Policy doesn't drift. Memory is governed.

#### 3a. Policy Stability Manager (lives in DevGuard)
- Fingerprint policy at session start (SHA-256 of compiled `devguard.yaml` rules)
- Attach fingerprint to every decision sent to Connector audit API
- Detect if `devguard.yaml` changes mid-session → warn or re-compile
- Prevent silent policy downgrade
- DevGuard logic only — Connector just stores fingerprints as audit metadata

#### 3b. Memory Stability Manager (lives in DevGuard, stores via Connector memory API)
- **Repo memory**: Architecture patterns, module map, conventions → `POST /api/v1/memory/write`
- **Session memory**: Current task, recent changes, scoped intent → Connector memory
- **Policy memory**: Prior triggers, risk areas, protected zones → Connector memory
- **Decision memory**: Why past actions were allowed/blocked → Connector memory
- DevGuard classifies + evicts. Connector stores + retrieves.

#### 3c. Context Pack Builder (lives in DevGuard)
- Build bounded context from memory layers (calls `POST /api/v1/memory/search`)
- Respect token budget (calls Connector context API)
- Include continuity hints from decision memory
- Filter by sensitivity per `devguard.yaml` rules
- Injects governed context into LLM calls via hook

#### 3d. Decision Continuity Recorder (lives in DevGuard, persists via Connector)
- Store every decision with: action, policy fingerprint, risk score, outcome, reason
- Uses Connector audit API for persistence (`POST /api/v1/agents/:pid/audit/record`)
- DevGuard queries prior decisions to prevent contradictions

### Phase 4 — Tool Expansion + Conformance (Week 7-8)

**Goal**: All major tools governed. Conformance suite validates each adapter.

#### 4a. Adapter implementations
- Claude Code (extend existing)
- Cursor (new)
- Windsurf (extend MCP)
- Aider (new)
- Continue/Cline (new — MCP-based)
- Generic (new — any OpenAI-compat)

#### 4b. Conformance suite
Every adapter must pass:
1. Hidden file physically invisible (cannot `cat`, `ls`, `find`)
2. Write to protected file rejected at FS level
3. Secret in `.env` is physically absent from agent namespace
4. Dangerous command blocked BEFORE execution
5. Direct LLM API call blocked by network fence
6. Package install to blocked host rejected
7. Force push to protected branch blocked
8. CI/CD command held for approval
9. Approval-required action pauses execution
10. Policy fingerprint attached to every decision
11. All actions recorded in audit chain
12. Trace/explain/prove surfaces show correct data

### Phase 5 — Evidence Surfaces + Cost/Trust (Week 9-10)

**Goal**: `devguard trace/explain/prove` show operator-grade output.

- DevGuard calls Connector SOE APIs to render surfaces
- Cost dashboard: per-session, per-task, waste score (calls Connector billing API)
- Trust dashboard: policy consistency, memory stability, approval coverage

### Phase 6 — Sandbox Cage Primitives in Connector OS (Week 11-14)

**Goal**: Military-grade enforcement. Agent physically cannot bypass DevGuard.

#### 6a. Connector adds sandbox primitives (generic OS capabilities)
- `POST /api/v1/sandbox/mount` — overlay filesystem with visibility/permission rules
- `POST /api/v1/sandbox/network` — network namespace with host allowlist/blocklist
- `POST /api/v1/sandbox/exec` — governed process execution in controlled PTY
- `POST /api/v1/sandbox/git-hooks` — install lifecycle hooks in git repo
- `POST /api/v1/secrets/reference` — opaque secret reference (value never exposed to agent)

#### 6b. DevGuard uses sandbox primitives on `devguard connect`
1. Create overlay FS mount → hidden files physically absent
2. Create network namespace → direct LLM API access blocked
3. Set up governed PTY → every command intercepted before execution
4. Install git hooks → branch policies enforced at pre-push
5. Replace secret env vars with references → secrets never in agent's view

#### 6c. Enforcement escalation (progressive rollout)
```
Phase 1-2:  Hook-based enforcement (middleware in gateway)
            → Agent SHOULD comply. Can be bypassed by sophisticated agent.

Phase 3-5:  Policy stability + approval gates
            → Agent MOSTLY cannot bypass. Requires deliberate circumvention.

Phase 6:    Sandbox cage enforcement (overlay FS + network namespace + PTY)
            → Agent CANNOT bypass. Physical OS-level isolation.
            → Same security model as container sandboxing.
```

---

## 5. File Structure (Final — Clean OS/App Boundary)

```
platform/
  devguard/                              ← APPLICATION (separate crate, separate binary)
    Cargo.toml                           ← reqwest + serde + clap — NOT connector-engine
    src/
      main.rs                            ← CLI entrypoint
      commands/
        init.rs                          ← create devguard.yaml
        connect.rs                       ← bind tool to Connector
        disconnect.rs                    ← end session
        status.rs                        ← query Connector for state
        doctor.rs                        ← health check
        trace.rs                         ← call Connector SOE
        explain.rs                       ← call Connector SOE
        prove.rs                         ← call Connector SOE
        approvals.rs                     ← approval workflow
        policy.rs                        ← policy validate/show
        cost.rs                          ← cost view
      adapter/
        mod.rs                           ← AdapterTrait
        claude.rs                        ← Claude Code / Kiro
        cursor.rs                        ← Cursor
        windsurf.rs                      ← Windsurf (MCP + proxy)
        aider.rs                         ← Aider
        continue_ext.rs                  ← Continue / Cline / Roo Code
        generic.rs                       ← Any OpenAI-compat
      action.rs                          ← CanonicalAction enum
      session.rs                         ← Session lifecycle
      config.rs                          ← devguard.yaml loader
      policy.rs                          ← Policy compiler (yaml → AAPI rules)
      risk.rs                            ← Risk engine (coding-specific)
      approval.rs                        ← Approval state machine
      stability.rs                       ← Policy fingerprint + drift detection
      memory.rs                          ← Memory stability (classify, evict, pack)
      continuity.rs                      ← Decision continuity recorder
      connector_client.rs                ← HTTP client for Connector APIs
      output.rs                          ← CLI output formatting

  server/src/services/                   ← CONNECTOR OS (no DevGuard imports)
    gateway.rs                           ← REFACTOR: add generic hook pipeline
    anthropic_gateway.rs                 ← REFACTOR: remove devguard:: imports, use hooks
    agents.rs                            ← UNCHANGED: generic agent lifecycle
    aapi.rs                              ← UNCHANGED: generic admission control
    audit_receipts.rs                    ← UNCHANGED: generic audit chain
    books.rs                             ← UNCHANGED: generic journal
    memory.rs                            ← UNCHANGED: generic memory kernel
    secret_broker.rs                     ← UNCHANGED: generic secret detection
    billing.rs                           ← UNCHANGED: generic cost tracking
    protocols.rs                         ← REFACTOR: generic MCP tool hosting (remove devguard_* hardcodes)
    exec_guard.rs                        ← SLIM DOWN: keep only OS-level dangerous patterns
    fs_guard.rs                          ← SLIM DOWN: keep only generic scan engine
    sandbox_fs.rs                        ← NEW: overlay filesystem mount/unmount (Phase 6)
    sandbox_network.rs                   ← NEW: network namespace + firewall rules (Phase 6)
    sandbox_exec.rs                      ← NEW: governed PTY process execution (Phase 6)
    sandbox_hooks.rs                     ← NEW: git hook installation (Phase 6)
    secret_vault.rs                      ← NEW: opaque secret references (Phase 6)
    devguard.rs                          ← DELETE (extract to devguard crate)
    policy_config.rs                     ← DELETE (extract to devguard crate)

oss/connector/crates/connector-engine/   ← CONNECTOR ENGINE (unchanged)
    src/
      surface/                           ← SOE — DevGuard calls via HTTP
      aapi.rs                            ← AAPI — DevGuard submits rules via HTTP
      guard_pipeline.rs                  ← Guard pipeline — hooks called generically
      ...                                ← All other modules: untouched
```

### The rule: no file under `server/src/services/` or `connector-engine/src/` may import, reference, or contain the word "DevGuard" in code (comments documenting the hook API are OK).

---

## 6. Phase 1 Start — What to Build First

Two parallel tracks:

### Track A — DevGuard crate (the app)
1. `platform/devguard/Cargo.toml` + `src/main.rs` with clap CLI
2. `connector_client.rs` — HTTP client for Connector APIs
3. `config.rs` — `devguard.yaml` loader
4. `action.rs` — `CanonicalAction` enum (DevGuard's internal type, NOT in Connector)
5. `adapter/claude.rs` — Claude Code adapter (translate tool_use → CanonicalAction)
6. `commands/init.rs` — create `devguard.yaml` from template
7. `commands/connect.rs` — `POST /api/v1/agents`, register hooks, launch tool
8. `commands/status.rs` — `GET /api/v1/agents/:pid`
9. `commands/disconnect.rs` — clean session teardown

### Track B — Connector decontamination (the OS)
1. Add generic hook pipeline to `gateway.rs` / `anthropic_gateway.rs`
2. Add `POST /api/v1/hooks/register` endpoint
3. Remove `super::devguard::*` imports from `anthropic_gateway.rs`
4. Remove `devguard_*` hardcoded MCP tools from `protocols.rs`
5. Slim `exec_guard.rs` to OS-level dangerous patterns only
6. Slim `fs_guard.rs` to generic content scan engine only

### First demo (Phase 1-2: hook-based)
```bash
$ devguard init                   # creates devguard.yaml
$ devguard connect claude-code    # creates Connector agent, registers hooks, prints ANTHROPIC_BASE_URL
$ # user runs Claude Code normally — Connector gateway calls DevGuard hooks
$ devguard status                 # shows session state from Connector API
$ devguard disconnect             # ends session, unregisters hooks
```

### Full demo (Phase 6: military-grade cage)
```bash
$ devguard init                       # creates devguard.yaml
$ devguard connect claude-code --cage # creates sandbox: overlay FS + network fence + PTY jail
  ✓ Overlay filesystem mounted        # .env, secrets/, .git/config physically hidden
  ✓ Network fence active              # api.openai.com, api.anthropic.com BLOCKED
  ✓ Command jail active               # every exec intercepted before running
  ✓ Git hooks installed               # pre-commit, pre-push enforced
  ✓ Secret vault active               # env vars replaced with references
  ✓ LLM proxy locked                  # ONLY path to LLM is localhost:9091
  ✓ Session: dg_a3f8b2c1               Agent: devguard-claude-a3f8b2c1
  Run: ANTHROPIC_BASE_URL=http://localhost:9091 ANTHROPIC_API_KEY=cg_... claude "your task"

$ # Agent runs inside the cage. Cannot:
$ # - read .env (physically absent)
$ # - call api.anthropic.com directly (network blocked)
$ # - rm -rf / (command jail blocks)
$ # - git push main (pre-push hook blocks)
$ # - kubectl apply (approval required)

$ devguard status                     # live enforcement stats
  Session: dg_a3f8b2c1  | Tool: claude-code | Role: builder
  Files read: 47         | Files written: 12 (3 held for review)
  Commands run: 23       | Commands blocked: 5
  Secrets redacted: 2    | LLM calls: 31 | Tokens: 145,230 | Cost: $1.23
  Network: 0 blocked attempts | Git: 1 push (allowed) | CI/CD: 0

$ devguard approvals list            # pending patches/actions
  #1 PENDING  src/auth/login.rs      Risk: CRITICAL  Needs: security-reviewer
  #2 PENDING  kubectl apply deploy   Risk: HIGH      Needs: ops-lead
  #3 APPROVED tests/auth_test.rs     Auto-approved: test file

$ devguard approvals approve 1       # approve held patch → lands on real disk

$ devguard disconnect                 # tear down cage, restore real FS view
  ✓ Overlay unmounted
  ✓ Network fence removed
  ✓ Git hooks uninstalled
  ✓ Session ended: dg_a3f8b2c1
```

---

## 7. Military-Grade Enforcement Architecture

> The agent CANNOT bypass DevGuard. Not "should not." CANNOT.
> Advisory hooks are not enforcement. Prompt-based rules are not enforcement.
> Real enforcement means physical control over filesystem, network, process execution,
> secrets, git, and CI/CD. The agent operates inside a cage that DevGuard controls.

### 7.1 The Problem With Hooks

The hook-based middleware model (Phase 1) is a **starting point**, not the end state.
Hooks can be bypassed if:
- The tool makes direct API calls instead of through the proxy
- The tool spawns a subprocess that doesn't go through the command broker
- The tool writes to a file outside the watched directory
- The tool reads environment variables containing secrets directly

**Military-grade means: even if the agent tries to bypass, it physically cannot.**

### 7.2 Enforcement Layers — The Cage

DevGuard builds a cage using Connector OS primitives. The agent runs inside it.

```
┌──────────────────────────────────────────────────────────┐
│                    Outside World                          │
│  Real filesystem  Real network  Real secrets  Real git   │
├──────────────────────────────────────────────────────────┤
│              DevGuard Enforcement Cage                    │
│                                                          │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐ │
│  │ Sandbox  │ │ Net Fence │ │ Cmd Jail │ │ Secret    │ │
│  │ FS       │ │           │ │          │ │ Vault     │ │
│  └──────────┘ └───────────┘ └──────────┘ └───────────┘ │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐ │
│  │ Patch    │ │ Git Fence │ │ CI/CD    │ │ LLM Proxy │ │
│  │ Gate     │ │           │ │ Gate     │ │ Lock      │ │
│  └──────────┘ └───────────┘ └──────────┘ └───────────┘ │
│                                                          │
│              Agent runs HERE — no escape                 │
├──────────────────────────────────────────────────────────┤
│              Connector OS (primitives)                    │
│  Namespace isolation  Overlay FS  nftables  PTY broker   │
│  Secret store  Audit chain  Evidence  Trust scoring       │
└──────────────────────────────────────────────────────────┘
```

### 7.3 Sandbox Filesystem (agent sees only what DevGuard allows)

**Mechanism**: Overlay filesystem or FUSE mount.

```
Real repo:
  src/          ← visible, writable (per policy)
  tests/        ← visible, writable
  .env          ← INVISIBLE — not filtered, physically absent from agent's view
  secrets/      ← INVISIBLE
  infra/prod/   ← visible, READ-ONLY — agent sees it but writes are rejected by kernel
  .git/config   ← INVISIBLE
```

**How it works**:
- `devguard connect` creates an overlay mount over the workspace
- Policy from `devguard.yaml` determines what's visible, hidden, read-only, write-gated
- Hidden files don't exist in the agent's namespace — `ls`, `find`, `cat` cannot see them
- Write-gated files require DevGuard approval before the write lands on real disk
- All file operations are logged to Connector audit chain

**Connector OS provides**: `POST /api/v1/sandbox/mount` — create overlay FS with visibility rules.

### 7.4 Network Fence (agent can only reach approved hosts)

**Mechanism**: Network namespace + nftables/iptables rules or transparent proxy.

```
Agent's network view:
  api.openai.com     → BLOCKED (must go through Connector proxy)
  api.anthropic.com  → BLOCKED (must go through Connector proxy)
  pypi.org           → ALLOWED (per policy)
  npmjs.com          → ALLOWED (per policy)
  github.com         → ALLOWED (per policy)
  *                  → BLOCKED by default
  localhost:9091     → Connector gateway (the ONLY LLM path)
```

**How it works**:
- `devguard connect` creates network rules that block direct LLM API access
- Agent's `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` points to Connector proxy
- Even if agent tries to override the URL, DNS/firewall blocks the real endpoint
- Package installs (`npm install`, `pip install`, `cargo add`) go through allowed hosts only
- All outbound requests logged to Connector audit chain

**Connector OS provides**: `POST /api/v1/sandbox/network` — create network rules per session.

### 7.5 Command Jail (every command goes through DevGuard)

**Mechanism**: PTY wrapper / shell replacement.

```
Agent thinks it runs:  rm -rf /tmp/build && npm install malicious-pkg
DevGuard intercepts:   CanonicalAction::CommandExec { command: "rm -rf /tmp/build && npm install malicious-pkg" }
DevGuard decides:      BLOCK — "rm -rf" + unknown package install
Agent sees:            "[DevGuard] Command blocked: recursive delete + unverified package install"
```

**How it works**:
- `devguard connect` wraps the agent's shell in a DevGuard-controlled PTY
- Every command is intercepted BEFORE execution — not after
- Commands are parsed, tokenized, risk-scored against `devguard.yaml`
- Dangerous patterns (`rm -rf`, `curl | bash`, `sudo`, `eval`) → instant BLOCK
- Package installs → require approval or allowlist match
- Long-running commands → timeout enforcement
- Command stdout/stderr → captured for audit
- Background processes → denied unless explicitly allowed

**Connector OS provides**: `POST /api/v1/sandbox/exec` — execute command in governed PTY.

### 7.6 Secret Vault (secrets never touch the agent's environment)

**Mechanism**: Reference-only secret access.

```
Agent requests:  "I need the database password"
DevGuard gives:  CONNECTOR_SECRET_REF:db_password_v3 (a reference, not the value)
At execution:    Connector injects the real value at the moment of use, in memory only
After execution: Value is zeroed from memory
```

**How it works**:
- `.env` files are physically invisible (sandbox FS)
- Environment variables containing secrets are replaced with references
- Agent can request secret access — DevGuard logs and approves/denies
- Approved secrets are injected by Connector at execution time, not exposed in text
- All secret access attempts logged to audit chain
- LLM traffic is scanned by Connector's secret broker before leaving the proxy

**Connector OS provides**: `POST /api/v1/secrets/reference` — create opaque reference for a secret.

### 7.7 Patch Gate (every code change is validated before landing)

**Mechanism**: Write interception + diff validation.

```
Agent writes:  src/auth/login.rs (modifies authentication logic)
DevGuard:      CanonicalAction::PatchApply { path: "src/auth/login.rs", lines_changed: 47 }
Risk Engine:   CRITICAL — auth code modified
Approval:      Requires security-reviewer approval
Action:        Patch held in staging, not applied to real filesystem
               → devguard approvals list shows pending patch
               → reviewer: devguard approvals approve <id>
               → patch lands on real disk
```

**How it works**:
- All writes go through overlay FS → DevGuard intercepts them
- Diff is computed, hashed, and risk-scored
- Low-risk patches (tests, docs, non-sensitive code) → auto-approve
- High-risk patches (auth, billing, infra, migrations) → held for human review
- Critical patches (secrets, production config) → requires security approval
- Patch hash recorded in Connector evidence chain for tamper-proof audit

**Connector OS provides**: Overlay FS write interception + `POST /api/v1/evidence/record`.

### 7.8 Git Fence (no uncontrolled repo operations)

**Mechanism**: Git hooks + command interception.

```
Agent runs:    git push origin main
DevGuard:      BLOCK — "main" branch is protected, requires PR
Agent runs:    git push origin feature/add-auth
DevGuard:      ALLOW — feature/* branches permitted
Agent runs:    git push --force origin feature/add-auth
DevGuard:      BLOCK — force push denied by policy
```

**How it works**:
- `devguard connect` installs git hooks (pre-commit, pre-push, pre-rebase)
- Git commands are also caught by Command Jail
- Branch policies from `devguard.yaml` enforced at both layers
- Force push, rebase on protected branches → always blocked
- Commit messages can be required to include session/task reference
- All git operations logged to audit chain

### 7.9 CI/CD Gate (no uncontrolled deployments)

**Mechanism**: Command interception + approval workflow.

```
Agent runs:    kubectl apply -f deployment.yaml
DevGuard:      BLOCK — production deployment requires ops-lead approval
Agent runs:    terraform apply
DevGuard:      BLOCK — infrastructure change requires architecture approval
Agent runs:    docker push myapp:latest
DevGuard:      REQUIRE_APPROVAL — container publish needs review
```

**How it works**:
- CI/CD commands (`kubectl`, `terraform`, `docker push`, `helm`, `cdk deploy`) → always flagged
- Deployment commands → require explicit approval from designated reviewer
- Infrastructure changes → require architecture-level approval
- All deployment attempts logged to audit chain with full context

### 7.10 LLM Proxy Lock (the ONLY path to any LLM)

**Mechanism**: Network fence + proxy authentication.

```
The agent's ONLY way to call any LLM:
  → Through Connector gateway at localhost:9091
  → Authenticated with session-scoped token
  → Secret-scanned before sending
  → Audited with full request/response
  → Budget-enforced (token limit, cost limit)

Direct access to api.openai.com / api.anthropic.com:
  → DNS blocked
  → Network fence rejects
  → Even if agent hardcodes IP: firewall blocks
```

**How it works**:
- Network fence blocks all known LLM API endpoints
- Agent's API keys are session tokens that only work through Connector proxy
- Connector proxy runs full pipeline: admission → secret scan → audit → forward → record
- Budget enforcement: if token/cost limit exceeded → proxy returns budget_exceeded
- Model routing: DevGuard policy can force specific models per role/task

---

## 8. Connector OS Primitives Needed for Military-Grade

These are **generic OS capabilities** — Connector provides them, DevGuard (or any app) uses them.

| Connector Primitive | API | What it does |
|---|---|---|
| Overlay Filesystem | `POST /api/v1/sandbox/mount` | Create sandboxed workspace with visibility rules |
| Network Namespace | `POST /api/v1/sandbox/network` | Create network rules (allow/block hosts) |
| Governed Exec | `POST /api/v1/sandbox/exec` | Execute command in controlled PTY with interception |
| Secret Reference | `POST /api/v1/secrets/reference` | Create opaque secret reference (value never exposed) |
| Git Hook Install | `POST /api/v1/sandbox/git-hooks` | Install pre-commit/pre-push hooks |
| Write Interception | overlay FS primitive | Catch file writes before they land on real disk |
| Audit Record | `POST /api/v1/audit/record` | Record any event to durable audit chain |
| Evidence Record | `POST /api/v1/evidence/record` | Record hash to tamper-proof evidence chain |

Connector does NOT know why these are being used. DevGuard decides the rules. Connector enforces them.

---

## 9. Enforcement Guarantee Per Layer

| Layer | Bypass Method | DevGuard Prevention | Guarantee |
|---|---|---|---|
| Filesystem | Agent reads hidden file | File physically absent (overlay FS) | **Cannot bypass** |
| Filesystem | Agent writes outside scope | Overlay rejects write at kernel level | **Cannot bypass** |
| Network | Agent calls LLM API directly | DNS blocked + firewall rule | **Cannot bypass** |
| Network | Agent uses raw IP | nftables blocks by IP | **Cannot bypass** |
| Commands | Agent spawns subprocess | All exec goes through PTY broker | **Cannot bypass** |
| Commands | Agent runs `eval` | PTY broker parses before exec | **Cannot bypass** |
| Secrets | Agent reads `.env` | File physically absent | **Cannot bypass** |
| Secrets | Agent reads env var | Var contains reference, not value | **Cannot bypass** |
| Git | Agent force-pushes | Pre-push hook + command jail | **Cannot bypass** |
| LLM | Agent overrides API URL | Network blocks real API endpoints | **Cannot bypass** |
| Packages | Agent installs malicious pkg | Network fence + command jail | **Cannot bypass** |
| CI/CD | Agent runs `kubectl apply` | Command jail + approval gate | **Cannot bypass** |

---

## 10. Support Level Matrix (Updated for Military-Grade)

| Tool | Integration | Level | FS | Cmd | Net | Secrets | Git | CI/CD | Approval | Audit |
|---|---|---|---|---|---|---|---|---|---|---|
| Claude Code | Sandbox + proxy | 0 Total | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Kiro | Sandbox + proxy | 0 Total | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Aider | Sandbox + proxy | 0 Total | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Cursor | Sandbox + proxy | 1 Strong | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Windsurf | Sandbox + MCP + proxy | 0 Total | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Continue | Sandbox + MCP | 1 Strong | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Cline | Sandbox + MCP | 1 Strong | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Roo Code | Sandbox + MCP | 1 Strong | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Copilot | Sandbox + proxy | 1 Strong | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | ✅ |
| Zed | Sandbox + proxy | 1 Strong | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ◐ | ✅ |

**Level 0 — Total Enforcement**: DevGuard controls ALL actions. Agent has zero unmonitored paths.
**Level 1 — Strong Enforcement**: Sandbox controls FS/Net/Cmd/Secrets/Git. Tool-specific actions may not be fully interceptable.

**Key insight**: The sandbox (overlay FS + network fence + command jail) gives military-grade control
regardless of the tool, because control happens at the OS level, not the tool level.
Even a tool with zero integration points is controlled by the cage it runs inside.

✅ = enforced  ◐ = partial (tool doesn't expose enough for full interception)

---

## 11. RBAC — Role-Based Access Control for Teams

> Every person + machine + tool combination gets a specific role.
> The role determines EVERYTHING: what files they see, what commands they run,
> what branches they touch, what budget they burn, what approvals they need.
> One `devguard.yaml` governs the entire team. Easy to set up, impossible to bypass.

### 11.1 The Model: Identity → Role → Policy

```
                      devguard.yaml
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         identities      roles       assignments
              │            │            │
              ▼            ▼            ▼
    who they are    what they can do    who gets what role
```

**Identity** = a person or machine (GitHub user, email, SSH key, API token)
**Role** = a named set of permissions (junior, senior, lead, reviewer, deployer, intern)
**Assignment** = binds identity + tool to a role

### 11.2 devguard.yaml — Full RBAC Example

```yaml
version: "2.0"
workspace: my-company/backend-api

# ── Identity Provider ────────────────────────────────────────
identity:
  provider: github           # github | gitlab | okta | ldap | local
  org: my-company            # required for github/gitlab
  require_auth: true         # all sessions must authenticate
  mfa_required: false        # set true for production repos
  # For local mode (single developer):
  # provider: local
  # require_auth: false

# ── Roles ────────────────────────────────────────────────────
# Define as many roles as needed. Each role is a complete permission set.
# Roles can inherit from other roles with `extends`.
roles:

  # ── Intern / Junior Engineer ─────────────────────────────
  intern:
    clearance: 1                     # lowest
    files:
      read: ["src/**", "tests/**", "docs/**", "README.md"]
      write: ["tests/**"]            # can ONLY write tests
      hidden: ["infra/**", "deploy/**", ".env*", "secrets/**",
               "src/auth/**", "src/billing/**", "database/migrations/**"]
    execution:
      allow: ["cargo test", "cargo check", "npm test", "npm run lint",
              "git status", "git diff", "git log -n *"]
      deny: ["*"]                    # everything not allowed is denied
      require_approval: ["git push*"]
    branches:
      allow: ["feature/intern-*"]    # can only push to intern-prefixed branches
    secrets: none                    # zero secret access
    network:
      allow: ["pypi.org", "npmjs.com", "crates.io"]
      deny: ["*"]                    # no other outbound
    budget:
      max_tokens_per_task: 50000
      max_cost_usd_per_day: 2.00
      model: cheap                   # forced to use cheaper model
    context:
      max_tokens: 16000
      inject: [".connector/intern_guidelines.md"]
    approvals:
      all_writes: { require: senior }

  # ── Junior Engineer ──────────────────────────────────────
  junior:
    clearance: 2
    extends: intern                  # inherits intern, overrides below
    files:
      read: ["src/**", "tests/**", "docs/**", "*.toml", "*.json", "*.yaml", "*.md"]
      write: ["src/**", "tests/**"]  # can write source + tests
      hidden: [".env*", "secrets/**", "infra/prod/**", "database/migrations/**"]
      read_only: ["infra/dev/**", "src/auth/**"]
    execution:
      allow: ["cargo build", "cargo test", "cargo check", "cargo clippy",
              "npm test", "npm run build", "npm run lint", "pytest",
              "git status", "git diff", "git add", "git commit", "git log*"]
      deny: ["rm -rf*", "sudo*", "curl | bash", "eval*", "ssh*",
             "docker*", "kubectl*", "terraform*"]
      require_approval: ["git push*"]
    branches:
      allow: ["feature/*", "fix/*"]
      deny: ["main", "release/*", "production"]
    secrets: none
    network:
      allow: ["pypi.org", "npmjs.com", "crates.io", "github.com"]
      deny: ["*"]
    budget:
      max_tokens_per_task: 200000
      max_cost_usd_per_day: 5.00
      model: standard
    approvals:
      sensitive_files: { require: senior }  # auth, billing files

  # ── Senior Engineer ──────────────────────────────────────
  senior:
    clearance: 4
    files:
      read: ["**"]                   # can read everything
      write: ["src/**", "tests/**", "docs/**", "database/migrations/**"]
      hidden: [".env.production", "secrets/prod/**"]
      read_only: ["infra/prod/**"]
    execution:
      allow: ["cargo*", "npm*", "pytest*", "make", "docker build*",
              "docker compose*", "git*"]
      deny: ["rm -rf /", "sudo rm*", "curl | bash", "eval*"]
      require_approval: ["git push origin main", "docker push*"]
    branches:
      allow: ["feature/*", "fix/*", "refactor/*", "release/*"]
      deny: ["production"]
    secrets:
      allowed_via_broker: ["dev_db_password", "staging_api_key"]
      direct_access: none
    network:
      allow: ["pypi.org", "npmjs.com", "crates.io", "github.com",
              "docker.io", "*.amazonaws.com"]
      deny: ["*"]
    budget:
      max_tokens_per_task: 500000
      max_cost_usd_per_day: 20.00
      model: best                    # can use best available model

  # ── Tech Lead ────────────────────────────────────────────
  tech_lead:
    clearance: 5
    extends: senior
    files:
      read: ["**"]
      write: ["**"]                  # can write anywhere
      no_delete: ["migrations/**", "LICENSE"]
    execution:
      allow: ["*"]                   # can run anything
      deny: ["rm -rf /", ":(){ :|:& };:", "> /dev/sda"]  # only catastrophic
      require_approval: ["kubectl apply*", "terraform apply*"]
    branches:
      allow: ["*"]
    secrets:
      allowed_via_broker: ["*"]      # all secrets via broker
      direct_access: none            # still no raw secrets
    budget:
      max_tokens_per_task: 1000000
      max_cost_usd_per_day: 50.00

  # ── Reviewer (read-only) ─────────────────────────────────
  reviewer:
    clearance: 2
    files:
      read: ["**"]
      write: []                      # ZERO write permission
    execution:
      allow: ["cargo check", "cargo clippy", "npm run lint", "pytest",
              "git diff", "git log*", "git blame*", "git status"]
      deny: ["*"]
    branches:
      allow: ["*"]                   # can read any branch
    secrets: none
    budget:
      max_tokens_per_task: 50000
      model: cheap

  # ── Release Agent ────────────────────────────────────────
  release_agent:
    clearance: 4
    files:
      read: ["**"]
      write: ["CHANGELOG.md", "Cargo.toml", "package.json", "version.*"]
    execution:
      allow: ["cargo build --release", "cargo test", "npm run build",
              "npm test", "git tag*", "git log*", "git status"]
      require_approval: ["git push*", "cargo publish", "npm publish", "docker push*"]
      deny: ["rm*", "sudo*", "git rebase*", "git reset --hard*"]
    branches:
      allow: ["release/*", "main"]
    secrets:
      allowed_via_broker: ["npm_token", "cargo_token", "docker_token"]
    budget:
      max_tokens_per_task: 100000
    approvals:
      publish: { require: [tech_lead, product_owner], quorum: 2 }

  # ── Deploy Agent ─────────────────────────────────────────
  deployer:
    clearance: 5
    files:
      read: ["infra/**", "deploy/**", "k8s/**", "docker-compose*.yaml"]
      write: ["infra/**", "deploy/**"]
    execution:
      allow: ["kubectl*", "terraform plan", "docker build*",
              "helm template*", "helm lint*"]
      require_approval: ["terraform apply*", "kubectl apply*",
                         "helm install*", "helm upgrade*", "docker push*"]
      deny: ["rm*", "sudo*", "git*"]  # deploy agent should not touch git
    secrets:
      allowed_via_broker: ["kube_config", "aws_access_key", "docker_registry_token"]
    network:
      allow: ["*.amazonaws.com", "*.kubernetes.io", "docker.io", "github.com"]
    budget:
      max_tokens_per_task: 100000
    approvals:
      production: { require: [ops_lead, tech_lead], quorum: 2 }
      staging: { require: ops_lead }

# ── Assignments: who gets what role with which tool ──────────
# This is where identity meets role meets tool.
assignments:

  # ── By GitHub username ─────────────────────────────────
  - identity: github:alice
    role: tech_lead
    tools: [claude_code, cursor, windsurf]     # all tools, same permissions

  - identity: github:bob
    role: senior
    tools: [claude_code, windsurf]

  - identity: github:charlie
    role: junior
    tools: [claude_code]                        # junior only gets Claude Code

  - identity: github:diana
    role: junior
    tools: [cursor]                             # junior on Cursor

  - identity: github:eve
    role: intern
    tools: [claude_code]                        # intern — most restricted

  - identity: github:frank
    role: reviewer
    tools: [claude_code, cursor]               # reviewer — read only

  # ── By team / group ───────────────────────────────────
  - identity: github:team/frontend
    role: junior
    tools: [cursor, windsurf]
    overrides:                                  # team-level overrides
      files:
        write: ["src/frontend/**", "src/components/**", "tests/frontend/**"]
        hidden: ["src/backend/**", "infra/**"]

  - identity: github:team/backend
    role: senior
    tools: [claude_code, aider]
    overrides:
      files:
        write: ["src/backend/**", "src/api/**", "tests/backend/**"]

  - identity: github:team/devops
    role: deployer
    tools: [claude_code]

  # ── By machine / CI ───────────────────────────────────
  - identity: machine:ci-runner-01
    role: release_agent
    tools: [aider]                              # CI uses Aider for release automation

  - identity: machine:deploy-bot
    role: deployer
    tools: [claude_code]

  # ── Catch-all (anyone not listed) ─────────────────────
  - identity: "*"
    role: intern                                # unknown users get intern role
    tools: ["*"]

# ── Global overrides per tool ────────────────────────────────
# Some tools need additional restrictions regardless of role.
tool_overrides:
  cursor:
    # Cursor can't intercept commands directly, so restrict to safe commands
    execution:
      deny_append: ["docker*", "kubectl*", "terraform*"]
  windsurf:
    # Windsurf MCP tools get full governance
    mcp_governed: true

# ── File visibility (global, applied before role) ────────────
files:
  always_hidden: [".env*", "*.key", "*.pem", "*.p12", "secrets/**",
                  ".git/config", "node_modules/**", ".connector/tokens/**"]
  always_read_only: ["LICENSE", ".github/CODEOWNERS"]

# ── Secret shielding ────────────────────────────────────────
secrets:
  detect_and_redact: true
  patterns: default
  vault_backend: connector           # use Connector secret vault API
  rotation_alert: true               # alert if a secret appears in code

# ── Git governance ───────────────────────────────────────────
git:
  no_force_push: true
  max_diff_lines: 2000
  require_signed_commits: false      # set true for enterprise
  protected_branches: ["main", "production", "release/*"]

# ── Budget (global caps) ────────────────────────────────────
budget:
  max_tokens_per_day: 5000000        # org-wide daily cap
  max_cost_usd_per_day: 100.00       # org-wide daily cost cap
  alert_at_percent: 80               # alert when 80% consumed

# ── Audit ────────────────────────────────────────────────────
audit:
  level: full
  receipts: true
  proof: true
  retention_days: 90
  export: ["json", "csv"]            # exportable audit trail

# ── Enforcement ──────────────────────────────────────────────
enforcement:
  mode: cage                         # cage | hooks | audit_only
  deny_by_default: true
  least_privilege: true
  no_raw_secret_exposure: true
  all_actions_receipted: true
```

### 11.3 How Assignment Resolution Works

When a person runs `devguard connect claude-code`:

```
1. Identity check:
   → Who is this? (GitHub auth, SSH key, local user)
   → Example: github:charlie

2. Assignment lookup:
   → Find matching assignment in devguard.yaml
   → github:charlie → role: junior, tools: [claude_code]

3. Tool check:
   → Is claude_code in their allowed tools? YES
   → Apply tool_overrides if any

4. Role compilation:
   → Load role "junior" definition
   → If role has `extends`, merge parent role
   → Apply team overrides if identity is team member
   → Apply global files.always_hidden on top

5. Cage construction:
   → Sandbox FS: mount overlay with junior's visible/hidden/read_only files
   → Network fence: junior's allowed hosts only
   → Command jail: junior's allowed commands only
   → Secret vault: junior gets zero secrets
   → Budget: 200K tokens, $5/day, standard model
   → LLM proxy: all calls through Connector gateway

6. Session created:
   → Agent PID: devguard-claude-charlie-a3f8b2c1
   → Role: junior
   → Every action audited with role + identity
```

### 11.4 Role Hierarchy and Inheritance

```
                    tech_lead (clearance: 5)
                    ├── can do everything
                    ├── approves others' actions
                    └── only catastrophic commands denied
                         │
                    senior (clearance: 4)
                    ├── read everything, write most things
                    ├── can use docker, access staging secrets
                    └── needs approval for main push, deploy
                         │
                    junior (clearance: 2)
                    ├── read source+tests, write source+tests
                    ├── no docker, no kubectl, no secrets
                    └── needs approval for any push
                         │
                    intern (clearance: 1)
                    ├── read source+tests, write ONLY tests
                    ├── minimal commands, zero secrets
                    └── needs approval for everything
```

Special roles (not in hierarchy):
- **reviewer** — read-only across everything, zero writes
- **release_agent** — narrow write scope, approval-gated publishing
- **deployer** — infra-only, approval-gated apply/push

### 11.5 Multiple People, Same Repo, Different Cages

```
Alice (tech_lead) on Cursor:
  → sees ALL files, can write anywhere
  → can run docker, kubectl (with approval)
  → $50/day budget, best model
  → access to staging secrets via vault

Bob (senior) on Claude Code:
  → sees all files, writes most
  → no production infra access
  → $20/day budget, best model
  → dev secrets only

Charlie (junior) on Claude Code:
  → sees src + tests, cannot see auth/billing/infra
  → writes src + tests only
  → no docker, no deploy commands
  → $5/day budget, standard model

Eve (intern) on Claude Code:
  → sees src + tests, cannot see auth/billing/infra
  → writes ONLY tests
  → minimal commands
  → $2/day budget, cheap model
  → every write needs senior approval

CI Runner (release_agent) on Aider:
  → can tag, changelog, version bump
  → publish requires 2 approvals
  → automated, no interactive commands

Deploy Bot (deployer) on Claude Code:
  → infra files only
  → terraform plan OK, terraform apply needs 2 approvals
  → production deploy needs ops_lead + tech_lead
```

### 11.6 Easy Setup — One Command

```bash
# Initialize with team mode
$ devguard init --team --provider github --org my-company
  ✓ Created devguard.yaml with RBAC template
  ✓ Created roles/ directory with role templates
  Edit devguard.yaml to assign roles to your team.

# Or quick single-user setup
$ devguard init
  ✓ Created devguard.yaml (single user, builder role)

# Validate RBAC config
$ devguard policy validate
  ✓ 7 roles defined
  ✓ 12 assignments resolved
  ✓ No orphan identities
  ✓ Catch-all assignment present
  ✓ All roles have deny-by-default enforcement
  ⚠ Warning: github:charlie has no secret access — intentional?

# Show effective permissions for a person
$ devguard policy show --identity github:charlie --tool claude_code
  Role: junior
  Files visible: src/**, tests/**, docs/**, *.toml, *.json, *.yaml, *.md
  Files writable: src/**, tests/**
  Files hidden: .env*, secrets/**, infra/prod/**, database/migrations/**
  Commands allowed: cargo build, cargo test, npm test, ...
  Commands denied: docker*, kubectl*, terraform*, sudo*, rm -rf*, ...
  Branches: feature/*, fix/*
  Secrets: NONE
  Budget: 200K tokens/task, $5/day, standard model
  Network: pypi.org, npmjs.com, crates.io, github.com
  Approvals needed: git push (any), sensitive file writes

# Show who has access to what
$ devguard policy matrix
  ┌──────────────┬────────┬────────┬────────┬────────┬──────────┐
  │ Person       │ Files  │ Cmds   │ Secrets│ Deploy │ Budget   │
  ├──────────────┼────────┼────────┼────────┼────────┼──────────┤
  │ alice (lead) │ ★★★★★ │ ★★★★★ │ ★★★★  │ ★★★★  │ $50/day  │
  │ bob (senior) │ ★★★★  │ ★★★★  │ ★★    │ ○      │ $20/day  │
  │ charlie (jr) │ ★★    │ ★★    │ ○      │ ○      │ $5/day   │
  │ eve (intern) │ ★     │ ★     │ ○      │ ○      │ $2/day   │
  │ frank (rev)  │ ★★★★★ │ ★     │ ○      │ ○      │ $2/day   │
  │ ci-runner    │ ★★★   │ ★★    │ ★★    │ ○      │ $5/day   │
  │ deploy-bot   │ ★★    │ ★★★   │ ★★★   │ ★★★★★ │ $10/day  │
  └──────────────┴────────┴────────┴────────┴────────┴──────────┘
```
