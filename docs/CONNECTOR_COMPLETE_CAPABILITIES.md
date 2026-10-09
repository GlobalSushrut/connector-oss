# Connector Complete Capabilities

**What this document is:** a deep inventory of what a complete Connector install can do as software, and what an agent gets when it runs in production.

**Product stance:** Connector is a **self-hosted intelligence OS / operating substrate** — not “better RAG,” not a coding-agent product, and not a finished global mesh. Institutions such as DevGuard, TraceTramp, and WitnessCtl run **on** the OS. Cognition planes (CRK, SVF, Knot, CIP) **never** mint Allow/Deny; **PATE / ActionBinding** remain the effect PDP.

**Maturity tags used below:**

- **Shipped** — present in code and usable on an operator path
- **Gated** — implemented; fail-closed or flag / host-attach / preset required
- **Partial** — real surface; depth or productization incomplete
- **Scaffold** — API or store exists; not a finished product claim
- **Deferred** — planned or secondary; not equal to the control plane

---

## Section 1 — What complete Connector software can do

### 1.1 Product shape and install

- Install as a **single-node sovereign package**: `connector-platform` + `connectorctl` + embedded operator UI.
- Package via `make package` into Linux tarballs; self-host with `CONNECTOR_DATA_DIR`, presets, and license tiers.
- Run **Dev / Pilots / Production** runtime modes with profile presets (`local`, `playground`, `production`, `defense-strict`, `unbypassable`).
- Separate **vendor control plane** (`connector-license-server`) for portal, keys, pilots, and billing handoff — distinct from the customer node.
- Expose a large Axum `/api/v1/*` surface with JWT / `cpk_live_*` auth (allowlisted public health/auth/playground paths).
- Ship an embedded **Leptos dashboard** (fleet, console, books, workbench, plugins, DevGuard, monitor, setup).
- Operate via **connectorctl** namespaces: node, data, workload, govern, substrate, access (+ IIA).

### 1.2 Identity, principals, and DNA

- Issue and verify **JWT / API keys**, RBAC, SSO hooks, and principal context.
- Mint **IntelligencePrincipal + AgentContract** per agent at register time.
- Maintain **agent foundation** blocks (intelligence hash, knowledge address, handshake receipt, fusion MAC).
- Serve **identity envelopes** (setup, activation, who-am-i, namespace scope, forensic posture).
- Apply **IntelligenceSpec / Charter Studio** charters: purpose, parameters, BoundSkills, knowledge, limitations, portals, rules.
- Stamp **Agent Packet DNA** (seven genome slots) on network/effect hops (`x-connector-dna`); missing/mutated DNA can fail closed when required.
- Stamp **Memory Sequence DNA** on CRK memory nodes (agent / type / cid / data / var / index / auth_root) so type and sequencing matter in activation.
- Detect **continuity breaks** (model/runtime hash changes) and require re-bind where configured.
- Scope identity and memory under MAC namespaces (`/m/`, `/k/`, `/v/`, …).

### 1.3 Agents and lifecycle

- Register agents with unique `/m/…` namespaces, caps from license/kernel.
- Activate / boot with capability manifests; optional setup gate before Talk.
- Talk through OpenAI-compatible and Anthropic gateways.
- Dispatch tools only as **proposals** until Admit.
- Pause, quarantine, unquarantine (HITL), terminate, kill, reap idle/zombie/over-cap agents.
- Track progeny trees (parent/child ACBs) with cascade terminate.
- Seed playground demo agents under capped multi-tenant sessions.

### 1.4 Admission, PATE, and world effects

- Run **admission gates** (health, quarantine, exclusivity, matrix).
- Decide effects with **ActionBinding AutonomyGateway** → Allow | Ask | Block.
- Wrap admits in **PATE** (Augmented Task Unit) envelopes over LLM / tool / CONP / CNP / memory effect kinds.
- Issue **WorldGrants** and maintain a **pore table** (default DROP; grant opens destinations).
- Pin egress with **Landlock child** workers and optional vendor cut for LLM destinations.
- Enforce **effect exclusivity** so concurrent effect paths cannot bypass the membrane.
- Hold **HITL** for Ask verdicts; resume or cancel without silent dispatch.
- Gate tool dispatch with optional **ARC leases** (NoLease ⇒ NoEffect when enabled).

### 1.5 Talk, LLM broker, and projection

- Inject kernel **who-am-i**, charter, vendor-brain denial, and work-unit envelopes into Talk.
- Mint opaque **LLM context tokens** (`ctx_tok_…`) via the context broker; quarantine bumps generation and voids tokens.
- Bind **ContextTransferEnvelope** (CRK exact render digest + broker generation) into Talk without replacing identity.
- Apply **Principal Projection** (PASS / PROJECT / DENY) so model text cannot invent authority.
- Support stub LLM mode for full-pipeline evaluation without a vendor key.
- Provide Workbench sessions: turn → orders → Admit → tool journal (turn ≠ execute).
- Soft-fail CRK inject on Talk when empty memory (does not block identity or Admit).

### 1.6 Memory substrate (VAC, Knot, agent memory)

- Persist **MemPackets** (content-addressed) as doctrine source of truth.
- Use VAC kernel store / EngineStore folders for durable agent and substrate state.
- Run **Knot** entity/belief slices, RRF-style retrieve, interference edges, and KECS-related health signals (ranking/health — not CRK authorization).
- Enable **AgentMemoryCapsule** hot plane (bounded JSON) with evidence chains and MomentProof cold plane when `CONNECTOR_AGENT_MEMORY` (or augmented env) is on.
- Support context **rollup / fade** (F0–F3) and rehydrate policies under rollup APIs.
- Provide composite recall / RAG-style retrieve as belief-field assist — never as Admit.
- Keep Object Fabric CAS put/get (assembled-blob depth still partial).

### 1.7 RangeGuard / Cognitive Range Kernel (CRK)

- Decide **which memories may influence this action** and prove exposure (not model-internal causality).
- Return CRK states only: `READY | AMBIGUOUS | STALE | UNTRUSTED | INSUFFICIENT` — **never Allow/Deny**.
- Enforce **trust firewall** T0–T4 (transform may lower, never raise).
- Keep **temporal StateClaims** (valid_from/until, supersedes; historical truth vs present cognition).
- Commit **VerifiedProcedureCapsules** as executable methods for BoundSkills.
- Run **MemoryCommit** roots (atomic visibility, root mismatch refuse).
- Index **MemoryRelations** (Requires, Causal, Conflicts, …) with type pairing gates.
- Run **type-aware Dynamic Node Activation** (seeds, bi-wave, inhibition, trajectory soft seeds).
- Compile **budget-first covers** and hydrated **ContextFrames** (Full→Omit degradation).
- Mint **InfluenceManifests** and transfer digests for receipts.
- Support continuity rollup (state + procedures + open work — not recursive summary chains).
- Offer hot `window` path and cold paginated `search` under pinned RecallSession.
- Expose APIs: `/range/status|window|observe|commit|relate|search|rollup|replay|demo`.

### 1.8 SVF, CIP, DIM, and cognition control

- **SVF**: SEMANTICIZE / PROJECT / EXPAND / RESOLVE / MATERIALIZE / OBSERVE — shrinks affordances; never PDP.
- **CIP**: goals, attention, inhibition, stop signals for DAL/control (not admission).
- **DIM**: homeodynamic / radius / wake surfaces for intelligence manifold control (gated).
- **Probabilistic LLM / distrust** modes that force broker and stricter Talk posture.
- Keep cognition and authority **explicitly separated** in honesty strings and APIs.

### 1.9 DAL (Dynamic Agent Loop)

- Start CID-only durable runs (no raw reasoning stored as SoT).
- On each turn: Observe → Recall (**CRK window**) → optional Plan from procedure → Propose → Admit → Act → Verify/Replan.
- Bind InfluenceManifest ids onto working memory for Admit exposure proof.
- On Verify fail, replan path can reseed missing required evidence next recall.
- Never auto-dispatch tools from Talk without the sandwich.

### 1.10 Protocols and native bridges

- **MCP** client/server hosting and tool last-mile (grant/egress gated).
- **A2A** AgentCard / send / subscribe bridges (grant-gated).
- **CNP** cell networking surface + packet DNA on wire (peer crypto / soak partial).
- **CONP** actuation commands through authority/SIL interlock (Connector owns gate, not partner PLC certification).
- **ACP** local message-bridge store (**partial**).
- **ANP** local DID register/resolve (**partial**).
- **AP2** payment mandate store (**scaffold**).
- Funnel protocol effects through ActionBinding/PATE (no ambient authority).

### 1.11 Institutions and plugins

- First-party **TraceTramp** (trace / custody projection plane).
- First-party **WitnessCtl** (witness / quorum-oriented custody plane).
- First-party **DevGuard** (governed coding/session institution — not “Connector is a coding agent”).
- Plugin matrix favoring TT / WC / DG in production gates.
- Plugin runtime with subprocess / docker_lab / microvm / wasm backends (wasm experimental).
- AGOS / `.cpkg` / Hub packaging (Hub workflow publish still honesty-stubbed).
- Secondary plugins (Conductor, AgentLoop, Engram, …) **deferred** — not equal control planes.

### 1.12 Isolation, sandbox, and runtime hardening

- Runtime isolation tiers and manifests (T0–T5 style postures).
- DockLock / Ring-1 / QPR / IIA spine when presets demand.
- Landlock pores and destination pinning for granted world dials.
- Optional Firecracker / MicroVM paths (**gated**, not default claim).
- Optional kerneld / eBPF attach (**host-gated**).
- Sandbox unbypassable bar under defense presets.
- Playground deliberately relaxes Firecracker/kerneld/unbypassable for trial UX while keeping Admit sandwich.

### 1.13 Multi-agent, council, and coordination

- Multiagent pipelines (waves, cost/token breakers, HITL step approve).
- Namespace grant/revoke and shared knowledge ports for multiagent tasks.
- **Council** of sibling intelligence cells with hash-chained floor and shared pores (no ambient `/k`).
- Handoff queue as WitnessCtl/TT custody backpressure — not Autogen-style shared brain.

### 1.14 Audit, forensics, proof, and books

- Keyed audit HMAC and recompute paths (prod requires real keys).
- Actionlog, proof certificates, SCITT/VC-oriented exports.
- Agent audit receipt APIs.
- Forensics packages, CFNI, SOAS honesty reports.
- AACR mint/verify (court-adoptable only after gates — not auto court-grade).
- UsageEvent / Books usage-first accounting (unavailable ≠ $0).
- Mission journal for lineage / no-duplicate effect discipline when enabled.

### 1.15 Billing, license, tenancy

- Node license activate/status/tiers/features.
- Billing usage, entitlements, Stripe webhook paths.
- Tenant id derivation from agent meta / API keys.
- Pilots scoped access mode.
- SCIM surface (**partial** enterprise).
- Do **not** claim finished SaaS HA multi-tenant condo or automatic failover.

### 1.16 Cluster / mesh (honest)

- vac-cluster CRDT libraries and local membership heartbeat / peer ping.
- Product SoT remains **single-node** (`mesh_fabric: false`, no automatic failover claim).
- CNP peer overlay / mTLS and L5 market packaging remain **partial / unsigned**.

### 1.17 Operator, playground, and developer surfaces

- Full dashboard atlas (connect, console, books, fleet, theater/workbench, plugins, monitor).
- Playground sessions with TTL, agent caps, email ledger, demo isolate/govern/prove receipts.
- Lab/advanced-lab environments for soak and gates.
- SDKs / glue exist but are not the full shipping integration claim.

### 1.18 What complete Connector software deliberately does *not* claim

- Better RAG / temporal-KG product positioning.
- Court-grade or military-grade custody without attach evidence + WitnessCtl N-of-M.
- Firecracker-by-default or “GPU OS complete.”
- Chromium computer-use (click/type) — browser world is granted-origin document GET.
- Coding-agent replacement for Cursor/Claude Code (DevGuard is an institution on the OS).
- CRK/SVF/CIP/DIM minting Allow.
- Global multi-master mesh with automatic failover.
- Partner SIL certifying robots/PLCs.
- Exact $0 books when meters are unavailable.

---

## Section 2 — What capabilities an agent gets in production

### 2.1 What an agent *is* on Connector

- A **kernel principal**, not “whatever the model says.”
- Bound to `agent_pid` + namespace + contract + foundation + activation profile.
- Allowed to **reason freely**; not allowed to **mint effects** from chat text alone.
- Separated from other agents by namespace MAC, budgets, and (when enabled) isolation backends.

### 2.2 Lifecycle capabilities

- Be registered with a charter/purpose and unique memory namespace.
- Receive principal, contract, foundation, and identity envelope at birth.
- Activate with a capability manifest (or wait behind setup gate in hardened presets).
- Talk through governed gateways with injected identity and stance rules.
- Propose tool calls; execute only after Admit.
- Be paused, quarantined, resumed via HITL, terminated, or reaped when over policy.

### 2.3 Identity capabilities the agent (and its LLM) receive

- Authoritative **who-am-i** from kernel (not vendor model marketing).
- Charter / BoundSkills / limitations from IntelligenceSpec.
- Opaque broker token and/or binding envelope so identity is Connector-owned.
- Work-unit stance: shared LLM brain, Connector owns authority.
- Vendor-brain denial: must not claim to be ChatGPT/Claude/etc. as identity.

### 2.4 Memory capabilities

- **VAC MemPackets** under its `/m/{agent}/…` tree (durable cognitive packets).
- Optional **AgentMemoryCapsule** hot context when agent-memory plane is enabled.
- **CRK RangeGuard** working set for the current action:
  - eligibility-first selection
  - type-aware Sequence DNA activation
  - procedure + required state must-include when BoundSkill applies
  - conflict frames when AMBIGUOUS
  - influence/transfer receipts of what was exposed
- **Temporal claims**: old truth stays historical; only active claims gate cognition.
- **Trust firewall**: poison/low-trust cannot promote itself into high-trust cover.
- **Knot** belief/retrieve as discovery assist — cannot authorize cover alone.
- **Procedure capsules**: know the method; LLM may parameterize, not rediscover Admit ops.
- Cold **search/pagination** when stuck (pinned RecallSession) without auto-Admit.
- Continuity rollups so long runs do not require endless raw transcript as SoT.

### 2.5 Reasoning and Talk capabilities

- Full vendor model capability for language/reasoning (OpenAI- or Anthropic-shaped APIs).
- Fullest **eligible** context under `token_budget` (budget-fill, not starvation-only and not distractor dump).
- Typed frames that mark evidence as data, not instructions.
- Workbench theater for operator-visible turns and admissions.
- Stub mode for dry-run of the whole membrane without a live key.
- **AiPassport** on finalized talk egress (`connector_aipsprt` + `x-connector-aipsprt-sig`) — agent/time/digest leave-behind, not watermarking.
- **SpendCease** ceilings, hop reserve, Stop=kernel Cease (fence + void `ctx_tok`); expansive-intent scope gate; post-Cease retry quarantine.

### 2.6 Action and tool capabilities

- Propose MCP/tools/CONP/CNP effects from model output.
- Pass **opaque validate → PATE admit → expand secrets → dispatch**.
- Use BoundSkill-scoped capabilities and risk/HITL annotations from charter.
- Receive Ask → human approve/deny when AutonomyGateway requires it.
- Be blocked when quarantined, exclusivity fails, lease missing, budget hard-stops, or namespace deny fires.
- Emit receipts/ATUs for admitted work.

### 2.7 Planning / loop capabilities (DAL)

- Run durable DAL sessions with CID-only run state.
- Get CRK MomentRange + optional next procedure step each Recall.
- Keep influence_manifest_id / moment_range_id on working memory for Admit binding.
- Verify/replan without inventing a second PDP.

### 2.8 Coordination capabilities

- Participate in multiagent pipelines and task dispatch under grants.
- Sit in a **council** of sibling cells with shared pores and chained floor (no ambient knowledge bleed).
- Spawn/relate via progeny trees where registered as children.
- Do **not** assume Autogen-style shared process memory across agents.

### 2.9 Budget and quota capabilities

- Per-agent token budgets and patches.
- AAPI BCR-style reserve/commit/consume for tokens/API/cost meters when wired.
- Economy hard-stop when over budget.
- License-level agent caps.
- CRK context token budgets for range compilation.
- Playground session caps (agents, tokens, TTL) when on hosted trial.

### 2.10 Observation and proof capabilities

- See (in operator/forensic planes) InfluenceManifests of what memory was selected.
- Carry ContextTransfer digests proving exact Talk render bytes.
- Leave PATE ATUs / workbench journal entries / audit receipts.
- Produce MomentProof / evidence chain entries when agent-memory plane is on.
- Surface SOAS/AACR node honesty artifacts for the host — agent does not self-certify court grade.

### 2.11 Failure modes the agent experiences

- **Deny / Block** — no world effect.
- **Ask / HITL** — held until human decision.
- **Quarantine** — Talk/tools denied; broker tokens void; needs human path.
- **CRK INSUFFICIENT / AMBIGUOUS / STALE / UNTRUSTED** — context exposure limited or conflict shown; still not an Allow.
- **Budget / lease failure** — 429 / hard stop / NoEffect.
- **START_REFUSED** — isolation/setup missing required controls on hardened hosts.
- **Pin break** — RecallSession invalid after memory root commit; must begin again.

### 2.12 Playground agent vs production agent

| Capability | Playground agent | Production agent |
|------------|------------------|------------------|
| Admit sandwich | Same PATE → dispatch | Same |
| Identity inject | Same kernel who-am-i pattern | Same, often stricter broker |
| Setup gate | Typically off for demo Talk | Typically on |
| Isolation | Soft (no Firecracker/kerneld default) | Hardened presets / gated MicroVM |
| Caps | Session TTL, often `MAX_AGENTS=1` | License/kernel caps |
| Court claims | Issuer HMAC demo ≠ court | Still not auto court-grade |

### 2.13 What the agent’s LLM must not get (by design)

- Raw ability to mint WorldGrants, pores, or Allow.
- Ability to promote T0 poison into T3/T4 memory via summarization.
- Ability to treat CRK evidence frames as instructions.
- Ability to use stale client transcripts as live authority after quarantine.
- Ability to bypass exclusivity / DockLock / Landlock with prompt text.

### 2.14 Net production promise to the agent

An agent on Connector gets:

- a **chartered, namespaced identity**;
- **governed memory** (durable packets + optional capsule + RangeGuard selection);
- **full model reasoning** inside a Connector-owned context packet;
- **tools and world dials only through Admit**;
- **budgets, leases, HITL, and quarantine**;
- **receipts of what influenced and what executed**;

…while Connector fulfills the OS jobs of identity, isolation, admission, durable truth, and institutions — without pretending cognition planes are the PDP, and without claiming mesh/court/Firecracker defaults that are not product SoT.

---

## Quick map: seven agentic memory problems → agent benefit

| # | Problem | Agent gets |
|---|---------|------------|
| 1 | Context pollution | MomentRange + budget fill of eligible frames only |
| 2 | Similar ≠ correct | Eligibility + typed Sequence DNA before ranking |
| 3 | Poison durability | Trust firewall; no promotion |
| 4 | Old vs current truth | Temporal ledger gates cognition |
| 5 | Knows method, fails execute | Procedure capsules + same next Admit op |
| 6 | Endless context | Rollup + degradation + pagination |
| 7 | Cannot prove influence | InfluenceManifest + transfer digest |
| 8 | LLM egress has no agent passport | AiPassport.sig — which agent, when, payload DigestRef |
| 9 | Stop ignored / runaway spend | SpendCease — generation fence + void ctx_tok + hop reserve |

---

*Generated from deep codebase/architecture research of this repository. Prefer live honesty endpoints (`/soas/report`, `/range/status`, Seven Pillars / known-limitations docs) over marketing language when making external claims.*
