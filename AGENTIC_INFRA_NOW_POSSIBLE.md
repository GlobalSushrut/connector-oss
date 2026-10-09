# What this agentic infra now makes possible

**Date:** 2026-08-13  
**Audience:** operators, builders, security, product.  
**Architecture:** [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) **v3 §0** (L0 host → L8 human).  
**Create:** [INTELLIGENCE_5MIN.md](INTELLIGENCE_5MIN.md) · **World:** [OPERATOR_WORLD_AGENTS.md](OPERATOR_WORLD_AGENTS.md) · **Status:** [IIA_STATUS_REPORT.md](IIA_STATUS_REPORT.md)

**One sentence:** Until today, agents were prompts behind a shared API. This node is a **distributed intelligence OS** — chartered principals with private character, filesystem, and world grants — so work that used to be unsafe, un-auditable, or impossible to isolate is now **possible under kernel admission**.

This file is the **enablement list**: features, quality, and security that the coded membrane (ACS, NS FS, three layers, world grants, share portals, `light_ns`) unlocks. It is not a court certificate and not SIL.

---

## 0. The shift

| Before (typical agent stack) | Now (this infra) |
|------------------------------|------------------|
| One LLM key, many chats, shared memory | One **principal per pid** — Talk as that pid only |
| “The agent can use tools” | Every tool/Talk/CONP crossing hits `admit_*` — **no bypass** |
| Shared workspace / RAG dump | Private **NS FS** (`/m` `/k` `/p` `/v` `/out` `/share`) — `/p` never LLM |
| All agents see the same APIs | Grant matrix: **A→P ≠ A→Q ≠ B→P** |
| HITL is a vibe checkbox | Digest-bound approve; digest A **cannot** execute digest B |
| Isolation = hope + docker if you pay the density cost | **`light_ns`**: docker-grade materials, **shared kernel**, max agents |
| Share by copying files or a common bucket | Isolated by default; share only after a **human+root contract** mints a portal |
| Automation = “trust the model” | **App Allow** only if a human + kernel root **justifies** that pid × address × cap |
| Security in the prompt | Security in **AutonomyGateway** Allow / Ask / Block + fold |
| Proof = logs if you remembered to log | **DecisionTrace** on every membrane crossing + forensic package |

Human is **root**. Agents cannot mint skip-HITL, cannot mint share portals, cannot inherit another pid’s ACS.

---

## 1. Features now possible

These were not a product on a chat API. They are kernel paths.

### 1.1 Create a real intelligence in minutes

- Declare **parameters → skills → knowledge → limitations → portals → rules**.
- `POST /api/v1/intelligence/apply` or `connectorctl iia apply` (or Setup → Create).
- Result is not a chat thread: it is a **pid** with charter, ACS, NS FS, and zero world until you grant.

Possible now: **fleet of distinct intelligences** on one node, each with its own character, not N tabs on one bot.

### 1.2 Any kind of agent, one cage language

Class is identity (`app` / `robotics` / `iot` / `cybernetic` / `service`), not a topic ban. Purpose is what the charter **allows**, not a prompt slogan.

Possible now: the same node runs a support agent, a machine cell agent, and an IoT watcher — **different cages**, same OS.

### 1.3 Talk as a forced principal

- Completions force path pid (no anonymous façade).
- `who_am_i` + RAG injected as that intelligence.
- Threads belong to the pid.

Possible now: two agents in one conversation **cannot impersonate each other**. Smoke: `connectorctl iia smoke`.

### 1.4 Outer world as a grant matrix (not “enable CONP”)

Every target is an **address** (type + address + params + CNP caps). Owner fills the **gateway form** + **kernel root passcode**.

Possible now:

- Agent A may move **arm-1** and must Ask for **arm-2**.
- Agent B may call **https://payments** and is Blocked from **arm-1**.
- Same agent, new address → new form. Same address, new agent → new form.

CONP (30 message types, 120 caps) and CNP speak through the **same** `admit_conp_or_ask`. Missing grant under harden = **Cone Ask**, not silent Allow.

### 1.5 Custom logic as `.cpkg` under the cage

Ship your runtime as AGOS `.cpkg`, install via Hub, run in DockLock. It calls memory / tools / Talk **as that agent** — still admitted, still traced.

Possible now: **your code** on the intelligence OS without giving it the host.

### 1.6 Multi-agent work without a shared brain

- Dispatch and A2A exist as fabric.
- Cross-pid data does **not** exist until a human files **what / where / how much / why** and root mints `/share/{id}`.

Possible now: a planner and a worker on the same node that **cannot** read each other’s `/p` or `/k` unless you contracted it.

### 1.7 Link any LLM without putting keys in the cage

Settings paste or `connectorctl llm link` → vault + hot-wire router. Keys never in cage env.

Possible now: swap OpenAI / Anthropic / Ollama / OpenRouter **without** leaking the key into agent memory or plugin env.

### 1.8 Operator cockpit as OS, not a chatbot skin

Workbench: Control (start/pause/kill + cage logs) · Talk · Identity · Charter · Manage (HITL, grants, share contract, dispatch) · Evidence. ACS strip at the **top**. Charter Studio for the full constitution. MONITOR / WATCH for posture.

Possible now: run intelligences the way you run services — **lifecycle + constitution + evidence**, not a playground.

---

## 2. Quality now possible

Quality here means **the action that ran is the action that was admitted**, and you can prove it.

| Quality bar | What the infra does |
|-------------|---------------------|
| **Typed skills, not markdown packs** | Bound skills on the pid; tools/CONP must match when set |
| **Action-bound HITL** | `ActionBinding` digest; consume-once; timeout fail-closed |
| **No param swap** | Approval for digest A cannot execute digest B |
| **Charter change is real** | Edit demotes Active → SetupReady, voids quanta, needs reactivate |
| **Missions survive crash** | Journal + idempotency keys — resume without double side effects |
| **A2A has terminal states** | Task machine (INPUT_REQUIRED → resume → COMPLETED), not fire-and-forget |
| **Traces are chained** | DecisionTrace hash chain in the forensic package |
| **Posture does not lie** | `applied_truth` on Landlock / matrix / DockLock / L7 — intent ≠ applied |
| **LAB MODE is loud** | Banner when Ring-1 / HITL / DockLock / QPR off; one-click harden |
| **Verify offline** | `connectorctl iia verify-export` on a package |
| **Budget / anomaly** | Token budget + deny-rate gate on Talk when enabled |
| **Credential proxy** | Tool secrets stay out of the cage |

Possible now: **ship a change to an agent’s constitution** and know the old approvals died. Possible now: **export evidence** of what the intelligence did, not a screenshot of a chat.

Court-green still requires live WitnessCtl + CFNI soak. The quality machinery is in code; the court claim is an ops event.

---

## 3. Security now possible

Security is the membrane. Prompts are not the membrane.

### 3.1 Three admission layers (no bypass)

| Layer | Who executes | When it runs |
|-------|----------------|--------------|
| **1 Root HITL** | Human | Only after digest approve + consume |
| **2 Cone** | Human + AI (AI **suggests**) | Default. Ask until you approve |
| **3 App** | Automation | Only caps you **justified** on this pid × address, with kernel root |

Fold: **Block > Cone/Root Ask > App Allow**. App Allow **cannot** turn Ask or Block into Allow. Agents **cannot** grant themselves App Allow.

Possible now: let a cell agent **App Allow** `machine.status` on arm-1, and **Cone Ask** every `machine.move_axis` — without a second product.

### 3.2 Per-intelligence isolation (A cannot see B)

Each pid owns:

- **ACS** — character + isolation + NS FS + grants (`GET /runtime/acs/:pid`; header cannot read another pid)
- **NS FS** — `{DATA}/nsfs/{pid}/` · `/p` is not public and not for the LLM
- **Memory / knowledge** — private unless a portal exists
- **World grants** — only the addresses you filled

Possible now: **tenant-grade isolation on one box** without a VM per agent.

### 3.3 Density without dropping the materials

`light_ns` uses the **same class** of controls as Docker (Landlock, seccomp, cgroup v2, DockLock, matrix mark) on a **shared host kernel**. MicroVM is explicit high-risk only (untrusted `.cpkg`), not the default — so the node can run **max agents**.

Possible now: **many intelligences**, docker-grade cut, without Firecracker tax on every pid.

### 3.4 Host cut by intelligence, not OS PID

Continuity break → nftables / iptables-nft cut keyed by **intelligence mark** `0xCD…` derived from `agent_pid`. The product is not “iptables this process.”

Possible now: **kill egress for an intelligence** when its continuity breaks, even if the OS PID churned.

### 3.5 Deny-default network + L7 app allowlist

Cage network deny-default until the operator widens it. Talk uses the platform LLM proxy. Optional L7 app allowlist (`CONNECTOR_L7_EGRESS_PROXY`).

Possible now: an agent that **Talks** but cannot **phone home** unless you granted the address.

### 3.6 Kernel root as sudo (node-wide)

World grants, App Allow, and share contracts require the **kernel root passcode** (Linux sudo analogue). It is not stored in the agent. Rank gates still apply (human operator, not `x-connector-agent-pid`).

Possible now: **the model cannot authorize the model**.

### 3.7 Sharing is a contract, not a folder

No contract → no portal → isolated. Contract fields: **what, where, how much, why**. Then `/share/{portal_id}` on both NS FS trees.

Possible now: **controlled collaboration** between intelligences without a global memory pool.

---

## 4. Work this infra now lets you run

These jobs were previously “don’t put an LLM on that.” They are possible **if** you charter, grant, and (where needed) Cone-approve.

| Job | What you use |
|-----|----------------|
| **Plant / robot cell** | Intelligence class `robotics` · world grant per machine address · Cone on motion · App Allow on telemetry · partner HAL for certified e-stop |
| **IoT / MQTT / Modbus** | Address per topic/device · CONP caps · deny-default cage net |
| **HTTP API worker** | Grant per URL/address · bound skill · credential proxy (key out of cage) |
| **MCP / tool agent** | Bound skills · `admit_tool_or_ask` · digest HITL on high risk |
| **Multi-agent desk** | Two pids · share contract for the one dataset they may both see · dispatch |
| **Regulated desk (HIPAA-shaped)** | Forensic ≥ standard · HITL ≥ tool · Evidence package · WC session when configured · BAA still legal/org |
| **Custom runtime** | `.cpkg` in DockLock · same `admit_*` |
| **Fleet on one node** | `light_ns` density · MONITOR charter drift · LAB banner until harden |

E-stop CONP caps stay **ambient Allow** (safety channel). That is deliberate. Certified SIL loops stay **partner-side**.

---

## 5. Feature map (coded)

| Area | You can |
|------|---------|
| Create | 5-min apply, Charter Studio, Setup wizard |
| Identity | Principal, ACS, `who_am_i`, envelope |
| Execute | Force-pid Talk, tools, MCP, CONP Command |
| Admit | Allow / Ask / Block · 3 layers · bound skills |
| Isolate | NS FS, DockLock, `light_ns`, matrix mark, L7 |
| World | Gateway form, `(pid × address)` grants, kernel root |
| Share | Human+root contract → portal |
| Fabric | Grants, dispatch, A2A states |
| LLM | Vault link, no keys in cage |
| Evidence | DecisionTrace, forensic package, TT, WC iia-join |
| Ops | Start/pause/kill, cage logs, LAB → harden, smoke |

---

## 6. Still not possible (honesty)

Keep these out of marketing and out of operator assumptions:

| Not this | Why |
|----------|-----|
| Court-green out of the box | Follow [COURT_DEFENSIBLE_CHECKLIST.md](COURT_DEFENSIBLE_CHECKLIST.md) — `connectorctl iia court --agent-pid` |
| SIL / ROS / certified robot safety | CONP is a taxonomy + admit path; e-stop hardware is partner |
| Silent MicroVM or eBPF | `light_ns` is shared kernel; Host Active is systemd drop-in until BPF is attached |
| Ambient A↔B memory | Isolation is default; no contract = no portal |
| Agent self-authorizing App Allow | Human + kernel root only |
| Lab = production | Many gates default off; enable hardening |
| Bypass `admit_*` | Talk / tool / CONP all fold through the gateway |

---

## 7. How to use it (shortest path)

1. Link an LLM (Settings paste or `connectorctl llm link`).  
2. Create an intelligence (`POST /intelligence/apply` or Setup).  
3. Start it from Control. Talk as that pid.  
4. For the outer world: gateway form + kernel root for **this pid × this address**; pick Cone or justified App Allow.  
5. To let two agents share: Manage → sharing contract (human+root).  
6. To prove it: Evidence → forensic package / traces.

Architecture picture: plan **§0**. Operator world map: [OPERATOR_WORLD_AGENTS.md](OPERATOR_WORLD_AGENTS.md).

---

*This is the “now possible” list for the coded membrane as of 2026-08-13. If a sentence cannot point at `admit_*`, ACS/NS FS, a world grant, or a share portal, it does not belong here.*
