# Connector OS — when we are done, how people actually use it (story)

> **Purpose:** A single **post–Definition of Done** narrative so everyone agrees what “success” *feels like* for operators, developers, and agentic systems wiring into **TraceTramp**, **WitnessCtl**, **DevGuard**, and **custom CLS workflows**.  
> **Assumption:** **`CONNECTOR_OS_ROADMAP.md`** §10 (Definition of Done) is satisfied, and the **blueprint tracks** in **`CONNECTOR_OS_REMAINING_TO_REAL_SOFTWARE.md`** §3 are real (not aspirational text).  
> **Companion:** **`CONNECTOR_OS_PUBLIC_LAUNCH_CHECKLIST.md`** — master checklist (story acceptance + Definition of Done + launch gates) to reach this narrative and ship publicly.  
> **Topology:** one **customer node** (`connector-platform` + embedded dashboard) vs optional **vendor plane** (`connector-license-server` + portal) — **`ARCHITECTURE.md`**.

## 1. The shared premise (every story starts the same way)

**Maya** (platform engineer) downloads **`connector-os-<version>-<arch>-linux.tar.gz`**, unpacks it on a VM in the team’s VPC, runs **`connectorctl start`**, and opens the **operator dashboard** on the node’s HTTPS origin. She does **not** assemble compose files or hunt for which process is “the” Connector.

The **Apps / catalog** already lists what the org cares about: **TraceTramp**, **WitnessCtl**, **DevGuard**, a few **AGOS** plugins from the Hub, and **dozens of CLS workflows** (some shipped as reference templates, some dropped in by other teams and **picked up automatically** with stable names). Anything **enabled** shows a **green row**: **active**, **PID** (if supervised), **listen port** (if any), **public proxy path** (`/plugin/<slug>/…`), and **cage hostname** (`<slug>.<cage_tld>`) so automation never guesses URLs from tribal knowledge.

From here, three teams plug in **without** Maya running ad‑hoc shell for every line of business.

---

## 2. Story A — “We run agents and models; we need traces and spend under control”

**Who:** **Jordan** (ML platform). Their stack is a mix of **OpenAI‑compatible SDKs**, in‑house Python agents, and a few **Node** services. They do **not** want to fork every repo to add tracing.

**What they do**

1. Jordan opens **Settings → LLMs** on the node and registers providers (commercial API keys live in the **vault**; local **Ollama** / **vLLM** endpoints are first‑class options in the same panel).
2. In **Service Map**, Jordan copies the node’s **gateway base URL** and a **scoped API key** minted for the `payments-agents` workspace (roles: call gateway, emit traces, no admin).
3. In each agent service, Jordan sets the **OpenAI client `base_url`** (or equivalent) to that gateway URL and uses the scoped key. No library import from Connector is required — the **HTTP surface** is the contract.
4. Jordan enables **TraceTramp** from the catalog (already installed from the Hub or first‑party bundle). TraceTramp’s row shows **reachable** and the **URI** Jordan can open for the TraceTramp operator UI (via the kernel’s **`/plugin/tracetramp/…`** proxy and stable cage addressing).

**What they get**

- Every governed LLM call flows through the **kernel gateway** (policy, admission, routing, cost).
- **TraceTramp** receives the **trace stream** the team expects from a serious observability product: search by agent id, trace id, latency, errors, spend — without running a separate Prometheus stack just to see prompts.
- If a model provider fails, **routing rules** Jordan configured in the dashboard decide fallback; Jordan does not SSH into the box to edit env vars.

**Mental model:** the **Connector node** is the **control plane for model traffic**; **TraceTramp** is the **observability app** on top of that traffic. Agentic infra “connects” by **pointing HTTP at the gateway** and **using vault‑scoped credentials**.

---

## 3. Story B — “We need receipts: auditors, not just dashboards”

**Who:** **Sam** (security / compliance). They care that when an agent takes an action, there is a **tamper‑evident narrative** suitable for review — not only logs in someone’s terminal.

**What they do**

1. Sam enables **WitnessCtl** from the same catalog Maya prepared. WitnessCtl shows **active** with its **management URI** and health.
2. Sam wires the **governance policy** so that **high‑risk tool paths** (e.g. production DB writes, PII‑class memory namespaces) require a **WitnessCtl receipt** or HITL step — expressed as **CLS workflow** rules the legal team can read (not a Python script only Jordan understands).
3. Product agents continue to call the **same gateway** as Story A. The difference is **orchestration**: selected workflows **attach witness events** at defined steps; WitnessCtl is the **system of record** for those receipts.

**What they get**

- Auditors use **WitnessCtl’s UI** (reachable through the same **`/plugin/`** and cage patterns) to answer “who approved this, under which policy version, with what evidence,” without cloning raw application logs from twelve services.
- When something goes wrong, **rollback of a workflow version** is a **catalog action**, not a redeploy of five microservices.

**Mental model:** **WitnessCtl** is the **audit / evidence app**; agentic infra connects **indirectly** — still through the **kernel + workflows**, so receipts stay aligned with **policy versions** the node enforced.

---

## 4. Story C — “We bought a custom workflow from another team (or Hub); it just shows up”

**Who:** **Riley** (automation engineer). They maintain **CLS** packages that orchestrate plugins (notify, ticket, LLM steps).

**What they do**

1. Riley’s CI publishes a new **workflow package** to the org’s process (Hub mirror or internal registry). The node **detects the new version**, names it from package metadata, and Maya sees it in the **workflow catalog** next morning — **no** per‑release ticket for Maya to run twenty CLI commands.
2. Riley clicks **Enable** on the new version (or the kernel auto‑stages per policy). **Dry‑run** shows what *would* have fired on recent traffic patterns **without** side effects.
3. When satisfied, Riley promotes to **ENABLED**. Downstream, Jordan’s agents do not change their URLs; **behavior** changes because **CNP‑mediated** dispatch now includes the new edges the workflow defines.

**What they get**

- **Hundreds of workflows** remain manageable: catalog + lifecycle + diff, not a spreadsheet of shell history.
- Third‑party and internal workflows are **the same object type** — first‑class apps on the OS.

**Mental model:** **CLS workflows** are **programs on the substrate**; plugins are **capabilities**; **CNP** is the **syscall‑like boundary** between them — agents stay dumb to inner wiring.

---

## 5. Story D — “DevGuard: our dev tools talk to the same node as production policy”

**Who:** **Alex** (staff engineer). They use **Cursor / VS Code**, local **terminals**, and sometimes **browser‑based** agent UIs. They want **computer‑level** guardrails (egress, sensitive file paths, “no exfil on paste”) **consistent** with what Sam enforces in production — not a different story in every IDE.

**What they do**

1. Alex enables **DevGuard** from the catalog. First‑run wizard (dashboard + small host helper) installs the **DevGuard sidecar / host shim** appropriate for Alex’s OS — one time, not per repo.
2. Alex selects a **Dev profile** bound to a **CLS workflow pack** the security team published (e.g. “local dev: allow research APIs; block known bad domains; redact PII patterns on clipboard export”). The profile is **versioned on the node** like any other workflow.
3. The IDE (or a thin local agent shipped with DevGuard) **registers** with the node using a **short‑lived device token**. From then on, **tool calls** from the coding agent are **mediated**: either allowed, blocked with a clear reason, or routed through **gateway + TraceTramp** when they touch models.
4. When Alex runs the same repo’s integration tests against the **Connector gateway** in staging, **policy IDs match** what DevGuard enforced locally — no “works on my machine” gap for governance fields that matter.

**What they get**

- Developers experience Connector as **an OS service for safe building**, not only as a server “somewhere in staging.”
- Security gets **one policy lineage** from laptop to cluster, instead of a separate browser extension policy, a separate firewall SKU, and a separate LLM proxy.

**Mental model:** **DevGuard** is the **host‑integrated app**; it **binds dev tools to the same kernel** as TraceTramp/WitnessCtl, with **extra local hooks** the pure in‑kernel plugins do not need.

---

## 6. Pulling it together — who points where (cheat sheet)

| Persona | They want… | They connect agentic infra by… | They verify success in… |
|---------|------------|----------------------------------|---------------------------|
| **ML platform (Jordan)** | Cost + traces + safe LLM routing | **`base_url` → node gateway**, vault‑scoped keys | Gateway metrics, **TraceTramp** UI, Service Map |
| **Security / audit (Sam)** | Receipts + policy | Workflow + WitnessCtl config on the **same node** | **WitnessCtl** UI, workflow version history |
| **Automation (Riley)** | Composable ops | Publishing/enabling **CLS** packages | Catalog, dry‑run, enable/rollback |
| **Developer (Alex)** | Safe local agentic coding | **DevGuard** + IDE registration to the node | DevGuard status, blocked/allowed reasons, shared policy ids |

**One sentence for the whole company:** *Everything agentic talks **HTTP** to **one origin** the platform team runs; **plugins** are apps; **workflows** are programs; **DevGuard** is the bridge to the **human dev environment** — and Maya can prove all of it from **one dashboard** without opening five vendor consoles.*

---

## 7. Why this story is the finish line

If we cannot tell Stories **A–D** truthfully for a fresh install, we are not done — regardless of how many internal crates compile. The remaining engineering is everything in **`CONNECTOR_OS_REMAINING_TO_REAL_SOFTWARE.md`** that still blocks **stable URIs**, **catalog scale**, **CNP‑true workflows**, **microVM‑default isolation**, and **RBAC/UI‑RPC hardening** so these connections are **safe by default**, not “possible if you read the right internal doc.”

**Related:** **`ARCHITECTURE.md`** (node vs vendor plane, operator loop), **`PLUGIN_CONTRACT.md`** (handshake + cage), **`CONNECTOR_OS_ROADMAP.md`** §1.1 (vision checklist in prose), **`docs/32-connectorctl.md`** (CLI mental model).
