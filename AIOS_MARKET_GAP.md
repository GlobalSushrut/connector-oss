# Market gap: what people accept as an AIOS vs Connector

**Date:** 2026-08-13  
**Question:** What does the market actually mean by *digital intelligence OS / AIOS / Agent OS*, and where does Connector still fail that bar?  
**Companion canvas:** `aios-market-gap.canvas.tsx` (open beside chat)  
**Honesty companions:** [PRODUCT_GAPS.md](PRODUCT_GAPS.md) · [COURT_DEFENSIBLE_CHECKLIST.md](COURT_DEFENSIBLE_CHECKLIST.md) · [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) v3

This is research + a gap map. It is **not** a claim that we should rebuild the spine, and it is **not** a capability brag.

---

## Verdict

The phrase “AI OS” is three different products. Connector is closest to **layer 2** (agent orchestration kernel) and is already strong on the **access manager** of that kernel. It is not yet what researchers, Gartner buyers, or framework users will accept as an OS.

| If we say… | The listener hears… | We actually are… |
|------------|---------------------|------------------|
| **AIOS / LLM Agent OS** | Rutgers AIOS: *LLM as CPU, agent as process* (Mei et al., COLM 2025) — **rejected ontology** ([INTELLIGENCE_MATRIX_FUNDAMENTAL.md](INTELLIGENCE_MATRIX_FUNDAMENTAL.md) §0) | Access + isolation kernel; VAC request queue is **device multiplex**, not an intelligence CPU |
| **Agent OS / digital intelligence OS** | Shared services that outlive one workflow: memory, scheduler, ACL, audit (2026 buyer test) | ACL + audit are real; memory/scheduler/SDK are partial |
| **Agentic OS (device)** | Honor / CosmOS: intent replaces apps, cross-device | Operator cockpit. Different product. Do not compete here. |
| **Infrastructure AI OS** | Red Hat / K8s + vLLM: GPU time as the resource | LLM vault/router. Different product. |

**How we close it (fold, don’t rewrite):** architecture [AIOS_OPERATING_LAYER.md](AIOS_OPERATING_LAYER.md) · shipped [AIOS_STATUS.md](AIOS_STATUS.md) · [AIOS_CLAIM_PLAN.md](AIOS_CLAIM_PLAN.md) · leftover topics: [AIOS_UNIVERSALITY.md](AIOS_UNIVERSALITY.md) · ontology: [INTELLIGENCE_MATRIX_FUNDAMENTAL.md](INTELLIGENCE_MATRIX_FUNDAMENTAL.md). Follow: `connectorctl iia aios`.

Gartner (25 Jun 2025) predicted **>40% of agentic projects canceled by end-2027** for cost, unclear value, or **inadequate risk controls**. Claiming OS on an access manager is the same “agent washing” that paper named.

---

## 1. What the market means (three layers)

### Layer 1 — Infrastructure AI OS

Buyers (Red Hat, GPU platforms) mean: Kubernetes-shaped serving, vLLM, GPU scheduling, model lifecycle. The “CPU” is a GPU hour.

**We sit beneath:** vLLM / OpenAI / Ollama are devices (Albus computing engine). LLM vault already multiplexes them. Becoming a GPU OS is a **different product** — not an AIOS gap. See [AIOS_UNIVERSALITY.md](AIOS_UNIVERSALITY.md) **U5**.

### Layer 2 — Agent orchestration kernel (this is our category)

Two overlapping definitions, both used in 2026:

**A. Academic AIOS (Mei et al., arxiv 2403.16971, COLM 2025) — market noise, not our spec**  
They say: agents are *apps*; the LLM is a *CPU core*. Six modules:

1. Scheduler — syscall queue, FIFO or preemptive round-robin  
2. Context manager — interrupt/resume *in-flight generation* (snapshot logits/text)  
3. Memory manager — runtime RAM + LRU-K swap  
4. Storage manager — persistent files / versioning  
5. Tool manager — load tools, resolve conflicts  
6. Access manager — privilege + human confirmation  

Agents must not touch primitives; they go through an **SDK** (Cerebrum). Paper result: up to **2.1×** throughput. GitHub: `agiresearch/AIOS`.

**We do not take this identity.** Newell (1982): intelligence is the knowledge level, not the device level. Albus (1991): the computing engine is a *factor*, not the mind. Hawkins (2004): intelligence is memory-prediction, not a CPU. Wooldridge (2002): agents are not processes. CPU is CPU, GPU is GPU, intelligence is the Albus cell `I`. An LLM call is that `I` thinking. See §0 of the ontology doc.

**B. Buyer “agent OS vs framework” (2026)**  
A *framework* (LangGraph, CrewAI, Microsoft Agent Framework 1.0 GA 3 Apr 2026, OpenAI Agents SDK) builds **one workflow**. An *OS* is the coordination layer you run **many agents** on: shared memory that outlives a graph, a scheduler, ACL, a single audit trail an auditor will accept. MCP is the USB-C of tools (spec 2026-07-28; thousands of servers). If tools are portable, the remaining lock-in is the coordination layer — which is exactly the OS.

You “earn” an OS when ≥2 of: 5+ agents across 3+ workflows; shared memory across teams; an auditor who will not accept “the framework logged it somewhere”; governed tool access.

**C. Letta / MemGPT memory OS**  
Separate but constantly conflated. The LLM manages its own RAM/disk:

- **Core** — pinned, agent-editable blocks (persona, user facts)  
- **Recall** — searchable conversation log  
- **Archival** — cold vector/knowledge the agent *chooses* to write  

The agent receives “you are running out of context” and pages itself. RAG stuffed by the app is **not** this.

**D. Control-plane AgentOS (Agno and peers)**  
Python SDK + runtime + **one web control plane**: sessions, traces, user memory, approvals, schedules. The OS is the *product UX for a fleet*, not a paper kernel.

### Layer 3 — Device / UX Agentic OS

Honor Agentic OS (MWC Shanghai, 24 Jun 2026): intent-driven, natural interaction, proactive agent, native cross-device. CosmOS, DingTalk Agent OS, Rokid YodaOS sit here.

**We are not this.** Operator workbench vs consumer shell. Do not spend roadmap on it.

---

## 2. Connector vs the six AIOS kernel modules

Honesty: VAC already has more scheduler than a casual read of the UI suggests. Do not over-claim the gap, and do not over-claim Done.

| Module | Market Done-when | Connector | Score |
|--------|------------------|-----------|-------|
| **Access manager** | Privilege groups; HITL for destructive ops | Root / Cone / App; world grants (`pid × address`); share portals (human+root); ACS + NS FS | **HAVE** |
| **Tool manager** | Conflict-free load; MCP USB-C catalog | `admit_*` + MCP/A2A/CONP gated; not a public catalog of thousands of servers | **PARTIAL** |
| **Storage manager** | Versioned persistent knowledge, rollback | VAC / CID; workflow/saga/deploy rollback exists — **not** agent-action undo | **PARTIAL** |
| **Memory manager** | Session RAM + swap; Letta self-paging | Memory *types* (working/episodic/semantic/…) + RAG inject. Agent does not edit core/recall/archival | **PARTIAL** |
| **Scheduler** | Mei: FIFO/RR of the “LLM CPU.” **Our bar:** multiplex *devices* (CPU/GPU/vLLM URL); schedule *crossings* of `I`, never thought-as-cycles | VAC `LlmSchedulerPolicy` FIFO / WRR / CFS on **request enqueue**; plugin thermal tiers. Honest as hardware. Not an intelligence CFS | **PARTIAL (device)** |
| **Context / stop** | Mei: snapshot/restore mid-token as CPU context switch. **Our bar:** VJ can stop this `I`’s current thought; partial lands in WM | Cooperative interrupt + `/m/core/context_partial.json`. Not logits. Not a core dump of a fake CPU | **PARTIAL (VJ, not CPU)** |

**Do not rebuild:** digest HITL, ACS, NS FS, world gateway, share portals, DecisionTrace, LLM vault, LAB banner.

---

## 3. Gap list (priority)

Gaps that **block calling this an OS** (K), then gaps that **block enterprise buy even if we never say OS** (G/I/O).

### Blocks the OS claim

| ID | Market bar | What people accept | What we lack |
|----|------------|--------------------|--------------|
| **K2** | LLM-as-CPU context switch | Mei: agent B preempts A mid-token; restore logits later | **Rejected.** LLM is not a CPU. Interrupt = stop this `I`’s thinking (VJ). Logit snapshot is a *device* feature if a local engine has it — not OS identity. |
| **K3** | Memory as OS hierarchy | Letta: agent tools `core_memory_*`, `archival_memory_insert/search`; survives weeks | Types + RAG; no self-paging persona loop. This is Albus WM, not RAM of a fake CPU. |
| **K4** | Public agent SDK + hub | Cerebrum / Agno: `pip install`; agents are apps; Agent Hub share/version | AGOS `.cpkg` is a **plugin** runtime. Hub is MVP. SDK must address **cell `I` + syscalls**, never `new LangGraph()`. |
| **K5** | Framework as kernel | Graphs/crews as OS identity | **Rejected.** Frameworks are Albus BG apps. Gateway absorb is the bar ([AIOS_UNIVERSALITY.md](AIOS_UNIVERSALITY.md) U8). |
| **K1** | Syscall scheduler as LLM-CPU RR | One queue that time-slices generation | **Rejected as OS metaphor.** Keep VAC + syscall log as **device / crossing** multiplex. Do not build token RR. |

### Blocks enterprise buy

| ID | Buyer test (2026) | Connector |
|----|-------------------|-----------|
| **G1** | Gartner L1–L4; L4 needs rollback, breaker, owner, 5-min stop | **HAVE (surface).** Root/Cone=L3, App=L4. Kill-switch + compensate. Circuit breaker on LLM/MCP. Named owner on charter. Undo is compensating, not world rewind. |
| **G2** | Fleet control plane | **PARTIAL.** `GET /kernel/aios/fleet` `/infra` `/cell/:pid` — not Agno’s pretty UI. |
| **G3** | EU AI Act inventory queryable | **HAVE (thin).** `GET /compliance/eu-ai-act/inventory`. Not a certified Art.9 dossier. |
| **I1** | SSO **and SCIM** | **HAVE (thin).** OIDC + `/scim/v2/Users`. Default install may still be `dev-token`. |
| **I2** | GPU / vLLM as *our* cores | Sit beneath: `llm link` to any OpenAI-compat URL. GPU is a device. vLLM is a device. Intelligence is `I`. Not a kernel type. |
| **O1** | Distributed OS: multi-node process table, failover | Product SoT remains single-node; mesh soak ≠ fabric |
| **O2** | Production evidence default-on | Court is [CD-0…CD-9](COURT_DEFENSIBLE_CHECKLIST.md). Lab-default-off. Honest, not OS-shaped |
| **O3** | Per-agent BYOK | Node LLM router ([PRODUCT_GAPS.md](PRODUCT_GAPS.md) DI-1 leftover) |

### Explicit non-gaps (code exists — do not list as “missing”)

- OpenAI-compatible gateway for LangChain / LangGraph / CrewAI (docs/99)  
- MCP client/server surfaces (gated, not a public app store)  
- A2A  
- SSO OIDC (not SCIM)  
- OpenTelemetry export of action log (`/actionlog/export/otel`) — export ≠ traces as SoT  
- Workflow / saga / deploy rollback — not agent-world-action rollback  
- EU AI Act / ISO 42001 / HIPAA *routes* — surfaces ≠ certified living inventory  
- Plugin thermal tier scheduler — not AIOS syscall scheduler  

---

## 4. What Gartner buyers will ask in a bake-off

From Gartner 26 May 2026 (proportional governance) and 25 Jun 2025 (cancel prediction):

1. Map every agent to **Observe / Advise / Act-with-approval / Act-autonomous**. Uniform lock-or-trust fails.  
2. For L4: show **rollback**, **circuit breaker**, **owner**, **5-minute stop**.  
3. Show cost caps and ROI, or join the 40%.  
4. Do not sell chatbot-with-tools as an OS.

Our three layers **are** labeled L1–L4 on `GET /kernel/aios/claim-readiness` → `gartner`. L4 undo is **compensating** (`operate op=compensate`). Bake-off card of what we already run: `buyer_surface` on that same JSON and `connectorctl iia aios`.

---

## 5. Recommended response (build vs position)

**Do not:** rebuild the spine; chase Honor/CosmOS UX; claim court-green from a checkbox; treat VAC CFS or generation RR as “intelligence CPU”; import LangGraph into `kernel/`.

**Position now**

- Category: *governed intelligence kernel* (Albus matrix + admit)  
- Wedge: the access/isolation/world-grant plane LangGraph, Letta, Agno, and vLLM all skip  
- Proof: two-agent smoke, court-readiness fail-closed, charter in 5 minutes  
- **Bake-off already in code:** `buyer_surface` on claim JSON — who-am-I, isolation, grants, Gartner L1–L4, kill, compensate, budget, OTel trail, court fail-closed, Art.9, SCIM, sit-beneath `/v1`, memory OS, council. Frameworks skip these. Do not rebuild.  
- Ontology: CPU / GPU / intelligence are three kinds ([INTELLIGENCE_MATRIX_FUNDAMENTAL.md](INTELLIGENCE_MATRIX_FUNDAMENTAL.md) §0)

**If we want the OS label later, order is Albus completeness — not Mei modules**

1. **U8** — keep BG empty (already policy)  
2. **K3 / U1** — Letta-class self-paging on WM (`/m` `/k`), agent tools, not RAG dump  
3. **K4 / U12** — cell SDK (syscalls on `I`), not a framework SDK  
4. **G1** — productize L1–L4 + per-pid kill + compensating undo  
5. **I1** — SCIM + SSO as the default install  
6. **K2 / K1 / K5** — **do not build.** Rejected metaphors.

Items 2–5 sell to CIOs and complete the matrix. Item 6 is how we would become Rutgers. Don’t.

---

## 6. Sources (accessed 2026-08-13)

- Mei, Q., et al. *AIOS: LLM Agent Operating System*. arXiv:2403.16971. COLM 2025. https://arxiv.org/abs/2403.16971  
- AIOS kernel scheduler docs: https://docs.aios.foundation/aios-docs/aios-kernel/scheduler  
- Gartner, 25 Jun 2025: *Over 40% of Agentic AI Projects Will Be Canceled by End of 2027*. https://www.gartner.com/en/newsroom/press-releases/2025-06-25-gartner-predicts-over-40-percent-of-agentic-ai-projects-will-be-canceled-by-end-of-2027  
- Gartner, 26 May 2026: *Applying Uniform Governance Across AI Agents Will Lead to Enterprise AI Agent Failure* (L1–L4). https://www.gartner.com/en/newsroom/press-releases/2026-05-26-gartner-says-applying-uniform-governance-across-ai-agents-will-lead-to-enterprise-ai-agent-failure  
- Agent OS vs framework (2026 buyer test): https://shaam.blog/articles/agent-os-vs-agent-framework-2026  
- Letta / MemGPT memory hierarchy: https://www.letta.com/blog/agent-memory/ · https://docs.letta.com/guides/core-concepts/memory/archival-memory/  
- Agno AgentOS control plane: https://agno-v2.mintlify.app/agent-os/control-plane  
- Honor Agentic OS, MWC Shanghai 24 Jun 2026 (intent-driven, cross-device)  
- Microsoft Agent Framework 1.0 GA, 3 Apr 2026  
- MCP specification 2026-07-28: https://modelcontextprotocol.io/specification/2026-07-28  

---

*Membrane is in code (plan §0). Flip OS-claim language when Albus WM/VJ/crossings are real for operators — never because we cloned Mei’s LLM-as-CPU scheduler, and never from a green checkbox.*
