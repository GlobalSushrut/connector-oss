# What’s left for a real AIOS — universality, absorbability, sit-beneath

**Date:** 2026-08-13  
**Architecture (read first):** [AIOS_OPERATING_LAYER.md](AIOS_OPERATING_LAYER.md) — Connector is the operating layer; three sockets; vendors interchangeable.  
**Achieved till now:** [AIOS_STATUS.md](AIOS_STATUS.md)  
**Rule:** Kernel = Albus matrix (SP · WM · VJ · BG-socket). Apps (LangGraph, vLLM, Crew, MCP) sit **on** it. We never wrap each vendor into the kernel.  
**Ontology:** [INTELLIGENCE_MATRIX_FUNDAMENTAL.md](INTELLIGENCE_MATRIX_FUNDAMENTAL.md)  
**Follow:** this file’s **Done-when** lines. Claim bar: [AIOS_CLAIM_PLAN.md](AIOS_CLAIM_PLAN.md)

Three tests. Fail any one → not a real AIOS.

| Test | Meaning | Easy check |
|------|---------|------------|
| **Fundamental** | Kernel is the matrix + admit of typed `A`. No framework types in `kernel/`. | `rg LangGraph platform/server/src/kernel` is empty |
| **Universal** | Any BG/SP engine can use the same crossings | Point vLLM *or* OpenAI *or* a robot loop at the same pid gateway |
| **Absorbable** | Existing apps keep working without a rewrite | `OPENAI_BASE_URL=…/v1` (docs/99) — we sit beneath |

Exokernel (Engler, SOSP 1995): protect and multiplex **hardware**; do not provide the abstraction. POSIX is a **libOS**, not the kernel. vLLM / LangGraph are our POSIX. Do **not** apply this by calling the LLM “the CPU.”

Newell (1982): intelligence is the **knowledge level**, above program and device. Albus (1991): the computing engine is a *factor*, not the mind. Hawkins (2004): memory-prediction, not a CPU. Wooldridge (2002): agents ≠ objects ≠ processes.

Albus: WM is the world database **all levels query**. BG does not own WM. Fleet orchestration is **more nodes in the matrix**, not a bigger graph. CPU is CPU, GPU is GPU, `I` is intelligence.

---

## Leftover map (kernel AIOS only)

Enterprise packaging is folded, not rebuilt: SCIM = `/scim/v2/Users` over user_store; Art.9 = `/compliance/eu-ai-act/inventory`; court = existing readiness (never green from AIOS JSON); Honor/GPU OS stay out.

| ID | Topic | Albus box | Now | Blocks AIOS? |
|----|--------|-----------|-----|--------------|
| **U1** | Memory as WM (core / recall / archival actually used) | WM | Files + syscalls + Talk inject + kernel page-to-archival + retrieve | **Shipped (kernel paging)** |
| **U2** | Knowledge as WM SoT (`/k`), not RAG dump | WM | `memory.knowledge.search` + `wm.retrieve` (portal `/k` + archival); VAC RAG still cache | **Shipped (RAG remains cache)** |
| **U3** | Fleet knowledge without ambient A↔B | WM + pores | Portal `/k` + **council desk** (Talk inject, owner-μ tasks, hash floor) | **Shipped (not shared RAM)** |
| **U4** | All ingress is SP → WM packets | SP | Completions/grants/CONP/MCP logged as crossings | **Shipped (log)** |
| **U5** | Model backends absorbed — **devices** | SP resource | `llm link` + absorb catalog; no kernel vendor type | **Shipped — don’t overbuild** |
| **U6** | Every effect through VJ (`admit_*`) | VJ | Talk/tool/CONP/A2A/share + **syscall C9** + notebook-when-bound | **Shipped (lab still skips missing contract)** |
| **U7** | Stop + compensate | VJ | Kill-switch + `operate compensate` / grant revoke / portal close / deny tool | **Shipped (compensating)** |
| **U8** | BG is an empty socket | BG | Gateway exists; no framework types in `kernel/` | **Policy — keep empty** |
| **U9** | Named time-levels | Hierarchy | ACS/matrix `level` from clocks + optional `horizon` | **Shipped (labels)** |
| **U10** | Fleet = many cells | Hierarchy | `GET /kernel/aios/fleet` + infra plane | **Shipped** |
| **U11** | One crossing ABI | Matrix I/O | Talk logs `llm.complete`; syscall + world recorded | **Shipped** |
| **U12** | Cell SDK | Absorb | `docs/cell_sdk.py` + docs/99 (not pip / not LangGraph) | **Shipped (thin)** |
| **U13** | Schedule *crossings*, not LLM cores | Matrix I/O + devices | VAC queue + crossing log. Cap off unless `CONNECTOR_I_INFLIGHT` | **Shipped (honest)** |
| **U14** | Tools/MCP as resources behind admit | SP/BG resource | Gated MCP + world crossing log | **Shipped — don’t catalog 6000 servers** |
| **U15** | VJ default-on (lab off) | VJ ops | Production-like ENV applies hardening. Lab = `CONNECTOR_PRESET=local` / `CONNECTOR_LAB=1` | **Shipped (lab explicit)** |
| **U16** | Same matrix, more nodes | Hierarchy ops | Fleet `μ`; infra `topology` = mesh SoT (`single_node` until soak + flag) | **Shipped (honest)** |

**Already enough (do not rebuild):** ACS, NS FS, 3 layers, world grants, share portals, DecisionTrace, LLM vault, OpenAI-compat gateway, CONP admit, kill-switch, memory OS *files*.

---

## How to reach each (practical, easy)

Each item: **Done-when** (one test) · **Do** (≤3 steps) · **Sit-beneath** · **Don’t**.

### U1 — Memory is WM, not a prompt dump

**Research:** Albus WM is queried by BG at every level. Letta/MemGPT is one *app* paging policy on that WM. Kernel owns the tiers; the model’s paging loop is BG.

**Done-when:** A pid can `memory.core.set` / `recall.search` / `archival.insert` via `POST /kernel/syscall`, Talk injects core, and a second turn uses archival without the app stuffing RAG.

**Do:**
1. Bind those three syscalls as `admit_tool` tools on the pid (still VJ).  
2. Keep inject of `/m/core` (already in gateway).  
3. On long context, one system line: “core is full — archival.search or core.set eviction.” No new database.

**Sit-beneath:** LangGraph memory / Mem0 / Zep write through the same syscalls. Their store is not SoT.

**Don’t:** Import Letta. Don’t make Pinecone the kernel.

### U2 — Knowledge (`/k`) is world model SoT

**Research:** Albus: one world model, many readers. Knowledge ingest (`/v` → `/k`) is SP cleaning then WM store.

**Done-when:** `GET` knowledge for a pid returns CID-backed `/k` packets; Talk retrieves via WM syscall, not a private vector DB in the app.

**Do:**
1. Document: app RAG = cache; VAC `/k` = SoT.  
2. One syscall `memory.knowledge.search` that reads `/k` + vector-box **of this I** (and granted portals).  
3. Keep the existing ingest pipeline — don’t replace it.

**Sit-beneath:** LlamaIndex / LangChain retrievers pointed at our search syscall.

**Don’t:** Embed Weaviate as kernel. Don’t share `/k` across I without a portal.

### U3 — Fleet knowledge = licensed pores

**Research:** Albus shop/cell: higher level WM is a **summary** of lower WMs, not a dump of everyone’s RAM. Our pore is already the share portal + grant.

**Done-when:** Two pids share a fact only after human+root portal; council Talk inject shows named members + owner-μ tasks; `GET /intelligence/council/inbox` is this `I` only.

**Do:**
1. Treat mesh knowledge-plane as **read-only operator view** of grants + Knot.  
2. Any “fleet memory” write goes `share-contract` → `/share/{id}` → WM of each I.  
3. Talk between `I`s: `POST /intelligence/council` (root) then `speak` / `council.speak` syscall — never a shared `/k`.

**Sit-beneath:** A “company brain” product is an **app** that holds a portal, not the kernel.

**Don’t:** Ambient `/k/shared` for all agents.

### U4 — Ingress is sensory processing

**Research:** Albus SP: sense → filter → update WM. Talk, CONP sensor, MCP resource, file drop are all SP.

**Done-when:** Completions, CONP observe, MCP resource, `/v` ingest each leave a WM packet (or a traced refuse). No silent side channel.

**Do:**
1. List ingress in ACS `matrix.functions.sensory_processing`.  
2. Fold new ingress onto existing memory write + DecisionTrace.  
3. Skip a grand “sensor bus” rewrite.

**Sit-beneath:** Cameras, webhooks, vLLM logprobs = SP apps writing WM.

### U5 — Absorb vLLM / OpenAI / abc (do not become them)

**Research:** Exokernel multiplexes the disk; it is not ext3. LLM vault already multiplexes providers. GPU OS (Red Hat + vLLM) is a **different product** (Albus “computing engine”). The LLM is **not** that engine’s personality and **not** an intelligence CPU — it is how a given `I` may think (BG), running on GPU/CPU metal.

**Done-when:** `connectorctl llm link` can point at OpenAI **or** `http://vllm:8000/v1` **or** Ollama; pid Talk does not change; kernel has no `VllmScheduler` type and no “LLM core” table.

**Do:**
1. Keep vault + OpenAI-compat. Add one doc line: “vLLM = local OpenAI URL.”  
2. Optional: per-pid model **name** in charter (already parameters.model) — still not a vendor type.  
3. Stop listing “GPU OS” as an AIOS gap.

**Sit-beneath:** They run vLLM; we admit the completion as `A` and meter it.

**Don’t:** Vendor adapters in `kernel/`. Don’t schedule CUDA. Don’t RR in-flight tokens as if the model were a core.

### U6 — VJ on every remaining effect

**Research:** Containment only works if every effect is typed (CPM L1). Leftover C9 paths are the only kernel hole that can fake an OS.

**Done-when:** `require_contract_action` / `admit_*` on every tool/MCP/A2A/memory-share path still listed in PRODUCT_GAPS / IIA backlog.

**Do:** Close remaining C9 items one path at a time. No new framework.

### U7 — Stop and compensate

**Done-when:** `POST /agents/:pid/kill-switch` < 5 min (shipped) **and** operator can revoke grant / close portal / disable tool as the undo.

**Do:** One Manage UI / ctl verb that calls existing revoke + portal close. Don’t build world rewind.

### U8 — Keep BG empty

**Done-when:** No LangGraph/Crew/vLLM types under `platform/server/src/kernel/`.

**Do:** Code review gate. Gateway + syscall stay the socket. docs/99 is the absorb path.

### U9 — Name the time levels (fleet orchestration, the Albus way)

**Research:** Albus: each level ~10× slower, wider. Our quanta ≈ servo, missions ≈ task, fabric/dispatch ≈ shop. “Fleet orchestration” is **not** a LangGraph supervisor — it is a **higher-level node** whose BG plans in hours and whose WM holds summaries.

**Done-when:** ACS or posture shows `level: servo|task|mission|shop` with the existing mechanism (quantum TTL / mission journal / fabric task) — labels only, no new runtime.

**Do:**
1. Map: quantum → servo, mission → task, fabric.task → shop.  
2. One field on IntelligenceSpec `parameters.horizon` optional. Kernel already has the clocks.  
3. Fleet UI lists cells by level, not a mega-graph.

**Don’t:** One orchestrator agent that is secretly LangGraph.

### U10 — Fleet = many matrix cells

**Research:** NIST RCS machining example: robot, buffer, machine tool = **sibling nodes** under a workstation. Coordination = commands down, status up, **not** shared RAM.

**Done-when:** `connectorctl iia smoke` (two I, grant, dispatch, distinct who_am_i) is the fleet primitive. Scale = more cells + grants.

**Do:** Keep dispatch queued. Document smoke as the fleet test. Optional MONITOR list of all `μ`.

**Don’t:** Shared Brain object in kernel.

### U11 — One crossing ABI

**Done-when:** Talk, memory, tool, CONP are all recorded as syscalls (Talk may still use `/v1/chat/completions` as the *absorb* URL, but it logs `llm.complete` on the syscall log).

**Do:** Gateway already interrupts via aios; add `log_syscall(pid, "llm.complete")` on success/fail. Cheap.

### U12 — Cell SDK (thin)

**Done-when:** 40-line Python: set `I`, `OPENAI_BASE_URL`, optional `POST /kernel/syscall`. No `from langgraph`.

**Do:** One file `docs/99` extra section “cell SDK”. Don’t publish a framework.

### U13 — Schedule crossings (devices and I/O, not thought-as-CPU)

**Done-when:** Two pids’ `llm.complete` share VAC FIFO/CFS (already) **and** memory/tool syscalls share the same visible queue in `GET /kernel/aios/modules` or syscall log. Claim JSON must **not** call this an LLM-CPU.

**Do:** Use existing VAC scheduler; append tool/memory to the syscall log (U11). Don’t RR-preempt Python graphs. Don’t RR tokens.

**Don’t:** `VllmScheduler` in `kernel/`. Don’t market CFS of enqueue as intelligence.

### U14 — Absorb tools, don’t catalog them

**Research:** MCP is USB-C. Kernel is the **port + VJ**, not the device tree of 6000 servers.

**Done-when:** An MCP server the operator adds is admitted as tools of `I`. Kernel has no full MCP registry as identity.

**Do:** Keep gated MCP. Operator adds servers per pid (charter S7).

### U15 — VJ on by default (ops)

**Done-when:** Harden preset path without LAB (already scripted). Product default in install docs.

**Do:** Docs + installer. Not a new kernel module.

### U16 — Same matrix, more nodes (ops)

**Done-when:** Mesh soak claim with `.l5-mesh-soak.ok` when marketing multi-node. Until then honesty: single-node SoT.

**Do:** Don’t invent a second identity per cell. `μ` travels with the intelligence, not the Linux host PID.

---

## Absorbability cheat-sheet (what users actually do)

| They use | They point at | Kernel sees |
|----------|---------------|-------------|
| OpenAI SDK / LangChain / LangGraph / Crew | `OPENAI_BASE_URL=/v1` | SP/BG completion + VJ |
| vLLM / Ollama / abc | Same URL or `llm link` endpoint | Same |
| Letta / Mem0 | `/kernel/syscall` memory.* | WM |
| MCP servers | Charter bind + admit_tool | Resource + VJ |
| Robot / CONP | `/protocol/conp/command` | admit_conp |
| Another Connector node | Grant + fabric / CNP | Higher-level matrix node |

If a design needs a new vendor crate in `kernel/`, it failed absorbability.

---

## Order (easy sequence)

1. **U8** freeze (don’t import frameworks) — today  
2. **U11** log Talk as syscall — small  
3. **U1** memory tools + inject — unblocks “WM is real”  
4. **U2** knowledge.search syscall — unblocks knowledge SoT  
5. **U9** label levels — unblocks “fleet orchestration” story  
6. **U3 / U10** portal-only fleet — already mostly true; tighten honesty  
7. **U6** remaining C9  
8. **U12** 40-line cell SDK  
9. **U5 / U14 / U15 / U16** absorb + ops — no new kernel types  

---

## Sources

- Newell 1982 — knowledge level above symbol and device; LLM-as-CPU collapses this  
- Albus 1991, 1994 NISTIR 5502 — matrix of SP/WM/VJ/BG; computing engine ≠ intelligence  
- Minsky 1992 — methods (graphs, nets, logic, later transformers) are not the architecture  
- Engler et al. SOSP 1995 / ExOS — sit beneath **hardware**; POSIX is a libOS  
- Wooldridge 2002 — agents ≠ objects ≠ OS processes  
- Hawkins 2004 — memory-prediction, not a CPU  
- Letta/MemGPT — *one* paging policy on WM, not the kernel  
- MCP 2026-07-28 — USB-C; we are the port  
- Mei et al. 2024 — **rejected** LLM-as-CPU definition  

*Universality = same crossings. Absorbability = they don’t rewrite. Fundamental = Albus boxes, not vendors.*
