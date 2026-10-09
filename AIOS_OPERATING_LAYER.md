# AIOS operating layer — universal architecture

**Date:** 2026-08-13  
**Spine:** do not rewrite [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) §0 (L0–L8). This is that spine **read as an OS**: Connector is the operating layer; everything else is interchangeable app or device.  
**Ontology:** [INTELLIGENCE_MATRIX_FUNDAMENTAL.md](INTELLIGENCE_MATRIX_FUNDAMENTAL.md) §0 — CPU ≠ GPU ≠ intelligence.  
**Close remaining holes:** [AIOS_UNIVERSALITY.md](AIOS_UNIVERSALITY.md). **Claim language:** [AIOS_CLAIM_PLAN.md](AIOS_CLAIM_PLAN.md).  
**Achieved till now:** [AIOS_STATUS.md](AIOS_STATUS.md).  
**Picture:** open [aios-operating-layer](/home/umesh/.cursor/projects/home-umesh-Projects-connector-private/canvases/aios-operating-layer.canvas.tsx) beside the chat.

---

## One sentence

Connector does not run LangGraph, vLLM, Ollama, Crew, MCP, or Letta. Those products **do what they do**. Connector **charters intelligence `I`, admits every effect `A`, keeps the world model, and can stop `I`**. That is the operating system. Vendors are identical because they only touch **three sockets**.

---

## 1. Research → layers (do not invent a fourth kind)

Newell (1982): knowledge level sits above symbol/program, which sits above device. Albus (1991): every intelligent node is SP · WM · VJ · BG; the computing engine is a *factor*, not the mind. Engler (1995): the kernel protects and multiplexes; it does not become POSIX. Minsky (1992): methods are not the architecture. Wooldridge (2002): agents are not processes.

| Newell / Albus | Connector band | What lives here |
|----------------|----------------|-----------------|
| Device | L0 host + L2 cage + LLM vault URL | CPU, GPU, disk, **vLLM / Ollama / OpenAI as disks** |
| Symbol / program | App layer (outside `kernel/`) | LangGraph, Crew, Talk, robot loops, MCP servers |
| Knowledge level | **Operating layer** = L1 admit + L3 bubble + L4 world + L6 control + L7 VJ + L8 human | Chartered `I`, typed `A`, WM, stop, evidence |
| Architecture (Albus matrix) | Same operating layer, recursive per `I` | SP · WM · VJ · BG-socket at every time-level |

Mei’s “LLM = CPU” is rejected: it puts the knowledge level on the device row.

---

## 2. Picture (universal — names on the top row never enter the kernel)

```text
 APP  they do what they do
      thinkers     LangGraph  Crew  AutoGen  MAF  Talk  PID  robot
      engines      vLLM  Ollama  OpenAI  abc  llama.cpp
      sensors      MCP  webhook  CONP observe  /v ingest
      mem-apps     Letta  Mem0  LlamaIndex     (cache only)
           │
           │  THREE SOCKETS  — same bytes for every vendor
           │  1. completion   POST /v1/chat/completions
           │  2. syscall      POST /kernel/syscall
           │  3. world        CONP + grant + portal
           ▼
 OPERATE  Connector  (this is the AIOS)
      I · μ 0xCD · charter C
      SP  ingress → WM packet
      WM  /m /k  SoT     (app stores are cache)
      VJ  admit_* · HITL · interrupt · kill
      BG  empty socket   typed A only
      evidence  DecisionTrace
           │
 MANAGE   same kernel, operator face
      IntelligenceSpec apply · llm link · bind MCP · grants · lab/harden
      You charter and wire. You do not pick a framework as OS identity.
           │
 MATRIX   Albus node, recursive     servo / task / mission / shop
 HOST     Linux CPU · GPU · nft     devices only
```

**Manage becoming operate:** chartering `I`, linking a device URL, and setting a grant *is* the OS. Runtime admit/stop/trace is the same layer seen in motion. There is no separate “orchestration product” above this. A LangGraph supervisor is still BG on some `I`.

---

## 3. Three sockets (why Connector does not care which vendor)

Kernel types are only: **`I`**, **`A`**, **WM packet**, **grant**, **device URL**. If a design needs `LangGraphState` or `VllmEngine` under `platform/server/src/kernel/`, it has already failed.

| Socket | Absorb URL / verb | App thinks it is | Kernel sees |
|--------|-------------------|------------------|-------------|
| **Completion** | `POST /v1/chat/completions` (docs/99) | OpenAI | `I` thinking: SP/BG crossing, VJ, meter. Backend is whatever `llm link` pointed at. |
| **Syscall** | `POST /kernel/syscall` | OS API | WM get/set/search, tool.invoke, llm.interrupt, kill. |
| **World** | CONP / grant form / share portal | Robot bus, A2A, MCP | `admit_conp` / `admit_tool` + pore. |

vLLM and Ollama are the same socket as OpenAI: an OpenAI-compat **device URL**. LangGraph and Crew are the same socket as a bash loop: they call completion and/or syscall as some `I`. MCP is not a kernel catalog; it is a resource bound on that `I` and admitted as `A`.

**Universality test:** swap vLLM → Ollama → OpenAI without changing Talk. Swap LangGraph → Crew → a script without changing ACS/`μ`. Fail either → not an OS.

**Absorbability test:** they keep their own tools; they only change `OPENAI_BASE_URL` (and optionally syscall). Fail → we wrapped them, we did not sit beneath.

---

## 4. Four app roles, two kernel kinds

| App role | Examples | Kernel kind | Kernel must not |
|----------|----------|-------------|-----------------|
| **Thinker** | LangGraph, Crew, AutoGen, Talk, PID | BG method — emits `A` | Import the graph type |
| **Engine** | vLLM, Ollama, OpenAI, abc | Device (computing engine) | `VllmScheduler` / “LLM core” |
| **Sensor / tool** | MCP, CONP, webhook | SP resource or effect `A` | Catalog of 6000 servers as identity |
| **Memory client** | Letta, Mem0, LlamaIndex | WM *client* | Treat their DB as SoT |

All four are **parameters of a cell**, never identity of the cell. `reasoner_dialect` stays app metadata. Kernel ignores it.

---

## 5. Map onto L0–L8 (fold)

| Operating-layer job | Already in spine | Fold (do not add a vendor crate) |
|---------------------|------------------|----------------------------------|
| Individuate `I` | mint + ACS + `μ` 0xCD | Keep. Never Linux PID as `I`. |
| World model SoT | NS FS `/m` `/k`, VAC | U1/U2: Talk actually pages; knowledge.search |
| Value / admit | `admit_*`, 3 layers, charter | U6 shipped (syscall C9) |
| Stop | kill-switch, `llm.interrupt` | Manage UI: revoke grant / close portal |
| Completion absorb | OpenAI gateway + LLM vault | U5: `llm link` to any URL; no kernel vendor type |
| Framework absorb | docs/99 `OPENAI_BASE_URL` | U8 freeze: BG empty |
| One ABI | `POST /kernel/syscall` | U11: log Talk as `llm.complete` |
| Fleet | grants, portals, dispatch | U10: more cells, not a mega-graph |
| Evidence | DecisionTrace | Keep |
| Device multiplex | VAC queue, cgroups | Honest as **hardware**. Not intelligence CFS. |

---

## 6. Invariants (the OS claim is these, not a vendor list)

1. **`rg LangGraph platform/server/src/kernel` is empty.** Same for Crew, vLLM, Ollama types.  
2. **Every effect is typed `A` and passes VJ** (or a traced refuse).  
3. **WM of `I` is SoT.** App checkpointers and vector DBs are cache.  
4. **BG is an empty socket.** Kernel admits commands; it does not run planners.  
5. **Engines are URLs.** `connectorctl llm link` is how Ollama and vLLM enter the node.  
6. **CPU / GPU / `I` stay three kinds.** No LLM-as-CPU scheduler.  
7. **Manage = operate.** Charter, link, grant, kill are kernel verbs, not a SaaS beside the kernel.

Reach AIOS = these seven hold **and** the U-order in [AIOS_UNIVERSALITY.md](AIOS_UNIVERSALITY.md) is done. Not = clone Mei modules.

---

## 7. Operator loop (what “operating” feels like)

1. **Charter** `I` (`POST /intelligence/apply`) — manage.  
2. **Link engine** (`llm link` → vLLM or Ollama or OpenAI) — still a device.  
3. **Point the app** at `/v1` — LangGraph/Crew/script unchanged.  
4. **Bind tools / MCP / world grants** — pores, not ambient.  
5. **Runtime:** every completion and tool is admit + trace; interrupt/kill stops **this `I`**.  
6. **Swap** the engine or the thinker tomorrow. ACS and `μ` do not change.

That loop *is* the product. The framework is a customer choice, like which editor they use on POSIX.

---

## 7b. Shipped operator API (2026-08-13)

| Method | Path | Job |
|--------|------|-----|
| GET | `/api/v1/kernel/aios/claim-readiness` | V1/V2 claim + **buyer_surface** bake-off card |
| GET | `/api/v1/agents/:pid/identity-envelope` | Kernel who-am-I (model must not invent) |
| GET | `/api/v1/economy/budget-gate/:pid` | Per-I cost cap |
| GET | `/api/v1/actionlog/export/otel` | Auditor trail (export ≠ SoT) |
| GET | `/api/v1/kernel/aios/infra` | Node + devices + fleet + verbs |
| GET | `/api/v1/kernel/aios/fleet` | Many `I` |
| GET | `/api/v1/kernel/aios/absorb` | How vLLM/Ollama/future enter |
| GET | `/api/v1/kernel/aios/cell/:pid` | One `I` operate card |
| GET | `/api/v1/kernel/aios/crossings` | Completion / syscall / world log |
| POST | `/api/v1/kernel/syscall` | WM / interrupt (**C9 charter-gated**) |
| POST | `/api/v1/kernel/aios/operate` | interrupt / retrieve / fleet / infra / **compensate** |
| POST | `/api/v1/intelligence/gateway/grant/revoke` | Undo world grant |
| POST | `/api/v1/intelligence/share-portals/close` | Close share pore |
| POST | `/api/v1/intelligence/council` | Human+root mint council (pairwise pores) |
| GET | `/api/v1/intelligence/council` | List (operator: all; `I`: memberships) |
| GET | `/api/v1/intelligence/council/:id` | Roster + μ cards (members only if header) |
| GET | `/api/v1/intelligence/council/:id/floor` | Hash-chained who-said-what |
| GET | `/api/v1/intelligence/council/inbox` | This `I`'s open tasks + recent floor (Talk also injects this) |
| GET | `/api/v1/intelligence/council/:id/tasks` | Named work with living owner `μ` |
| POST | `/api/v1/intelligence/council/:id/speak` | This `I` only; `kind=speak\|task\|ack\|done\|refuse\|handoff` |
| POST | `/api/v1/intelligence/council/:id/members` | Root adds an `I` |
| POST | `/api/v1/intelligence/council/:id/close` | Close pores; floor remains evidence |
| POST | `/api/v1/agents/:pid/kill-switch` | Stop this `I` |
| GET/POST | `/api/v1/scim/v2/Users` | Thin SCIM over user_store |
| GET | `/api/v1/compliance/eu-ai-act/inventory` | Art.9 living inventory |
| GET | `/api/v1/forensics/court-readiness` | Court checklist (never auto-green) |
| POST | `/v1/chat/completions` | Thinker absorb (unchanged) |
| POST | `/api/v1/settings/llms/link` | Device absorb (unchanged + `absorb` field) |

Kernel module: `platform/server/src/kernel/operating_layer.rs`.

---

## 8. Forbidden designs (look like OS, fail universality)

- Adapter crate per vendor in `kernel/` (`langgraph.rs`, `vllm.rs`, `ollama.rs`).  
- “LangGraph fleet” as the orchestrator (that is one BG on a higher-level `I`).  
- Shared brain / ambient `/k` for all agents.  
- GPU OS / CUDA scheduler as Connector core.  
- Mei token RR / logit context-switch as identity.  
- Publishing a new agent framework and calling it the kernel.

---

*Operating layer = manage + admit + WM + stop, vendor-blind. Apps keep their names. We never take them.*
