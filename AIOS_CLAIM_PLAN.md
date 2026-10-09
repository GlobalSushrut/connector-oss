# AIOS claim plan — fold, don’t rewrite

**Date:** 2026-08-13  
**Rule:** never rewrite the spine ([DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) §0). Every gap closes by **naming and wiring** what already exists.  
**Market bar:** [AIOS_MARKET_GAP.md](AIOS_MARKET_GAP.md)  
**Leftover topics (how to reach):** [AIOS_UNIVERSALITY.md](AIOS_UNIVERSALITY.md) — sit beneath vLLM/LangGraph; don’t wrap them.  
**Ontology:** [INTELLIGENCE_MATRIX_FUNDAMENTAL.md](INTELLIGENCE_MATRIX_FUNDAMENTAL.md)  
**Architecture:** [AIOS_OPERATING_LAYER.md](AIOS_OPERATING_LAYER.md) — manage + operate, vendor-blind.  
**Achieved till now:** [AIOS_STATUS.md](AIOS_STATUS.md)  
**Follow:** `GET /api/v1/kernel/aios/claim-readiness` · `GET /api/v1/kernel/aios/infra` · `connectorctl iia aios`

We already have the hard part (access, isolation, world grants, evidence). **Wave 0 ABI + infra plane are in code.** V1 buyer OS may be said. V2 Albus-complete may not.

---

## Two bars (do not mix)

| Bar | What “OS” means | When we may say it |
|-----|-----------------|--------------------|
| **V1 — buyer Agent OS** | Shared services that outlive one workflow: syscall ABI, memory hierarchy, interrupt, kill in 5 min, L1–L4 map, one audit trail | `claim.v1_buyer_os == true` |
| **V2 — Albus matrix complete** | Every `I` is SP·WM·VJ·BG; crossings admitted; WM SoT; sit-beneath vendors. **Not** Mei LLM-as-CPU. | `claim.v2_academic_aios == true` (later; rename in JSON when we flip) |

Honor / CosmOS device OS is **out**. Infrastructure GPU OS is **out** of product core (partner).

**Do not flip V2 from a checkbox.** V1 is the claim we reach on this spine.

---

## Map: market gap → existing artifact → fold

| ID | Gap | Already have | Fold into |
|----|-----|--------------|-----------|
| Access | — | 3 layers, ACS, NS FS, grants, portals | Keep. Map to Gartner L1–L4. |
| **K1** | Device / crossing multiplex (not LLM-CPU RR) | VAC FIFO/WRR/CFS request queue; plugin tiers | Keep as hardware. Log crossings. **Do not** token-RR. |
| **K2** | Stop this `I` thinking (VJ, not CPU switch) | Talk request/response; pause/kill | Cooperative interrupt + partial text on `/m/core`. Logit snapshot is a **device** parameter if a local engine has it — not OS identity. |
| **K3** | Letta memory OS | `/m` `/k` + VAC types + RAG | `/m/core` RAM, `/m/recall` log, `/k/archival` cold — agent syscalls |
| **K4** | Public SDK | HTTP + `.cpkg` | Syscall ABI **is** the SDK. Thin clients later. |
| **K5** | Framework lock-in | OpenAI gateway | Frameworks stay in **Albus BG (app)**. Kernel is SP·WM·VJ. [INTELLIGENCE_MATRIX_FUNDAMENTAL.md](INTELLIGENCE_MATRIX_FUNDAMENTAL.md) |
| **G1** | L4 kill + rollback | `POST /agents/:pid/kill`, pause, freeze | Kill-switch SLA + interrupt in-flight Talk. Rollback = revoke grant / close portal / disable tools (compensating). |
| **I1** | SCIM | OIDC + user_store | **Shipped thin** `GET/POST /scim/v2/Users` |
| **O2** | Court default-on | CD checklist | Separate ops path. Not this plan. |

---

## Wave 0 — kernel ABI (**shipped**)

`connectorctl iia aios` prints V1 modules; `claim.v1_buyer_os == true`.

1. `kernel/aios.rs` + `kernel/operating_layer.rs` — syscall catalog, WM trees, crossings, infra plane, absorb catalog.  
2. `POST /api/v1/kernel/syscall` — agents do not touch primitives.  
3. NS FS: `/m/core`, `/m/recall`, `/k/archival` created with the pid tree.  
4. Talk: `llm.complete` logged; `llm.interrupt` cancels `complete()`; partial on `/m/core`. **Not** a CPU context switch.  
5. `POST /agents/:pid/kill-switch` — interrupt + existing kill; elapsed_ms.  
6. Admission → Gartner: Root/Cone = L3; App = L4 (kill required). Undo = compensating.  

## Wave 1 — operating plane (**shipped, fold**)

Does **not** replace list_agents, ACS, llm link, or VAC RAG.

- `GET /kernel/aios/infra` · `/fleet` · `/absorb` · `/cell/:pid` · `/crossings`  
- `POST /kernel/aios/operate` — interrupt / retrieve / fleet / infra  
- `wm.retrieve` + `memory.knowledge.search` (portal `/k` only with share contract)  
- Talk prepends WM SoT when `/m`/`/k` hit; VAC `[MEM-N]` block **unchanged** otherwise  
- Albus level labels on existing clocks; ACS `operate` block  
- `llm link` returns device absorb (vLLM = Ollama = OpenAI)  

## Wave 2 — close leftover gaps (**shipped, fold**)

- HTTP `POST /kernel/syscall` is **C9** (`require_contract_action`). Portal `/k` on retrieve when state is present.  
- Notebook execute bound to an `I` is charter-gated. MCP invoke logs a **world** crossing.  
- Compensate: `operate op=compensate` + `POST /intelligence/gateway/grant/revoke` + `POST /intelligence/share-portals/close` + deny tool.  
- Cell SDK: [docs/99-gateway-sdk-examples.md](docs/99-gateway-sdk-examples.md) + [`docs/cell_sdk.py`](docs/cell_sdk.py).  

## Wave 3 — leftover U1/U15/U16 (**shipped, fold**)

- Kernel pages core overflow into archival; Talk retrieve includes archival.  
- Production-like `CONNECTOR_ENV` applies VJ hardening; lab is `CONNECTOR_PRESET=local` / `CONNECTOR_LAB=1`.  
- Fleet cells include `μ`; infra `topology` uses the same mesh SoT (`single_node` until soak + flag).  

## Wave 4 — enterprise leftovers (**shipped, fold**)

- Thin SCIM 2.0 over `user_store` (`/api/v1/scim/v2/Users`). OIDC remains SSO.  
- Art.9 living inventory: `GET /compliance/eu-ai-act/inventory`.  
- Court stays `GET /forensics/court-readiness` — claim JSON **never** says court-green.  
- Compensate appends a WM recall line. WM tools: MCP bridge `wm` + syscall name, behind `admit_tool`.  
- Honor / GPU OS remain `false` / out of product.  

## Still not claimed

CD-9 human+counsel. Honor Agentic OS. Infrastructure GPU OS. World rewind. Live mesh fabric until soak flag.

Do **not** add vLLM/LangGraph types to the kernel. Do **not** build Mei-style generation RR.

---

## Honesty

| May say after Wave 0–1 | Must not say |
|------------------------|--------------|
| Governed intelligence kernel (V1): syscalls, WM files, stop-this-`I`, kill-switch, infra plane | Mei et al. AIOS / LLM-as-CPU / 2.1× serving / logit context switch |
| We sit beneath vLLM/Ollama/LangGraph; they are devices or thinkers | We *are* vLLM / we *are* LangGraph |
| VJ interrupt of a completion (text partial in WM) | The LLM is a CPU; we time-slice thought |
| Memory OS files the agent owns | We are Letta |
| Kill in seconds on this node | Certified L4 / SOC2 / court-green |

CPM still applies: which blanket, was the crossing admitted, is it traced?
