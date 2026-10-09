# AIOS — what we have achieved (2026-08-13)

**Spine unchanged:** [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) §0 (L0–L8).  
**Ontology:** [INTELLIGENCE_MATRIX_FUNDAMENTAL.md](INTELLIGENCE_MATRIX_FUNDAMENTAL.md) — CPU ≠ GPU ≠ intelligence. Mei LLM-as-CPU **rejected**.  
**Architecture in code:** `platform/server/src/kernel/operating_layer.rs` · [AIOS_OPERATING_LAYER.md](AIOS_OPERATING_LAYER.md)  
**Claim JSON:** `GET /api/v1/kernel/aios/claim-readiness` · `connectorctl iia aios`

---

## Claim (honest)

| Bar | Status |
|-----|--------|
| **V1 buyer Agent OS** | **Shipped.** Syscall ABI (C9-gated), WM files, stop-this-`I`, kill-switch, compensating undo, Gartner map, infra plane. |
| **V2 Albus complete** | **Not claimed.** CD-9 / Honor / GPU OS out. Undo is compensating (now in WM). |
| Court-green / SOC2 / Honor / GPU OS | **Must not say.** |

---

## Ontology locked (research → kernel)

- Intelligence is Newell **knowledge level** (1982), not a CPU.  
- Node is Albus **SP · WM · VJ · BG-socket** (1991/1994). BG is empty; frameworks are apps.  
- vLLM / Ollama / OpenAI are **devices** (computing engine). Sharing them is disk multiplex.  
- LangGraph / Crew / MCP / Letta **do what they do**. Connector charters `I`, admits `A`, keeps WM, stops `I`.

Code: `operating_layer.rs`, `intelligence_matrix.rs`, `aios.rs`. Kernel has **no** LangGraph / vLLM / Ollama types.

---

## Shipped in this drop (fold, not a rewrite)

### Three sockets (vendor-blind)

| Socket | Path | In code |
|--------|------|---------|
| Completion | `POST /v1/chat/completions` | Talk `with_interrupt` logs `llm.complete` |
| Syscall | `POST /api/v1/kernel/syscall` | `aios::dispatch` |
| World | CONP + grant + portal | `world_gateway` + CONP record crossings |

### Memory / RAG / knowledge

- `/m/core` `/m/recall` `/k` `/k/archival` on the pid NS FS.  
- Syscalls: `memory.core.*`, `recall.*`, `archival.*`, `memory.knowledge.search`, `wm.retrieve`.  
- Talk injects core + WM prompt. Kernel **pages** core overflow into archival; second turn retrieves archival via `wm.retrieve`. VAC `[MEM-N]` RAG **unchanged** when `/m`/`/k` miss.  
- Knowledge search can read **portal `/k`** (share contract only — no ambient A↔B).

### Fleet / concurrency / infra plane

- Many cells in parallel. Per-`I` inflight cap **off** unless `CONNECTOR_I_INFLIGHT` is set.  
- `GET /kernel/aios/fleet` — cells, inflight, grants, portals, WM ready.  
- `GET /kernel/aios/infra` — node + devices + fleet + crossings + admit + operate verbs.  
- `GET /kernel/aios/cell/:pid` — one `I` operate card (ACS stays character).  
- `POST /kernel/aios/operate` — interrupt / retrieve / fleet / infra. **Stop** stays `POST /agents/:pid/kill-switch`.  
- ACS includes `operate` (inflight, WM, kill URL).

### External AI world (now and later)

- `GET /kernel/aios/absorb` — device / thinker / resource / memory-client. Future vendors use the **same rows**.  
- `llm link` still vault + router; response adds `absorb` (vLLM = Ollama = OpenAI = device URL).  
- Thinkers keep `OPENAI_BASE_URL=/v1` (docs/99). Runnable cell client: `docs/cell_sdk.py`.

### Stop / value

- `llm.interrupt` + kill-switch (Gartner 5-min clock). Partial text in `/m/core`. Not logit CPU dump.  
- **Compensate:** `POST /kernel/aios/operate` `op=compensate` — revoke grant / close portal / deny tool. Same verbs as HTTP `grant/revoke` and `share-portals/close`.  
- Root/Cone → Gartner L3; App → L4 map (undo is compensating, not world rewind).  
- HTTP syscalls are **charter-gated** (U6). Talk inject still writes WM as SP.  
- **U15:** VJ on when `CONNECTOR_ENV` is production-like. First-run without license stays lab. `CONNECTOR_LAB=1` names lab. `connectorctl harden` still forces flags.  
- **U16:** Fleet cells carry `μ` (0xCD). Infra `topology.product_sot` is `single_node` until `CONNECTOR_MESH_FABRIC=1` and peers≥2 (same soak as mesh).

### Council (root-minted floor, μ identity)

Isolated `I`s do not share a brain. Human+root mints a council → pairwise pores + hash-chained floor. **Talk injects the desk** so Crew/LangGraph on `/v1` see members, open tasks, and who said what. Kinds: `speak` / `task` (named assignee `I`) / `ack` / `done` / `refuse` / `handoff`. Each task has a living owner `μ`. Header speaker must be that `I`. This is the buyer “many agents, who did what” bar Crew/AutoGen skip (they share one process and invent names). Not LangGraph. Not ambient `/k`.

### Bake-off already in code (surface, don’t rebuild)

Market wants: kernel who-am-I, isolation by default, pid×address grants, Gartner L1–L4, 5-min kill, compensating undo, budget caps, one auditor trail, court fail-closed, Art.9 inventory, SCIM, sit-beneath `/v1`, memory that outlives a graph. Frameworks skip or fake these. They are on `GET /kernel/aios/claim-readiness` → `buyer_surface` and `connectorctl iia aios`.

---

## Operator loop (what you run)

1. Charter `I` — `POST /intelligence/apply`  
2. Link device — `POST /settings/llms/link` (vLLM / Ollama / OpenAI / …)  
3. Point app at `/v1`  
4. Grant world / bind MCP  
5. Runtime: admit + trace; interrupt or kill **this `I`**  
6. Swap engine or thinker tomorrow — `μ` and ACS stay  

`connectorctl iia aios` prints claim + infra (mode, llm wired, device count, fleet size).

---

## Still open (do not over-claim)

| Item | Honesty |
|------|---------|
| CD-9 court-green | `GET /forensics/court-readiness` — human+counsel. Never from claim JSON |
| Honor / GPU OS | Out of product (`claim.enterprise.honor_os/gpu_os = false`) |
| Live multi-node fabric | `single_node` until soak + `CONNECTOR_MESH_FABRIC=1` |
| World rewind | Compensating only (WM records the compensate line) |

SCIM and Art.9 inventory are **in code** (thin fold). SSO default install may still be API key / `dev-token`.

**Do not build:** Mei token RR, `VllmScheduler` in `kernel/`, LangGraph as a Connector process.

Leftover how-to: [AIOS_UNIVERSALITY.md](AIOS_UNIVERSALITY.md). Claim wording: [AIOS_CLAIM_PLAN.md](AIOS_CLAIM_PLAN.md).
