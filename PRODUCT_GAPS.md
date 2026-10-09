# Product gaps — “own contract + any LLM + feels like an OS”

**Date:** 2026-08-13  
**Vision (user):** Operators write their own contracts / HITL / full config; link any LLM with **one CLI command** or **paste key in UI**; product feels like an **OS** — real security, operations, execution.  
**Architecture SoT:** [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) **v3** — kernel → ACS / 3 layers / world / share. Picture: **§0**.  
**Research:** [EXECUTION_SUBSTRATE_REPORT.md](EXECUTION_SUBSTRATE_REPORT.md) · [PARTIAL_TO_TOP_GRADE_RESEARCH.md](PARTIAL_TO_TOP_GRADE_RESEARCH.md) · [CONSCIOUS_PHYSICS_BOUNDED_INTELLIGENCE.md](CONSCIOUS_PHYSICS_BOUNDED_INTELLIGENCE.md)  
**Companions:** [IIA_STATUS_REPORT.md](IIA_STATUS_REPORT.md) · [BACKEND_IIA_COMPLETION_BACKLOG.md](BACKEND_IIA_COMPLETION_BACKLOG.md) · [UI_IIA_ENHANCEMENT_PLAN.md](UI_IIA_ENHANCEMENT_PLAN.md)  
**Market AIOS bar:** [AIOS_MARKET_GAP.md](AIOS_MARKET_GAP.md) — what buyers/researchers accept as an OS vs what we still lack.  
**Reach the claim:** [AIOS_CLAIM_PLAN.md](AIOS_CLAIM_PLAN.md) · leftover U1–U16: [AIOS_UNIVERSALITY.md](AIOS_UNIVERSALITY.md)

---

## Verdict

| Pillar | Status |
|--------|--------|
| **Write own charter (cage + HITL + forensic + memory + grants)** | **Done** — API + Charter Studio / 5-min apply / workbench |
| **Full config (tools, clearance, budgets, HIPAA)** | **Studio S7/S8 shipped**; HIPAA/BAA still org-legal; rich multi-grant UX thin |
| **Link any LLM in one command / paste in UI** | **Shipped (DI-1)** — Settings paste + `connectorctl llm link` + vault + hot-wire `LlmRouter` |
| **Feels like secured OS** | **Membrane in code** — ACS, NS FS, 3 layers, world grants, share portals, light_ns. Remaining is **ops honesty**: court only with WC+CFNI, mesh only with soak. Lab-default-off still true. |

---

## 1. What already works

### Charter / config you can write today

| Area | API | UI |
|------|-----|-----|
| Contract cage (purpose, caps, denied, FS, network, receipt) | `PATCH /agents/:pid/contract` | Charter Studio S2 + workbench Charter |
| HITL policy + forensic + name/acume + memory types + KB | `POST /agents/:pid/setup` | Studio S1/S3–S5 |
| Grants (common spaces) | setup + `/multiagent/grant\|revoke` | Charter + Manage (justification + portal) |
| World grant (pid × address) | `/intelligence/gateway/*` | Setup / Power · world |
| Share contract → portal | `/intelligence/share-contract` | Manage |
| ACS + NS FS | `/runtime/acs/:pid` · `/runtime/nsfs/:pid` | Workbench ACS strip |
| HITL queue | `/agents/:pid/hitl*` | Manage |
| Activate / compliance / WC align | `POST …/activate` | Studio S10–S11 |
| Talk as principal | `POST …/completions` | Talk tab |
| Clearance / tools / budget | **API yes** | Charter Studio S7/S8 |

### LLM today (works, but ops-heavy)

```bash
# Closest “one shot” — first boot only; restart required
connectorctl init --llm-key sk-...
# or
export CONNECTOR_LLM_PROVIDER=openai   # openrouter|ollama|anthropic|…
export CONNECTOR_LLM_MODEL=gpt-4o
export CONNECTOR_LLM_API_KEY=sk-...
export CONNECTOR_LLM_ENDPOINT=…        # ollama / azure / custom
# restart connector-platform
```

Engine already supports many providers (`openai`, `anthropic`, `openrouter`, `ollama`, `groq`, …) in `oss/connector/crates/connector-engine/src/llm.rs`.

---

## 2. Critical lacks (priority order)

### P0 — LLM: paste-in-UI + live one-command — **Done (DI-1)**

| Piece | Status |
|-------|--------|
| `POST /settings/llms/link` | Vault + hot-wire `LlmRouter` (keys never in cage) |
| `GET /settings/llms/status` | Wired/provider/model for UI |
| Settings → LLM tab | Paste form + ping |
| `connectorctl llm link / status` | One-command link |
| Stub vs live | Live router wins over `CONNECTOR_LLM_STUB` |
| Per-agent / BYOK | Still node router (acceptable for DI-1) |

---

### P1 — Config UI incomplete vs “write all as needed”

| Missing Studio / workbench | API exists? | Feel |
|----------------------------|-------------|------|
| **S7 Tools / clearance** | Yes | **Studio S7 shipped** (clearance + scoped bind) |
| **S8 Budgets / HIPAA risk** | Yes | **Studio S8 token budget shipped**; HIPAA/BAA still org legal |
| Rich grants (`writable_by`, multi-grant, expiry) | Yes | Charter writes one path |
| `use_case_def` / philosophy | Yes | API-only |
| Manage grant/revoke buttons | Yes | **Manage grant/revoke shipped** (`/multiagent/grant\|revoke`) |

**Ship target:** Charter Studio S7 + S8 + Manage grant actions; keep deep plugin consoles for WC/TT.

---

### P2 — “Feels like an OS” — remaining is ops, not TG-0…6

TG-0…6 + ACS / 3 layers / world grants / share portals are **shipped**. What still breaks the *claim* (not the API):

| Lack | Why it still matters | Evidence |
|------|----------------------|----------|
| **Hardening lab-default-off** | Security is opt-in until you enable the preset | `connector_profile.rs`, LAB banner |
| **Host Active = systemd_dropin honesty** | Not silent eBPF OS | `kernel_host.rs`, kerneld |
| **Landlock / matrix soft-fail in lab** | Cage can look applied when host cut didn’t | `applied_truth` on posture |
| **Court / mesh soak** | APIs exist; live WC+CFNI / multi-cell not claimed Done | `GET /forensics/court-readiness`, `make l5-mesh-soak` |
| **WATCH depth** | Crumbs shipped; richer event lens still thinner | `surfaces/watch.rs` |

**Do not rebuild:** digest HITL, journals, A2A terminals, DecisionTraces, LAB banner, Control Start, ACS, world gateway, share portals.

---

### P3 — Polish / honesty

| Item | Gap |
|------|-----|
| Stale docs still say “no PATCH contract” | `UI_IIA_ENHANCEMENT_PLAN.md` leftovers |
| ~~OpenAI RAG inject parity with Anthropic~~ | **Shipped** — `inject_connector_rag` on stream + non-stream OpenAI gateway |
| Forensic package download button | Evidence still JSON-heavy (download API exists; UX polish optional) |
| ~~Two-agent smoke gate~~ | **Shipped** — `connectorctl iia smoke` / `platform/scripts/iia-two-agent-smoke.sh` |
| Court e2e (WC + CFNI + signed package) | Checklist shipped; live soak not claimed Done |

---

## 3. Gap map (vision → status)

```text
Write own contract / HITL / cage     ███████████████ ~98%  (Studio + 5-min apply + ACS)
Call connector + link any LLM         █████████████░  ~92%  (paste + llm link; BYOK per-agent later)
Feel like OS security                 ██████████████  ~96%  (3 layers + world grants + share portals + light_ns)
Feel like OS operations               ████████████░░  ~85%  (MONITOR posture/fleet/geo; WATCH crumbs)
Feel like OS execution                ██████████████  ~96%  (Talk+C9+fabric+cage+Cone/App fold)
Distributed fabric / court soak       ██████████░░░░  ~70%  (APIs shipped; multi-cell + WC/CFNI ops soak)
```

---

## 4. Recommended build order

**DI-0…DI-5 and TG-0…6 are shipped.** Remaining order is ops, not another wave. Historical DI list kept below for orientation.

### DI-0 / Sprint C start — intelligence OS language

1. LAB MODE banner when Ring-1/QPR/DockLock/HITL off.  
2. WATCH/MONITOR crumbs: principal · quantum · intelligence mark (not PID).

### DI-1 / Sprint A — “paste key → Talk” (unblocks everyone)

1. Settings LLM form → vault + hot-reload `LlmRouter` (**keys never in cage**).  
2. `connectorctl llm link …` (same backend).  
3. Live provider ping + gateway status in UI.

### DI-2 / Sprint B — “write all config”

1. Charter Studio **S7** (tools bind + clearance).  
2. Charter Studio **S8** (budget + HIPAA warning).  
3. Manage: grant / revoke actions.  
4. Charter checks on remaining effect paths (C9).

### DI-3 / Sprint C finish — “OS feel” for intelligence

1. One-click enable hardening preset.  
2. MONITOR: cage/matrix applied vs soft-fail, continuity, deny rate.  
3. Control start + real logs.  
4. Credential proxy for tool secrets (NVIDIA/healthcare pattern).

### DI-4 / DI-5 — distributed fabric + evidence

1. **Fleet + fabric + geo + cells soak honesty** shipped; multi-cell **scheduler** still ops (`make l5-mesh-soak`).  
2. **Package UX + budget/anomaly gates + court-readiness checklist** shipped (`GET /forensics/court-readiness`); live WC+CFNI ops soak still not claimed Done.  
3. **L7 app allowlist** shipped (`CONNECTOR_L7_EGRESS_PROXY`) — honesty: not a full transparent proxy.

---

## 5. Explicit non-goals (keep)

- Purpose tags as a ban on topics (identity only).  
- Claiming court-grade from a green checkbox.  
- Claiming Host Active = eBPF without real BPF apply.  
- Ambient shell / modify_contract open by default.

---

## 6. One-page operator truth (today)

| Goal | Do this now |
|------|-------------|
| Write contract / HITL | `/agents/:pid/charter` or `POST /intelligence/apply` |
| Talk | Workbench Talk (after LLM env set) |
| Link LLM | Settings paste **or** `connectorctl llm link …` (no restart) |
| World access | Setup / Power · world — this pid × this address + kernel root |
| Share A↔B | Manage sharing contract (human+root) → portal |
| ACS / isolation | Workbench ACS strip · `GET /runtime/acs/:pid` |
| Tools / clearance / budget | Charter Studio S7/S8 · Manage grants · `/economy/budget-gate` |
| Hardened OS posture | LAB banner → **Enable intelligence hardening** / `connectorctl harden` |
| Evidence | Evidence tab + `/plugins/witnessctl` · `/plugins/tracetramp` |

---

*This is the living “where we lack” list. Membrane is in code (plan §0). Flip remaining items only when ops soaks are real — never claim court / SIL / silent MicroVM.*
