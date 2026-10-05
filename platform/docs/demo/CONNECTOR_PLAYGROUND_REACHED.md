# Connector playground — software reached (operator spine)

**Status:** Hosted product surface on **https://try.cnktros.com** (90‑minute tenant session)  
**Audience:** Operators, engineers, demos — what is *actually runnable* today, not a roadmap  
**Flagship story:** [BANK_OPS_PLAYGROUND.md](./BANK_OPS_PLAYGROUND.md)  
**45s pitch deck:** [POWER_DEMO_45S.md](./POWER_DEMO_45S.md) · [`power-demo-45s.html`](./power-demo-45s.html)  
**Explaining brief (PDF):** [CONNECTOR_EXPLAINING_BRIEF.md](./CONNECTOR_EXPLAINING_BRIEF.md) · [CONNECTOR_EXPLAINING_BRIEF.pdf](./CONNECTOR_EXPLAINING_BRIEF.pdf)

This document is the **reached** picture of Connector as operational software: intelligence proposes, Connector admits, the world changes only through PATE/ToolDispatch, and operators can **see** authority, exposure, and every step of the loop.

---

## One-line product

> A governed agent runtime with **Workbench** (Talk → Orders → Admit), **Expometer** (live cease/quarantine/world/LLM exposure), **Action Trail** (full-page loop timeline + manage), and **SpendCease** (admit is law after Cease) — demonstrated on a real BankOps ledger, not a cinematic reel.

---

## What you can run today

| Capability | What it does | Where |
|------------|--------------|--------|
| Hosted trial | Email → 90m tenant-isolated session | https://try.cnktros.com/trial |
| BankOps agent | Score / Hold / Decide / Ledger on a commercial book | Workbench Talk chips |
| Workbench | Proposals never auto-run; Admit = identity → DAL → PATE → ToolDispatch | `/run/workbench/:pid` |
| Expometer | Live verdict: active / ceased / quarantined / paused / egress; world grants; LLM stub vs linked | Talk + Control + Trail |
| Action Trail | Dedicated page (not a sidebar): journal + watch + activity; filter Orders/Evidence/Standing; Admit / Reject / Cease | `/run/trail/:pid?session=&focus=` |
| Admit refuse UI | Refusal opens a reason dialog (identity, cease, policy) — not a dead button | Workbench tool cards |
| SpendCease | Fence generation, void ctx_tok, reap; further admits refuse | Control · Trail · `POST /agents/:pid/cease` |
| Optional real LLM | Link tenant key for free-text Talk; chips work without a key | LLM connect on Workbench |
| Institutions | DevGuard / TraceTramp / WitnessCtl on the node — **not** the BankOps agent | Plugin consoles |

---

## Operator surfaces (UI map)

```text
/trial                         → session mint
/run                           → agents + Action Trail entry
/run/workbench/:pid?session=   → Operations Theater (journal + rails)
/run/trail/:pid?session=&focus= → Action Trail (full page)
/watch                         → fleet/kernel event planes
/fix                           → HITL / PATE Ask approvals
```

### Expometer (`GET /api/v1/agents/:pid/expometer`)

Single operator snapshot:

| Block | Fields |
|-------|--------|
| Authority | `verdict`, `admit` (LIVE / REFUSED_*), ceased, quarantined, paused, egress_isolated, generation, latest_cease |
| World | grant_count + grant addresses/effects (what the agent may touch after Admit) |
| LLM | mode: `simulation_stub` \| `linked_router` \| `unlinked`; inflight provider calls; burn remaining |
| Spend | ceiling burn / hint |

Honesty: after Cease/quarantine, **new** Admit hops refuse for that fence; cancel-tax on already-started provider work may remain.

### Action Trail (`/run/trail`)

- **Dedicated page** — journal links say “Open Evidence **trail** →” and navigate here (URL changes). They do **not** only flip a Workbench sidebar.
- Tabs: All · Orders · Evidence · Standing · HITL · Activity  
- Manage: Admit all pending · Reject all · Cease generation  
- Composes: Workbench journal + `/operator/watch/events` + agent activity + DAL snapshot + Expometer  

Deep links from Talk/Workbench:

| Focus | Meaning |
|-------|---------|
| `focus=orders` | Pending / proposal steps |
| `focus=evidence` | ToolDispatch, admission, `policy_denied`, PATE |
| `focus=standing` | System / charter / identity |
| `focus=hitl` | HITL held |

### Workbench loop (unchanged law)

```text
Talk → order proposals (Ring-1, never dispatch)
  → Admit → identity stack → DAL → PATE → ToolDispatch → receipt
  → next Talk
```

Refuse paths surface a **popup** with reason (e.g. identity incomplete when enforced, generation fenced, policy deny).

---

## BankOps — flagship real ops demo

Not Reel Mode. Tenant ledger on the node after Admit:

| Tool | Effect |
|------|--------|
| `bank_score_tx` | Risk 0–100 + recommendation (`WIRE-CY-47500`) |
| `bank_hold_funds` | Available ↓, hold opens |
| `bank_decide` | APPROVE / DECLINE / REVIEW |
| `bank_ledger` | Balances / holds / last decision |

**Authority beat:** Cease mid-ops → continue / re-Admit → Expometer `CEASED` + admit refused.

Full click-path: [BANK_OPS_PLAYGROUND.md](./BANK_OPS_PLAYGROUND.md).

---

## API surface (operator-relevant)

| Method | Path | Role |
|--------|------|------|
| GET | `/api/v1/agents/:pid/expometer` | Authority + world + LLM exposure |
| POST | `/api/v1/agents/:pid/cease` | SpendCease kernel stop |
| GET | `/api/v1/spend/burn/:pid` | Live burn meter |
| GET | `/api/v1/spend/cease/latest/:pid` | Latest CeaseReceipt |
| GET/POST | `/api/v1/agents/:pid/workbench/sessions…` | Journal, turn, admit, cancel |
| GET | `/api/v1/operator/watch/events` | Kernel/AAPI planes for Trail |
| GET | `/api/v1/agents/:pid/activity` | Activity slice |
| GET | `/api/v1/dal/:run_id` | DAL loop snapshot |

Schemas / deep theory: [SPEND_CEASE.md](../arch/SPEND_CEASE.md) · [AIPSPRT_SIG.md](../arch/AIPSPRT_SIG.md) · [LLM_WORKBENCH.md](../arch/LLM_WORKBENCH.md).

---

## Honesty bounds (do not overclaim)

| Claim | Truth |
|-------|--------|
| FedWire / core banking | **No** — playground tenant ledger |
| Court-grade attestation | **No** on hosted trial (`playground_demo` / lab HMAC) |
| Isolate DROP | Grant-list on Fly when `KERNEL_ENFORCE=0` |
| Cease | Stops **new** admits for the fenced generation; cancel-tax may remain |
| World grants empty | ≠ “no tools” if MCP lane minted separately |
| Institutions | Node plugins; they are not BankOps |

---

## How to verify (5 minutes)

1. https://try.cnktros.com/trial → session.  
2. `/run/workbench` → **BankOps** → Score wire → **Admit**.  
3. Confirm Expometer `active` / `admit · LIVE`.  
4. Click **Open Evidence trail →** → URL is `/run/trail/…?focus=evidence` with cyan “Dedicated page” banner.  
5. **Cease** → Expometer `CEASED` → Score/continue again → refuse dialog / trail evidence.  

Redeploy:

```bash
./scripts/build-and-deploy.sh
```

---

## Related architecture

| Doc | Topic |
|-----|--------|
| [LLM_WORKBENCH.md](../arch/LLM_WORKBENCH.md) | Workbench as orchestrator (not chat) |
| [SPEND_CEASE.md](../arch/SPEND_CEASE.md) | Ceilings, Cease, burn meter |
| [AIPSPRT_SIG.md](../arch/AIPSPRT_SIG.md) | AiPassport leave-behind |
| [CONNECTOR_OPERATIONAL_SOFTWARE.md](../arch/CONNECTOR_OPERATIONAL_SOFTWARE.md) | Live ops map (kernel spine) |
| [CONNECTOR_PRODUCT_PROMISE.md](../arch/CONNECTOR_PRODUCT_PROMISE.md) | What we guarantee / do not |
| [SOAS.md](../arch/SOAS.md) | Playground grade honesty |

---

*Reached build family: hosted `connector-playground` on Fly · UI Action Trail + Expometer + Admit refuse · BankOps MCP tools.*
