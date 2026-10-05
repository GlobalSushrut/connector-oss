# BankOps playground demo (real operations, not Reel Mode)

**Product reached (full surface):** [CONNECTOR_PLAYGROUND_REACHED.md](./CONNECTOR_PLAYGROUND_REACHED.md)  
**45s explain deck:** [POWER_DEMO_45S.md](./POWER_DEMO_45S.md) · open [`power-demo-45s.html`](./power-demo-45s.html)

Hosted at **https://try.cnktros.com** — 90-minute session, real Connector Workbench, optional real LLM via link.

## Story

A commercial book sees a **$47,500 Cayman wire** (`WIRE-CY-47500`). BankOps proposes tools; **you Admit**. Holds and decisions mutate a **tenant ledger** on the node. That is the product: intelligence proposes, Connector admits, ledger changes.

Then show authority: **Cease** mid-ops → type **continue** → **admit refused** (reason popup + Expometer `CEASED`).

## Tools (after Admit / PATE)

| Tool | Effect |
|------|--------|
| `bank_score_tx` | Risk score 0–100 + recommendation |
| `bank_hold_funds` | Deducts available, opens hold on ledger |
| `bank_decide` | APPROVE / DECLINE / REVIEW |
| `bank_ledger` | Inspect balances / holds / last decision |

Also: Isolate, Prove, Stop (Workbench cancel — not SpendCease).

## Operator path (no cinematic UI)

1. Open https://try.cnktros.com/trial → email → session.
2. Link a real LLM key (Talk free-text). Chips work without a key.
3. Workbench → Talk on **BankOps**.
4. Watch the **Expometer** (Talk + Control): verdict `active` / `ceased` / `quarantined`, admit line, world grants, LLM mode (`simulation_stub` vs `linked_router`).
5. Open **Action Trail** — click **Open Evidence trail →** (or `/run/trail/{pid}?session=&focus=evidence`). This is a **dedicated page** (cyan banner), not the Workbench sidebar.
6. **Score wire** → Admit → see risk score receipt (refuse → reason popup if blocked).
7. **Hold funds** → Admit → ledger `held_usd` rises.
8. Optional: free-text Talk (“score then recommend hold”) with linked LLM.
9. **Control → Cease (SpendCease)** or Cease on Action Trail.
10. Expometer / Trail flip to **CEASED** / `admit · REFUSED_GENERATION_FENCED`. Send **continue** or **Hold funds** again → expect refuse.
11. **Ledger** / **Prove** / Evidence trail tab to show evidence.

APIs: `GET /api/v1/agents/{pid}/expometer` · Trail UI: `/run/trail/{pid}?session=…&focus=…` · Cease: `POST /api/v1/agents/{pid}/cease`.

## Honesty

- Ledger is playground tenant store — **not** FedWire / core banking.
- Isolate DROP is grant-list on Fly (`KERNEL_ENFORCE=0`).
- Cease stops **new admits** for the fenced generation; cancel-tax on already-started provider work may remain.
- Expometer world grants = addresses this agent may touch after Admit; empty ≠ no MCP tools if the lane minted separately.
- Hosted grade is `playground_demo` — never court attestation.

## Redeploy

```bash
./scripts/build-and-deploy.sh
```
