# LLM Workbench — Connector orchestrator (not chat)

> Companion: [LLM_PRINCIPAL_PROJECTION.md](./LLM_PRINCIPAL_PROJECTION.md) · [LLM_CONTEXT_BROKER.md](./LLM_CONTEXT_BROKER.md) · [CONNECTOR_SVF.md](./CONNECTOR_SVF.md)

## Product claim

**Universal** means one Workbench hosts any Connector principal and composes **registered** capabilities, institutions, tools, evidence, and world bindings for that principal.

It does **not** mean Connector invents browser, IDE, terminal-stream, or domain adapters. Absent worlds appear only as `unsupported_here` in vitals/posture — never as fake product tabs.

```text
INTELLIGENCE ≠ IDENTITY ≠ AUTHORITY ≠ EXECUTION ≠ EVIDENCE

Workbench = Project(Talk) → Orders → Admit(PATE) → ToolDispatch → Receipt → next Talk
```

The operator surface is **Workbench**, not chat. The model reasons freely.
Connector speaks as the principal, admits effects, and proves what ran.

## API façade

| Method | Path | Behavior |
|--------|------|----------|
| POST | `/api/v1/agents/:pid/workbench/sessions` | Create session journal |
| GET | `/api/v1/agents/:pid/workbench/sessions` | List |
| GET | `/api/v1/agents/:pid/workbench/sessions/:sid` | Snapshot + **vitals** |
| POST | `…/turn` | Governed Talk + projection; proposals → **orders** (never dispatch) |
| POST | `…/admit` | Identity stack → DAL → PATE → Connector ToolDispatch → continue Talk |
| POST | `…/cancel-orders` | Void pending orders |
| POST | `…/hitl-resume` | After FIX approve: re-queue held Ask orders for Admit |
| POST | `…/hitl-deny` | Cancel held Ask orders; no ToolDispatch |
| GET | `/api/v1/workbench/posture` | Honesty surface |

`POST /agents/:pid/completions` and `POST /dal/:run_id/turn` stay as lower-level APIs.

## Order pipe (`connector.order.v1`)

Ring-1 Workbench does **not** send native OpenAI `tools` without CPO. Instead:

1. Consult injects an order-proposal system block listing **registered MCP tool names**.
2. The model may return a fenced `connector.order.v1` JSON block and/or native `tool_calls` if the gateway surfaces them.
3. Server parses proposals, **filters to registered tools only**, validates MCP `input_schema.required` keys, and mints pending orders.
4. Unknown tool names / schema failures are journaled; they never mint orders and never dispatch.

Admit remains the only effect path.

## HITL Ask hold / resume

When PATE returns Ask:

- Orders move to `held_order_ids` (not pending Admit).
- Session stores `hitl_request_id` for FIX correlation.
- **hitl-resume** re-queues held orders for Admit and marks HITL resolved.
- **hitl-deny** cancels held orders without ToolDispatch.

## Session journal (event kinds)

`user` · `assistant` (projected) · `order` · `admission` · `tool` · `hitl` · `system`

B15 chat threads are **not** the Workbench journal.

Vitals (duty strip) also carry inexpensive posture summaries:

- `mission` / `dal` — mission_id, run phase, budgets (when a DAL run exists)
- `context` — pressure_pct when tracked
- `budget` — economy budget-gate remaining / exceeded
- `progeny` — direct child count
- deep links to context, budget gate, FIX, capabilities, proof, progeny, charter

Order minting validates MCP `input_schema.required` keys before an order is created.

## UI

| Surface | Role |
|---------|------|
| Theater `/run/workbench/:pid?session=` | Duty strip (mission/DAL/ctx/budget · Quarantine/Kill) · Needs you / Idle sessions · agent tree · journal · rails |
| Drawer Talk | Same consult + shared session focus (`WorkbenchFocusBus`) + **Expometer** strip |
| **Action Trail** `/run/trail/:pid?session=&focus=` | **Dedicated page** — journal+watch+activity timeline; Orders/Evidence/Standing tabs; Admit/Reject/Cease. Journal “Open … trail →” navigates here (URL change), not only a sidebar chip |
| Expometer | Live cease/quarantine/world grants/LLM mode — Talk, Control, Trail (`GET /agents/:pid/expometer`) |
| Orders / HITL rails | Per-order Admit/Reject; Approve→Resume chains FIX to held orders |
| Mission / Context / Evidence rails | Vitals + mission steps / pressure / receipt digests + Prove (still on Theater) |
| Caps / DevGuard / Standing | Registry truth; DevGuard only when installed; identity pillars |

Human loop: Consulting status · starter chips · sticky composer · **refuse Admit → reason popup** · journal cards open **Action Trail** with `focus=`.

Reached product map: [CONNECTOR_PLAYGROUND_REACHED.md](../demo/CONNECTOR_PLAYGROUND_REACHED.md) · BankOps: [BANK_OPS_PLAYGROUND.md](../demo/BANK_OPS_PLAYGROUND.md).

## Acceptance checklist

1. Select/create session (Needs you vs Idle).
2. Chat → projected reply; proposals mint Orders (no dispatch).
3. Admit → DAL/PATE/ToolDispatch once; receipt in journal.
4. PATE Ask → held → **FIX approve** → hitl-resume → Admit; Resume without FIX returns `fix_approve_required`.
5. Caps rail lists installed vs not; DevGuard / WitnessCtl tabs only when installed.
6. Identity incomplete disables Admit with refusal card; Kill requires confirm.
7. Capability ≠ authority called out; lab HMAC never painted as court.

## Honesty

- Turn never executes tools.
- Admit never skips PATE / identity stack / effect exclusivity.
- Lab HMAC is never painted as court.
- Workbench composes what is installed; it does not cosplay Cursor/browser/terminal when those runtimes are absent.
