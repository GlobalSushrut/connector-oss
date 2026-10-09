# AAPI Behavior Runtime (Effect-Field)

**Status:** Implemented substrate surface  
**Parent:** [DYNAMIC_INTELLIGENCE_MANIFOLD.md](DYNAMIC_INTELLIGENCE_MANIFOLD.md)  
**Outcomes:** A12, A23, A24, S16–S19  
**Promise:** [CONNECTOR_PRODUCT_PROMISE.md](CONNECTOR_PRODUCT_PROMISE.md)

AAPI is Connector’s **effect-field**: budgets, receipts, reserve-execute-commit, and compensation records. It does **not** admit world effects — ActionBinding / PATE remain the sole admit boundary.

## Surfaces

| Concern | Code | Persistence |
|---------|------|-------------|
| In-memory engine | `connector_engine::ActionEngine` | hydrated from store at boot |
| Post-admit audit | `substrate::aapi_bridge` | `aapi_action_ledger` + BehaviorInvocation |
| BCR spend | `ActionEngine::{reserve,commit,release}_*` + `aapi_effect_field` | `aapi_budget_ledger`, `aapi_bcr_reservations` |
| Inverse / compensate | `aapi_effect_field::{register_inverse,compensate}` | `aapi_inverse_registry`, `aapi_compensation_receipts` |

## BCR (bounded capability receipt)

1. **Reserve** — hold amount against budget (`POST /aapi/budgets/reserve`); idempotent on `idempotency_key`; refuse when exhausted.  
2. **Execute** — world effect via PATE/ActionBinding (unchanged).  
3. **Commit** — convert hold to used (`POST /aapi/budgets/commit`).  
4. **Release** — return hold on cancel/failure (`POST /aapi/budgets/release`).  
5. **Indeterminate** — commit failure marks reservation indeterminate and raises DIM `consequence_pressure` / `prediction_error` (sensor only).

Immediate `POST /aapi/budgets/consume` remains for soft/playground paths.

## HTTP

- `GET /aapi/ledger/:agent_pid` — durable action ledger  
- `POST /aapi/budgets/reserve|commit|release`  
- `POST /aapi/inverse/register`  
- `POST /aapi/compensate` — records CompensationReceipt; inverse effect still needs PATE  

## Honesty

- No budget configured → reserve succeeds (unlimited / soft).  
- Compensation without inverse → refuse under harden policy language; never claims Autonomous.  
- Durable ledger proves *what was recorded*, not absolute security.
