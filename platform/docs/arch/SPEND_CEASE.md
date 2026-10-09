# SpendCease — hard cost and stop plane

Schemas: `connector.spend_ceiling.v1`, `connector.hop_reservation.v1`, `connector.cease_receipt.v1`

## Problem

Consumer agents often expand a cheap ask into unbounded tool/LLM loops. User says Stop; the UI stops; **provider streams and backend workers keep billing**. The model still holds “finish the task” in context and **disobeys** any soft cancel.

That is not intelligence. Connector must make continued spend **mechanically impossible**.

## Guarantees

| Guarantee | Mechanism |
|-----------|-----------|
| Task ceiling | `max_usd` + `max_tokens` + `max_iterations` per generation (env defaults) |
| Reserve-then-consume | Estimate → atomic reserve → call → commit/release (SpendGuard-style) |
| Fail-closed | Unverifiable spend → refuse admit |
| Stop = kernel Cease | Fence generation, void `ctx_tok`, reap sandbox/sealed brain, release reservations |
| Clean refuse | No silent output clamping |

Env: `CONNECTOR_SPEND_MAX_USD` (default 5), `CONNECTOR_SPEND_MAX_TOKENS`, `CONNECTOR_SPEND_MAX_ITERATIONS`.

## How the LLM cannot disobey

The model may still *want* to continue. After Cease:

1. **Generation fence** — stale `generation_id` admits refuse  
2. **Void context broker tokens** — `llm_context_broker::invalidate_agent`  
3. **Close sandbox / sealed brain epoch**  
4. **Release hop reservations**  
5. **CeaseReceipt** durable audit  

Invariant: model output is opinion; **admit is law**. Bypass of the admit choke is a quarantine-class defect.

## Cancellation tax (honest)

Hosted providers often bill tokens already generated before abort lands. Client TCP close ≠ server cancel. OpenAI `responses.cancel` exists only for background responses. Connector:

- Stops the **next** hop for sure  
- Aborts Connector-held streams best-effort  
- Records `cancel_tax_usd_est` on CeaseReceipt  
- Bounds tax with per-hop `max_tokens`

## API

| Method | Path | Effect |
|--------|------|--------|
| POST | `/api/v1/agents/:pid/cease` | Kernel Cease + CeaseReceipt |
| POST | `/api/v1/agents/:pid/pause` | Lifecycle pause **and** SpendCease |
| POST | `/api/v2/agents/:id/stop` | V2 stop **and** SpendCease |
| GET | `/api/v1/spend/ceiling/:pid` | Current generation ceiling |
| GET | `/api/v1/spend/burn/:pid` | Live burn meter (remaining + inflight LLM) |
| GET | `/api/v1/spend/cease/latest/:pid` | Latest CeaseReceipt pointer |
| GET | `/api/v1/agents/:pid/expometer` | Authority (cease/quarantine) + world grants + LLM mode/inflight — operator Expometer |

Talk/tool PATE admits reserve a hop; `complete_augmented_task` commits. Gateway and Anthropic paths clamp `max_tokens` via `clamp_max_tokens` (cancel-tax bound).

Expansive intents ("make this video", …) hit `scope_estimate_gate` before spend; over ceiling → policy deny.

Post-Cease stale admits are counted; after 3 retries the agent is **quarantined** (HITL unquarantine).

CLI:
- `connectorctl govern aipsprt schema|get <id>|verify <file.json>`
- `connectorctl govern spend ceiling|burn|cease-latest|cease <pid>`

UI: Expometer panel (Talk/Control/Trail) + Action Trail Cease control — see [CONNECTOR_PLAYGROUND_REACHED.md](../demo/CONNECTOR_PLAYGROUND_REACHED.md).


## Code

- Types: `connector_trust::spend_cease`
- Runtime: `platform/server/src/substrate/spend_cease.rs`
- In-flight abort: `platform/server/src/substrate/llm_inflight.rs`
- Broker void: `llm_context_broker::invalidate_agent`

Related: [AIPSPRT_SIG.md](./AIPSPRT_SIG.md), [PROBABILISTIC_LLM.md](./PROBABILISTIC_LLM.md), [PACKET_DNA.md](./PACKET_DNA.md).
