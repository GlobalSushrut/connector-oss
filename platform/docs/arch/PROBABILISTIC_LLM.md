# Probabilistic LLM guard

> Companion: **[How Any LLM Responds Through Connector](./LLM_PRINCIPAL_PROJECTION.md)** — why vendor origin does not define the agent; PASS / PROJECT / DENY.

Connector does not treat the model as ready for unaugmented autonomy. The LLM is
probabilistic. Identity, memory, character, knowledge, HITL, and parameters stay
**Connector-owned**. The model follows them; it does not replace them.

## Stance

The system assumes the model will sometimes be wrong, drift, or try another path.
Connector keeps behavior right:

| Event | What Connector does |
| --- | --- |
| Bypass of a Connector rule (forged ticket, ungoverned in-process tool path, handshake skip, exclusivity skip) | **Quarantine** that intelligence. It cannot continue until a human retrieves it (`POST /api/v1/agents/:pid/unquarantine` after HITL). |
| Failure of identity, memory, character, knowledge, HITL, or parameters | **Human approval is mandatory**. The model cannot continue autonomously. |

## Enforcement

Set `CONNECTOR_LLM_DISTRUST=1` (production default via `connector_profile`).

Lab/playground may leave it unset so ordinary denials stay denials without
auto-quarantine.

Wired paths:

- Tool dispatch: zero-trust handshake failure and in-process exclusivity deny → quarantine
- Contract / autonomy Block / missing pillars → digest-bound HITL
- Governed effects (LLM, tools, memory): character, entropy (parameters), contract (knowledge), identity stack

## Retrieval

1. Review the HITL item created by the guard.
2. Unquarantine only after that review:
   `POST /api/v1/agents/{agent_pid}/unquarantine`
3. For rule failures (not bypass), approve the bound HITL:
   `POST /api/v1/agents/{agent_pid}/hitl/{request_id}/approve`

## API

`GET /api/v1/runtime/probabilistic-llm/status`

Also included on `GET /api/v1/runtime/enforcement` as `data.probabilistic_llm`.

## Honest remainder

This is a **runtime** membrane. Pair with **docker_lab** / **microvm** isolation membrane
so guests physically cannot open sockets around Connector:

| Runtime | Closure under `CONNECTOR_LLM_DISTRUST` |
| --- | --- |
| `docker_lab` | `--network none`, docker-grade caps, secrets stripped from `-e`, optional broker UDS mount |
| `microvm` | vsock-only (no TAP), no API keys on guest cmdline; **all tool I/O** runs in guest |

### Agentic context (talk / any action)

Once bound to a Connector agent, every LLM talk injects cryptographic who-am-I,
character, last memory, knowledge contract, and rules. Incomplete stack → HITL
(`CONNECTOR_AGENTIC_CONTEXT_REQUIRE=1`).

Break-glass (weakens claim): `CONNECTOR_ALLOW_GUEST_EGRESS=1`, `CONNECTOR_ALLOW_IN_PROCESS_EFFECTS=1`.

See also `platform/docs/arch/EFFECT_EXCLUSIVITY.md`.
