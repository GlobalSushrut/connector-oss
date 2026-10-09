# LLM Context Broker — shared brain, locked identity

> See also: **[How Any LLM Responds Through Connector](./LLM_PRINCIPAL_PROJECTION.md)** — Obey-Once binding, work units, and Principal Projection (PASS / PROJECT / DENY).  
> **[LLM Workbench](./LLM_WORKBENCH.md)** — operator orchestrator session (turn / admit / ToolDispatch).

## Problem

One LLM provider can power **100+ agents**. Without Connector mediation, the model
could treat prompt text as identity and keep acting from leftover conversation
after deny/quarantine.

## Rule

Identity and authority live **only** in the Connector broker.

| Layer | What the LLM sees | What Connector holds |
|-------|-------------------|----------------------|
| Talk inject (enforced) | Opaque `ctx_tok_…` + short refs | Token → agent_pid + generation + MAC |
| Effects / tools | Nothing usable alone | Must resolve **live** active token |
| After quarantine/deny | Prior tokens void | Generation bump + window flush |

## Enforcement

On when any of:

- `CONNECTOR_LLM_CONTEXT_BROKER=1`
- `CONNECTOR_LLM_DISTRUST` / effect exclusivity / unbypassable bar

## Lifecycle

1. Admission + agentic stack OK → `mint_for_talk` → opaque token in system prompt  
2. Tools/effects → `assert_live_for_agent(active_token)`  
3. Quarantine / unquarantine / atomic revoke → `invalidate_agent` (generation++)  
4. Next talk must mint a **new** token; old prompt text cannot authorize

## Honesty

- Client-held chat transcripts may still exist until operators purge them.  
- They **cannot** mint effects without a live broker token.  
- Memory/RAG inject under broker mode still may carry content; **identity/authority** is tokenized.  
- Under data tokenization (`LLM_TOKENIZATION_PLANE.md`), chat/tool strings become `⟦conn:…⟧` before the provider; maps live in agent-scoped store and void on quarantine.  
- Not a substitute for eBPF / microVM — this is L7 identity + data isolation for the shared model.

## Code

- `platform/server/src/substrate/llm_context_broker.rs`
- `platform/server/src/substrate/data_tokenization.rs`
- Wired: `gateway.rs`, `anthropic_gateway.rs`, `tools.rs`, `admission::quarantine_agent`, `atomic_revoke`
