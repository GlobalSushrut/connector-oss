# 76 — Cost Infrastructure

How the platform tracks, records, and exposes real LLM API costing per agent.

---

## Overview

Every LLM call made by an agent flows through the **gateway service** (`services/gateway.rs`). At the end of each call — whether non-streaming (`/gateway/chat`) or streaming (`/gateway/stream`) — the platform computes the exact cost in USD, records it into a **per-agent cost ledger**, and exposes it through the agent cost API.

The system is designed around three principles:

- **Accuracy over estimates** — costs are computed from real token counts returned by the provider, not prompt length guesses.
- **Ledger over totals** — every individual LLM call is stored as a line item; totals are derived, not primary.
- **Live over cached** — the CLI always fetches from the API, never reads stale SOE kernel values.

---

## Data Flow

```
Agent Task
    │
    ▼
Gateway (/gateway/chat or /gateway/stream)
    │
    ├── Calls LLM provider (DeepSeek / OpenAI / Anthropic)
    │       Returns: prompt_tokens, completion_tokens, response_text
    │
    ├── estimate_usd_for_tokens(provider, model, in, out)
    │       Looks up cost_per_million rates from built-in catalogue
    │       Returns: cost_usd (f64)
    │
    ├── record_llm_gateway_usage(state, account_id, agent_pid, ...)
    │       Updates user_store tokens_used_today / tokens_used_month
    │       (skipped if account_id has no User entry — demo agents)
    │
    └── engine_store.folder_put("agent_cost_ledger", agent_pid, ledger)
            Read-modify-write:
            - Append call entry to calls[] (max 200 entries, rolling)
            - Increment total_cost_usd, total_tokens, call_count
            - Set first_call_at / last_call_at timestamps
            - Store model + provider name
```

---

## Cost Ledger Schema

Each agent has a single document stored at `engine_store["agent_cost_ledger"][agent_pid]`:

```json
{
  "agent_pid": "agent_c8f25f67bbcc466fa6fef14992b50565",
  "total_cost_usd": 0.003412,
  "total_tokens": 14820,
  "total_prompt_tokens": 9300,
  "total_completion_tokens": 5520,
  "call_count": 7,
  "cost_per_1k_tokens": 0.000230,
  "model": "deepseek-chat",
  "provider": "deepseek",
  "first_call_at": "2026-04-15T03:06:19Z",
  "last_call_at": "2026-04-15T03:41:02Z",
  "calls": [
    {
      "timestamp": "2026-04-15T03:06:19Z",
      "model": "deepseek-chat",
      "provider": "deepseek",
      "prompt_tokens": 1240,
      "completion_tokens": 380,
      "total_tokens": 1620,
      "cost_usd": 0.000281,
      "token_source": "provider_api"
    }
  ]
}
```

The `calls[]` array is a rolling window of the last **200 calls**. When full, the oldest entry is evicted (FIFO). The running totals (`total_cost_usd`, `total_tokens`, `call_count`) are never reset — they represent lifetime cost.

---

## Token Source

Each call entry carries a `token_source` field indicating where token counts came from:

| Value | Meaning |
|---|---|
| `provider_api` | Real counts from the LLM provider's response |
| `stub_heuristic` | `CONNECTOR_LLM_STUB=true` — estimated, $0 cost |
| `no_router_heuristic` | No LLM router configured, estimation fallback |
| `error` | LLM call failed |

When `token_source` is `stub_heuristic`, `cost_usd` is always `0.0`. To see real costs, configure a live LLM provider and unset `CONNECTOR_LLM_STUB`.

---

## Cost Rate Table

Built into `connector_engine::llm_router::estimate_usd_for_tokens` and the adaptive router catalogue:

| Provider | Model | Input $/1M | Output $/1M |
|---|---|---|---|
| DeepSeek | deepseek-chat | $0.14 | $0.28 |
| DeepSeek | deepseek-reasoner | $0.55 | $2.19 |
| OpenAI | gpt-4o-mini | $0.15 | $0.60 |
| OpenAI | gpt-4o | $2.50 | $10.00 |
| Anthropic | claude-3-5-haiku | $0.80 | $4.00 |
| Anthropic | claude-3-7-sonnet | $3.00 | $15.00 |

---

## API Endpoint

### `GET /api/v1/agents/:pid/cost`

Returns the full ledger for an agent. Auth required.

**Priority**: reads from `agent_cost_ledger` first (live gateway data). Falls back to SOE kernel ACB for agents registered directly with the kernel.

**Response**:
```json
{
  "pid": "agent_...",
  "total_cost_usd": 0.003412,
  "total_tokens": 14820,
  "total_prompt_tokens": 9300,
  "total_completion_tokens": 5520,
  "call_count": 7,
  "cost_per_1k_tokens": 0.000230,
  "model": "deepseek-chat",
  "provider": "deepseek",
  "budget_tokens": 500000,
  "budget_pct": 2.9,
  "budget_status": "ok",
  "first_call_at": "...",
  "last_call_at": "...",
  "calls": [ ... ]
}
```

---

## CLI: `connectorctl cost`

```
connectorctl cost agent <agent-pid>
```

Fetches `/api/v1/agents/:pid/cost` and renders:

1. **Summary header** — agent PID, model, provider, call count
2. **Token breakdown** — total / prompt / completion split
3. **Cost line** — total USD + cost per 1K tokens
4. **Time range** — first call and last call timestamps
5. **Cost Ledger table** — last 20 individual LLM calls with columns:
   ```
   TIMESTAMP                MODEL                IN      OUT    COST (USD)
   ────────────────────────────────────────────────────────────────────────────────
   2026-04-15T03:06:19Z     deepseek-chat      1240     380    0.000281
   2026-04-15T03:12:44Z     deepseek-chat       980     210    0.000195
   ────────────────────────────────────────────────────────────────────────────────
   RUNNING TOTAL                                                0.003412
   ```

---

## Storage

The cost ledger is stored in the **engine store** (`SQLite` in production, in-memory in test mode). The key is:

```
namespace: "agent_cost_ledger"
key:       "<agent_pid>"
value:     JSON document (see schema above)
```

Each gateway call performs a **read-modify-write** under the engine_store mutex. Because the mutex is already held per-request, there are no race conditions — calls are serialised naturally.

---

## Known Limitations

- **Stub mode** (`CONNECTOR_LLM_STUB=true`): all costs are $0.00. This is intentional for local dev without an LLM key.
- **Rolling window**: the `calls[]` array stores at most 200 entries. Older individual calls are evicted but `total_cost_usd` and `total_tokens` are never evicted — lifetime totals are always accurate.
- **No persistence across wipe**: if the engine store is deleted, cost history is lost. The totals in the SOE kernel ACB are also in-memory only. For production, back up the engine store database.
