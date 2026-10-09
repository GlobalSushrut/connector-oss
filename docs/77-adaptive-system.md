# 77 — Adaptive System

How the platform's adaptive LLM routing and Knowledge Transfer Graph work together to deliver cost-optimised, stable, self-improving agent execution.

---

## Overview

The adaptive system has two interlocking components:

1. **Adaptive LLM Router** (`services/adaptive.rs`) — selects the best LLM provider for each agent call using a multi-factor scoring algorithm with real-time health tracking and automatic failover.

2. **Knowledge Transfer Graph** (`services/knowledge_transfer.rs`) — tracks how knowledge flows between agents, builds capability profiles for each agent, and automatically propagates context to semantically-similar agents after significant LLM interactions.

Both systems are always-on, zero-config by default, and progressively improve as agents accumulate call history.

---

## Part 1 — Adaptive LLM Router

### Concept

Rather than always routing to a single configured LLM provider, the adaptive router maintains a **pool of providers** and dynamically selects the best one for each request based on four real-time signals:

```
score(provider, task) =
    W_cap    × capability_match(provider, required_caps)
  + W_cost   × cost_efficiency(provider, estimated_tokens, budget_remaining)
  + W_health × health_score(provider, recent_success_rate, p50_latency)
  + W_quality× quality_score(provider, model_tier)
  + W_explore× ucb1_bonus(provider, total_calls_globally)
```

Weights vary by routing strategy:

| Strategy | Cap | Cost | Health | Quality | Explore |
|---|---|---|---|---|---|
| `cost_optimal` | 0.20 | 0.55 | 0.15 | 0.05 | 0.05 |
| `performance` | 0.20 | 0.05 | 0.20 | 0.50 | 0.05 |
| `balanced` *(default)* | 0.20 | 0.30 | 0.25 | 0.20 | 0.05 |
| `stable` | 0.15 | 0.15 | 0.60 | 0.05 | 0.05 |

### Scoring Factors

**Capability match** — providers are pre-filtered to those supporting all required capabilities (Chat, Code, Reasoning, Vision, LongContext, FunctionCalling, Embeddings). Unmatched providers are excluded before scoring.

**Cost efficiency** — estimates the USD cost for the expected token counts using the built-in rate table. Score is `1.0 - (est_cost / budget_remaining)`, so providers become cheaper-biased as budget shrinks. At zero remaining budget, all providers score 0.0 and calls are hard-blocked.

**Health score** — composite of:
- `success_rate` over the last 100 calls (70% weight)
- `p50_latency_ms` normalised over 0–5000 ms range (30% weight)

**Quality score** — static model quality rating from the provider catalogue (0–100 → 0–1).

**UCB1 exploration bonus** — `sqrt(2 × ln(total_calls) / provider_calls)`, bounded at 1.0. Ensures under-utilised providers get probe calls to keep health estimates fresh. Providers with zero calls always get bonus 1.0.

### Circuit Breaker

Each provider has an independent circuit breaker:

```
CLOSED ──→ (5 consecutive failures) ──→ OPEN
OPEN   ──→ (30 seconds elapsed)     ──→ HALF-OPEN (one probe allowed)
HALF-OPEN ─→ (probe succeeds)       ──→ CLOSED
HALF-OPEN ─→ (probe fails)          ──→ OPEN
```

When a provider's circuit is OPEN, it is excluded from the candidate pool. The router automatically falls back to the next highest-scoring eligible provider. If no eligible providers remain, the call is rejected with a clear error.

### Per-Agent Configuration

Each agent can have its own routing preferences set via the API:

```
PUT /api/v1/adaptive/agents/:pid/config
```

```json
{
  "agent_pid": "agent_c8f25f67...",
  "strategy": "cost_optimal",
  "budget_ceiling_usd": 0.50,
  "required_capabilities": ["Chat", "Code"],
  "preferred_providers": ["deepseek"],
  "blocked_providers": ["openai"]
}
```

- `budget_ceiling_usd` is a **hard stop** — calls are refused once accumulated cost exceeds it.
- `preferred_providers` adds +0.15 score boost (soft preference, not a hard lock).
- `blocked_providers` removes the provider from the candidate pool entirely.

### Provider Catalogue

Built-in providers (all enabled by default):

| Provider ID | Provider | Model | Quality | Capabilities |
|---|---|---|---|---|
| `deepseek:deepseek-chat` | DeepSeek | deepseek-chat | 82 | Chat, Code, Reasoning, FunctionCalling |
| `deepseek:deepseek-reasoner` | DeepSeek | deepseek-reasoner | 95 | Chat, Reasoning, Code |
| `openai:gpt-4o-mini` | OpenAI | gpt-4o-mini | 78 | Chat, Code, Vision, FunctionCalling |
| `openai:gpt-4o` | OpenAI | gpt-4o | 97 | Chat, Code, Vision, Reasoning, LongContext, FunctionCalling |
| `anthropic:claude-3-5-haiku` | Anthropic | claude-3-5-haiku | 80 | Chat, Code, FunctionCalling |
| `anthropic:claude-3-7-sonnet` | Anthropic | claude-3-7-sonnet | 98 | Chat, Code, Reasoning, Vision, LongContext, FunctionCalling |

### Decision Logging

Every routing decision is appended to an in-memory ring buffer (last 1000 decisions). Each entry records:

```json
{
  "timestamp_ms": 1744685219000,
  "agent_pid": "agent_c8f25f67...",
  "selected_provider": "deepseek",
  "selected_model": "deepseek-chat",
  "strategy": "balanced",
  "score": 0.714,
  "reason": "strategy=Balanced score=0.714 health=100.0% p50=312ms cost_est=$0.000281",
  "estimated_cost_usd": 0.000281
}
```

Inspect via: `GET /api/v1/adaptive/decisions`

### API

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/adaptive/status` | Pool status: all providers, health metrics, circuit state |
| GET | `/api/v1/adaptive/decisions` | Last 50 routing decisions with scores and reasons |
| GET | `/api/v1/adaptive/agents/:pid/config` | Agent routing config |
| PUT | `/api/v1/adaptive/agents/:pid/config` | Update agent routing config |

---

## Part 2 — Knowledge Transfer Graph (KTG)

### Concept

As agents run, they accumulate a **capability profile** — a vector of domain tags weighted by frequency. Two agents that have handled similar tasks (code generation, API calls, data analysis) develop similar profile vectors. The KTG tracks these profiles and the history of knowledge flowing between agents.

### Graph Model

```
Nodes  = Agents (one node per agent_pid)
Edges  = Directed transfer relationships (A → B)
Weight = similarity × acceptance_rate × log(1 + count) × recency_decay(30d)
```

A **transfer** is a structured event where agent A's completed context summary is pushed to agent B's namespace. Transfers happen:
- **Automatically** — after every significant LLM call (>100 tokens), agent A finds all agents with similarity ≥ 0.65 and pushes a context summary to them
- **Manually** — via `POST /api/v1/knowledge-graph/transfer`

### Capability Profile

Each agent node holds a `capability_vector` — a normalised frequency map of domain tags:

```json
{
  "deepseek-chat": 0.85,
  "deepseek": 1.00,
  "llm": 1.00,
  "code": 0.72,
  "api": 0.58
}
```

Tags are derived from model names, provider names, and task-type labels accumulated across all LLM calls. The vector is recomputed on every call using term frequency normalisation.

### Similarity Scoring

Cosine similarity between two capability vectors:

```
sim(A, B) = dot(A, B) / (|A| × |B|)
```

This naturally captures:
- Agents using the same models are more similar
- Agents with overlapping task domains are more similar
- Agents with entirely different profiles score near 0.0

### Edge Weights

The weight of a transfer edge decays over time and increases with successful use:

```
weight = similarity × (accepted / transfer_count) × ln(1 + count) × exp(-age_days / 30)
```

- High-weight edges represent active, trusted knowledge channels.
- Edges with old last-transfer dates decay to near-zero over ~90 days.

### Transfer Record

Each transfer creates a `TransferRecord`:

```json
{
  "transfer_id": "ktf_195b3fa8c",
  "from_pid": "agent_c8f25f67...",
  "to_pid": "agent_d3a9b1e2...",
  "content_summary": "llm-context-agent_c8f",
  "tokens": 1620,
  "similarity": 0.87,
  "timestamp_ms": 1744685219000,
  "accepted": true
}
```

The last 500 transfers are kept in the rolling in-memory log.

### API

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/knowledge-graph` | Full graph: all nodes and edges |
| GET | `/api/v1/knowledge-graph/agents/:pid` | Node detail: profile, similar agents, edges, recent transfers |
| GET | `/api/v1/knowledge-graph/transfers` | Last 50 transfers across all agents |
| POST | `/api/v1/knowledge-graph/transfer` | Manually trigger a knowledge transfer |

---

## How They Work Together

```
Agent makes LLM call
        │
        ▼
Gateway records cost → agent_cost_ledger
        │
        ├── AdaptiveRouter.record_outcome(provider, success, latency, tokens, cost)
        │       Updates provider health for next routing decision
        │
        └── KnowledgeGraph.update_node(agent_pid, tags, cost)
                Updates agent capability profile
                │
                └── auto_transfer(agent_pid, context_summary, tokens, threshold=0.65)
                        Finds similar agents, pushes context to those above threshold
                        Updates KTG edges with new transfer record
```

On the **next** LLM call from any agent, the adaptive router uses the updated health scores to make a better provider selection — completing the feedback loop.

---

## State & Persistence

Both systems are **in-memory** with process lifetime:

| Component | Storage | Persistence |
|---|---|---|
| AdaptiveRouter (health, decisions) | `Arc<Mutex<HashMap>>` | Lost on restart — rebuilt from new calls |
| KnowledgeGraph (nodes, edges, transfers) | `Arc<Mutex<GraphState>>` | Lost on restart — rebuilt from new calls |
| Cost ledger | `engine_store` (SQLite) | **Persistent across restarts** |

The cost ledger is the only durable record. The KTG and adaptive state are ephemeral performance optimisers — they self-rebuild within minutes as agents resume work.

Future: periodic serialisation of KTG state to `engine_store` will be added to preserve graph history across restarts.

---

## Configuration Summary

| Feature | Default | Override |
|---|---|---|
| Adaptive router enabled | Yes (all 6 providers) | Remove from catalogue via API |
| Default routing strategy | `balanced` | Per-agent via `PUT /adaptive/agents/:pid/config` |
| Budget ceiling | None (unlimited) | Per-agent `budget_ceiling_usd` |
| KTG auto-transfer | Enabled at threshold 0.65 | Adjust threshold in `gateway.rs` |
| KTG transfer min tokens | 100 | Adjust in `gateway.rs` |
| Circuit breaker trip threshold | 5 consecutive failures | Hardcoded in `adaptive.rs` |
| Circuit breaker cooldown | 30 seconds | Hardcoded in `adaptive.rs` |
| Decision log size | 1000 entries | Hardcoded in `adaptive.rs` |
| Transfer log size | 500 entries | Hardcoded in `knowledge_transfer.rs` |
