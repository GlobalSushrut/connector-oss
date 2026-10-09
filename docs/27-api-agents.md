# 27 — API: Agent Lifecycle

> All agent endpoints with request/response schemas.

---

## `POST /api/v1/agents` — Create Agent

```json
// Request
{
  "name":        "my-agent",
  "description": "Description of the agent",
  "clearance":   3
}
```

```json
// Response (top-level — no .data wrapper)
{
  "pid":          "agent_e1e311894a474dc7b4cfa91b3caa1821",
  "name":         "my-agent",
  "namespace":    "m/my-agent",
  "role":         "worker",
  "token_budget": 16000,
  "registered":   true,
  "kernel_pid":   "pid:000019",
  "created_by":   "dev"
}
```

---

## `GET /api/v1/agents` — List Agents

```
GET /api/v1/agents?limit=50&page=1
```

```json
// Response
{
  "agents": [
    {
      "pid":          "agent_abc123",
      "name":         "my-agent",
      "namespace":    "m/my-agent",
      "status":       "healthy",
      "role":         "worker",
      "model":        "gpt-4o",
      "registered_at": "2026-04-16T09:00:00Z",
      "kecs_score":   85,
      "maturity_level": "production",
      "paused":       false,
      "tags":         ["demo", "hipaa"]
    }
  ],
  "count": 1
}
```

Agent status values: `healthy`, `paused`, `quarantined`, `stopping`, `stopped`

---

## `GET /api/v1/agents/:pid` — Inspect Agent

```
GET /api/v1/agents/agent_abc123
```

```json
// Response (full agent state)
{
  "pid":       "agent_abc123",
  "name":      "my-agent",
  "namespace": "m/my-agent",
  "status":    "healthy",
  "context_budget": {
    "max_tokens":       128000,
    "used_tokens":      30768,
    "remaining_tokens": 97232,
    "utilization_pct":  24.0,
    "needs_eviction":   false
  },
  "cost": {
    "total_cost_usd":      0.012,
    "total_tokens_consumed": 4500,
    "budget_tokens":       64000,
    "budget_pct":          7.0,
    "budget_status":       "ok"
  },
  "kecs": {
    "k_vn":     0.82,
    "s_renyi":  0.78,
    "k_topo":   0.91,
    "formula":  "KECS = 0.4×K_vn + 0.4×S_renyi + 0.2×K_topo"
  }
}
```

---

## `POST /api/v1/agents/:pid/start` — Start Agent

```
POST /api/v1/agents/agent_abc123/start
{}
```

```json
// Response
{"ok": true, "pid": "agent_abc123", "status": "healthy"}
```

---

## `POST /api/v1/agents/:pid/kill` — Kill Agent

```
POST /api/v1/agents/agent_abc123/kill
{}
```

Graceful shutdown: drains in-flight requests, flushes journal, seals receipts.

---

## `GET /api/v1/agents/:pid/cost` — Cost Summary

```json
{
  "total_cost_usd":         0.124,
  "total_tokens_consumed":  45000,
  "budget_tokens":          100000,
  "budget_pct":             45.0,
  "budget_status":          "ok",
  "by_model": {
    "gpt-4o": {"tokens": 40000, "cost_usd": 0.10},
    "gpt-4o-mini": {"tokens": 5000, "cost_usd": 0.024}
  }
}
```

---

## `GET /api/v1/agents/:pid/policy/check` — Policy Check

```
POST /api/v1/agents/agent_abc123/policy/check
{
  "operation": "mem_read",
  "resource":  "/p/patients/p001"
}
```

```json
{
  "verdict":     "DENY",
  "reason":      "namespace_isolation: /p/ requires clearance 5",
  "enforcement": "kernel_policy",
  "allowed":     false
}
```

---

## `POST /api/v1/chat/completions` — Governed LLM Call

OpenAI-compatible endpoint with Connector governance extensions:

```json
// Request
{
  "model":       "gpt-4o",
  "messages":    [
    {"role": "system",  "content": "You are a helpful assistant."},
    {"role": "user",    "content": "What is the capital of France?"}
  ],
  "agent_pid":   "agent_abc123",
  "namespace":   "m/my-agent",
  "stream":      false
}
```

```json
// Response (OpenAI format + Connector fields)
{
  "id":      "chatcmpl-...",
  "object":  "chat.completion",
  "model":   "gpt-4o",
  "choices": [
    {
      "index":         0,
      "message":       {"role": "assistant", "content": "Paris."},
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens":     25,
    "completion_tokens": 2,
    "total_tokens":      27
  },
  "audit_cid":       "mem1-sha256-...",
  "decision_id":     "dec_uuid...",
  "grounding_score": 0.0,
  "namespace":       "m/my-agent"
}
```

---

## `GET /api/v1/agents/:pid/traces` — Agent Traces

```json
{
  "traces": [
    {
      "trace_id":  "trace_uuid...",
      "action":    "chat.invoke",
      "outcome":   "allow",
      "model":     "gpt-4o",
      "tokens":    27,
      "latency_ms": 450,
      "timestamp": "2026-04-16T09:00:00Z"
    }
  ],
  "count": 1
}
```

---

## `POST /api/v1/agents/:pid/unquarantine` — Release from Quarantine

If an agent is quarantined due to policy violations:

```
POST /api/v1/agents/agent_abc123/unquarantine
{}
```

```json
{"ok": true, "pid": "agent_abc123", "status": "healthy"}
```

---

## `GET /api/v1/agents/:pid/memory/stats` — Memory Stats

```json
{
  "total_packets": 42,
  "by_namespace": {
    "m/my-agent": 38,
    "m/shared":   4
  },
  "by_type": {
    "evidence":  20,
    "working":   18,
    "episodic":  4
  },
  "total_bytes": 128000,
  "hot_tier_pct": 85
}
```

---

## `GET /api/v1/agents/:pid/sessions` — Active Sessions

```json
{
  "sessions": [
    {
      "session_id": "sess_abc...",
      "started_at": "2026-04-16T09:00:00Z",
      "packets":    15,
      "active":     true
    }
  ],
  "count": 1
}
```

---

## Next Steps

- **[28 — API: Memory](28-api-memory.md)**
- **[30 — API: Governance](30-api-governance.md)**
- **[04 — Python SDK](04-python-sdk.md)**
