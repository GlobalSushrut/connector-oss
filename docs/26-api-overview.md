# 26 — API Overview: Conventions, Auth, and Versioning

> Every API call follows these conventions. Read this first.

---

## Base URL

```
http://localhost:9091          # development
https://connector.yourdomain.com   # production
```

---

## Versioning

| Prefix | Version | Status |
|---|---|---|
| `/api/v1/` | v1 | Current stable |
| `/api/v2/` | v2 | Available for select endpoints |
| `/v1/` | LLM gateway | OpenAI-compatible |
| `/health` | — | Unversioned |

---

## Authentication

### API Key (standard)
```
Authorization: Bearer your-api-key
```

### Agent PID (intra-system)
```
Authorization: Bearer <session_token>
X-Agent-Pid: agent_abc123
```

### Dev Mode
```bash
export CONNECTOR_DEV_MODE=1
# No Authorization header required
```

---

## Response Envelope

Every API response wraps data in a `V2Response<T>` envelope:

```json
{
  "data": { ... },           // success payload (null on error)
  "error": null,             // error object (null on success)
  "actions": [               // optional: suggested next actions
    {"label": "inspect", "url": "/api/v1/agents/pid:000005"}
  ],
  "audit_cid": "mem1-sha256-...",   // on mutating operations
  "decision_id": "dec_uuid..."      // on governed operations
}
```

**Exception:** Some endpoints return data at the top level (no `.data` wrapper). The Python SDK normalizes these — use the SDK rather than parsing raw HTTP where possible.

---

## Error Format

```json
{
  "data": null,
  "error": {
    "code":       "agent_not_found",
    "message":    "Agent pid:000099 does not exist",
    "hint":       "Run connectorctl agents to list valid PIDs",
    "regulation": null,
    "audit_cid":  "mem1-sha256-..."
  }
}
```

Common error codes:

| Code | HTTP | Meaning |
|---|---|---|
| `unauthorized` | 401 | Missing or invalid API key |
| `forbidden` | 403 | Agent lacks permission |
| `agent_not_found` | 404 | PID does not exist |
| `budget_exceeded` | 402 | Token/cost limit reached |
| `firewall_blocked` | 403 | Guard pipeline blocked request |
| `chain_break` | 500 | Journal HMAC chain broken |
| `rate_limit_exceeded` | 429 | Too many requests |

---

## Pagination

```
GET /api/v1/agents?page=2&limit=20
GET /api/v1/books/journal?limit=50&cursor=seq:100
```

Response includes:
```json
{
  "data": { "items": [...] },
  "pagination": {
    "page":        2,
    "limit":       20,
    "total":       85,
    "next_cursor": "seq:120",
    "has_more":    true
  }
}
```

---

## Idempotency Keys

For write operations, supply an idempotency key to prevent duplicate writes:

```
POST /api/v1/memory/write
Idempotency-Key: my-unique-key-for-this-write
```

Repeated requests with the same key return the original response without re-executing.

---

## The `audit_cid` Field

Every mutating API response includes `audit_cid` — the CID of the journal entry that records this operation:

```json
{
  "data": {"cid": "mem1-sha256-abc...", "ok": true},
  "audit_cid": "mem1-sha256-xyz..."   // ← this is the journal record
}
```

Use `audit_cid` to retrieve the exact journal entry:
```
GET /api/v1/memory/mem1-sha256-xyz...
```

---

## The `decision_id` Field

Every governed operation includes `decision_id`:

```json
{
  "data": { "content": "LLM response..." },
  "decision_id": "dec_uuid..."
}
```

Use `decision_id` to retrieve the governance decision:
```
GET /api/v1/disputes/dec_uuid...
```

Or in CLI:
```bash
connectorctl explain dec_uuid...
```

---

## Content Types

| Request | Header |
|---|---|
| JSON body | `Content-Type: application/json` |
| File upload | `Content-Type: multipart/form-data` |

All responses: `Content-Type: application/json`

---

## Rate Limiting Headers

```
X-RateLimit-Limit:     1000
X-RateLimit-Remaining: 847
X-RateLimit-Reset:     1713298800
Retry-After:           1         (on 429 only)
```

---

## Health Endpoint

```
GET /health
```
```json
{
  "status": "ready",
  "version": "1.x.x",
  "rings_active": 9,
  "chain_verified": true,
  "uptime_seconds": 3600,
  "agents_active": 5,
  "journal_seq": 247
}
```

```
GET /health/maturity
```
Returns `200` only when all 12 boot stages are complete.

---

## Next Steps

- **[27 — API: Agents](27-api-agents.md)**
- **[04 — Python SDK](04-python-sdk.md)**
- **[32 — connectorctl](32-connectorctl.md)**
