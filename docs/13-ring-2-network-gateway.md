# 13 — Ring 2: Network and Gateway

> How requests enter the Connector node — protocols, auth, rate limiting, and routing.

---

## Protocol Support

| Protocol | Port | Use Case |
|---|---|---|
| HTTP/1.1 | 9091 | Standard REST API |
| HTTP/2 | 9091 | Multiplexed high-throughput |
| WebSocket | 9091 | Streaming responses, event streams |
| mTLS | 9091 | Production mutual authentication |

---

## Request Flow Through Ring 2

```
External Request
    │
    ▼
TLS Termination
    │
    ▼
Auth Middleware (API key / bearer / agent PID)
    │
    ▼
Rate Limiter (per-key, per-agent, global)
    │
    ▼
Route Dispatcher → /v1/* or /api/v1/*
    │
    ▼
Ring 3 (Firewall)
```

---

## Authentication

### API Key
```
GET /api/v1/agents
Authorization: Bearer your-api-key
```

### Agent PID Auth
Agents authenticate with their PID + session token for intra-system calls:
```
POST /api/v1/memory/write
Authorization: Bearer <session_token>
X-Agent-Pid: agent_abc123
```

### mTLS (Production)
```yaml
api:
  tls:
    enabled: true
    cert: /etc/connector/tls/server.crt
    key:  /etc/connector/tls/server.key
    client_ca: /etc/connector/tls/ca.crt   # require client cert
    verify_client: true
```

---

## Rate Limiting

```yaml
api:
  rate_limit:
    requests_per_minute: 1000   # global
    burst: 100                  # token bucket burst
    per_agent:
      requests_per_minute: 100  # per-agent limit
    per_key:
      requests_per_minute: 500  # per-API-key limit
```

Rate limit response:
```json
HTTP 429 Too Many Requests
{"error": "rate_limit_exceeded", "retry_after_seconds": 1}
```

Headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 847
X-RateLimit-Reset: 1713298800
```

---

## Route Prefixes

| Prefix | Purpose |
|---|---|
| `/health` | Health and maturity checks |
| `/v1/chat/completions` | Governed LLM calls (OpenAI-compatible) |
| `/v1/models` | Available model list |
| `/api/v1/agents/*` | Agent lifecycle |
| `/api/v1/memory/*` | Memory kernel |
| `/api/v1/firewall/*` | Guard pipeline |
| `/api/v1/disputes/*` | Decision recording |
| `/api/v1/books/*` | Audit journal |
| `/api/v1/proof/*` | Proof generation |
| `/api/v1/compliance/*` | Compliance surfaces |
| `/api/v1/tools/*` | Tool bridge |

---

## Internal DNS (`internal_dns/`)

Connector nodes in a cluster register themselves with the internal DNS. Agents in the same cluster can reference each other by name:

```
coordinator.agents.internal  →  pid:000005  @  connector-01:9091
specialist.agents.internal   →  agent_abc   @  connector-02:9091
```

---

## Cross-Cell Port Routing (`cross_cell_port.rs`)

In a multi-node cluster, requests for agents on other cells are transparently forwarded:

```
Request for agent on cell-2
    │
    ▼ connector-01 (receives request)
    │
    ▼ Internal routing: agent is on cell-2
    │
    ▼ connector-02 receives forwarded request
    │
    ▼ Processes through full 9-ring pipeline
    │
    ▼ Response returned to original caller
```

---

## Session Stickiness

Long-running agent sessions are pinned to a cell. The gateway maintains session affinity based on `X-Agent-Pid` header or session cookie.

---

## Network Topology (Single Node)

```
                    [Load Balancer / Nginx]
                             │
                    ┌────────▼────────┐
                    │  connector:9091  │
                    │  (HTTP/2 + TLS)  │
                    └─────────────────┘
                             │
               ┌─────────────┴──────────────┐
               │                            │
        /v1/chat/...                 /api/v1/...
     (LLM gateway)               (management API)
```

---

## Network Topology (Multi-Node)

```
            ┌──────────────────────────────────┐
            │           Load Balancer           │
            └────────┬─────────────┬────────────┘
                     │             │
           ┌─────────▼──┐    ┌─────▼──────┐
           │ connector-01│    │ connector-02│
           │ (primary)   │◄──►│ (replica)  │
           └─────────────┘    └────────────┘
                     │
           ┌─────────▼──────────┐
           │  Shared Storage     │
           │  (optional NFS/S3)  │
           └─────────────────────┘
```

---

## CORS Configuration

```yaml
api:
  cors:
    enabled: true
    origins:
      - "https://app.yourdomain.com"
      - "https://admin.yourdomain.com"
    methods: [GET, POST, DELETE]
    headers: [Authorization, Content-Type, X-Agent-Pid]
    max_age_seconds: 3600
```

---

## Next Steps

- **[14 — Ring 3: Firewall](14-ring-3-firewall-guard.md)**
- **[25 — External Deployment](25-infra-external.md)**
- **[53 — Global Distribution](53-global-agent-distribution.md)**
