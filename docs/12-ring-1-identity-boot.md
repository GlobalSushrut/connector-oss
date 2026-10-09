# 12 — Ring 1: Identity and Boot

> Node identity, keypair establishment, and the 12-stage boot sequence.

---

## Node Identity

Every Connector node has a unique Ed25519 keypair generated at first boot and stored securely. The public key is the node's identity — used to sign contracts, surface documents, and proof bundles.

```
node_id: node_abc123...                # derived from public key
public_key: ed25519:34d0bdcb...        # node's identity key
keypair_path: /etc/connector/keys/     # Ed25519 keypair on disk (or KMS)
```

### Binary Attestation (`binary_id.rs`)

At boot, the node computes a SHA-256 hash of its own binary. This hash is signed with the node keypair and included in the boot journal entry. Any modification to the binary produces a different hash — detectable by verifiers.

---

## The 12-Stage Boot Sequence

```
Stage 1:  IDENTITY   — Load or generate Ed25519 keypair
Stage 2:  CONFIG     — Parse connector.yaml, validate schema
Stage 3:  SECRETS    — Connect to secrets broker (KMS/Vault/env)
Stage 4:  STORAGE    — Open redb + SQLite stores, verify integrity
Stage 5:  KERNEL     — Initialize memory kernel, namespace registry
Stage 6:  POLICIES   — Load and compile policies/*.yaml
Stage 7:  SCHEDULER  — Start background task scheduler
Stage 8:  CAPABILITIES — Register ring capabilities, plugin loading
Stage 9:  RESTORE    — Restore agent state from persistent storage
Stage 10: SERVICES   — Start HTTP gateway, MCP bridge, internal DNS
Stage 11: ACCESS     — Validate auth tokens, initialize rate limiters
Stage 12: READY      — Signal systemd / Kubernetes, open for traffic
```

Each stage is logged to the journal before proceeding to the next. A failure at any stage halts boot — the node does not partially start.

---

## Boot Journal Entries

```json
{"seq": 1, "action": "AccountOpened", "outcome": "Cleared",
 "payload": {"stage": "IDENTITY", "node_id": "node_abc123",
             "public_key": "ed25519:34d0bdcb..."}}
{"seq": 2, "action": "AccountActivated", "outcome": "Cleared",
 "payload": {"stage": "READY", "rings_active": 9}}
```

---

## Agent Identity

Each registered agent gets:
- A **PID** (`pid:000005` or `agent_uuid`) — persistent identifier
- A **namespace** (`m/agent-name`) — scoped memory space
- A **clearance level** (1–5) — determines what namespaces and tools are accessible
- A **role** — binds to policy rules
- A **session token** — ephemeral auth token for API calls

```python
agent = p.register_agent("my-agent", "Description", clearance=3)
pid       = agent["pid"]        # permanent
namespace = agent["namespace"]  # permanent
token     = agent.get("token")  # ephemeral
```

---

## Auth Middleware

Three authentication methods, evaluated in order:

1. **API Key** — `Authorization: Bearer <api_key>` header
2. **Agent PID Auth** — requests from a known agent PID with valid session token
3. **Dev Mode** — `CONNECTOR_DEV_MODE=1` disables auth (development only)

```bash
# API key auth
curl -H "Authorization: Bearer your-api-key" http://localhost:9091/api/v1/agents

# Dev mode
export CONNECTOR_DEV_MODE=1
```

---

## Trust Anchors

The trust anchor is the node keypair. Every signed artifact traces back to this anchor:

```
Node Keypair (Ed25519)
    │
    ├── Signs: Compiled CCL contracts (cls1-sha256-*)
    ├── Signs: Surface documents (soe1-sha256-*)
    ├── Signs: Proof bundles
    └── Signs: Boot attestation
```

---

## Kubernetes Integration

```yaml
# liveness probe — node is alive
livenessProbe:
  httpGet:
    path: /health
    port: 9091
  initialDelaySeconds: 10
  periodSeconds: 30

# readiness probe — node is fully booted (stage 12)
readinessProbe:
  httpGet:
    path: /health/maturity
    port: 9091
  initialDelaySeconds: 15
  periodSeconds: 10

# startup probe — allow up to 60s for boot
startupProbe:
  httpGet:
    path: /health
    port: 9091
  failureThreshold: 12
  periodSeconds: 5
```

---

## systemd Integration

```ini
[Unit]
Description=Connector Governed AI Node
After=network.target

[Service]
Type=notify                          # systemd Type=notify for readiness signal
ExecStart=/usr/bin/connector-server --config /etc/connector/connector.yaml
Restart=on-failure
RestartSec=5
User=connector
Group=connector

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
ReadWritePaths=/var/lib/connector /var/log/connector

[Install]
WantedBy=multi-user.target
```

---

## Graceful Shutdown

On SIGTERM:
1. Stop accepting new requests
2. Drain in-flight requests (max 30s)
3. Flush journal to disk
4. Write shutdown entry to journal
5. Close storage
6. Signal systemd (`sd_notify("STOPPING=1")`)

---

## Next Steps

- **[13 — Ring 2: Network](13-ring-2-network-gateway.md)**
- **[25 — External Deployment](25-infra-external.md)**
