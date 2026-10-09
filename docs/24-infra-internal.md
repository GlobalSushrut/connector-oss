# 24 — Internal Infrastructure Design

> How the platform server is wired internally.

---

## Module Dependency Graph

```
connector-server (binary entry point)
    │
    ├── connector-api        HTTP layer — routes, middleware, handlers
    │       └── depends on connector-engine
    │
    ├── connector-engine     Core runtime — all 9 rings
    │       ├── identity/    Ring 1
    │       ├── network/     Ring 2
    │       ├── firewall/    Ring 3
    │       ├── memory/      Ring 4
    │       ├── policy/      Ring 5
    │       ├── cognitive/   Ring 6
    │       ├── tools/       Ring 7
    │       ├── audit/       Ring 8
    │       └── surface/     Ring 9
    │
    ├── connector-glue       Unified developer surface
    │       ├── cli/         connectorctl verbs
    │       ├── sdk/         Python/Rust SDK
    │       └── grammar/     Verb/noun/selector language
    │
    └── connector-cli        connectorctl binary
            └── depends on connector-glue
```

---

## Internal IPC

Components communicate through typed message passing over Tokio channels (Rust async):

```
HTTP Handler
    │
    ▼ Request message
Boot System (Ring 1)
    │
    ▼ Auth verified message
Policy Engine (Ring 5)
    │
    ▼ Decision message
Memory Kernel (Ring 4)
    │
    ▼ Context assembled message
LLM Router (Ring 6)
    │
    ▼ Response message
Audit Logger (Ring 8)
    │
    ▼ Journal entry message
Surface Engine (Ring 9)
```

Messages are typed structs — no stringly-typed dispatch. A message for the wrong recipient is a compile error.

---

## Storage Zones (`storage_zone.rs`)

```
/var/lib/connector/
├── memory/
│   ├── hot/     ← redb (memory-mapped)
│   ├── warm/    ← SQLite
│   └── cold/    ← archive (configurable)
├── journal/
│   └── books.redb
├── receipts/
│   └── receipts.redb
├── secrets/
│   └── (encrypted store — keys from KMS)
├── keys/
│   └── node.ed25519
└── contracts/
    └── *.ccl compiled
```

---

## KMS Integration (`kms/`)

Three KMS backends:

| Backend | Config | Use Case |
|---|---|---|
| Local file | `kms.provider: file` | Development |
| AWS KMS | `kms.provider: aws` | AWS production |
| HashiCorp Vault | `kms.provider: vault` | On-premise production |
| GCP KMS | `kms.provider: gcp` | GCP production |

```yaml
secrets:
  provider: aws_secrets_manager
  region: us-east-1
  key_id: arn:aws:kms:us-east-1:123:key/abc-123
```

---

## Secrets Broker (`secret_store.rs`)

The secrets broker intercepts all references to secrets in configuration and resolves them at runtime — secrets are never written to YAML in plaintext:

```yaml
llm:
  providers:
    openai:
      api_key: "${OPENAI_API_KEY}"          # env var
      # or:
      api_key: "vault://secret/openai/key"  # Vault path
      # or:
      api_key: "aws://my-secret-name"       # AWS Secrets Manager
```

---

## Background Task Scheduler

```
Scheduler (runs at boot, Stage 7)
├── Journal flush           every 1s
├── Memory tier migration   every 5m (hot → warm → cold)
├── Chain verification      every 10m
├── Budget recalculation    every 30s
├── Trust score update      every 1m
├── Health metrics          every 15s
└── Certificate rotation    every 24h (if TLS auto-renew enabled)
```

---

## `connector-glue` — The Unified Developer Surface

`connector-glue` is not an SDK — it is a semantic surface. The same intent expressed through any of these interfaces produces identical governed execution:

```
CLI: connectorctl prove agent pid:000005

Python: p.generate_proof("pid:000005", title="q1")

Rust:   connector_glue::run("pid:000005")
            .generate_proof()
            .title("q1")
            .execute()

HTTP:   POST /api/v1/proof/generate
        {"agent_pid": "pid:000005", "title": "q1"}
```

All four produce the same `proof_id`, same journal entry, same audit trail.

---

## The `knot` Consensus System

For distributed deployments, `knot` provides distributed agreement on governance decisions:

- **Leader election** (Raft-based)
- **Decision replication** — governance decisions replicated across nodes
- **Memory synchronization** — namespace writes propagate to replicas
- **Chain consistency** — HMAC chains are consistent across the cluster

```yaml
cluster:
  enabled: true
  consensus: raft
  replication_factor: 3
  election_timeout_ms: 5000
```

---

## Watchdog and Circuit Breaker

```
Watchdog
├── Monitors: LLM provider response time
├── Monitors: Memory kernel write latency
├── Monitors: Journal flush latency
└── On threshold exceeded: emit SystemAlert + circuit break

Circuit Breaker (per LLM provider)
├── State: Closed (normal) / Open (failing) / Half-open (testing)
├── Open on: N consecutive failures
├── Half-open after: recovery_seconds
└── Close on: successful test call
```

---

## Performance Targets

| Operation | Target Latency | Notes |
|---|---|---|
| Firewall inspect | < 50ms | 5 layers, including PII scan |
| Memory write | < 10ms | Hot tier only |
| Memory recall | < 20ms | Top-50 by recency |
| Journal flush | < 5ms | Async, batched |
| Proof generation | < 500ms | Full chain traversal |
| LLM call | Model-dependent | Not counted in ring overhead |

---

## Next Steps

- **[25 — External Deployment](25-infra-external.md)**
- **[53 — Global Distribution](53-global-agent-distribution.md)**
- **[63 — Hosting and Deployment](63-hosting-deployment.md)**
