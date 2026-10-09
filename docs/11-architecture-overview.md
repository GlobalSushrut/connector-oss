# 11 — Architecture Overview: The 9-Ring Model

> Nine concentric enforcement rings. Every request passes through every ring. No ring can be skipped.

---

## The 9-Ring Model

```
                        External Caller
                             │
                    ┌────────▼────────┐
                    │   RING 1        │  Identity & Boot
                    │  ┌─────────┐   │  Node keypair, auth, boot sequence
                    │  │ RING 2  │   │  Network & Gateway
                    │  │ ┌─────┐ │   │  HTTP, TLS, rate limiting
                    │  │ │ R3  │ │   │  Firewall & Guard (5 layers)
                    │  │ │ ┌─┐ │ │   │
                    │  │ │ │4│ │ │   │  Memory Kernel
                    │  │ │ └─┘ │ │   │  Namespaces, CID, isolation
                    │  │ │ R5  │ │   │  Policy & Governance
                    │  │ │ R6  │ │   │  Reasoning & LLM Interface
                    │  │ │ R7  │ │   │  Tool Execution
                    │  │ └─────┘ │   │
                    │  │  R8     │   │  Audit Chain & Books
                    │  └─────────┘   │
                    │  RING 9        │  Surface Output Engine
                    └────────────────┘
```

---

## Ring Summary

| Ring | Name | Purpose | Fail Mode |
|---|---|---|---|
| 1 | Identity & Boot | Node keypair, 12-stage boot, auth tokens | Boot aborts |
| 2 | Network & Gateway | HTTP/2, TLS, rate limiting, session routing | Connection refused |
| 3 | Firewall & Guard | 5-layer content inspection | Request blocked |
| 4 | Memory Kernel | CID-addressed storage, namespace isolation | Write/read denied |
| 5 | Policy & Governance | CCL execution, decision recording, HITL | Action denied |
| 6 | Reasoning & LLM | Selective context, grounding, LLM routing | Response withheld |
| 7 | Tool Execution | Schema validation, allowlist, receipts | Tool call denied |
| 8 | Audit Chain | HMAC journal, receipts, proof generation | Chain alert |
| 9 | Surface Output | Role-based rendering, SOE, export | Redacted output |

**All rings fail closed.** A failure at any ring denies the request — it does not fall through to an unprotected path.

---

## How the 9 rings map to today’s intelligence OS

The rings are still the **request path**. On top of them we built **per-intelligence membrane** (plan **v3 §0** — [DISTRIBUTED_INTELLIGENCE_PLAN.md](../DISTRIBUTED_INTELLIGENCE_PLAN.md)):

| Ring | Intelligence OS layer (2026-08-13) |
|------|-------------------------------------|
| 1 Identity | Principal mint · `agent_pid` · ACS character |
| 2 Gateway | LLM vault · force-pid Talk · kernel root for world grants |
| 3 Firewall | AutonomyGateway Allow/Ask/Block · 3 layers (Root / Cone / App) |
| 4 Memory | VAC + **NS FS** (`/m` `/k` `/p` `/share`) — A cannot see B |
| 5 Policy | Charter / IntelligenceSpec · world grant `(pid × address)` · share contract |
| 6 Reasoning | Bound skills · Cone suggests, human approves |
| 7 Tools | `admit_tool_or_ask` / `admit_conp_or_ask` · DockLock + light_ns |
| 8 Audit | DecisionTraces · forensic package · TT / WC |
| 9 Surface | Workbench ACS strip · Charter Studio · compliance PDF |

Honesty: court-green only with WC+CFNI; CONP taxonomy ≠ SIL; MicroVM/eBPF only when those backends are real.

---

## The Four Primary Data Paths

### Path 1: Chat Invocation

```
POST /v1/chat/completions
  → Ring 1: Verify caller identity + agent PID
  → Ring 2: TLS termination, rate check
  → Ring 3: Firewall inspect prompt (5 layers)
  → Ring 4: Retrieve relevant memory (namespace-fenced)
  → Ring 5: Policy check (CCL contract evaluation)
  → Ring 6: Selective context construction → LLM call
  → Ring 7: (no tool call on basic chat)
  → Ring 8: Journal entry + receipt
  → Ring 9: Surface rendering + audit_cid in response
```

### Path 2: Memory Write

```
POST /api/v1/memory/write
  → Ring 1: Auth
  → Ring 2: Network
  → Ring 3: PII scan on content
  → Ring 4: Namespace policy check + CID computation + store
  → Ring 5: Policy tag application
  → Ring 7: (no tool call)
  → Ring 8: Journal entry (MemoryDeposit event)
  → Ring 9: (no surface output)
```

### Path 3: Tool Dispatch

```
POST /api/v1/tools/mcp/invoke
  → Ring 1: Auth
  → Ring 2: Network
  → Ring 3: Schema validation on tool args
  → Ring 4: Namespace policy for tool scope
  → Ring 5: Allowlist check + budget check
  → Ring 7: Execute tool call + receipt generation
  → Ring 8: Receipt chained + journal entry
  → Ring 9: (structured result)
```

### Path 4: Proof Generation

```
POST /api/v1/proof/generate
  → Ring 1: Auth
  → Ring 5: Policy check (who can generate proofs)
  → Ring 8: Traverse all 9 chains → assemble bundle
  → Ring 9: Render proof surface (JSON/Markdown/PDF)
```

---

## Ring Interaction Map

```
Ring 1 ──────────────────────────────────────► Ring 5 (trust anchor for policy)
Ring 3 ──────────────────────────────────────► Ring 8 (every guard event journaled)
Ring 4 ──────────────────────────────────────► Ring 6 (memory feeds selective context)
Ring 5 ──────────────────────────────────────► Ring 8 (every decision journaled)
Ring 7 ──────────────────────────────────────► Ring 8 (every tool call receipted)
Ring 8 ──────────────────────────────────────► Ring 9 (journal feeds proof/surface)
```

---

## System Topology

```
connector-server (binary)
├── connector-engine (core runtime)
│   ├── Identity module (ring 1)
│   ├── Network gateway (ring 2)
│   ├── Firewall / guard pipeline (ring 3)
│   ├── Memory kernel — redb + SQLite (ring 4)
│   ├── Policy engine + CLS executor (ring 5)
│   ├── Reasoning pipeline + LLM router (ring 6)
│   ├── Tool bridge + saga executor (ring 7)
│   ├── Books + audit + proof (ring 8)
│   └── SOE surface engine (ring 9)
├── connector-api (HTTP layer)
│   └── /api/v1/* routes
├── connector-glue (developer surface)
│   └── CLI, Python SDK, unified grammar
└── connector-cli (connectorctl binary)
```

---

## Key Properties

### Fail Closed
Every ring has a defined failure mode that **denies** the request. There is no path to LLM or tool execution that bypasses a ring.

### Independent Operation
Each ring can be evaluated independently. A firewall can be tested without a running LLM. A proof can be generated without active agents.

### Monotonic Journal
Ring 8 records every event from every other ring. The journal sequence is monotonically increasing. Any gap is detectable.

### CID Addressing
Every piece of data in the system — memory packets, contracts, surface documents, proof bundles — has a content-addressed identifier. Tampering changes the CID.

---

## Next Steps

- **[12 — Ring 1: Identity and Boot](12-ring-1-identity-boot.md)**
- **[14 — Ring 3: Firewall](14-ring-3-firewall-guard.md)**
- **[19 — Ring 8 and 9: Audit and Surface](19-ring-8-9-audit-surface.md)**
