# 02 — Product Overview

> What Connector is, why it exists, and the mental model that makes everything else make sense.

---

## The Problem

Modern AI systems have a fundamental architecture gap. LLMs are powerful reasoning engines — but they have no enforcement layer. When an LLM calls a tool, reads from a database, or produces an output that gets acted upon:

- There is no record of why the decision was made
- There is no proof that the output was grounded in real data
- There is no audit trail that survives a compliance review
- There is no enforcement boundary that stops the LLM from accessing data it should not see
- There is no mechanism to prove to a regulator that the system behaved correctly

This is not a model problem. It is an **infrastructure problem**.

---

## What Connector Is

Connector is a **governed AI infrastructure layer** that sits between your application code and the LLM (and any tool the LLM calls). Every request entering the system passes through nine enforcement rings. No ring can be skipped. Every decision is recorded. Every chain is cryptographically sealed.

```
Your Application
       │
       ▼
┌─────────────────────────────────────────────────────┐
│                   CONNECTOR NODE                     │
│                                                     │
│  Ring 1: Identity        Ring 6: Reasoning          │
│  Ring 2: Network         Ring 7: Tool Execution     │
│  Ring 3: Firewall        Ring 8: Audit Chain        │
│  Ring 4: Memory          Ring 9: Surface Output     │
│  Ring 5: Governance                                 │
└─────────────────────────────────────────────────────┘
       │
       ▼
     LLM / Tools / APIs
```

Connector is **not** a wrapper around one LLM. It is a layer between your code and the world — governing every interaction regardless of which model, tool, or API is on the other side.

---

## The Three-Layer Product Model

### Layer 1 — The Node

The `connector-server` binary. The daemon that runs on your infrastructure. Contains all nine rings, the memory kernel, the policy engine, the audit journal, and the proof system. Self-contained. No external dependencies required for basic operation.

### Layer 2 — Glue

The unified developer surface. Spans CLI (`connectorctl`), HTTP API (`/api/v1/`), Python SDK (`ConnectorPlatform`), and the CCL contract language. Builders interact with Connector through Glue. The same governance intent expressed in Python, YAML, or CLI produces the same governed execution with the same audit trail.

### Layer 3 — Workloads

Agents, pipelines, and memory that run on top of the Node. An agent is a governed execution context: it has an identity (`pid`), a namespace, a policy contract, a memory space, and a cost budget. Workloads are what you build. The Node governs them.

---

## The Governed AI Problem — Solved Structurally

| Problem | Connector Solution |
|---|---|
| No audit trail | HMAC-chained journal — every event, forever |
| LLM sees data it should not | Namespace isolation — `/p/` (private) never reaches LLM |
| No proof of data minimization | Selective context construction + cryptographic proof |
| Unprovable reasoning | Dehallucination chain — every output linked to source |
| Uncontrolled tool calls | Tool bridge with allowlist + schema validation |
| No compliance evidence | `generate_proof` — SOC2/HIPAA/GDPR bundle in one call |
| Silent policy violations | 5-layer firewall — blocks before any action occurs |
| Cost overruns | Budget enforcement at Ring 5 — hard limits |

---

## Mental Model

> **Connector is a kernel for AI agents.**

Just as an OS kernel mediates between application code and hardware — enforcing isolation, managing resources, auditing system calls — Connector mediates between your application logic and AI capabilities.

A system call in Linux requires privilege checks, resource allocation, and audit logging. An LLM call through Connector requires identity verification, policy evaluation, PII scanning, and chain recording.

The difference: a Linux kernel audit log proves what happened at the syscall level. Connector's proof system proves what happened at the **decision level** — including why, by whom, and with what evidence.

---

## What Connector Is Not

- **Not an LLM.** Connector does not contain a language model. It governs access to any model.
- **Not an agent framework.** Connector is the enforcement layer. You build the agent logic.
- **Not a monitoring tool.** Monitoring observes. Connector enforces — and then records.
- **Not a compliance document.** Compliance documents describe intent. Connector produces cryptographic proof.

---

## Primary Use Cases

### Regulated Industry AI
Healthcare (HIPAA), finance (SOC2), EU (GDPR + EU AI Act). Connector is the technical layer that makes compliance claims provable rather than aspirational.

### Governed Coding Agents
DevGuard plugin: govern Claude Code, Cursor, Windsurf, Kiro. Every file access, command, and code generation is gated, audited, and sealed.

### Enterprise Agent Pipelines
Multi-agent networks with delegation chains, consensus, conflict resolution, and proof-of-authority. Every agent has a governed identity. Every inter-agent call is audited.

### Audit-Ready AI Systems
Systems where the answer to "prove what your AI did and why" is a single `connectorctl prove agent <pid>` command.

---

## Key Numbers

| Metric | Value |
|---|---|
| Enforcement rings | 9 |
| Guard pipeline layers | 5 |
| Chain types | 9 |
| CCL compiler passes | 11 |
| Cognitive pipeline layers | 11 |
| Knowledge forms | 8 |
| Compliance frameworks built-in | 4 (HIPAA, SOC2, GDPR, EU AI Act) |

---

## Next Steps

- **[03 — YAML Configuration](03-yaml-configs.md)** — configure a node
- **[11 — Architecture Overview](11-architecture-overview.md)** — deep dive into the 9 rings
- **[58 — Compliance Framework](58-compliance-framework.md)** — regulatory coverage
