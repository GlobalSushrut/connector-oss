# 15 — Ring 4: Memory Kernel

> CID-addressed, namespace-isolated, HMAC-chained memory for governed agents.

---

## Overview

The memory kernel is the persistent state layer for all agents. Every piece of data is:
- **Content-addressed** — identified by `mem1-sha256-*` CID
- **Namespace-isolated** — fenced by MAC enforcement
- **HMAC-chained** — every write extends the namespace chain
- **Structured** — `MemPacket` schema with metadata

---

## Memory Packet Schema (`memory_format.rs`)

```json
{
  "cid":         "mem1-sha256-3a4b5c...",
  "content":     "Patient has Type 2 Diabetes. Medication: Metformin.",
  "namespace":   "m/medical-agent",
  "packet_type": "clinical_note",
  "agent_pid":   "agent_abc123",
  "memory_type": "evidence",
  "tags":        ["hipaa", "patient:p001"],
  "entity_kind": "clinical_observation",
  "timestamp":   "2026-04-16T09:00:00Z",
  "hmac":        "sha256:...",
  "embedding":   [0.1, 0.3, ...]   // optional vector embedding
}
```

---

## Namespaces

Four primary namespace trees:

| Prefix | Name | Security Level | LLM Access |
|---|---|---|---|
| `/p/` | Private / PHI | 5 (highest) | **Never** |
| `/m/` | Agent memory | 3 | Allowed |
| `/k/` | Knowledge base | 2 | Read-only |
| `/s/` | System | 5 | **Never** |

Sub-namespace patterns:
```
/p/patients/p001/records    ← individual patient PHI
/m/agent-abc/session/       ← agent working memory
/m/shared/                  ← cross-agent shared memory
/k/medical/protocols/       ← curated medical knowledge
/s/policies/                ← system policy state
```

---

## Storage Backend (`redb_store.rs`)

**Hot tier:** redb (embedded key-value store) — fast in-memory + memory-mapped disk
**Warm tier:** SQLite — larger capacity, slower
**Cold tier:** Archive — configurable (S3, GCS, local)

Data moves through tiers by age and access frequency. Cold-archived packets remain verifiable via CID.

---

## Write Operations

```python
# Python SDK
result = p.write_memory(
    agent_pid=pid,
    content="Factual observation or structured data",
    ptype="clinical_note",          # packet_type
    memory_type="evidence",         # working | evidence | episodic | semantic
    session_id="sess_abc",          # group related packets
    tags=["hipaa", "patient:p001"],
    entity_kind="clinical_note"
)
cid = result["cid"]   # mem1-sha256-...
```

**On every write:**
1. Content is CBOR-encoded
2. SHA-256 CID is computed
3. Deduplication check (same CID = same content = already stored)
4. HMAC extends the namespace chain
5. Journal entry (MemoryDeposit) recorded at Ring 8

---

## Read Operations

### Recall by namespace
```python
result = p.recall_memory("m/my-agent", limit=50, memory_type="evidence")
packets = result["packets"]   # list of MemPackets
```

### Semantic search
```python
result = p.search_memory("m/my-agent", "hypertension treatment options", top_k=5)
```

### Knowledge query
```python
result = p.query_knowledge(
    entities=["hypertension", "ACE inhibitor"],
    keywords=["dosage", "protocol"],
    token_budget=2048,
    max_facts=10
)
```

### By CID (exact lookup)
```
GET /api/v1/memory/<cid>
```

---

## Namespace Isolation (MAC Enforcement)

The memory kernel enforces **Mandatory Access Control** at Ring 4. An agent with clearance level 3 and namespace `m/agent-abc` **cannot**:
- Read from `m/agent-xyz` (another agent's namespace)
- Read from `/p/` (private namespace) — regardless of clearance
- Write to `/k/` (knowledge namespace) — read-only for agents
- Write to `/s/` (system namespace)

```python
# Test isolation (use in CI/CD)
result = p.test_mac_enforcement("agent_a_pid", "m/agent_b/private")
assert result["verdict"] == "DENY"   # enforced at kernel level
```

---

## Contradiction Detection (`get_interference`)

When contradictory facts exist in the same namespace, the kernel detects it:

```python
# Write contradictory facts
p.write_memory(pid, "Patient is allergic to penicillin.")
p.write_memory(pid, "Patient can safely take amoxicillin (penicillin-type).")

# Detect contradiction
interference = p.get_interference(pid)
# {"contradictions": [{"a": "...", "b": "...", "score": 0.87}], "count": 1}
```

**Memory stability under noise:** Even with 31 writes of contradictory data, if one instruction has higher confidence and more supporting evidence, it survives as the stable truth. The interference system tracks which facts are dominant.

---

## Memory Tree (`get_agent_memory_tree`)

```python
tree = p.get_agent_memory_tree(pid)
# Returns hierarchical structure of all memory packets for the agent
# Used by Ring 9 surface engine for explainability views
```

---

## CBOR Encoding and DAG Structure

Memory packets are stored in CBOR (Concise Binary Object Representation) — binary format that is:
- More compact than JSON
- Canonical (same content → same bytes → same CID)
- DAG-structured: packets can reference other packets by CID

The DAG enables:
- Partial verification (verify a branch without the full tree)
- Prolly tree structure for ordered range scans
- Incremental updates to large knowledge bases

---

## Memory Stats

```python
stats = p.get_agent_memory_stats(pid)
# {
#   "total_packets": 42,
#   "by_namespace": {"m/my-agent": 38, "/k/medical": 4},
#   "by_type": {"evidence": 20, "working": 18, "episodic": 4},
#   "total_bytes": 128000
# }
```

---

## Next Steps

- **[16 — Ring 5: Policy and Governance](16-ring-5-policy-governance.md)**
- **[28 — API: Memory](28-api-memory.md)**
- **[34 — Tutorial: Memory Patterns](34-tutorial-memory-patterns.md)**
- **[56 — Namespace and Storage Architecture](56-namespace-storage.md)**
