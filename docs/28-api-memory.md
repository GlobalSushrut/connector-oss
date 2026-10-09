# 28 — API: Memory Kernel

> All memory read/write endpoints with schemas.

---

## `POST /api/v1/memory/write` — Write Memory Packet

```json
// Request
{
  "agent_pid":   "agent_abc123",
  "content":     "Patient has Type 2 Diabetes. Medication: Metformin.",
  "packet_type": "clinical_note",
  "memory_type": "evidence",
  "session_id":  "sess_abc",
  "tags":        ["hipaa", "patient:p001"],
  "entity_kind": "clinical_observation"
}
```

```json
// Response
{
  "agent_pid":  "agent_abc123",
  "cid":        "mem1-sha256-3a4b5c...",
  "ok":         true,
  "enrichment": {
    "auto_enriched":   true,
    "knot_entities":   12
  },
  "interference": null
}
```

**`memory_type` values:**
- `working` — short-term, session-scoped
- `evidence` — persistent, audit-grade
- `episodic` — event-based, narrative
- `semantic` — abstracted, generalised knowledge

If `interference` is non-null, the write created a contradiction with existing memory.

---

## `GET /api/v1/memory/recall2/:namespace` — Recall Memory

```
GET /api/v1/memory/recall2/m%2Fmy-agent?limit=20&memory_type=evidence
```

Parameters:
- `limit` — max packets to return
- `memory_type` — filter by type (optional)
- `session_id` — filter by session (optional)
- `tier` — `hot`, `warm`, `cold`
- `ts_from` / `ts_to` — Unix timestamp range

```json
// Response
{
  "count":    5,
  "namespace": "m/my-agent",
  "packets": [
    {
      "cid":         "mem1-sha256-...",
      "content":     "Patient has Type 2 Diabetes.",
      "namespace":   "m/my-agent",
      "packet_type": "clinical_note",
      "memory_type": "evidence",
      "agent_pid":   "agent_abc123",
      "tags":        ["hipaa", "patient:p001"],
      "timestamp":   "2026-04-16T09:00:00Z"
    }
  ],
  "filters_applied": {
    "memory_type": "evidence",
    "session_id":  null,
    "tier":        null
  }
}
```

---

## `GET /api/v1/memory/:cid` — Retrieve by CID

```
GET /api/v1/memory/mem1-sha256-3a4b5c...
```

Returns the exact memory packet for that content address. If the CID does not exist or has been deleted, returns 404.

---

## `GET /api/v1/memory/semantic-search` — Semantic Search

```
GET /api/v1/memory/semantic-search?q=hypertension+treatment&namespace=m%2Fmy-agent&limit=5
```

```json
{
  "results": [
    {
      "cid":       "mem1-sha256-...",
      "content":   "Patient prescribed ACE inhibitor for hypertension.",
      "score":     0.92,
      "namespace": "m/my-agent"
    }
  ],
  "query": "hypertension treatment",
  "count": 1
}
```

---

## `POST /api/v1/memory/knowledge/query` — Knowledge Query

```json
// Request
{
  "entities":  ["hypertension", "ACE inhibitor"],
  "keywords":  ["dosage", "protocol"],
  "agent_pid": "agent_abc123"
}
```

```json
// Response
{
  "facts": [
    {
      "cid":        "mem1-sha256-...",
      "content":    "Standard ACE inhibitor dosage for hypertension: ...",
      "confidence": 0.95,
      "namespace":  "k/medical/protocols"
    }
  ],
  "count": 1,
  "token_usage": 450
}
```

---

## `POST /api/v1/memory/knowledge/query2` — Knowledge Query v2

Extended version with token budgeting, relevance threshold, and time filtering:

```json
// Request
{
  "entities":      ["hypertension"],
  "keywords":      ["treatment"],
  "token_budget":  2048,
  "max_facts":     10,
  "min_relevance": 0.7,
  "ts_from":       1700000000,
  "ts_to":         1713298800
}
```

---

## `GET /api/v1/agents/:pid/memory/tree` — Memory Tree

Returns hierarchical structure of all memory for an agent:

```json
{
  "tree": [
    {
      "namespace":  "m/my-agent",
      "packets":    38,
      "children": [
        {"namespace": "m/my-agent/session", "packets": 15},
        {"namespace": "m/my-agent/output",  "packets": 23}
      ]
    }
  ],
  "total_packets": 38
}
```

---

## `GET /api/v1/memory/interference/:agent_pid` — Contradiction Detection

```json
{
  "contradictions": [
    {
      "packet_a": {"cid": "mem1-sha256-abc...", "content": "Patient is allergic to penicillin."},
      "packet_b": {"cid": "mem1-sha256-def...", "content": "Patient takes amoxicillin daily."},
      "conflict_score": 0.87,
      "resolution": "packet_a has higher confidence"
    }
  ],
  "count": 1
}
```

---

## `DELETE /api/v1/memory/:cid` — Delete Packet

Audit-logged deletion. The packet is removed from the namespace, but a tombstone entry is written to the journal.

```
DELETE /api/v1/memory/mem1-sha256-3a4b5c...
```

```json
{
  "ok":         true,
  "tombstone":  "mem1-sha256-...",   // tombstone entry CID
  "audit_cid":  "mem1-sha256-...",   // journal entry CID
  "decision_id": "dec_uuid..."
}
```

---

## Memory Packet Schema (Full)

```json
{
  "cid":         "mem1-sha256-...",
  "content":     "string or base64-encoded bytes",
  "namespace":   "m/my-agent",
  "packet_type": "clinical_note",
  "memory_type": "evidence",
  "agent_pid":   "agent_abc123",
  "session_id":  "sess_abc",
  "tags":        ["hipaa"],
  "entity_kind": "clinical_observation",
  "user":        "physician_001",
  "timestamp":   "2026-04-16T09:00:00Z",
  "hmac":        "sha256:...",
  "embedding":   [0.1, 0.3, ...]
}
```

---

## Next Steps

- **[15 — Ring 4: Memory Kernel](15-ring-4-memory-kernel.md)**
- **[34 — Tutorial: Memory Patterns](34-tutorial-memory-patterns.md)**
- **[56 — Namespace Architecture](56-namespace-storage.md)**
