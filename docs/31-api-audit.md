# 31 — API: Audit, Books, and Proof

> The complete audit system API.

---

## `GET /api/v1/books/journal` — HMAC-Chained Journal

```
GET /api/v1/books/journal?limit=50
```

```json
{
  "entries": [
    {
      "seq_no":    42,
      "cid":       "mem1-sha256-...",
      "action":    "MemoryDeposit",
      "outcome":   "Cleared",
      "agent_pid": "agent_abc123",
      "timestamp": "2026-04-16T09:00:00Z"
    }
  ],
  "total":             247,
  "t0_chain_verified": true,
  "limit":             50,
  "offset":            0
}
```

**`t0_chain_verified: false`** = tamper detected somewhere in the chain. Immediately alert.

---

## `GET /api/v1/books` — Current Journal Position

```json
{
  "seq":            247,
  "cid":            "mem1-sha256-...",
  "chain_verified": true,
  "last_event":     "MemoryDeposit",
  "timestamp":      "2026-04-16T09:00:00Z"
}
```

---

## `GET /api/v1/books/receipt/:seq_no` — Receipt by Sequence

```
GET /api/v1/books/receipt/42
```

Returns the full receipt for sequence number 42.

---

## `GET /api/v1/books/statement/:account_id` — Ledger Statement

```
GET /api/v1/books/statement/platform
```

Returns the full ledger statement for the platform or a specific agent account.

---

## `GET /api/v1/books/ledger/:account` — Ledger

```
GET /api/v1/books/ledger/platform
GET /api/v1/books/ledger/agent_abc123
```

---

## `GET /api/v1/agents/:pid/audit/receipts` — Audit Receipts

```
GET /api/v1/agents/agent_abc123/audit/receipts?limit=20
```

```json
{
  "receipts": [
    {
      "receipt_id":   "rec_uuid...",
      "tool":         "read_patient_record",
      "agent_pid":    "agent_abc123",
      "input_hash":   "sha256:...",
      "output_hash":  "sha256:...",
      "prev_receipt": "rec_prev_uuid...",
      "signature":    "ed25519:...",
      "audit_cid":    "mem1-sha256-...",
      "timestamp":    "2026-04-16T09:00:00Z"
    }
  ],
  "total_receipts": 42,
  "chain_verified": true
}
```

---

## `POST /api/v1/proof/generate` — Generate Proof Bundle

```json
// Request
{
  "agent_pid": "agent_abc123",
  "title":     "q1_compliance_audit"
}
```

```json
// Response
{
  "proof_id":        "prf_b5ec5c71-c20a-4ec7-b8c3-dd8c2d196fb3",
  "agent_pid":       "agent_abc123",
  "title":           "q1_compliance_audit",
  "chain_verified":  true,
  "journal_entries": 247,
  "receipts":        42,
  "decisions":       89,
  "merkle_root":     "sha256:...",
  "signature":       "ed25519:...",
  "cid":             "mem1-sha256-...",
  "generated_at":    "2026-04-16T09:00:00Z"
}
```

---

## `POST /api/v1/compliance/verify` — Verify a Proof Bundle

```json
// Request
{"proof_id": "prf_b5ec5c71-..."}
```

```json
// Response
{
  "verified":              true,
  "chain_intact":          true,
  "all_signatures_valid":  true,
  "receipt_chain_intact":  true,
  "decision_count":        89,
  "journal_entries":       247,
  "verified_at":           "2026-04-16T09:10:00Z"
}
```

---

## `POST /api/v1/safety/claims/verify` — Verify LLM Claims

```json
// Request
{
  "claims":      ["The patient's HbA1c is 7.2%"],
  "source_text": "lab_hba1c: 7.2% (2026-03-15)"
}
```

```json
// Response
{
  "verified":       true,
  "verified_claims": ["The patient's HbA1c is 7.2%"],
  "failed_claims":   [],
  "confidence":      0.97
}
```

---

## `GET /api/v1/safety/grounding/verify` — Grounding Verification

```
POST /api/v1/safety/grounding/verify
{
  "text": "The patient has well-controlled diabetes with HbA1c 7.2%",
  "categories": ["clinical_facts"]
}
```

```json
{
  "grounded":          true,
  "grounding_score":   0.94,
  "supporting_cids":   ["mem1-sha256-..."],
  "ungrounded_claims": []
}
```

---

## `GET /api/v1/safety/formal/report` — Formal Safety Report

```json
{
  "executive_summary": {
    "agent_health_score": 85,
    "grade":              "A",
    "invariants_passed":  "5/6",
    "verdict":            "Invariant violations detected — review required"
  },
  "invariants": [
    {"name": "namespace_isolation",    "status": "passed"},
    {"name": "chain_integrity",        "status": "passed"},
    {"name": "pii_containment",        "status": "passed"},
    {"name": "budget_bounds",          "status": "passed"},
    {"name": "termination",            "status": "passed"},
    {"name": "policy_consistency",     "status": "warning",
     "detail": "2 rules with overlapping conditions"}
  ]
}
```

---

## `GET /api/v1/actionlog/traces/stats` — Trace Statistics

```json
{
  "total_traces":   1234,
  "by_event":       {"MemoryDeposit": 500, "DecisionRecorded": 300, "LLMInvoked": 200},
  "by_outcome":     {"Cleared": 1100, "Blocked": 89, "Denied": 45},
  "chain_ok":       true,
  "avg_latency_ms": 45
}
```

---

## Audit Verification Checklist

Use this sequence to verify a session audit trail:

```python
# 1. Get journal
journal = p.get_books_journal(limit=1000)
assert journal.get("t0_chain_verified"), "CHAIN BREAK DETECTED"

# 2. Get receipts
receipts = p.list_audit_receipts(pid, limit=100)

# 3. Generate proof
proof = p.generate_proof(pid, title="audit_verification")
assert proof.get("proof_id"), "Proof generation failed"

# 4. Verify proof
verify = p.get_verify_report()
grade = verify.get("executive_summary", {}).get("grade")
assert grade in ("A", "B"), f"Governance grade too low: {grade}"

print(f"✓ Audit verified: {len(journal['entries'])} entries, proof {proof['proof_id']}")
```

---

## Next Steps

- **[19 — Ring 8 and 9: Audit and Surface](19-ring-8-9-audit-surface.md)**
- **[37 — Tutorial: Audit Proof](37-tutorial-audit-proof.md)**
- **[59 — The 9 Chains](59-chains-overview.md)**
