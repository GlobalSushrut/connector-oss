# 19 — Ring 8 and 9: Audit Chain and Surface

> The tamper-evident journal and the role-based output surface.

---

## Ring 8 — Audit Chain and Books

### The Integrity-Chained Journal (`books.rs`)

Every event in the system produces a journal entry. Entries are currently **SHA-256 hash-linked** (predecessor `after_hash` → successor `before_hash`). A keyed HMAC chain with full entry recomputation on verify is the constitutional target; do not treat today's chain as HMAC until that lands:

```
Entry 1: prev_hmac=genesis  hmac=H(genesis + payload_1)
Entry 2: prev_hmac=hmac_1   hmac=H(hmac_1 + payload_2)
Entry 3: prev_hmac=hmac_2   hmac=H(hmac_2 + payload_3)
...
```

**Tamper detection:** Modifying any entry changes its HMAC, which breaks the chain from that point forward. The break is detectable by `chain_verified: false` in the journal response.

### Journal Entry Schema

```json
{
  "seq_no":      42,
  "cid":         "mem1-sha256-...",
  "prev_hmac":   "sha256:abc...",
  "hmac":        "sha256:def...",
  "action":      "MemoryDeposit",
  "outcome":     "Cleared",
  "agent_pid":   "agent_abc123",
  "payload":     {...},
  "timestamp":   "2026-04-16T09:00:00Z",
  "causal_chain": ["seq:40", "seq:38"]
}
```

### Event Types in the Journal

| Event Type | Triggered By |
|---|---|
| `AccountOpened` | Node boot |
| `AccountActivated` | Node ready |
| `MemoryDeposit` | `write_memory()` call |
| `DecisionRecorded` | `record_decision()` call |
| `FirewallBlock` | Guard pipeline block |
| `FirewallAllow` | Guard pipeline allow |
| `ToolDispatched` | Tool bridge invocation |
| `LLMInvoked` | `/v1/chat/completions` |
| `ProofGenerated` | `generate_proof()` |
| `ChainBreak` | Tamper detected |

---

### Reading the Journal

```python
journal = p.get_books_journal(limit=100)
entries = journal["entries"]
chain_ok = journal.get("t0_chain_verified", True)

print(f"Total entries: {len(entries)}")
print(f"Chain verified: {chain_ok}")

for entry in entries[-5:]:
    print(f"[{entry['seq_no']:>4}] {entry['action']:<35} {entry['outcome']}")
```

```bash
connectorctl trace agent <pid>              # recent journal entries
connectorctl trace agent <pid> --last 1h    # last hour
connectorctl trace agent <pid> --memory     # memory writes only
```

---

### Books Position

```python
pos = p.get_books_position()
# {
#   "seq": 247,
#   "cid": "mem1-sha256-...",
#   "chain_verified": true,
#   "last_event": "MemoryDeposit"
# }
```

---

### Audit Receipts

Every governed operation generates a receipt separate from the journal entry:

```python
receipts = p.list_audit_receipts(pid, limit=20)
# Each receipt: receipt_id, tool, input_hash, output_hash, prev_receipt, signature
```

```python
receipt = p.get_receipt(seq_no=42)
```

---

### Proof Generation (`generate_proof`)

`generate_proof` traverses all 9 chains and assembles a cryptographic proof bundle:

```python
proof = p.generate_proof(pid, title="q1_compliance_audit")
# {
#   "proof_id":        "prf_uuid...",
#   "agent_pid":       "agent_abc123",
#   "title":           "q1_compliance_audit",
#   "chain_verified":  true,
#   "journal_entries": 247,
#   "receipts":        42,
#   "signature":       "ed25519:...",
#   "cid":             "mem1-sha256-...",
#   "generated_at":    "2026-04-16T09:00:00Z"
# }
```

```bash
connectorctl prove agent <pid>              # generate proof
connectorctl prove agent <pid> --export     # export to file
```

---

### Verify a Proof Bundle

```
POST /api/v1/compliance/verify
{
  "proof_id": "prf_uuid..."
}
```

Returns: `{"verified": true, "chain_intact": true, "all_signatures_valid": true}`

The verifier can run **offline** — the proof bundle is self-contained.

---

## Ring 9 — Surface Output Engine (SOE)

### Role-Based Rendering

The SOE renders the same underlying data differently for different audiences:

| Role | View Contains |
|---|---|
| `Developer` | Raw JSON, CIDs, chain hashes, latencies |
| `Operator` | Formatted summary, decision flow, alerts |
| `Auditor` | Compliance evidence, decision records, receipts |
| `Executive` | Grade summary, risk level, compliance posture |

```bash
connectorctl show agent <pid>              # Operator view
connectorctl show agent <pid> --developer  # Developer view
connectorctl show agent <pid> --auditor    # Auditor view
connectorctl explain agent <pid>           # SOE explain surface
```

---

### SOE Surface Document

Every rendered surface is a **content-addressed document** (`soe1-sha256-*`) — identical inputs always produce the same CID:

```json
{
  "cid":      "soe1-sha256-...",
  "view":     "operator",
  "agent_pid": "agent_abc123",
  "rendered_at": "2026-04-16T09:00:00Z",
  "receipt":  "rec_uuid...",
  "content":  { "summary": "...", "decisions": [...] }
}
```

---

### Export Formats

```bash
connectorctl prove agent <pid> --format json      # JSON bundle
connectorctl prove agent <pid> --format markdown  # Markdown report
connectorctl prove agent <pid> --format csv       # CSV for spreadsheet
connectorctl prove agent <pid> --format yaml      # YAML
```

---

### `connectorctl show agent` Output

```
── agent_abc123 ── ACTIVE │ VERIFIED │ COMPLIANT  trust:85/A
agent_abc123: my-agent | 42 decisions | active 2h 15m

  ✓ Evidence verified
  ✓ Health: HEALTHY
  ✓ Compliance: COMPLIANT

Decision: ALLOW — summarize.patient_record
Action: Record patient summary with HIPAA tagging
Trust: Verified evidence chain
Why: Confidence 0.95, minimum necessary access enforced
Risk: LOW — PHI fenced, chain verified
Compliance: ✓ HIPAA ✓ SOC2
```

---

### `connectorctl explain <decision_id>`

```
Decision: dec_uuid...
Action:   summarize.patient_record
Target:   /p/patients/p001
Outcome:  ALLOW
Confidence: 0.95
Rationale:  Attending physician access, treatment purpose
Regulations: [hipaa, soc2]
Audit CID:  mem1-sha256-abc...
Chain verified: true
Agent health: 85/A
Signed: ed25519:...
```

---

## Forensic Reconstruction

Given a complete session journal, you can reconstruct exactly what happened:

```python
def reconstruct_session(pid, from_seq, to_seq):
    journal  = p.get_books_journal(limit=1000)
    entries  = [e for e in journal["entries"]
                if from_seq <= e["seq_no"] <= to_seq]
    receipts = p.list_audit_receipts(pid)
    
    timeline = []
    for entry in entries:
        timeline.append({
            "seq":      entry["seq_no"],
            "time":     entry.get("timestamp"),
            "event":    entry["action"],
            "outcome":  entry["outcome"],
            "cid":      entry.get("cid")
        })
    return timeline
```

---

## Next Steps

- **[20 — CID, DAG, and CBOR](20-theory-cid-dag-cbor.md)**
- **[31 — API: Audit](31-api-audit.md)**
- **[37 — Tutorial: Audit Proof](37-tutorial-audit-proof.md)**
- **[59 — The 9 Chains Overview](59-chains-overview.md)**
