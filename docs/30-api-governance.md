# 30 — API: Governance, Decisions, and HITL

> Decision recording, policy evaluation, and human-in-the-loop endpoints.

---

## `POST /api/v1/disputes/record` — Record Decision

```json
// Request
{
  "agent_pid":   "agent_abc123",
  "action":      "summarize.patient_record",
  "target":      "/p/patients/p001",
  "outcome":     "allow_minimum_necessary",
  "model_name":  "gpt-4o",
  "rationale":   "Attending physician access, treatment purpose",
  "confidence":  0.95,
  "evidence_cids": ["mem1-sha256-abc..."],
  "regulations": ["hipaa", "soc2"]
}
```

```json
// Response (top-level — no .data wrapper)
{
  "decision_id":          "dec_63de9107-d5c8-4fa4-a59b-c6b27db15c8b",
  "action":               "summarize.patient_record",
  "agent_pid":            "agent_abc123",
  "target":               "/p/patients/p001",
  "outcome":              "allow_minimum_necessary",
  "confidence":           0.95,
  "regulations":          ["hipaa", "soc2"],
  "audit_chain_verified": true,
  "immutable":            true,
  "content_hash":         "sha256:18371112...",
  "signature":            "ed25519:34d0bdcb...",
  "trust_grade":          "A",
  "agent_health_score":   85,
  "public_key_hex":       "34d0bdcb0687806e..."
}
```

---

## `GET /api/v1/disputes/:decision_id` — Retrieve Decision

```
GET /api/v1/disputes/dec_63de9107-d5c8-4fa4-a59b-c6b27db15c8b
```

Returns the full decision record including rationale, evidence CIDs, and chain verification status.

---

## `GET /api/v1/disputes/:decision_id/report` — Decision Report

Full formatted report for a specific decision, including:
- Decision details
- Evidence chain
- Regulation mapping
- Audit CID links

---

## `GET /api/v1/disputes/:decision_id/defense-package` — Defense Package

Generates a compliance defense package for a specific decision — useful when responding to audit requests about a particular governance decision.

---

## `POST /api/v1/agents/:pid/policy/check` — Policy Check

```json
// Request
{
  "operation": "mem_read",
  "resource":  "/p/patients/p001"
}
```

```json
// Response
{
  "verdict":     "DENY",
  "reason":      "namespace_isolation: /p/ requires clearance 5",
  "enforcement": "kernel_policy",
  "allowed":     false,
  "reader_pid":  "agent_abc123",
  "target_ns":   "/p/patients/p001",
  "raw": {...}
}
```

---

## `GET /api/v1/compliance/policy-violations` — Policy Violations

```json
{
  "violations": [
    {
      "decision_id": "dec_uuid...",
      "action":      "attempted_phi_access",
      "outcome":     "denied",
      "severity":    "high",
      "regulation":  "hipaa",
      "timestamp":   "2026-04-16T09:00:00Z"
    }
  ],
  "count": 1
}
```

---

## HITL Endpoints

### `GET /api/v1/agents/:pid/hitl/pending` — List Pending HITL

```json
{
  "requests": [
    {
      "request_id":   "hitl_req_abc",
      "reason":       "Confidence below threshold: 0.65 < 0.85",
      "agent_pid":    "agent_abc123",
      "action":       "recommend_treatment",
      "data":         {"patient_id": "p001", "recommendation": "..."},
      "timeout_at":   "2026-04-16T10:00:00Z",
      "created_at":   "2026-04-16T09:00:00Z"
    }
  ],
  "count": 1
}
```

### `POST /api/v1/agents/:pid/hitl/:request_id/approve`

```json
// Request (optional reason)
{"reason": "Reviewed and approved by Dr. Smith"}

// Response
{"ok": true, "request_id": "hitl_req_abc", "outcome": "approved"}
```

### `POST /api/v1/agents/:pid/hitl/:request_id/deny`

```json
// Request
{"reason": "Insufficient evidence for this recommendation"}

// Response
{"ok": true, "request_id": "hitl_req_abc", "outcome": "denied"}
```

---

## `GET /api/v1/actionlog/regulation-report/:framework` — Regulation Report

```
GET /api/v1/actionlog/regulation-report/soc2
GET /api/v1/actionlog/regulation-report/hipaa
GET /api/v1/actionlog/regulation-report/gdpr
```

```json
{
  "framework":    "soc2",
  "report":       {...},
  "export_formats": ["json", "csv", "markdown"],
  "generated_at": "2026-04-16T09:00:00Z",
  "ok":           true
}
```

---

## Decision Schema Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `agent_pid` | string | Yes | Agent making the decision |
| `action` | string | Yes | Action being decided on |
| `target` | string | Yes | Resource/target of the action |
| `outcome` | string | Yes | Decision outcome |
| `model_name` | string | No | LLM model used |
| `rationale` | string | No | Human-readable explanation |
| `confidence` | float | No | 0.0–1.0 confidence score |
| `evidence_cids` | list | No | Memory CIDs supporting decision |
| `regulations` | list | No | Applicable regulation tags |

**Outcome values:** Any string, but common values:
- `allow`, `deny`, `allow_with_audit`, `deny_and_alert`
- `allow_minimum_necessary`, `allow_with_hitl`
- `blocked`, `redacted`, `escalated`

---

## Querying Decisions

```python
# Get all decisions for an agent (via journal)
journal = p.get_books_journal(limit=500)
decisions = p.get_policy_decisions(limit=100)

# Get decisions by regulation
report = p.get_regulation_report("hipaa")

# Get specific decision
dec = p.get_dispute_report("dec_uuid...")
```

---

## Next Steps

- **[16 — Ring 5: Policy and Governance](16-ring-5-policy-governance.md)**
- **[31 — API: Audit and Proof](31-api-audit.md)**
- **[39 — Tutorial: HITL Workflows](39-tutorial-hitl.md)**
