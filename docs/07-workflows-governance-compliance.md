# 07 — Governance and Compliance Workflows

> 25 workflow patterns for regulated environments.

---

## GC-01: HIPAA Minimum Necessary Enforcement

**Rings:** 3, 4, 5, 8 | **Cost:** Low | **Tags:** hipaa

Enforce the HIPAA minimum necessary principle: the LLM sees only the data required for the specific task, never raw PHI.

### CCL Contract

```ccl
contract HIPAAMinNec {
  intent: "Provide clinical summary without PHI exposure to LLM"

  memory {
    read  /p/patients/{{ patient_id }}    # PHI — read only, never forwarded to LLM
    read  /k/medical/icd10
    write /m/{{ agent_pid }}/summaries
  }

  governance {
    require namespace_clean: /p/patients   # PHI must not appear in LLM context
    require chain_verified: true
    tag hipaa
    on_violation: deny_and_audit
  }
}
```

### Python Implementation

```python
# 1. Register governed agent
agent = p.register_agent("hipaa-agent", "HIPAA minimum necessary", 3)
pid = agent["pid"]
ns  = agent["namespace"]

# 2. Write PHI to private namespace (never reaches LLM)
p.write_memory(pid, patient_json, ptype="phi_record",
               memory_type="evidence", tags=["hipaa", f"patient:{pid}"])

# 3. Firewall inspect the prompt before LLM call
fw = p.firewall_inspect(pid, prompt, ns)
assert not fw["blocked"], f"Firewall blocked: {fw['final_decision']}"

# 4. Governed chat — namespace isolation enforced at Ring 4
response = p.invoke_chat(pid, ns, prompt)

# 5. Record decision with HIPAA tag
p.record_decision(pid, "summarize.patient", f"/p/patients/{pid}",
                  "allow_minimum_necessary", regulations=["hipaa"])
```

### Verification

```bash
connectorctl prove agent <pid>          # generates HIPAA evidence bundle
connectorctl explain <decision_id>      # shows minimum necessary rationale
```

---

## GC-02: SOC2 Audit Trail Generation

**Rings:** 5, 8, 9 | **Cost:** Low | **Tags:** soc2

Every agent action produces a verifiable, HMAC-chained audit entry satisfying SOC2 CC7.

### Key Steps

```python
# All interactions auto-produce journal entries
# Additional explicit decision recording:
p.record_decision(pid, "data.access", resource, "allow",
                  rationale="Authorized read for business purpose",
                  regulations=["soc2"])

# Pull audit journal
journal = p.get_books_journal(limit=100)
entries = journal["entries"]

# Generate SOC2 compliance report
report = p.get_regulation_report("soc2")

# Generate cryptographic proof bundle
proof = p.generate_proof(pid, title="soc2_q1_audit")
```

### SOC2 Trust Service Criteria Coverage

| Criteria | Connector Mechanism |
|---|---|
| CC6 Logical Access | Agent identity + namespace isolation |
| CC7 Monitoring | HMAC journal + firewall events |
| CC7 Audit | `generate_proof` → SOC2 bundle |
| CC9 Change Management | Contract CID versioning |

---

## GC-03: GDPR Right-to-Erasure Agent

**Rings:** 4, 5, 8 | **Cost:** Medium | **Tags:** gdpr

Process a data subject erasure request: locate all data by subject ID, tombstone in journal, remove from namespaces.

### Implementation Pattern

```python
subject_id = "user_12345"

# 1. Find all memory packets for this subject
packets = p.recall_memory(f"m/users/{subject_id}", limit=1000)

# 2. For each packet, record erasure decision
for pkt in packets["packets"]:
    p.record_decision(pid, "erasure.request", pkt["cid"],
                      "erased", regulations=["gdpr"],
                      rationale=f"GDPR Art. 17 request by {subject_id}")

# 3. Tombstone in namespace
# (DELETE /api/v1/memory/:cid for each packet)

# 4. Generate GDPR erasure certificate
proof = p.generate_proof(pid, title=f"gdpr_erasure_{subject_id}")
```

---

## GC-04: EU AI Act Article 13 Transparency

**Rings:** 5, 8, 9 | **Cost:** Low | **Tags:** eu_ai_act

Every LLM output includes an `audit_cid` that allows the user to trace the reasoning to its source data — satisfying EU AI Act Article 13 (transparency for high-risk AI).

### Transparency Response Structure

```python
response = p.invoke_chat_raw(pid, ns, prompt)
body = response["body"]

# Every response contains:
audit_cid   = body.get("audit_cid")      # content-addressed audit entry
decision_id = body.get("decision_id")    # governance decision record

# Expose to end user
transparency_receipt = {
    "model_used": body.get("model"),
    "audit_cid": audit_cid,
    "decision_id": decision_id,
    "verifiable_at": f"{CONNECTOR_URL}/api/v1/decisions/{decision_id}",
    "regulation": "EU AI Act Art. 13"
}
```

---

## GC-05: Multi-Jurisdiction Policy Stack

**Rings:** 5, 8 | **Cost:** Low | **Tags:** hipaa, soc2, gdpr

Stack multiple compliance frameworks on a single agent — all decisions tagged simultaneously.

```python
p.record_decision(pid, action, target, outcome,
                  regulations=["hipaa", "soc2", "gdpr"],
                  rationale="Multi-jurisdiction: HIPAA §164.312, SOC2 CC7, GDPR Art.32")

# Single proof bundle satisfies all three frameworks
proof = p.generate_proof(pid, title="multi_jurisdiction_audit")
```

---

## GC-06: Automated Compliance Report

**Rings:** 5, 8, 9 | **Cost:** Medium | **Tags:** all

Schedule and generate compliance reports automatically.

```python
import datetime

def generate_quarterly_report(framework: str):
    report = p.get_regulation_report(framework)
    proof  = p.generate_proof(pid, title=f"{framework}_q{quarter}")
    
    return {
        "framework": framework,
        "generated_at": datetime.datetime.utcnow().isoformat(),
        "report": report,
        "proof_id": proof.get("proof_id"),
        "chain_verified": True
    }

# Run for all frameworks
for fw in ["hipaa", "soc2", "gdpr"]:
    rpt = generate_quarterly_report(fw)
    print(f"{fw}: proof_id={rpt['proof_id']}")
```

---

## GC-07: Decision Ledger Attestation

Every governance decision in the system forms a ledger that can be attested to a third party.

```python
# Pull all decisions for a time range
decisions = p.get_books_journal(limit=500)

# Generate attestation
proof = p.generate_proof(pid, title="ledger_attestation")

# The proof_id is the attestation reference
# Third party can verify at: POST /api/v1/compliance/verify
```

---

## GC-08: Regulatory Hold Workflow

Freeze all data for a subject under legal or regulatory hold.

```ccl
contract RegulatoryHold {
  intent: "Enforce read-only hold on subject data"
  memory {
    read /p/subjects/{{ subject_id }}
  }
  governance {
    require operation != "delete"
    require operation != "modify"
    tag hipaa
    tag soc2
    on_violation: deny_and_audit
  }
}
```

---

## GC-09: Incident Response Chain

**Rings:** 5, 7, 8 | **Cost:** High | **Tags:** soc2

Structured incident response with a governed audit trail from detection to resolution.

```python
# 1. Detect incident (firewall event or manual trigger)
incident_id = f"inc_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

# 2. Record incident open
p.record_decision(pid, "incident.open", incident_id, "investigating",
                  regulations=["soc2"], confidence=1.0,
                  rationale="Automated detection: firewall anomaly score > 0.8")

# 3. Collect evidence
journal  = p.get_books_journal(limit=200)
fw_evts  = p.get_guard_verdicts(limit=50)

# 4. Record resolution
p.record_decision(pid, "incident.resolve", incident_id, "contained",
                  regulations=["soc2"], rationale="Root cause: prompt injection attempt")

# 5. Seal incident bundle
proof = p.generate_proof(pid, title=f"incident_{incident_id}")
```

---

## GC-10 through GC-25: Additional Patterns

### GC-10: PHI Access Logging
```python
# Automatic — any read from /p/ namespace is logged
# Additional explicit tagging:
p.record_decision(pid, "phi.read", "/p/patients/p001", "allow",
                  regulations=["hipaa"], rationale="Treatment purpose")
```

### GC-13: HITL Escalation Chain
```python
# Check for pending HITL requests
pending = p.list_hitl_pending(pid)
for req in pending["requests"]:
    # Route to human reviewer
    print(f"Review required: {req['request_id']} — {req['reason']}")
    # After human decision:
    p.hitl_approve(pid, req["request_id"])
    # or:
    p.hitl_deny(pid, req["request_id"])
```

### GC-16: Proof Bundle Generation

```python
# Full proof bundle — all 9 chains in one call
proof = p.generate_proof(pid, title="q1_compliance_bundle")
# Returns: proof_id, signed bundle with HMAC chain verification
# Verify offline: POST /api/v1/compliance/verify with bundle
```

### GC-17: Chain Break Detection

```python
journal = p.get_books_journal(limit=1000)
chain_ok = journal.get("t0_chain_verified", True)
if not chain_ok:
    # Alert: tamper detected
    p.record_decision(pid, "audit.chain_break", "journal",
                      "alert_raised", regulations=["soc2"])
```

### GC-25: Formal Verification Report

```python
verify = p.get_verify_report()
summary = verify.get("executive_summary", {})
print(f"Grade: {summary.get('grade')}  "
      f"Invariants: {summary.get('invariants_passed')}  "
      f"Verdict: {summary.get('verdict')}")
```

---

## Compliance Decision Matrix

| Framework | Required Pattern | Evidence API |
|---|---|---|
| HIPAA §164.312(b) | GC-01, GC-10 | `generate_proof` |
| SOC2 CC6 | GC-05, GC-07 | `get_regulation_report("soc2")` |
| SOC2 CC7 | GC-02, GC-17 | `get_books_journal` |
| GDPR Art. 17 | GC-03 | `generate_proof` |
| GDPR Art. 32 | GC-05, GC-07 | `get_regulation_report("gdpr")` |
| EU AI Act Art. 13 | GC-04 | `audit_cid` in every response |
| EU AI Act Art. 14 | GC-13 | HITL queue |

---

## Next Steps

- **[08 — Data Privacy Workflows](08-workflows-data-privacy.md)**
- **[37 — Tutorial: Audit Proof](37-tutorial-audit-proof.md)**
- **[58 — Compliance Framework](58-compliance-framework.md)**
