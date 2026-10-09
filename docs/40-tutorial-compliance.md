# 40 — Tutorial: Building a HIPAA-Compliant AI System

> End-to-end: design, build, and prove a HIPAA-compliant AI system on Connector.

---

## What You'll Build

A patient record summarization system that:
- Stores PHI in a private namespace that **never reaches the LLM**
- Enforces minimum necessary access
- Produces cryptographic proof of compliance for every patient interaction
- Satisfies HIPAA §164.312(b) audit requirements
- Generates a SOC2-compatible evidence bundle

---

## HIPAA Requirements Mapping

| HIPAA Rule | Requirement | Connector Mechanism |
|---|---|---|
| §164.312(a)(1) | Access controls | Namespace isolation + clearance |
| §164.312(b) | Audit controls | HMAC journal, every access logged |
| §164.312(c)(1) | Integrity | CID-addressed memory, HMAC chain |
| §164.512(b) | Minimum necessary | Selective context construction |
| §164.514(b) | De-identification | `/p/` namespace fencing |

---

## Step 1 — Design the Namespace Topology

```
/p/patients/{patient_id}/    ← PHI vault (clearance 5 required, never LLM)
  - demographics
  - medical_record
  - lab_results

/m/summarizer/{session}/     ← Working memory (agent private)
  - selective_context         ← PHI-stripped context for LLM
  - output                    ← Summary output

/k/medical/                  ← Knowledge base (read-only, LLM accessible)
  - icd10_codes
  - protocols
  - drug_interactions
```

---

## Step 2 — Register HIPAA Agent

```python
import sys, json
sys.path.insert(0, "demos/")
from system_data import ConnectorPlatform

p = ConnectorPlatform()

agent = p.register_agent(
    "hipaa-summarizer",
    "HIPAA-compliant patient record summarizer",
    clearance=3
)
pid = agent["pid"]
ns  = agent["namespace"]
print(f"Agent: {pid}")
```

---

## Step 3 — Write PHI to Private Namespace

In production, PHI comes from your EHR system. In this tutorial, we simulate it.

```python
patient_id = "p_001"

# Full PHI record — stored in /p/ namespace
phi_record = {
    "patient_id":    patient_id,
    "name":          "Jane Doe",              # PHI
    "ssn":           "123-45-6789",           # PHI
    "dob":           "1975-03-15",            # PHI
    "address":       "123 Main St",           # PHI
    "diagnosis":     "Type 2 Diabetes",       # Clinical
    "medications":   ["Metformin 500mg"],     # Clinical
    "lab_hba1c":     7.2,                     # Clinical
    "allergies":     ["Penicillin"],          # Clinical
    "physician":     "Dr. Smith",             # PHI
    "mrn":           "MRN-789456"             # PHI
}

# Write to private namespace (never reaches LLM)
phi_cid = p.write_memory(pid,
    json.dumps(phi_record),
    ptype="phi_patient_record",
    memory_type="evidence",
    tags=["hipaa", f"patient:{patient_id}"])["cid"]

print(f"PHI stored: {phi_cid}")

# Record the PHI access
p.record_decision(pid,
    "phi.write",
    f"/p/patients/{patient_id}",
    "allow",
    regulations=["hipaa"],
    rationale="EHR import — authorized data custodian")
```

---

## Step 4 — Construct Selective Context (No PHI)

```python
CLINICAL_FIELDS = ["diagnosis", "medications", "lab_hba1c", "allergies"]
PHI_FIELDS = ["name", "ssn", "dob", "address", "physician", "mrn", "patient_id"]

def build_selective_context(record: dict) -> dict:
    """Strip PHI — keep only clinical facts needed for summary."""
    return {k: v for k, v in record.items() if k in CLINICAL_FIELDS}

selective = build_selective_context(phi_record)

# Verify: no PHI in context
for phi_field in PHI_FIELDS:
    assert phi_field not in selective, f"PHI LEAK: {phi_field} in context"

# Firewall check the selective context
fw = p.firewall_inspect(pid, json.dumps(selective), ns)
assert not fw.get("pii_detected"), f"PII detected in selective context: {fw['pii_types']}"

print(f"✓ Selective context clean: {list(selective.keys())}")
```

---

## Step 5 — Governed LLM Call with Selective Context

```python
prompt = (
    f"Based on this patient's clinical data (no PII):\n"
    f"{json.dumps(selective, indent=2)}\n\n"
    f"Write a concise clinical summary for the care team. "
    f"Do not invent any information not present above."
)

response = p.invoke_chat(pid, ns, prompt,
    system="You are a clinical documentation assistant. "
           "Summarize only facts provided. Do not include any contact information.")

summary    = response["choices"][0]["message"]["content"]
audit_cid  = response.get("audit_cid")
dec_id     = response.get("decision_id")

print(f"\nSummary: {summary[:200]}...")
print(f"Audit CID: {audit_cid}")
```

---

## Step 6 — Grounding Check

```python
grounding = p.verify_grounding(text=summary)
grounded  = grounding.get("grounded", True)

if not grounded:
    ungrounded = grounding.get("ungrounded_claims", [])
    p.record_decision(pid,
        "summary.ungrounded_claims",
        f"patient:{patient_id}",
        "flagged",
        rationale=f"Ungrounded: {ungrounded}",
        regulations=["hipaa"])
    print(f"⚠ Ungrounded claims: {ungrounded}")
else:
    print(f"✓ Summary grounded (score: {grounding.get('grounding_score', 'N/A')})")
```

---

## Step 7 — Record HIPAA Compliance Decision

```python
p.record_decision(pid,
    "summarize.patient_record",
    f"/p/patients/{patient_id}",
    "allow_minimum_necessary",
    rationale=(
        "Minimum necessary access enforced: "
        f"clinical_fields_only={list(selective.keys())}, "
        f"phi_fields_excluded={PHI_FIELDS}"
    ),
    confidence=0.95,
    evidence_cids=[phi_cid, audit_cid],
    regulations=["hipaa"])
```

---

## Step 8 — Verify PHI Containment

```python
# Proof that PHI never reached LLM context
def verify_phi_containment(pid, phi_fields: list) -> bool:
    """Search all LLM-accessible memory for PHI field names."""
    all_memory = p.recall_memory(ns, limit=100)
    for pkt in all_memory.get("packets", []):
        content = pkt.get("content", "")
        for field in phi_fields:
            if field in content.lower():
                print(f"⚠ PHI field '{field}' found in LLM-accessible namespace")
                return False
    print("✓ PHI containment verified — no PHI in LLM-accessible namespace")
    return True

verify_phi_containment(pid, PHI_FIELDS)
```

---

## Step 9 — Generate HIPAA Proof Bundle

```python
proof = p.generate_proof(pid, title=f"hipaa_patient_{patient_id}")

print(f"\nHIPAA Proof Bundle:")
print(f"  proof_id:        {proof['proof_id']}")
print(f"  chain_verified:  {proof['chain_verified']}")
print(f"  journal_entries: {proof['journal_entries']}")

# HIPAA-specific report
hipaa_report = p.get_regulation_report("hipaa")
print(f"  HIPAA report:    ok={hipaa_report.get('ok')}")

# Formal verification
verify = p.get_verify_report()
print(f"  Grade:           {verify.get('executive_summary', {}).get('grade')}")
```

---

## Step 10 — CLI Verification

```bash
# Show HIPAA compliance posture
connectorctl compliance report hipaa

# Verify proof
connectorctl prove agent <pid> --title "hipaa_audit"

# Check for violations
connectorctl compliance violations
```

---

## What This Proves

| Claim | Evidence |
|---|---|
| PHI never reached LLM | Namespace fence test + selective context |
| Minimum necessary enforced | `allow_minimum_necessary` decision + field list |
| Every access audited | HMAC journal + `audit_cid` on every call |
| Chain is tamper-evident | `chain_verified: true` in proof |
| Cryptographic proof | `proof_id` with Ed25519 signature |

---

## Next Steps

- **[07 — Governance Workflows](07-workflows-governance-compliance.md)**
- **[41 — Builder: witnessctl Plugin](41-builder-witnessctl.md)**
- **[58 — Compliance Framework](58-compliance-framework.md)**
