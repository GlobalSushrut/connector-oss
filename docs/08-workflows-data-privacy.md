# 08 — Data Privacy and PHI Workflows

> 25 workflow patterns for data-sensitive systems.

---

## DP-01: Selective Context Construction

**The core privacy pattern.** The system knows everything. The LLM sees only what the task requires.

```
Full Internal State             Selective LLM Context
─────────────────               ─────────────────────
/p/patients/p001                "Patient has diabetes.
  name: John Doe       ──────►  Medication: Metformin."
  ssn: 123-45-6789     ✗        (no PII, no SSN, no name)
  dob: 1970-01-01      ✗
  dx: diabetes         ✓
  rx: metformin        ✓
  address: 123 Main    ✗
```

```python
# Write full PHI to private namespace
p.write_memory(pid, full_patient_json, memory_type="working")

# Construct selective context — extract only needed fields
selective = {
    "diagnosis": patient["diagnosis"],
    "current_medications": patient["medications"],
    "relevant_history": patient["relevant_history"]
    # NO: name, SSN, DOB, contact info, address
}

# Pass selective context to LLM — not the full record
response = p.invoke_chat(pid, ns,
    f"Summarize treatment plan for: {json.dumps(selective)}")
```

---

## DP-02: PII Detection and Redaction

```python
# Before any outbound call or LLM invocation
fw = p.firewall_inspect(pid, content, ns)

if fw.get("pii_detected"):
    # Redact and log
    p.record_decision(pid, "pii.detected", "content",
                      "redact_and_allow", regulations=["gdpr"])
    # Use redacted version
    content = fw.get("redacted_content", content)
```

---

## DP-03: Namespace Isolation (Multi-Tenant)

Each tenant's data lives in its own fenced namespace. Cross-tenant access is architecturally impossible.

```
/p/hospital-a/patients/     ← Tenant A PHI
/p/hospital-b/patients/     ← Tenant B PHI
/m/hospital-a/agents/       ← Tenant A memory
/m/hospital-b/agents/       ← Tenant B memory
```

```python
# Agent for hospital-a cannot read hospital-b's namespace
result = p.test_mac_enforcement(
    reader_pid=agent_a_pid,
    target_ns="/p/hospital-b/patients"
)
assert result["verdict"] == "DENY"   # enforced at Ring 4
```

---

## DP-04: Identity-Aware Execution

```python
# Agent knows WHO is asking — but the LLM does not see the identity
caller_role = "attending_physician"
p.write_memory(pid, json.dumps({"caller_role": caller_role,
                                "authorized_for": ["treatment_summary"]}),
               memory_type="working")

# Policy check before action
check = p.policy_check(pid, "read_phi", f"/p/patients/{patient_id}")
if check["verdict"] != "ALLOW":
    raise PermissionError(f"Denied: {check['reason']}")
```

---

## DP-05: Cryptographic Data Minimization Proof

```python
# Generate proof that PHI never reached LLM
proof = p.generate_proof(pid, title="phi_minimization_proof")

# Proof contains:
# - Namespace access log (no /p/ reads in LLM calls)
# - Firewall events (pii_detected flags)
# - Decision records (minimization tag)
# - HMAC chain (tamper-evident)
```

---

## DP-06: PHI Field Classification

```python
# Classify all fields in a document
fields = {
    "name": "John Doe",
    "ssn": "123-45-6789",
    "diagnosis": "Type 2 Diabetes",
    "physician": "Dr. Smith",
    "medication": "Metformin 500mg"
}

for field, value in fields.items():
    fw = p.firewall_inspect(pid, str(value), ns)
    classification = "phi" if fw.get("pii_detected") else "clinical"
    print(f"{field}: {classification}")
    # name → phi, ssn → phi, diagnosis → clinical
    # physician → phi, medication → clinical
```

---

## DP-07: Cross-Border Data Residency

```yaml
# namespace declaration — EU data stays in EU cell
namespaces:
  - path: /p/eu-customers/
    data_residency: eu
    allowed_cells: [connector-eu-01, connector-eu-02]
    transfer_policy: deny_cross_border
```

```python
# Verify data residency before processing
check = p.policy_check(pid, "mem_read", "/p/eu-customers/data")
# Will DENY if the current cell is not in the EU cluster
```

---

## DP-08: Anonymization Chain

Full anonymization pipeline with HMAC-chained proof at each step.

```python
def anonymize_patient(raw_patient: dict) -> dict:
    # Step 1: Remove direct identifiers
    p.record_decision(pid, "anonymize.step1.remove_identifiers",
                      patient_id, "allow", regulations=["gdpr"])
    step1 = {k: v for k, v in raw_patient.items()
             if k not in ["name","ssn","dob","address","phone","email"]}

    # Step 2: Generalize quasi-identifiers
    p.record_decision(pid, "anonymize.step2.generalize",
                      patient_id, "allow", regulations=["gdpr"])
    if "age" in step1:
        step1["age_band"] = f"{(step1['age'] // 10) * 10}s"
        del step1["age"]

    # Step 3: Generate anonymization certificate
    proof = p.generate_proof(pid, title=f"anonymization_{patient_id}")

    return step1, proof["proof_id"]
```

---

## DP-09: De-identification with Re-linkage Prevention

```python
import hashlib, secrets

# Generate a deterministic pseudonym that cannot be reversed
salt = secrets.token_hex(32)  # stored in /s/ namespace, never exposed
pseudonym = hashlib.sha256(f"{patient_id}{salt}".encode()).hexdigest()[:16]

# Store mapping in private namespace (never exposed to LLM)
p.write_memory(pid,
    json.dumps({"pseudonym": pseudonym, "real_id": patient_id, "salt_ref": "/s/salt"}),
    memory_type="working")  # write to /s/ in production
```

---

## DP-10: PHI Vault Access with Audit

Every access to the PHI vault (`/p/` namespace) is logged and tagged.

```python
def read_phi(pid: str, patient_id: str, purpose: str) -> dict:
    # Policy check first
    check = p.policy_check(pid, "mem_read", f"/p/patients/{patient_id}")
    if check["verdict"] != "ALLOW":
        raise PermissionError(check["reason"])

    # Record access with purpose
    p.record_decision(pid, "phi.vault_access", f"/p/patients/{patient_id}",
                      "allow", regulations=["hipaa"],
                      rationale=f"Purpose: {purpose}")

    # Read
    return p.recall_memory(f"/p/patients/{patient_id}", limit=1)
```

---

## DP-11: Patient Consent Gate

```python
def check_consent(pid: str, patient_id: str, purpose: str) -> bool:
    consent = p.recall_memory(f"/p/patients/{patient_id}/consent", limit=1)
    packets = consent.get("packets", [])

    if not packets:
        p.record_decision(pid, "consent.missing", patient_id,
                          "deny", regulations=["hipaa", "gdpr"])
        return False

    consent_data = json.loads(packets[0]["content"])
    if purpose not in consent_data.get("authorized_purposes", []):
        p.record_decision(pid, "consent.purpose_mismatch", patient_id,
                          "deny", regulations=["hipaa"])
        return False

    p.record_decision(pid, "consent.verified", patient_id,
                      "allow", regulations=["hipaa", "gdpr"])
    return True
```

---

## DP-13: Namespace Fence Test

Verify that namespace isolation is enforced (use in CI/CD):

```python
def test_namespace_fence(agent_a_pid, agent_b_ns):
    result = p.test_mac_enforcement(agent_a_pid, agent_b_ns)
    assert result["verdict"] == "DENY", \
        f"SECURITY FAILURE: Agent {agent_a_pid} can read {agent_b_ns}"
    print(f"✓ Namespace fence enforced: {agent_a_pid} cannot read {agent_b_ns}")
```

---

## DP-15: PHI-Safe RAG Pipeline

```python
def phi_safe_rag(pid: str, query: str, patient_id: str) -> str:
    # 1. Retrieve from knowledge base (no PHI)
    knowledge = p.recall_memory("/k/medical", limit=10)

    # 2. Retrieve selective (non-PHI) patient context
    selective = get_selective_context(patient_id)  # strips PHI fields

    # 3. Firewall check on assembled context
    context = json.dumps({"knowledge": knowledge["packets"][:3],
                          "patient_context": selective})
    fw = p.firewall_inspect(pid, context, ns)
    assert not fw.get("pii_detected"), "PHI leaked into context"

    # 4. Governed chat with safe context
    return p.invoke_chat(pid, ns,
        f"Given this context: {context}\n\nAnswer: {query}")
```

---

## DP-22: PII Velocity Check

Detect if an agent is accessing/transmitting PII at an unusual rate.

```python
def check_pii_velocity(pid: str, window_minutes: int = 5) -> dict:
    journal  = p.get_books_journal(limit=500)
    entries  = journal.get("entries", [])
    pii_hits = [e for e in entries if "pii" in str(e.get("action","")).lower()]

    velocity = len(pii_hits) / window_minutes
    if velocity > 10:  # more than 10 PII events per minute
        p.record_decision(pid, "pii.velocity_alert", "journal",
                          "alert", regulations=["gdpr"],
                          rationale=f"PII velocity: {velocity:.1f}/min")
        return {"alert": True, "velocity": velocity}
    return {"alert": False, "velocity": velocity}
```

---

## Privacy Pattern Summary

| Pattern | What it prevents | Regulation |
|---|---|---|
| DP-01 Selective Context | PHI reaching LLM | HIPAA §164.514 |
| DP-02 PII Redaction | PII in outputs | GDPR Art. 25 |
| DP-03 Namespace Isolation | Cross-tenant data leak | HIPAA §164.312(a) |
| DP-05 Minimization Proof | Regulatory denial | GDPR Art. 5(1)(c) |
| DP-08 Anonymization | Re-identification | GDPR Art. 4(1) |
| DP-13 Fence Test | Access control regression | HIPAA §164.312(a) |

---

## Next Steps

- **[09 — DevOps Workflows](09-workflows-devops-execution.md)**
- **[15 — Ring 4: Memory Kernel](15-ring-4-memory-kernel.md)**
- **[40 — Tutorial: HIPAA System](40-tutorial-compliance.md)**
