# Code Dictionary — Python

> Every Python pattern explained: what to write, what it does, what you get back.
> Covers simple chatbot → enterprise pipeline → military-grade kernel access.

---

## How to Read This Dictionary

Each entry shows:
1. **The code** — exact, copy-pasteable
2. **What it does** — plain English
3. **What you get back** — exact return type and fields
4. **When to use it** — the right scenario

---

## Setup

```python
# Build the Rust FFI bridge first:
# cd vac/crates/vac-ffi && maturin develop --release

from vac_ffi import Connector
import os

# All examples assume this connector unless noted:
c = Connector(
    "deepseek",
    "deepseek-chat",
    os.environ["DEEPSEEK_API_KEY"]
)
```

---

## Pattern 1 — Hello World (3 lines)

```python
c = Connector("deepseek", "deepseek-chat", os.environ["DEEPSEEK_API_KEY"])
agent = c.agent("bot", "You are a helpful assistant.")
result = agent.run("What is 2+2?", "user:alice")
print(result.text)
```

**What you get back:**
```
result.text        → "2+2 equals 4."
result.trust       → 100
result.trust_grade → "A+"
result.ok          → True
result.cid         → "bafyreigima..."   ← content-addressed hash of the response
result.verified    → True
result.duration_ms → 843
```

**When to use:** Any simple chatbot, FAQ bot, internal tool.

---

## Pattern 2 — Load from YAML

```python
# connector.yaml has all config — no secrets in code
c = Connector.from_config("connector.yaml")
agent = c.agent("bot", "You are helpful.")
result = agent.run("Hello!", "user:alice")
```

**What it does:** Reads `connector.yaml`, interpolates `${ENV_VAR}` references, validates all fields, builds the Connector. Raises `ConfigError` if any required field is missing or env var is not set.

**When to use:** Any production code. Never hardcode API keys.

---

## Pattern 3 — Remember and Recall (Persistent Memory)

```python
# Store a fact
cid = agent.remember("Patient John Doe is allergic to Penicillin", "patient:P-001")
print(f"Stored as CID: {cid}")   # bafyreihgvk...

# Later — recall relevant facts
memories = agent.recall("allergies", "patient:P-001")
for m in memories:
    print(m["payload"])   # "Patient John Doe is allergic to Penicillin"
    print(m["cid"])       # bafyreihgvk...
```

**What `remember` returns:** `str` — the CID of the stored packet. Same content → same CID always.

**What `recall` returns:** `list[dict]` — each dict has `payload`, `cid`, `packet_type`, `timestamp`, `namespace`.

**When to use:** Any agent that needs to remember facts across conversations.

---

## Pattern 4 — Multi-Agent Pipeline (Sequential)

```python
# Agent 1: triage
triage = c.agent("triage", "Classify patients by urgency 1-5.")
t = triage.run("Patient: 45M, chest pain 2h, BP 158/95", "patient:P-001")

# Agent 2: doctor (reads triage memory automatically via AccessGrant)
doctor = c.agent("doctor", "Diagnose based on triage data.")
d = doctor.run("What is the diagnosis for patient P-001?", "patient:P-001")

print(f"Triage:    {t.text}")
print(f"Diagnosis: {d.text}")
print(f"Trust:     {d.trust}/100 ({d.trust_grade})")
```

**What happens internally:**
1. `triage.run()` → writes input + response to `ns:triage`
2. `doctor.run()` → kernel auto-grants read access to `ns:triage` (because `memory_from: [triage]` in YAML or set via builder)
3. Doctor's context includes triage packets

**When to use:** Any sequential workflow — triage→diagnosis, research→write, plan→execute.

---

## Pattern 5 — Check Trust Score

```python
result = agent.run("Summarize the patient's history", "patient:P-001")

print(f"Trust score: {result.trust}/100")
print(f"Grade:       {result.trust_grade}")   # A+ | A | B | C | D | F
print(f"Verified:    {result.verified}")       # True = all events kernel-verified

# Detailed provenance
prov = result.provenance()
# prov = {"kernel_verified": 4, "llm_unverified": 1, "total": 5, "trust_percentage": 80.0}
print(f"Kernel-verified events: {prov['kernel_verified']}/{prov['total']}")
```

**When to use:** Any regulated use case — healthcare, finance, legal. Show trust score to users.

---

## Pattern 6 — Compliance Report

```python
result = agent.run("Assess patient risk", "patient:P-001")

# Get HIPAA compliance report
report_json = result.to_json()
import json
report = json.loads(report_json)

# Or use the comply() method (Rust-side)
# result.comply("hipaa")  → ComplianceReport with score, grade, controls
```

**What you get:**
```json
{
  "text": "...",
  "trust": 95,
  "trust_grade": "A+",
  "provenance": {
    "kernel_verified": 6,
    "llm_unverified": 1,
    "total": 7,
    "trust_percentage": 85.7
  },
  "warnings": [],
  "errors": []
}
```

**When to use:** HIPAA, SOC2, GDPR audits. Export this JSON as your compliance evidence.

---

## Pattern 7 — Kernel Stats and Audit Trail

```python
# How many packets in memory?
print(f"Packets: {c.packet_count()}")
print(f"Audit:   {c.audit_count()}")

# Export full kernel state
import json
snap = json.loads(c.kernel_export(10))  # last 10 audit entries

stats = snap["stats"]
print(f"Total agents:  {stats['total_agents']}")
print(f"Total packets: {stats['total_packets']}")
print(f"Audit entries: {stats['total_audit_entries']}")
print(f"Namespaces:    {stats['namespaces']}")

# Print audit trail
for entry in snap["audit_tail"]:
    print(f"[{entry['outcome']:8}] {entry['operation']:20} {entry['duration_us']}µs")
```

**What `kernel_export(n)` returns:** JSON string with `stats`, `agents`, `sessions`, `namespaces`, `audit_tail`.

**When to use:** Debugging, compliance audits, monitoring dashboards.

---

## Pattern 8 — Integrity Check

```python
ok, error_count = c.integrity_check()
if ok:
    print("✅ All packets intact — no tampering detected")
else:
    print(f"❌ {error_count} integrity errors — possible tampering!")
```

**What it checks:**
- Every packet's CID matches its content (tamper detection)
- Session index consistency
- No duplicate CIDs in namespace index

**When to use:** After loading from persistent storage, before any compliance audit, after any suspected incident.

---

## Pattern 9 — Export Formats

```python
result = agent.run("Diagnose patient", "patient:P-001")

# Machine-readable JSON with provenance tags
json_output = result.to_json()

# OpenTelemetry spans (send to Jaeger, Grafana Tempo, etc.)
otel_output = result.to_otel()

# LLM-friendly summary (feed to another LLM)
llm_summary = result.to_llm()

# Check zero-fake guarantee
all_verified = result.is_verified()
print(f"Zero-fake: {'✅' if all_verified else '⚠️'}")
```

**When to use:**
- `to_json()` → store in database, send to API
- `to_otel()` → send to observability platform
- `to_llm()` → chain to another agent
- `is_verified()` → compliance gate — only proceed if True

---

## Pattern 10 — Error Handling

```python
from vac_ffi import (
    KernelError, KernelDenied, BudgetExceeded,
    RateLimited, AgentNotFound
)

try:
    result = agent.run("...", "user:alice")
    if not result.ok:
        print(f"Agent failed: {result.errors}")
    if result.warnings:
        print(f"Warnings: {result.warnings}")
except KernelDenied as e:
    print(f"Access denied: {e}")
    # → agent tried to read a namespace it doesn't have access to
except BudgetExceeded as e:
    print(f"Budget exceeded: {e}")
    # → token or cost limit hit
except RateLimited as e:
    print(f"Rate limited: {e}")
    # → too many calls per minute
except KernelError as e:
    print(f"Kernel error: {e}")
    # → catch-all for other kernel errors
```

---

## Pattern 11 — Tool Definition and Use

```python
# Define a tool in connector.yaml (see 31_YAML_DICTIONARY.md)
# Then call it from your agent:

result = agent.run(
    "Look up patient P-001's medication history and check for contraindications",
    "patient:P-001"
)
# The LLM will call classify_patient() and lookup_vitals() tools automatically
# Each tool call is logged as a ToolCall + ToolResult MemPacket in the kernel
# Each tool call requires a VAKYA authorization token (auto-built)

# See which tools were called:
import json
output = json.loads(result.to_json())
# output["steps"] → list of pipeline steps including tool calls
```

---

## Pattern 12 — Session Management

```python
# All packets from one conversation grouped under a session
# Sessions are created automatically per agent.run() call
# To explicitly group multiple runs under one session:

import json

# Run 1
r1 = agent.run("Patient arrives with chest pain", "patient:P-001")

# Run 2 (same patient, same session)
r2 = agent.run("Patient's BP is now 170/100", "patient:P-001")

# All packets from both runs are in ns:triage
# They share the same subject_id (patient:P-001)
snap = json.loads(c.kernel_export(20))
print(f"Total packets: {snap['stats']['total_packets']}")
```

---

## Pattern 13 — HIPAA-Compliant Healthcare Agent

```python
import os
from vac_ffi import Connector

# Load HIPAA config from YAML
c = Connector.from_config("hospital.yaml")
# hospital.yaml has: comply=[hipaa], signing=true, data_classification=PHI,
#                    retention_days=2555, firewall.preset=hipaa

# Triage agent
triage = c.agent("triage", """
You are a medical triage nurse. Classify patient urgency 1-5.
1=immediate, 2=emergent, 3=urgent, 4=less urgent, 5=non-urgent.
Always cite vital signs in your assessment.
""")

# Doctor agent (reads triage memory)
doctor = c.agent("doctor", """
You are an emergency physician. Review triage data and provide:
1. Primary diagnosis with ICD-10 code
2. Differential diagnoses
3. Immediate treatment plan
""")

# Run pipeline
patient_input = "45M, chest pain 2h, radiating to left arm, diaphoresis, BP 158/95, HR 102"

t = triage.run(patient_input, "patient:P-44291")
print(f"Triage: {t.text}")
print(f"Trust:  {t.trust}/100 ({t.trust_grade})")

d = doctor.run(f"Patient {patient_input}. Triage: {t.text}", "patient:P-44291")
print(f"Diagnosis: {d.text}")

# Compliance check
import json
snap = json.loads(c.kernel_export(10))
print(f"\nKernel stats:")
print(f"  Packets: {snap['stats']['total_packets']}")
print(f"  Audit:   {snap['stats']['total_audit_entries']}")

ok, errors = c.integrity_check()
print(f"  Integrity: {'PASS' if ok else 'FAIL'} ({errors} errors)")
```

**What you get:** Full HIPAA audit trail, tamper-evident packets, trust score, compliance evidence — all from 20 lines of Python.

---

## Pattern 14 — Finance Fraud Detection Pipeline

```python
c = Connector.from_config("finance.yaml")
# finance.yaml: comply=[soc2, gdpr], signing=true, pii_types=[credit_card, ssn]

analyzer = c.agent("fraud_analyzer", """
Analyze transactions for fraud indicators.
Flag: unusual amounts, geographic anomalies, velocity patterns.
Output: risk_score (0-100), indicators (list), recommendation (approve/review/block).
""")

explainer = c.agent("explainer", """
Explain fraud decisions in plain English for compliance reports.
Cite specific transaction data. Be precise.
""")

# Analyze transaction
tx = "Transaction: $4,200 at 3:47 AM, merchant: Electronics Store, location: Lagos, Nigeria. Card holder is in New York."
analysis = analyzer.run(tx, "user:card-holder-8821")

# Explain for compliance
explanation = explainer.run(
    f"Transaction: {tx}\nAnalysis: {analysis.text}",
    "user:card-holder-8821"
)

print(f"Risk analysis: {analysis.text}")
print(f"Explanation:   {explanation.text}")
print(f"Trust score:   {explanation.trust}/100")

# Export for SOC2 audit
import json
audit_json = explanation.to_json()
with open("fraud_audit.json", "w") as f:
    f.write(audit_json)
```

---

## Pattern 15 — Military-Grade Secure Agent

```python
import os
from vac_ffi import Connector, KernelDenied, BudgetExceeded

# Air-gapped: local Ollama, no external calls
c = Connector(
    "ollama",
    "llama3.2",
    "local",
    endpoint="http://localhost:11434"
)
# For full DoD config, use Connector.from_config("dod.yaml")
# dod.yaml: comply=[dod], signing=true, scitt=true, data_classification=TOP_SECRET,
#            require_mfa=true, max_delegation_depth=1, firewall.preset=strict

intel_analyst = c.agent("intel_analyst", """
Analyze intelligence reports. Classify findings by confidence level.
ALWAYS cite source documents. NEVER speculate without evidence.
""")

try:
    result = intel_analyst.run(
        "Analyze the following SIGINT report: [REDACTED]",
        "operator:ID-7734"
    )

    # Verify before using output
    if not result.is_verified():
        raise RuntimeError("Output not kernel-verified — cannot use")

    if result.trust < 90:
        raise RuntimeError(f"Trust score {result.trust} below threshold (90)")

    print(f"Analysis: {result.text}")
    print(f"Trust: {result.trust}/100 ({result.trust_grade})")

    # Chain-of-custody export
    import json
    custody = json.loads(result.to_json())
    print(f"CID: {custody['cid']}")   # immutable proof of this output

    # Integrity check before filing
    ok, errors = c.integrity_check()
    assert ok, f"Integrity check failed: {errors} errors"

except KernelDenied as e:
    print(f"SECURITY: Access denied — {e}")
except BudgetExceeded as e:
    print(f"SECURITY: Budget exceeded — {e}")
```

---

## Complete Field Reference

### Connector constructor
```python
Connector(provider, model, api_key, endpoint=None)
Connector.from_config(path: str)
Connector.from_config_str(yaml: str)
```

### Connector methods
```python
c.agent(name: str, instructions: str) → AgentHandle
c.packet_count() → int
c.audit_count() → int
c.integrity_check() → (bool, int)   # (all_ok, error_count)
c.kernel_export(audit_tail_limit: int) → str  # JSON
```

### AgentHandle methods
```python
agent.run(message: str, user_id: str) → PipelineOutput
agent.remember(text: str, user_id: str) → str  # returns CID
agent.recall(query: str, user_id: str) → list[dict]
```

### PipelineOutput fields
```python
result.text          # str — LLM response
result.trust         # int — 0-100
result.trust_grade   # str — A+/A/B/C/D/F
result.ok            # bool
result.verified      # bool
result.cid           # str — CID of response packet
result.trace_id      # str
result.duration_ms   # int
result.warnings      # list[str]
result.errors        # list[str]
result.actors        # list[str] — agent PIDs
result.steps         # list[str] — pipeline steps
result.event_count   # int
result.span_count    # int
```

### PipelineOutput methods
```python
result.to_json() → str        # JSON with provenance tags
result.to_otel() → str        # OTLP spans
result.to_llm() → str         # LLM-friendly summary
result.provenance() → dict    # {kernel_verified, llm_unverified, total, trust_percentage}
result.is_verified() → bool   # all events kernel-verified?
```
