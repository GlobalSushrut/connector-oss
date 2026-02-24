# Quickstart

> Zero to running in 5 minutes. Pick your use case — follow the path.

---

## Step 0 — Install

```bash
# Clone
git clone https://github.com/GlobalSushrut/connector-oss
cd connector-oss

# Set your LLM API key
export DEEPSEEK_API_KEY=sk-...   # or OPENAI_API_KEY, etc.
```

---

## Choose Your Path

```
What are you building?

  A) Simple chatbot / assistant          → Path A (2 minutes)
  B) Agent with persistent memory        → Path B (3 minutes)
  C) Multi-agent pipeline                → Path C (5 minutes)
  D) Healthcare / HIPAA system           → Path D (5 minutes)
  E) Finance / SOC2 + GDPR system        → Path E (5 minutes)
  F) Legal / audit trail system          → Path F (5 minutes)
  G) Military / DoD grade system         → Path G (5 minutes)
  H) TypeScript / Node.js                → Path H (5 minutes)
  I) Custom tool / industry system       → Path I (5 minutes)
```

---

## Path A — Simple Chatbot (Python, 2 minutes)

**Build:** A chatbot that answers questions with a verifiable trust score.

```bash
# Install
cd vac/crates/vac-ffi && maturin develop --release && cd ../../..
cd sdks/python && pip install -e . && cd ../..
```

```python
# chatbot.py
import os
from vac_ffi import Connector

c = Connector("deepseek", "deepseek-chat", os.environ["DEEPSEEK_API_KEY"])
agent = c.agent("bot", "You are a helpful assistant. Be concise.")

while True:
    msg = input("You: ")
    if msg == "quit": break
    result = agent.run(msg, "user:alice")
    print(f"Bot [{result.trust_grade}]: {result.text}")
```

```bash
python chatbot.py
```

**What you get:** Every response has a trust score (0-100), a CID (tamper-proof hash), and a full audit trail — automatically.

---

## Path B — Agent with Persistent Memory (Python, 3 minutes)

**Build:** An agent that remembers facts across restarts.

```yaml
# memory_agent.yaml
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}
  storage: redb:./data/memory.redb   # persists across restarts
```

```python
# memory_agent.py
import os
from vac_ffi import Connector

c = Connector.from_config("memory_agent.yaml")
agent = c.agent("assistant", "You are a helpful assistant with persistent memory.")

# Store facts
agent.remember("The user's name is Alice and she prefers concise answers.", "user:alice")
agent.remember("Alice is a software engineer working on distributed systems.", "user:alice")

# Query — agent uses stored memory as context
result = agent.run("What do you know about me?", "user:alice")
print(result.text)
# → "You are Alice, a software engineer working on distributed systems..."

print(f"\nMemory: {c.packet_count()} packets stored")
print(f"Trust:  {result.trust}/100 ({result.trust_grade})")
```

**What you get:** Memory survives restarts (redb file). Same content → same CID always. Tamper detection built in.

---

## Path C — Multi-Agent Pipeline (Python, 5 minutes)

**Build:** A research pipeline: Researcher → Analyst → Writer.

```yaml
# research.yaml
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}
  storage: redb:./data/research.redb

agents:
  researcher:
    instructions: "Research the topic thoroughly. List key facts with sources."
    role: writer
  analyst:
    instructions: "Analyze the research. Identify patterns and insights."
    role: tool_agent
    memory_from: [researcher]
  writer:
    instructions: "Write a clear, concise summary for a general audience."
    role: writer
    memory_from: [researcher, analyst]

pipelines:
  research_pipeline:
    flow: "researcher -> analyst -> writer"
    budget_tokens: 10000
```

```python
# research_pipeline.py
import os
from vac_ffi import Connector

c = Connector.from_config("research.yaml")

researcher = c.agent("researcher", "Research the topic thoroughly.")
analyst    = c.agent("analyst",    "Analyze the research findings.")
writer     = c.agent("writer",     "Write a clear summary.")

topic = "The impact of large language models on software development"

r = researcher.run(f"Research: {topic}", "user:alice")
a = analyst.run(f"Analyze this research: {r.text}", "user:alice")
w = writer.run(f"Write a summary based on: {a.text}", "user:alice")

print(f"Summary:\n{w.text}")
print(f"\nTrust: {w.trust}/100 ({w.trust_grade})")
print(f"Packets: {c.packet_count()}")
```

**What you get:** Each agent's output is stored as a tamper-evident packet. The writer has full context from researcher + analyst. Full audit trail of every step.

---

## Path D — Healthcare / HIPAA (Python, 5 minutes)

**Build:** A HIPAA-compliant ER triage + diagnosis pipeline.

```yaml
# hospital.yaml
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}
  storage: redb:./data/hospital.redb
  comply: [hipaa, soc2]
  security:
    signing: true
    data_classification: PHI
    jurisdiction: US
    retention_days: 2555      # 7 years — HIPAA requirement
  firewall:
    preset: hipaa             # blocks PHI leakage, injection, anomalies

agents:
  triage:
    instructions: |
      You are a triage nurse. Classify patient urgency 1-5.
      1=immediate, 2=emergent, 3=urgent, 4=less urgent, 5=non-urgent.
      Always cite: chief complaint, vital signs, pain scale.
    role: writer

  doctor:
    instructions: |
      You are an emergency physician. Based on triage data, provide:
      1. Primary diagnosis with ICD-10 code
      2. Top 3 differential diagnoses
      3. Immediate treatment plan
      4. Tests to order
    role: tool_agent
    memory_from: [triage]     # doctor reads triage packets

pipelines:
  er:
    flow: "triage -> doctor"
    comply: [hipaa]
    budget_tokens: 20000
```

```python
# hospital_er.py
import os, json
from vac_ffi import Connector

c = Connector.from_config("hospital.yaml")

triage = c.agent("triage", "Classify patients by urgency 1-5.")
doctor = c.agent("doctor", "Diagnose based on triage data.")

# Patient arrives
patient = "45M, chest pain 2h, radiating to left arm, diaphoresis, BP 158/95, HR 102, SpO2 97%"

t = triage.run(patient, "patient:P-44291")
print(f"Triage:    {t.text}")
print(f"Trust:     {t.trust}/100 ({t.trust_grade})")

d = doctor.run(f"Patient: {patient}\nTriage assessment: {t.text}", "patient:P-44291")
print(f"\nDiagnosis: {d.text}")
print(f"Trust:     {d.trust}/100 ({d.trust_grade})")

# Compliance evidence
print(f"\nAudit trail: {c.audit_count()} entries")
ok, errors = c.integrity_check()
print(f"Integrity:   {'PASS ✅' if ok else f'FAIL ❌ ({errors} errors)'}")

# Export for HIPAA audit
snap = json.loads(c.kernel_export(10))
print(f"\nKernel stats:")
print(f"  Packets:   {snap['stats']['total_packets']}")
print(f"  Agents:    {snap['stats']['total_agents']}")
print(f"  Audit:     {snap['stats']['total_audit_entries']}")
```

**What you get:** Full HIPAA audit trail, Ed25519-signed packets, PHI detection firewall, tamper-evident memory, 7-year retention — from a 30-line YAML + 20-line Python.

---

## Path E — Finance / SOC2 + GDPR (Python, 5 minutes)

**Build:** A fraud detection pipeline with SOC2 and GDPR compliance.

```yaml
# finance.yaml
connector:
  provider: openai
  model: gpt-4o-mini
  api_key: ${OPENAI_API_KEY}
  storage: redb:./data/finance.redb
  comply: [soc2, gdpr]
  security:
    signing: true
    data_classification: PII
    jurisdiction: EU
    retention_days: 1825      # 5 years
    require_mfa: true
  firewall:
    preset: strict
    pii_types: [ssn, credit_card, email, phone]
    max_calls_per_minute: 20
```

```python
# fraud_detection.py
import os, json
from vac_ffi import Connector

c = Connector.from_config("finance.yaml")

analyzer = c.agent("fraud_analyzer", """
Analyze this transaction for fraud indicators.
Output JSON: {"risk_score": 0-100, "indicators": [...], "recommendation": "approve|review|block"}
""")

transaction = "Transaction: $4,200 at 3:47 AM, Electronics Store, Lagos Nigeria. Cardholder in New York."

result = analyzer.run(transaction, "user:card-8821")

# Parse structured output
try:
    analysis = json.loads(result.text)
    print(f"Risk score:     {analysis['risk_score']}/100")
    print(f"Recommendation: {analysis['recommendation'].upper()}")
    print(f"Indicators:     {', '.join(analysis['indicators'])}")
except json.JSONDecodeError:
    print(f"Analysis: {result.text}")

print(f"\nTrust:    {result.trust}/100 ({result.trust_grade})")
print(f"CID:      {result.cid}")   # immutable audit evidence
print(f"Verified: {result.verified}")
```

---

## Path F — Legal / Audit Trail (Python, 5 minutes)

**Build:** A contract analysis agent with full chain-of-custody.

```yaml
# legal.yaml
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}
  storage: redb:./data/legal.redb
  comply: [soc2]
  security:
    signing: true
    scitt: true               # cross-org attestation
    data_classification: confidential
    retention_days: 3650      # 10 years
    audit_export: json
```

```python
# legal_analysis.py
import os, json
from vac_ffi import Connector

c = Connector.from_config("legal.yaml")

analyst = c.agent("contract_analyst", """
Analyze contracts for: key obligations, risk clauses, missing terms, compliance issues.
Always cite the exact clause text. Use precise legal language.
""")

contract = """
SERVICE AGREEMENT
Section 3.2: Provider may terminate with 30 days notice.
Section 7.1: Liability limited to fees paid in last 3 months.
Section 9.0: Governing law: Delaware.
"""

result = analyst.run(f"Analyze this contract:\n{contract}", "user:legal-team")

print(f"Analysis:\n{result.text}")
print(f"\nTrust: {result.trust}/100 ({result.trust_grade})")
print(f"CID:   {result.cid}")   # immutable proof — use as evidence in disputes

# Export full audit trail
snap = json.loads(c.kernel_export(20))
with open("legal_audit.json", "w") as f:
    json.dump(snap, f, indent=2)
print(f"\nAudit trail saved to legal_audit.json")
print(f"Entries: {snap['stats']['total_audit_entries']}")
```

---

## Path G — Military / DoD Grade (Python, 5 minutes)

**Build:** An air-gapped intelligence analysis agent with DoD-grade security.

```yaml
# dod.yaml
connector:
  provider: ollama              # local model — no external calls
  model: llama3.2
  api_key: local
  endpoint: http://localhost:11434
  storage: redb:./data/classified.redb
  comply: [dod]
  security:
    signing: true
    scitt: true
    data_classification: TOP_SECRET
    jurisdiction: US
    retention_days: 3650
    require_mfa: true
    max_delegation_depth: 1
    key_rotation_days: 30
  firewall:
    preset: strict
    block_injection: true
    max_calls_per_minute: 5
    weights:
      injection: 0.8
      boundary_crossing: 0.9
    thresholds:
      warn: 0.1
      block: 0.4
  behavior:
    anomaly_threshold: 0.3
    max_actions_per_window: 10
  checkpoint:
    write_through: true
    wal_enabled: true
```

```python
# intel_analysis.py
import os, json
from vac_ffi import Connector, KernelDenied, BudgetExceeded

# Start Ollama first: ollama run llama3.2
c = Connector.from_config("dod.yaml")

analyst = c.agent("intel_analyst", """
Analyze intelligence reports. Classify findings by confidence: HIGH/MEDIUM/LOW.
ALWAYS cite source. NEVER speculate without evidence. Flag contradictions.
""")

try:
    result = analyst.run(
        "Analyze the following SIGINT intercept: [CLASSIFIED CONTENT]",
        "operator:ID-7734"
    )

    # Hard security gates — all must pass
    assert result.ok,       f"Analysis failed: {result.errors}"
    assert result.verified, "SECURITY: Output not kernel-verified"
    assert result.trust >= 90, f"SECURITY: Trust {result.trust} below DoD threshold (90)"

    print(f"Analysis: {result.text}")
    print(f"Trust:    {result.trust}/100 ({result.trust_grade})")
    print(f"CID:      {result.cid}")   # chain-of-custody

    # Integrity check before filing
    ok, errors = c.integrity_check()
    assert ok, f"INTEGRITY FAILURE: {errors} errors detected"
    print(f"Integrity: PASS ✅")

except KernelDenied as e:
    print(f"SECURITY ALERT: Access denied — {e}")
except AssertionError as e:
    print(f"SECURITY GATE FAILED: {e}")
```

---

## Path H — TypeScript / Node.js (5 minutes)

**Build:** A TypeScript agent using the REST API.

```bash
# 1. Start connector-server
cd connector && cargo build --release -p connector-server
DEEPSEEK_API_KEY=sk-... ./target/release/connector-server &

# 2. Setup TypeScript
cd sdks/typescript && npm install && npm run build && cd ../..
```

```typescript
// agent.ts
import { Connector } from '@connector-oss/connector';

async function main() {
  const c = new Connector({
    provider: 'deepseek',
    model: 'deepseek-chat',
    apiKey: process.env.DEEPSEEK_API_KEY!,
    baseUrl: 'http://localhost:8080',
  });

  const agent = c.agent('bot', 'You are a helpful assistant.');
  const result = await agent.run('What is 2+2?', 'user:alice');

  console.log(`Response: ${result.text}`);
  console.log(`Trust:    ${result.trust}/100 (${result.trustGrade})`);
  console.log(`CID:      ${result.cid}`);
  console.log(`Verified: ${result.verified}`);
}

main().catch(console.error);
```

```bash
npx ts-node agent.ts
```

---

## Path I — Custom Tool / Industry System (5 minutes)

**Build:** An agent with custom tools for any industry.

```yaml
# custom.yaml
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}
  storage: redb:./data/custom.redb

tools:
  lookup_inventory:
    description: "Look up product inventory levels"
    parameters:
      product_id: {type: string, required: true}
      warehouse:  {type: string, required: false}
    requires_approval: false

  place_order:
    description: "Place a purchase order"
    parameters:
      product_id: {type: string, required: true}
      quantity:   {type: integer, required: true}
      supplier:   {type: string, required: true}
    requires_approval: true    # always requires human approval

agents:
  procurement_agent:
    instructions: |
      You are a procurement assistant. Help manage inventory and orders.
      Always check inventory before suggesting orders.
      Never place orders without explicit approval.
    role: tool_agent
    tools: [lookup_inventory, place_order]
    require_approval: [place_order]
```

```python
# procurement.py
import os
from vac_ffi import Connector

c = Connector.from_config("custom.yaml")

# Register tool implementations
# (Tools are defined in YAML; implementations are registered at runtime)
@c.tool("lookup_inventory")
def lookup_inventory(product_id: str, warehouse: str = "main") -> dict:
    # Your actual implementation
    return {"product_id": product_id, "quantity": 150, "warehouse": warehouse}

@c.tool("place_order")
def place_order(product_id: str, quantity: int, supplier: str) -> dict:
    # Your actual implementation — only called after human approval
    return {"order_id": "PO-8821", "status": "submitted"}

agent = c.agent("procurement_agent", "Help manage inventory and orders.")

result = agent.run(
    "We're running low on SKU-4421. Check inventory and suggest action.",
    "user:procurement-team"
)
print(result.text)
print(f"Trust: {result.trust}/100 ({result.trust_grade})")
```

---

## What Every Path Gives You (Automatically)

No matter which path you choose, you always get:

| Feature | How | Where to see it |
|---------|-----|-----------------|
| **Tamper-evident memory** | CIDv1 (SHA2-256 + DAG-CBOR) | `result.cid` |
| **Trust score** | Kernel-derived, not self-reported | `result.trust`, `result.trust_grade` |
| **Full audit trail** | Every syscall logged + HMAC-chained | `c.audit_count()`, `c.kernel_export()` |
| **Namespace isolation** | Kernel-enforced, no bypass | Automatic |
| **Integrity check** | CID re-hash verification | `c.integrity_check()` |
| **VAKYA authorization** | Auto-built for every operation | `result.cid` links back to token |
| **Provenance tracking** | Every output tagged with source | `result.verified`, `result.provenance()` |

---

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| `api_key: sk-...` hardcoded in YAML | Use `api_key: ${DEEPSEEK_API_KEY}` |
| No `storage:` set | Add `storage: redb:./data/agent.redb` for persistence |
| `result.text` used without checking `result.ok` | Always check `result.ok` first |
| Multi-agent but no `memory_from:` | Add `memory_from: [agent_name]` to let agents share memory |
| Trust score ignored | Check `result.trust >= 70` before using output in production |
| `kernel_export()` result accessed as `snap['total_agents']` | Use `snap['stats']['total_agents']` |

---

## Next Steps

| Goal | Read |
|------|------|
| Understand every YAML key | [31_YAML_DICTIONARY.md](31_YAML_DICTIONARY.md) |
| More Python patterns | [32_CODE_DICTIONARY_PYTHON.md](32_CODE_DICTIONARY_PYTHON.md) |
| Rust API patterns | [33_CODE_DICTIONARY_RUST.md](33_CODE_DICTIONARY_RUST.md) |
| TypeScript patterns | [34_CODE_DICTIONARY_TYPESCRIPT.md](34_CODE_DICTIONARY_TYPESCRIPT.md) |
| How the kernel works | [06_MEMORY_KERNEL.md](06_MEMORY_KERNEL.md) |
| Security model | [29_SECURITY_MODEL.md](29_SECURITY_MODEL.md) |
| Compliance frameworks | [22_COMPLIANCE_ENGINE.md](22_COMPLIANCE_ENGINE.md) |
| Deploy to production | [30_DEPLOYMENT.md](30_DEPLOYMENT.md) |
| Full system overview | [01_INDEX.md](01_INDEX.md) |
