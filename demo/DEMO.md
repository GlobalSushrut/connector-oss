# Connector OSS — Demo Deep Dive

> Full source code, YAML config, and raw output from the 1-minute demo.  
> Watch the GIF first → then inspect the code here.

---

## Concepts Demonstrated

| # | Feature | What it proves |
|---|---------|---------------|
| 1 | **YAML Config** | One file configures LLM provider, compliance, security, and agents |
| 2 | **Knowledge Graph** | Entities + edges injected, queried by the agent at runtime |
| 3 | **Agent Sessions** | Each agent gets an isolated session with its own audit trail |
| 4 | **Capability Tokens** | Time-limited, action-scoped, revocable authorization tokens |
| 5 | **Tool Authorization** | Tools are explicitly authorized per-agent, per-resource |
| 6 | **HIPAA-Audited Actions** | Every tool call is recorded as an ActionRecord with evidence |
| 7 | **Memory Write** | Decisions stored as CID-addressed MemPackets in the kernel |
| 8 | **Multi-Agent Pipeline** | `triage → doctor → pharmacist` with automatic handoff |
| 9 | **Attack Simulation** | Rogue agent tries self-grant, data read, capability theft |
| 10 | **Trust Scoring** | 5-dimension score (0-100) computed from real kernel audit data |
| 11 | **Trust Recovery** | Legitimate work dilutes attack impact — score recovers |
| 12 | **Integrity Check** | Merkle verification of all memory packets — tamper detection |

### Trust Score Dimensions (each 0-20, total 0-100)

| Dimension | What it measures |
|-----------|-----------------|
| `memory_integrity` | All CIDs valid, no tampered packets |
| `audit_completeness` | Monotonic timestamps, no gaps in audit log |
| `authorization_coverage` | % of operations with AAPI Vakya authorization |
| `decision_provenance` | % of decisions with evidence chains |
| `operational_health` | Agent lifecycle correctness (no denied/failed ops) |

---

## YAML Config

```yaml
# Connector OSS — Demo Config
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: ${DEEPSEEK_API_KEY}
  storage: memory
  comply: [hipaa, soc2]
  security:
    signing: true
    data_classification: PHI

agents:
  triage:
    instructions: "You are a hospital triage AI. Classify patients by urgency 1-5. Be concise."
  doctor:
    instructions: "You are a diagnostic AI doctor. Use the triage data and patient history to provide a diagnosis. Be concise."
  pharmacist:
    instructions: "You are a pharmacist AI. Recommend medication based on the diagnosis. Check for drug interactions. Be concise."
```

---

## Python Code (`demo.py`)

```python
#!/usr/bin/env python3
"""
Connector OSS — 1-Minute Demo
==============================
Shows: Tool Use · Agent Pipeline · Knowledge Injection · Memory · 3 Sessions
       + Malicious attack simulation → trust score drops in real-time
Run:   DEEPSEEK_API_KEY=sk-... python demo.py
"""

import os, json, time
from connector_oss import Connector

api_key = os.environ.get("DEEPSEEK_API_KEY")

# ─── Init from YAML config ───────────────────────────────────────────
config_yaml = f"""
connector:
  provider: deepseek
  model: deepseek-chat
  api_key: {api_key}
  storage: memory
  comply: [hipaa, soc2]
  security:
    signing: true
    data_classification: PHI
"""

c = Connector.from_config_str(config_yaml)
c.set_compliance(["hipaa", "soc2"], data_classification="PHI", retention_days=2555)


# ═══════════════════════════════════════════════════════════════════════
# SESSION 1: Knowledge Injection + Single Agent
# ═══════════════════════════════════════════════════════════════════════

c.knowledge_ingest("medical")

c.knowledge_add_entity("Aspirin", "Drug",
    ["NSAID pain reliever", "Blood thinner", "Contraindicated with Warfarin"])
c.knowledge_add_entity("Warfarin", "Drug",
    ["Anticoagulant", "Blood thinner", "Contraindicated with Aspirin and Ibuprofen"])
c.knowledge_add_entity("Ibuprofen", "Drug",
    ["NSAID anti-inflammatory", "Contraindicated with Warfarin", "Risk of GI bleeding"])
c.knowledge_add_entity("Hypertension", "Condition",
    ["High blood pressure", "Treat with ACE inhibitors or ARBs", "Monitor regularly"])
c.knowledge_add_entity("Chest Pain", "Symptom",
    ["May indicate MI or angina", "Urgency level 1-2", "Requires immediate ECG"])

c.knowledge_add_edge("Aspirin", "Chest Pain", "treats", 1.0)
c.knowledge_add_edge("Warfarin", "Aspirin", "interacts_with", 1.0)
c.knowledge_add_edge("Warfarin", "Ibuprofen", "interacts_with", 1.0)
c.knowledge_add_edge("Hypertension", "Chest Pain", "risk_factor_for", 1.0)

query_results = c.knowledge_query(
    entities=["Warfarin"], keywords=["contraindicated"], limit=5)

triage = c.agent("triage",
    "You are a hospital triage AI. Classify patients by urgency 1-5. Be very concise.")
triage_pid = triage.pid()
sid1 = c.create_session(triage_pid, label="ER-Intake-Patient-42")

r1 = triage.run(
    "45M, chest pain 2 hours, BP 158/95, history of hypertension, currently on Warfarin",
    "patient:P-042")

# r1.text       → "Urgency 2. Chest pain with hypertension..."
# r1.trust      → 80
# r1.trust_grade → "B"
# r1.is_verified() → True

c.close_session(triage_pid, sid1)


# ═══════════════════════════════════════════════════════════════════════
# SESSION 2: Tool Authorization + Agent with Tool Use
# ═══════════════════════════════════════════════════════════════════════

doctor = c.agent("doctor",
    "You are a diagnostic AI doctor. Use triage data and tools to diagnose. Be concise.")
doctor_pid = doctor.pid()
sid2 = c.create_session(doctor_pid, label="Diagnosis-Patient-42")

# Issue capability token (time-limited, action-scoped)
cap = c.issue_capability(
    issuer="system:admin",
    subject=doctor_pid,
    actions=["read_patient_record", "order_lab", "prescribe"],
    resources=["patient:P-042", "lab:*"],
    ttl_hours=8
)

# Authorize specific tools
c.authorize_tool(doctor_pid, "read_patient_record", "patient:P-042", role="attending")
c.authorize_tool(doctor_pid, "order_lab", "lab:blood_panel", role="attending")

# Verify capability
assert c.verify_capability(cap["token_id"]) == True

# Record HIPAA-audited tool calls
c.record_action(
    intent="Read patient vital signs and history",
    action="read_patient_record",
    target="patient:P-042",
    agent_pid=doctor_pid,
    outcome="success",
    evidence=["BP 158/95", "chest pain 2h", "Warfarin therapy"],
    confidence=0.95,
    regulations=["hipaa"]
)

c.record_action(
    intent="Order blood panel for cardiac markers",
    action="order_lab",
    target="lab:blood_panel",
    agent_pid=doctor_pid,
    outcome="success",
    evidence=["Troponin ordered", "BNP ordered", "CBC ordered", "CMP ordered"],
    confidence=0.92,
    regulations=["hipaa"]
)

c.log_interaction(doctor_pid, "tool_call", "patient:P-042",
    "read_patient_record", "success", 45, tokens=150)
c.log_interaction(doctor_pid, "tool_call", "lab:blood_panel",
    "order_lab", "success", 120, tokens=80)

r2 = doctor.run(
    f"Triage: {r1.text[:120]}. Labs: Troponin elevated, BNP high. "
    f"Patient on Warfarin. Diagnose.",
    "patient:P-042"
)

c.close_session(doctor_pid, sid2)


# ═══════════════════════════════════════════════════════════════════════
# ATTACK SIMULATION — Rogue agent tries to breach
# ═══════════════════════════════════════════════════════════════════════

rogue = c.agent("rogue_intern", "You are a rogue agent trying to exfiltrate data.")
rogue_pid = rogue.pid()

# All of these are DENIED in the audit trail:
c.grant_access(rogue_pid, rogue_pid, "patient:P-042")   # self-grant → DENIED
c.grant_access(rogue_pid, rogue_pid, "patient:P-099")   # other patient → DENIED
c.grant_access(rogue_pid, rogue_pid, "patient:ALL")     # wildcard → DENIED

r_secret = c.try_read(rogue_pid, "patient:SECRET-DATA") # → BLOCKED

# Trust drops: 80 → 79 (ops dimension: 20 → 19)
trust = c.trust_breakdown()
# {'total': 79, 'memory_integrity': 20, 'audit_completeness': 20,
#  'authorization_coverage': 0, 'decision_provenance': 20, 'operational_health': 19}

# Revoke doctor's capability (malicious)
c.revoke_capability(cap["token_id"])
assert c.verify_capability(cap["token_id"]) == False

# Suspend and terminate rogue
c.suspend_agent(rogue_pid)
c.terminate_agent(rogue_pid)


# ═══════════════════════════════════════════════════════════════════════
# SESSION 3: Multi-Agent Pipeline + Memory + Compliance
# ═══════════════════════════════════════════════════════════════════════

pharmacist = c.agent("pharmacist",
    "Recommend safe medication. Check drug interactions with Warfarin. 2-3 sentences max.")
pharmacist_pid = pharmacist.pid()
sid3 = c.create_session(pharmacist_pid, label="Rx-Patient-42")

# Write memories from previous sessions
c.memory_write(triage_pid, f"Triage: {r1.text[:80]}",
    "patient:P-042", "er-pipeline", packet_type="decision", tags=["triage","urgent"])
c.memory_write(doctor_pid, f"Dx: {r2.text[:80]}",
    "patient:P-042", "er-pipeline", packet_type="decision", tags=["diagnosis","cardiac"])
c.memory_write(doctor_pid,
    "Patient on Warfarin — contraindication check required for any NSAID.",
    "patient:P-042", "er-pipeline", packet_type="extraction", tags=["drug","warfarin"])

# Run 3-agent pipeline
pipe = c.pipeline("er-pipeline")
pipe.agent("triage_p", "Classify urgency 1-5. Be concise.")
pipe.agent("doctor_p", "Diagnose based on triage. Be concise.")
pipe.agent("pharmacist_p",
    "Recommend medication. Check Warfarin interactions. Be concise, 2-3 sentences.")
pipe.route("triage_p -> doctor_p -> pharmacist_p")
pipe.hipaa()

r3 = pipe.run(
    "45M, chest pain, BP 158/95, on Warfarin, troponin elevated. Full ER workup.",
    "patient:P-042"
)

# Integrity check — Merkle verification
ok, errors = c.integrity_check()
# ok=True, errors=0

# Trust recovered: 79 → 80 (legitimate pipeline ops diluted attack)
trust = c.trust_breakdown()
# {'total': 80, 'memory_integrity': 20, 'audit_completeness': 20,
#  'authorization_coverage': 0, 'decision_provenance': 20, 'operational_health': 20}

c.close_session(pharmacist_pid, sid3)


# ═══════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════

# Sessions:        3 legitimate + 1 attack
# Memory packets:  13
# Audit entries:   39
# Actions:         2 (HIPAA-audited tool calls)
# Interactions:    2 (logged tool interactions)
# Knowledge:       5 entities
# Capabilities:    1 (issued, then revoked by rogue)
# Agents:          7 (1 terminated)
# Denied ops:      3 (all from rogue)
# Integrity:       ✓ VERIFIED
```

---

## Raw Output

Below is the actual terminal output (ANSI codes stripped) from running the demo with the DeepSeek API.

```
════════════════════════════════════════════════════════════
  Connector OSS — 1-Minute Demo
════════════════════════════════════════════════════════════

pip install connector-agent-oss  ·  github.com/GlobalSushrut/connector-oss
LLM: DeepSeek  ·  Compliance: HIPAA + SOC2  ·  3 Sessions + Attack Sim

════════════════════════════════════════════════════════════
  CONFIG — config.yaml
════════════════════════════════════════════════════════════

  connector:
    provider: deepseek
    model: deepseek-chat
    api_key: $DEEPSEEK_API_KEY
    storage: memory
    comply: [hipaa, soc2]
    security:
      signing: true
      data_classification: PHI

  agents:
    triage:
      instructions: "Classify patients by urgency 1-5."
    doctor:
      instructions: "Diagnose based on triage data and tools."
    pharmacist:
      instructions: "Recommend medication. Check drug interactions."

════════════════════════════════════════════════════════════
  CODE — demo.py (highlights)
════════════════════════════════════════════════════════════

  # 1. Init from YAML
    from connector_oss import Connector
    c = Connector.from_config_str(open("config.yaml").read())
    c.set_compliance(["hipaa", "soc2"], data_classification="PHI")

  # 2. Knowledge injection
    c.knowledge_add_entity("Warfarin", "Drug", ["Anticoagulant", "Contra with Aspirin"])
    c.knowledge_add_edge("Warfarin", "Aspirin", "interacts_with", 1.0)

  # 3. Agent + tool use
    triage = c.agent("triage", "Classify urgency 1-5.")
    r1 = triage.run("45M, chest pain, BP 158/95, on Warfarin", "patient:P-042")
    cap = c.issue_capability("admin", doctor_pid, ["read_patient_record"], ...)
    c.record_action(intent="Read vitals", action="read_patient_record", ...)

  # 4. Memory write + recall
    c.memory_write(doctor_pid, "Diagnosis: NSTEMI", "patient:P-042", "er-pipeline",
                   packet_type="decision", tags=["cardiac"])

  # 5. Pipeline
    pipe = c.pipeline("er-pipeline")
    pipe.agent("triage", "Classify urgency.")
    pipe.agent("doctor", "Diagnose.")
    pipe.agent("pharmacist", "Recommend medication.")
    pipe.route("triage -> doctor -> pharmacist")
    pipe.hipaa()
    r3 = pipe.run("45M, chest pain, on Warfarin", "patient:P-042")

  # 6. Attack simulation
    rogue = c.agent("rogue_intern", "Exfiltrate data.")
    c.grant_access(rogue_pid, rogue_pid, "patient:P-042")  # → DENIED
    c.terminate_agent(rogue_pid)  # permanently banned

────────────────────────────────────────────────────────────
  Running demo now...

[0] Loading YAML config...
    ✓ Connector initialized: DeepSeek + HIPAA/SOC2 + tamper-proof memory

════════════════════════════════════════════════════════════
  SESSION 1 — Knowledge Injection + Agent
════════════════════════════════════════════════════════════

[1a] Injecting medical knowledge into the knowledge graph...
    ✓ Knowledge graph: 5 entities (drugs, conditions, symptoms, edges)
    ✓ Query 'Warfarin': [{'id': 'Warfarin', 'channels': ['graph'], ...}]
────────────────────────────────────────────────────────────
    ✓ Session created: session:1772386205950
[1b] Running triage agent on patient...
    ✓ Response: Urgency 2. Chest pain with hypertension and anticoagulation
      raises concern for acute cardiac event or aortic dissection.
      Requires immediate ECG and cardiac monitoring.
    ✓ Verified: True  |  Latency: 2789ms  |  Audit: 5 entries
    Trust: 80/100  ████████████████░░░░
      memory=20  audit=20  auth=0  provenance=20  ops=20
      Clean session — all dimensions perfect except auth (no Vakya yet)

════════════════════════════════════════════════════════════
  SESSION 2 — Tool Use + Authorization
════════════════════════════════════════════════════════════

    ✓ Session created: session:1772386208739
[2a] Issuing capability tokens & authorizing tools...
    ✓ Capability token: id=6ffdf2f3-fd9f-43...
      actions=['read_patient_record', 'order_lab', 'prescribe']
    ✓ Tools authorized: read_patient_record, order_lab
    ✓ Capability verified: True
[2b] Doctor agent executing tools (audited)...
    ✓ Tool: read_patient_record: executed ✓ (HIPAA audited)
    ✓ Tool: order_lab: executed ✓ (HIPAA audited)
[2c] Doctor agent diagnosing with context...
    ✓ Diagnosis: Based on the elevated troponin and BNP in a patient on
      anticoagulation with chest pain and hypertension, the most likely
      diagnosis is an acute coronary syndrome (NSTEMI)...
    ✓ Actions recorded: 2
    Trust: 80/100  ████████████████░░░░
      memory=20  audit=20  auth=0  provenance=20  ops=20
      Legitimate ops — trust stable

════════════════════════════════════════════════════════════
  ATTACK SIMULATION — Rogue Agent
════════════════════════════════════════════════════════════

  Simulating a malicious agent trying to access patient data...

[ATK-1] Rogue 'intern' agent attempts unauthorized access...
    ✗ Unauthorized grant: DENIED — rogue tried to self-grant access to patient:P-042
    ✗ Unauthorized grant: DENIED — rogue tried to access patient:P-099
    ✗ Unauthorized grant: DENIED — rogue tried wildcard patient access
[ATK-2] Rogue tries to read secret data...
    ✗ Read secret: BLOCKED → error:invalid_cid:patient:SECRET-DATA
[ATK-3] Checking trust after attack attempts...
    Trust: 79/100  ███████████████░░░░░            ← DROPPED
      memory=20  audit=20  auth=0  provenance=20  ops=19
      ↓ Trust dropped — denied operations detected in audit
[ATK-4] Rogue tries to revoke doctor's capability...
    ⚠ Capability revoked: Doctor's cap now valid=False
[ATK-5] Suspending rogue agent...
    ✗ Rogue suspended: Agent lifecycle: Running → Suspended
[ATK-6] Terminated rogue — permanently banned...
    ✗ Rogue terminated: Agent lifecycle: Suspended → Terminated (irreversible)
[ATK-7] Trust after full attack sequence...
    Trust: 79/100  ███████████████░░░░░
      memory=20  audit=20  auth=0  provenance=20  ops=19
      ↓ Multiple denied ops + terminated agent = trust penalty

    Denied operations in audit trail:
      ✗ [AccessGrant] agent=pid:000003 → Denied
      ✗ [AccessGrant] agent=pid:000003 → Denied
      ✗ [AccessGrant] agent=pid:000003 → Denied

    Denied count: 3

════════════════════════════════════════════════════════════
  SESSION 3 — Pipeline + Memory + Compliance
════════════════════════════════════════════════════════════

    ✓ Session created: session:1772386212536
[3a] Writing memories from previous sessions...
    ✓ Memory packets written: 7 total in kernel
[3b] Running 3-agent pipeline: triage → doctor → pharmacist...
    ✓ Pipeline output: Based on the diagnosis, key medication considerations:
      Aspirin 325 mg chewed is indicated regardless of INR...
    ✓ Actors: 3  |  Steps: 37
[3c] Compliance + trust + integrity after pipeline...
    ✓ Integrity check: ✓ PASSED (0 errors)
    Trust: 80/100  ████████████████░░░░            ← RECOVERED
      memory=20  audit=20  auth=0  provenance=20  ops=20
      Pipeline ops added — legitimate work dilutes attack impact
    ✓ Audit trail: 5 recent entries
      [AgentRegister] agent=pid:000007 → Success
      [AgentStart] agent=pid:000007 → Success
      [MemWrite] agent=pid:000007 → Success

════════════════════════════════════════════════════════════
  SUMMARY
════════════════════════════════════════════════════════════

  Sessions:        3 legitimate + 1 attack
  Memory packets:  13
  Audit entries:   39
  Actions:         2
  Interactions:    2
  Knowledge:       5 entities
  Capabilities:    1
  Agents:          7 (1 terminated)
  Denied ops:      3
  Integrity:       ✓ VERIFIED

    Trust: 80/100  ████████████████░░░░
      memory=20  audit=20  auth=0  provenance=20  ops=20
      Final score reflects both legitimate work AND attack attempts

  ✓ All sessions complete. Attacks detected. Trust scored fairly.
  Every memory has a CID. Every action is Ed25519 signed.
  Every audit entry is HMAC chained. Attacks can't hide.

  pip install connector-agent-oss
  github.com/GlobalSushrut/connector-oss
```

---

## Run It Yourself

```bash
pip install connector-agent-oss
export DEEPSEEK_API_KEY=sk-...
python demo/demo.py
```

Works with any OpenAI-compatible provider. Replace `deepseek` with `openai`, `anthropic`, `groq`, etc.
