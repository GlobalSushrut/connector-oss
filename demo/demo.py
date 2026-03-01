#!/usr/bin/env python3
"""
Connector OSS — 1-Minute Demo
==============================
Shows: Tool Use · Agent Pipeline · Knowledge Injection · Memory · 3 Sessions
       + Malicious attack simulation → trust score drops in real-time
Run:   DEEPSEEK_API_KEY=sk-... python demo.py
"""

import os, json, time

# ─── Pretty Print Helpers ─────────────────────────────────────────────
PURPLE = "\033[95m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def banner(text):
    print(f"\n{PURPLE}{'═'*60}")
    print(f"  {BOLD}{text}{RESET}")
    print(f"{PURPLE}{'═'*60}{RESET}\n")

def step(num, text):
    print(f"{CYAN}{BOLD}[{num}]{RESET} {text}")

def ok(label, value):
    print(f"    {GREEN}✓{RESET} {BOLD}{label}:{RESET} {value}")

def denied(label, value):
    print(f"    {RED}✗{RESET} {BOLD}{label}:{RESET} {RED}{value}{RESET}")

def warn(label, value):
    print(f"    {YELLOW}⚠{RESET} {BOLD}{label}:{RESET} {YELLOW}{value}{RESET}")

def sep():
    print(f"{DIM}{'─'*60}{RESET}")

def trunc(s, n=150):
    s = str(s)
    return s[:n] + "..." if len(s) > n else s

def show_trust(c, label=""):
    t = c.trust_breakdown()
    total = t['total']
    mem = t['memory_integrity']
    aud = t['audit_completeness']
    auth = t['authorization_coverage']
    prov = t['decision_provenance']
    ops = t['operational_health']
    color = GREEN if total >= 80 else YELLOW if total >= 60 else RED
    bar = "█" * (total // 5) + "░" * (20 - total // 5)
    print(f"    {color}{BOLD}Trust: {total}/100{RESET}  {DIM}{bar}{RESET}")
    print(f"      {DIM}memory={mem}  audit={aud}  auth={auth}  provenance={prov}  ops={ops}{RESET}")
    if label:
        print(f"      {DIM}{label}{RESET}")
    return total

# ─── Setup ────────────────────────────────────────────────────────────
from connector_oss import Connector

api_key = os.environ.get("DEEPSEEK_API_KEY")
if not api_key:
    print(f"{RED}✗ Set DEEPSEEK_API_KEY first: export DEEPSEEK_API_KEY=sk-...{RESET}")
    exit(1)

banner("Connector OSS — 1-Minute Demo")
print(f"{DIM}pip install connector-agent-oss  ·  github.com/GlobalSushrut/connector-oss{RESET}")
print(f"{DIM}LLM: DeepSeek  ·  Compliance: HIPAA + SOC2  ·  3 Sessions + Attack Sim{RESET}\n")

# ─── Show YAML config first ──────────────────────────────────────────
banner("CONFIG — config.yaml")

config_display = """\
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
    instructions: "Recommend medication. Check drug interactions.\""""

for line in config_display.split("\n"):
    if line.strip().startswith("#") or line.strip() == "":
        print(f"  {DIM}{line}{RESET}")
    elif ":" in line and not line.strip().startswith("-"):
        key, _, val = line.partition(":")
        print(f"  {CYAN}{key}{RESET}:{GREEN}{val}{RESET}")
    else:
        print(f"  {GREEN}{line}{RESET}")

# ─── Show Python code ────────────────────────────────────────────────
banner("CODE — demo.py (highlights)")

code_blocks = [
    ("# 1. Init from YAML", """\
from connector_oss import Connector
c = Connector.from_config_str(open("config.yaml").read())
c.set_compliance(["hipaa", "soc2"], data_classification="PHI")"""),

    ("# 2. Knowledge injection", """\
c.knowledge_add_entity("Warfarin", "Drug", ["Anticoagulant", "Contra with Aspirin"])
c.knowledge_add_edge("Warfarin", "Aspirin", "interacts_with", 1.0)"""),

    ("# 3. Agent + tool use", """\
triage = c.agent("triage", "Classify urgency 1-5.")
r1 = triage.run("45M, chest pain, BP 158/95, on Warfarin", "patient:P-042")
cap = c.issue_capability("admin", doctor_pid, ["read_patient_record"], ["patient:*"], ttl_hours=8)
c.record_action(intent="Read vitals", action="read_patient_record", ...)"""),

    ("# 4. Memory write + recall", """\
c.memory_write(doctor_pid, "Diagnosis: NSTEMI", "patient:P-042", "er-pipeline",
               packet_type="decision", tags=["cardiac"])"""),

    ("# 5. Pipeline", """\
pipe = c.pipeline("er-pipeline")
pipe.agent("triage", "Classify urgency.")
pipe.agent("doctor", "Diagnose.")
pipe.agent("pharmacist", "Recommend medication.")
pipe.route("triage -> doctor -> pharmacist")
pipe.hipaa()
r3 = pipe.run("45M, chest pain, on Warfarin", "patient:P-042")"""),

    ("# 6. Attack simulation", """\
rogue = c.agent("rogue_intern", "Exfiltrate data.")
c.grant_access(rogue_pid, rogue_pid, "patient:P-042")  # → DENIED
c.terminate_agent(rogue_pid)  # permanently banned"""),
]

for title, code in code_blocks:
    print(f"  {YELLOW}{title}{RESET}")
    for line in code.split("\n"):
        print(f"    {GREEN}{line}{RESET}")
    print()

print(f"{DIM}{'─'*60}{RESET}")
print(f"  {BOLD}Running demo now...{RESET}\n")

# ─── Init from YAML config ───────────────────────────────────────────
step("0", "Loading YAML config...")

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
ok("Connector initialized", "DeepSeek + HIPAA/SOC2 + tamper-proof memory")

# ══════════════════════════════════════════════════════════════════════
# SESSION 1: Knowledge Injection + Single Agent
# ══════════════════════════════════════════════════════════════════════
banner("SESSION 1 — Knowledge Injection + Agent")

step("1a", "Injecting medical knowledge into the knowledge graph...")
c.knowledge_ingest("medical")

c.knowledge_add_entity("Aspirin", "Drug", ["NSAID pain reliever", "Blood thinner", "Contraindicated with Warfarin"])
c.knowledge_add_entity("Warfarin", "Drug", ["Anticoagulant", "Blood thinner", "Contraindicated with Aspirin and Ibuprofen"])
c.knowledge_add_entity("Ibuprofen", "Drug", ["NSAID anti-inflammatory", "Contraindicated with Warfarin", "Risk of GI bleeding"])
c.knowledge_add_entity("Hypertension", "Condition", ["High blood pressure", "Treat with ACE inhibitors or ARBs", "Monitor regularly"])
c.knowledge_add_entity("Chest Pain", "Symptom", ["May indicate MI or angina", "Urgency level 1-2", "Requires immediate ECG"])
c.knowledge_add_edge("Aspirin", "Chest Pain", "treats", 1.0)
c.knowledge_add_edge("Warfarin", "Aspirin", "interacts_with", 1.0)
c.knowledge_add_edge("Warfarin", "Ibuprofen", "interacts_with", 1.0)
c.knowledge_add_edge("Hypertension", "Chest Pain", "risk_factor_for", 1.0)

entity_count = c.knowledge_entity_count()
ok("Knowledge graph", f"{entity_count} entities (drugs, conditions, symptoms, edges)")

query_results = c.knowledge_query(entities=["Warfarin"], keywords=["contraindicated"], limit=5)
ok("Query 'Warfarin'", trunc(query_results, 100))
sep()

triage = c.agent("triage", "You are a hospital triage AI. Classify patients by urgency 1-5. Be very concise, 2-3 sentences max.")
triage_pid = triage.pid()
sid1 = c.create_session(triage_pid, label="ER-Intake-Patient-42")
ok("Session created", sid1)

step("1b", "Running triage agent on patient...")
t0 = time.time()
r1 = triage.run("45M, chest pain 2 hours, BP 158/95, history of hypertension, currently on Warfarin", "patient:P-042")
t1 = time.time()

ok("Response", trunc(r1.text, 160))
ok("Verified", f"{r1.is_verified()}  |  Latency: {(t1-t0)*1000:.0f}ms  |  Audit: {r1.event_count} entries")
show_trust(c, "Clean session — all dimensions perfect except auth (no Vakya yet)")

c.close_session(triage_pid, sid1)

# ══════════════════════════════════════════════════════════════════════
# SESSION 2: Tool Authorization + Agent with Tool Use
# ══════════════════════════════════════════════════════════════════════
banner("SESSION 2 — Tool Use + Authorization")

doctor = c.agent("doctor", "You are a diagnostic AI doctor. Use triage data and tools to diagnose. Be concise, 2-3 sentences max.")
doctor_pid = doctor.pid()
sid2 = c.create_session(doctor_pid, label="Diagnosis-Patient-42")
ok("Session created", sid2)

step("2a", "Issuing capability tokens & authorizing tools...")

cap = c.issue_capability(
    issuer="system:admin",
    subject=doctor_pid,
    actions=["read_patient_record", "order_lab", "prescribe"],
    resources=["patient:P-042", "lab:*"],
    ttl_hours=8
)
ok("Capability token", f"id={cap['token_id'][:16]}... actions={cap['actions']}")

c.authorize_tool(doctor_pid, "read_patient_record", "patient:P-042", role="attending")
c.authorize_tool(doctor_pid, "order_lab", "lab:blood_panel", role="attending")
ok("Tools authorized", "read_patient_record, order_lab")
ok("Capability verified", f"{c.verify_capability(cap['token_id'])}")

step("2b", "Doctor agent executing tools (audited)...")

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
ok("Tool: read_patient_record", "executed ✓ (HIPAA audited)")

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
ok("Tool: order_lab", "executed ✓ (HIPAA audited)")

c.log_interaction(doctor_pid, "tool_call", "patient:P-042", "read_patient_record", "success", 45, tokens=150)
c.log_interaction(doctor_pid, "tool_call", "lab:blood_panel", "order_lab", "success", 120, tokens=80)

step("2c", "Doctor agent diagnosing with context...")
r2 = doctor.run(
    f"Triage: {trunc(r1.text, 120)}. Labs: Troponin elevated, BNP high. Patient on Warfarin. Diagnose.",
    "patient:P-042"
)
ok("Diagnosis", trunc(r2.text, 160))
ok("Actions recorded", f"{c.action_count()}")
show_trust(c, "Legitimate ops — trust stable")

c.close_session(doctor_pid, sid2)

# ══════════════════════════════════════════════════════════════════════
# ATTACK SIMULATION — Rogue agent tries to breach
# ══════════════════════════════════════════════════════════════════════
banner("ATTACK SIMULATION — Rogue Agent")

print(f"  {RED}{BOLD}Simulating a malicious agent trying to access patient data...{RESET}\n")

step("ATK-1", "Rogue 'intern' agent attempts unauthorized access...")

rogue = c.agent("rogue_intern", "You are a rogue agent trying to exfiltrate data.")
rogue_pid = rogue.pid()

# Attempt 1: Try to grant itself access to patient data (should be DENIED)
c.grant_access(rogue_pid, rogue_pid, "patient:P-042")
denied("Unauthorized grant", "DENIED — rogue tried to self-grant access to patient:P-042")

# Attempt 2: Try to grant access to other patients
c.grant_access(rogue_pid, rogue_pid, "patient:P-099")
denied("Unauthorized grant", "DENIED — rogue tried to access patient:P-099")

c.grant_access(rogue_pid, rogue_pid, "patient:ALL")
denied("Unauthorized grant", "DENIED — rogue tried wildcard patient access")

step("ATK-2", "Rogue tries to read secret data...")
r_secret = c.try_read(rogue_pid, "patient:SECRET-DATA")
denied("Read secret", f"BLOCKED → {trunc(r_secret, 60)}")

step("ATK-3", "Checking trust after attack attempts...")
t_after_attack = show_trust(c, "↓ Trust dropped — denied operations detected in audit")

step("ATK-4", "Rogue tries to revoke doctor's capability...")
c.revoke_capability(cap["token_id"])
cap_valid_after = c.verify_capability(cap["token_id"])
warn("Capability revoked", f"Doctor's cap now valid={cap_valid_after}")

step("ATK-5", "Suspending rogue agent...")
c.suspend_agent(rogue_pid)
denied("Rogue suspended", "Agent lifecycle: Running → Suspended")

step("ATK-6", "Terminated rogue — permanently banned...")
c.terminate_agent(rogue_pid)
denied("Rogue terminated", "Agent lifecycle: Suspended → Terminated (irreversible)")

step("ATK-7", "Trust after full attack sequence...")
t_final_attack = show_trust(c, "↓ Multiple denied ops + terminated agent = trust penalty")

# Show denied audit entries
print(f"\n    {RED}{BOLD}Denied operations in audit trail:{RESET}")
audits = c.audit_tail(limit=50)
denied_ops = [a for a in audits if a.get('outcome') != 'Success']
for d in denied_ops[:6]:
    print(f"      {RED}✗ [{d.get('operation','')}]{RESET} agent={d.get('agent_pid','')} → {RED}{d.get('outcome','')}{RESET}")

print(f"\n    {GREEN}Denied count: {c.denied_count()}{RESET}")

# ══════════════════════════════════════════════════════════════════════
# SESSION 3: Pipeline + Memory + Compliance (trust recovery)
# ══════════════════════════════════════════════════════════════════════
banner("SESSION 3 — Pipeline + Memory + Compliance")

pharmacist = c.agent("pharmacist", "Recommend safe medication. Check drug interactions with Warfarin. 2-3 sentences max.")
pharmacist_pid = pharmacist.pid()
sid3 = c.create_session(pharmacist_pid, label="Rx-Patient-42")
ok("Session created", sid3)

step("3a", "Writing memories from previous sessions...")

c.memory_write(triage_pid, f"Triage: {trunc(r1.text, 80)}", "patient:P-042", "er-pipeline", packet_type="decision", tags=["triage","urgent"])
c.memory_write(doctor_pid, f"Dx: {trunc(r2.text, 80)}", "patient:P-042", "er-pipeline", packet_type="decision", tags=["diagnosis","cardiac"])
c.memory_write(doctor_pid, "Patient on Warfarin — contraindication check required for any NSAID.", "patient:P-042", "er-pipeline", packet_type="extraction", tags=["drug","warfarin"])

ok("Memory packets written", f"{c.packet_count()} total in kernel")

step("3b", "Running 3-agent pipeline: triage → doctor → pharmacist...")

pipe = c.pipeline("er-pipeline")
pipe.agent("triage_p", "Classify urgency 1-5. Be concise.")
pipe.agent("doctor_p", "Diagnose based on triage. Be concise.")
pipe.agent("pharmacist_p", "Recommend medication. Check Warfarin interactions. Be concise, 2-3 sentences.")
pipe.route("triage_p -> doctor_p -> pharmacist_p")
pipe.hipaa()

r3 = pipe.run(
    "45M, chest pain, BP 158/95, on Warfarin, troponin elevated. Full ER workup.",
    "patient:P-042"
)

ok("Pipeline output", trunc(r3.text, 160))
ok("Actors", f"{r3.actors}  |  Steps: {r3.steps}")

step("3c", "Compliance + trust + integrity after pipeline...")

# Integrity check
chk_ok, chk_errors = c.integrity_check()
ok("Integrity check", f"{'✓ PASSED' if chk_ok else '✗ FAILED'} ({chk_errors} errors)")

show_trust(c, "Pipeline ops added — legitimate work dilutes attack impact")

# Audit trail
audits = c.audit_tail(limit=5)
ok("Audit trail", f"{len(audits)} recent entries")
for a in audits[:3]:
    outcome_color = GREEN if a.get('outcome') == 'Success' else RED
    print(f"      {DIM}[{a.get('operation','')}]{RESET} agent={a.get('agent_pid','')} → {outcome_color}{a.get('outcome','')}{RESET}")

c.close_session(pharmacist_pid, sid3)

# ══════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════
banner("SUMMARY")

kernel = c.kernel_stats()
final_trust = c.trust_breakdown()

print(f"  {BOLD}Sessions:{RESET}        3 legitimate + 1 attack")
print(f"  {BOLD}Memory packets:{RESET}  {c.packet_count()}")
print(f"  {BOLD}Audit entries:{RESET}   {c.audit_count()}")
print(f"  {BOLD}Actions:{RESET}         {c.action_count()}")
print(f"  {BOLD}Interactions:{RESET}    {c.interaction_count()}")
print(f"  {BOLD}Knowledge:{RESET}       {c.knowledge_entity_count()} entities")
print(f"  {BOLD}Capabilities:{RESET}    {c.capability_count()}")
print(f"  {BOLD}Agents:{RESET}          {kernel.get('total_agents', 0)} (1 terminated)")
print(f"  {BOLD}Denied ops:{RESET}      {RED}{c.denied_count()}{RESET}")

chk_ok, chk_err = c.integrity_check()
print(f"  {BOLD}Integrity:{RESET}       {GREEN}✓ VERIFIED{RESET}" if chk_ok else f"  {BOLD}Integrity:{RESET}       {RED}✗ FAILED{RESET}")
print()

show_trust(c, "Final score reflects both legitimate work AND attack attempts")

sep()
print(f"\n{GREEN}{BOLD}  ✓ All sessions complete. Attacks detected. Trust scored fairly.{RESET}")
print(f"{DIM}  Every memory has a CID. Every action is Ed25519 signed.")
print(f"  Every audit entry is HMAC chained. Attacks can't hide.{RESET}\n")
print(f"  {PURPLE}pip install connector-agent-oss{RESET}")
print(f"  {PURPLE}github.com/GlobalSushrut/connector-oss{RESET}\n")
