"""Demo 2 — Hospital ER  (DeepSeek · memory store/retrieval · isolated namespaces · HIPAA)

Four agents each live in their own namespace (ns:triage, ns:diagnosis, ns:treatment,
ns:audit). Real DeepSeek responses are stored as tamper-evident memory packets.
Each downstream agent retrieves the upstream agent's stored output via CID — not
by passing text in code. The audit agent reads across all namespaces after grants.

Run:  export DEEPSEEK_API_KEY=sk-...  &&  python demos/python/02_hospital_er.py
"""
import json, os, textwrap
from vac_ffi import Connector

HERE = os.path.dirname(__file__)
SEP  = "─" * 64

CASE = (
    "Patient: John Doe, 58M. Chest pain radiating to left arm, 2h onset. "
    "BP 158/95, HR 102, Temp 37.8°C, SpO2 97%. "
    "PMH: hypertension x10y, smoker 20 pack-years. "
    "Current meds: lisinopril 10mg daily. No known drug allergies."
)

CODES = json.dumps({
    "conditions": {
        "chest pain":        {"icd10": "R07.9",  "desc": "Chest pain, unspecified"},
        "hypertension":      {"icd10": "I10",    "desc": "Essential hypertension"},
        "tachycardia":       {"icd10": "R00.0",  "desc": "Tachycardia, unspecified"},
        "stemi":             {"icd10": "I21.3",  "desc": "STEMI, unspecified"},
        "nstemi":            {"icd10": "I21.4",  "desc": "NSTEMI"},
        "sepsis":            {"icd10": "A41.9",  "desc": "Sepsis, unspecified"},
        "acute coronary":    {"icd10": "I24.9",  "desc": "Acute coronary syndrome"},
    },
    "medications": {
        "lisinopril":        {"code": "29046",   "desc": "Lisinopril 10mg"},
        "aspirin":           {"code": "1191",    "desc": "Aspirin 325mg"},
        "nitroglycerin":     {"code": "7052",    "desc": "Nitroglycerin 0.4mg SL"},
        "heparin":           {"code": "5224",    "desc": "Heparin IV"},
        "metoprolol":        {"code": "41493",   "desc": "Metoprolol 50mg"},
        "clopidogrel":       {"code": "41493",   "desc": "Clopidogrel 75mg"},
    },
})

def hdr(n, title):
    print(f"\n{SEP}\n[{n}] {title}\n{SEP}")

def wrap(text, indent=4):
    prefix = " " * indent
    for line in textwrap.wrap(text, width=72):
        print(prefix + line)

# ── Setup ─────────────────────────────────────────────────────────────────────
c = Connector.from_config(os.path.join(HERE, "hospital.yaml"))
c.set_compliance(["HIPAA"], data_classification="PHI", retention_days=2555)
c.load_grounding_json(CODES)
print(repr(c))

# ── Register agents — each gets its own isolated namespace ────────────────────
pid_triage    = c.register_agent("triage")
pid_diagnosis = c.register_agent("diagnosis")
pid_treatment = c.register_agent("treatment")
pid_audit     = c.register_agent("audit")

hdr(1, "Namespace isolation — 4 agents, 4 namespaces (zero cross-read by default)")
for a in c.list_agents():
    print(f"    {a['name']:12s}  pid={a['pid']}  ns={a['namespace']}  status={a['status']}")

# ── STEP 1: Triage stores patient case as memory packet ───────────────────────
hdr(2, "Triage — store patient case as memory packet, run DeepSeek")

case_cid = c.write_packet(pid_triage, CASE, "user:nurse_jones", "pipe:er")
print(f"    patient case stored → CID={case_cid}")

triage_agent = c.agent("triage", (
    "You are an ER triage nurse. Given the patient case:\n"
    "1. Urgency level 1-5 (1=immediate)\n"
    "2. Top 3 differential diagnoses with ICD-10 codes\n"
    "3. Immediate nursing actions\n"
    "Be specific and clinical. 4-5 sentences."
))
r_t = triage_agent.run(CASE, "user:nurse_jones")
triage_cid = c.write_packet(pid_triage, r_t.text, "user:nurse_jones", "pipe:er")

print(f"    DeepSeek triage response stored → CID={triage_cid}")
print(f"    trust={r_t.trust}/100  grade={r_t.trust_grade}  ok={r_t.ok}")
print(f"    response:")
wrap(r_t.text)

# ── STEP 2: Diagnosis retrieves triage memory, runs DeepSeek ─────────────────
hdr(3, "Diagnosis — retrieve triage memory via CID (after access grant), run DeepSeek")

# Diagnosis cannot read triage namespace by default
denied = c.try_read(pid_diagnosis, triage_cid)
print(f"    before grant: {denied[:55]}")

# Triage grants diagnosis read access to its namespace
c.grant_access(pid_triage, "ns:triage", pid_diagnosis)
retrieved_triage = c.try_read(pid_diagnosis, triage_cid)
print(f"    after  grant: retrieved {len(retrieved_triage)} chars from ns:triage")
print(f"    retrieved: {retrieved_triage[:80]}...")

diag_agent = c.agent("diagnosis", (
    "You are an ER physician. You have the triage assessment below.\n"
    "Provide:\n"
    "1. Working diagnosis with ICD-10 code\n"
    "2. Immediate investigations (ECG, labs, imaging)\n"
    "3. Risk stratification (TIMI/GRACE score reasoning)\n"
    "Be specific. 4-5 sentences."
))
r_d = diag_agent.run(
    f"TRIAGE ASSESSMENT (retrieved from memory CID {triage_cid[:16]}...):\n{retrieved_triage}\n\nRAW CASE:\n{CASE}",
    "user:dr_smith"
)
diag_cid = c.write_packet(pid_diagnosis, r_d.text, "user:dr_smith", "pipe:er")

print(f"\n    DeepSeek diagnosis stored → CID={diag_cid}")
print(f"    trust={r_d.trust}/100  grade={r_d.trust_grade}")
print(f"    response:")
wrap(r_d.text)

# ── STEP 3: Treatment retrieves diagnosis memory, runs DeepSeek ───────────────
hdr(4, "Treatment — retrieve diagnosis memory via CID, run DeepSeek")

c.grant_access(pid_diagnosis, "ns:diagnosis", pid_treatment)
retrieved_diag = c.try_read(pid_treatment, diag_cid)
print(f"    retrieved diagnosis from ns:diagnosis: {len(retrieved_diag)} chars")

treat_agent = c.agent("treatment", (
    "You are a clinical pharmacist in the ER. You have the physician's diagnosis.\n"
    "Provide:\n"
    "1. First-line medications with RxNorm codes and exact dosing\n"
    "2. Drug interactions to check (patient is on lisinopril)\n"
    "3. Monitoring parameters\n"
    "Be specific and include codes. 4-5 sentences."
))
r_x = treat_agent.run(
    f"DIAGNOSIS (retrieved from memory CID {diag_cid[:16]}...):\n{retrieved_diag}\n\nRAW CASE:\n{CASE}",
    "user:pharmacist_lee"
)
treat_cid = c.write_packet(pid_treatment, r_x.text, "user:pharmacist_lee", "pipe:er")

print(f"    DeepSeek treatment stored → CID={treat_cid}")
print(f"    trust={r_x.trust}/100  grade={r_x.trust_grade}")
print(f"    response:")
wrap(r_x.text)

# ── STEP 4: Claim verification against stored patient case ────────────────────
hdr(5, "Claim verification — verify diagnosis claims against stored patient CID")

claims = [
    {"item": "chest pain",     "category": "conditions",  "quote": "Chest pain radiating", "support": "explicit"},
    {"item": "hypertension",   "category": "conditions",  "quote": "hypertension",          "support": "explicit"},
    {"item": "tachycardia",    "category": "conditions",  "quote": "HR 102",                "support": "implied"},
    {"item": "lisinopril",     "category": "medications", "quote": "lisinopril 10mg",       "support": "explicit"},
    {"item": "acute coronary", "category": "conditions",  "quote": "chest pain",            "support": "implied"},
    {"item": "sepsis",         "category": "conditions",  "quote": "",                      "support": "absent"},
]
v = c.verify_claims(claims, CASE, case_cid)
print(f"    confirmed={len(v.get('confirmed',[]))}  "
      f"needs_review={len(v.get('needs_review',[]))}  "
      f"rejected={len(v.get('rejected',[]))}  "
      f"validity_ratio={v.get('validity_ratio',0):.2f}")
for item in v.get("confirmed", []):
    code = c.lookup_code(item.get("category","conditions"), item.get("item",""))
    code_str = f" → {code['code']} [{code['system']}]" if code else ""
    print(f"    ✓ confirmed: {item.get('item','')}{code_str}")
for item in v.get("needs_review", []):
    print(f"    ⚠ review:   {item.get('item','')}")
for item in v.get("rejected", []):
    print(f"    ✗ rejected: {item.get('item','')}")

# ── STEP 5: Audit agent reads ALL namespaces ──────────────────────────────────
hdr(6, "Audit agent — granted access to all namespaces, reads full care chain")

for pid_owner, ns in [(pid_triage,"ns:triage"),(pid_diagnosis,"ns:diagnosis"),(pid_treatment,"ns:treatment")]:
    c.grant_access(pid_owner, ns, pid_audit)

print("    audit reads across all namespaces:")
print(f"    triage    CID {triage_cid[:20]}... → {c.try_read(pid_audit, triage_cid)[:60]}...")
print(f"    diagnosis CID {diag_cid[:20]}... → {c.try_read(pid_audit, diag_cid)[:60]}...")
print(f"    treatment CID {treat_cid[:20]}... → {c.try_read(pid_audit, treat_cid)[:60]}...")

# ── STEP 6: Trust evolution across the pipeline ───────────────────────────────
hdr(7, "Trust evolution — 5-dimension breakdown after full pipeline")

t = c.trust_breakdown()
print(f"    total              : {t['total']}/100")
print(f"    memory_integrity   : {t['memory_integrity']}/100  (all packets CID-verified)")
print(f"    audit_completeness : {t['audit_completeness']}/100  (every op logged)")
print(f"    authz_coverage     : {t['authorization_coverage']}/100  (grants tracked)")
print(f"    decision_provenance: {t['decision_provenance']}/100  (CID chain)")
print(f"    operational_health : {t['operational_health']}/100")

# ── STEP 7: Namespace packet counts ───────────────────────────────────────────
hdr(8, "Namespace summary — packets per agent namespace")

for ns_info in c.list_namespaces():
    bar = "█" * ns_info["packet_count"]
    print(f"    {ns_info['name']:20s}  {ns_info['packet_count']} packets  {bar}")

# ── STEP 8: Audit tail — every op cryptographically logged ────────────────────
hdr(9, "Audit tail — last 8 kernel operations (tamper-evident)")

for e in c.audit_tail(8):
    print(f"    [{e['outcome']:8s}] {e['operation']:18s}  agent={e['agent_pid']}  {e['duration_us']}µs")

# ── Final stats ───────────────────────────────────────────────────────────────
hdr(10, "Kernel stats")
s = c.kernel_stats()
print(f"    agents={s['total_agents']}  namespaces={s['namespaces']}  "
      f"packets={s['total_packets']}  audit_entries={s['total_audit_entries']}")
print(f"\n    CID chain: case→{case_cid[:16]} triage→{triage_cid[:16]} "
      f"diag→{diag_cid[:16]} treat→{treat_cid[:16]}")
