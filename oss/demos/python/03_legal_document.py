"""Demo 3 — Legal Document Review  (SOC2+GDPR · sessions · audit chain · export)

Run:  export OPENAI_API_KEY=sk-...  &&  python demos/python/03_legal_document.py
"""
import os
from vac_ffi import Connector

HERE     = os.path.dirname(__file__)
CONTRACT = (
    "SERVICE AGREEMENT between Acme Corp ('Client') and TechVendor Inc ('Vendor'). "
    "Term: 12 months from 2024-01-01. Payment: $50,000/month net-30. "
    "Data: Vendor may process Client PII for service delivery only. "
    "Termination: 30-day written notice. Liability cap: 3x monthly fees. "
    "Governing law: Delaware. No SLA or uptime guarantee specified."
)

# load from YAML — SOC2+GDPR, signing, confidential classification
c = Connector.from_config(os.path.join(HERE, "legal.yaml"))
c.set_compliance(["SOC2", "GDPR"], data_classification="confidential",
                 retention_days=2555, requires_human_review=True)

# 1. Multi-agent pipeline: intake → reviewer → approver
intake   = c.agent("intake",   "Contract intake. Extract parties, dates, obligations. 2 sentences.")
reviewer = c.agent("reviewer", "Legal reviewer. Identify top 3 risks and missing terms. 2 sentences.")
approver = c.agent("approver", "Senior counsel. APPROVE or REJECT with one-line rationale.")

r_i = intake.run(CONTRACT, "user:paralegal")
r_r = reviewer.run(f"Contract: {CONTRACT}\nIntake: {r_i.text}", "user:associate")
r_a = approver.run(f"Review: {r_r.text}\nContract: {CONTRACT}", "user:partner")

print(f"[1] pipeline: intake={r_i.trust} reviewer={r_r.trust} approver={r_a.trust}")
print(f"    intake:   {r_i.text[:100]}...")
print(f"    review:   {r_r.text[:100]}...")
print(f"    decision: {r_a.text[:100]}...")

# 2. Session lifecycle — group all ops into one auditable session
agents = {a["name"]: a["pid"] for a in c.list_agents()}
pid_i  = agents.get("intake", "")
cid    = ""
if pid_i:
    sid = c.create_session(pid_i, label="contract-review-2024-001")
    print(f"\n[2] session created: {sid}")
    cid = c.write_packet(pid_i, CONTRACT, "user:paralegal", "pipe:legal")
    # write intake response into the session namespace too
    c.write_packet(pid_i, r_i.text, "user:paralegal", "pipe:legal")
    print(f"    contract cid: {cid}")
    c.close_session(pid_i, sid)
    sessions = c.list_sessions()
    s = next((x for x in sessions if x["session_id"] == sid), None)
    if s:
        print(f"    session closed: packets={s['packet_count']} tokens={s['total_tokens']} tier={s['tier']}")

# 3. Trust breakdown evolves as more authorized ops accumulate
t = c.trust_breakdown()
print(f"\n[3] trust: total={t['total']} memory={t['memory_integrity']} "
      f"audit={t['audit_completeness']} authz={t['authorization_coverage']}")

# 4. Agent lifecycle — list then terminate
print("\n[4] agents:")
for a in c.list_agents():
    print(f"    {a['name']:10s} pid={a['pid']}  status={a['status']}  packets={a['total_packets']}")

# 5. Audit trail — integrity check BEFORE terminating agents
ok, errs = c.integrity_check()
print(f"\n[5] integrity_check: ok={ok}  errors={errs}  total_audit_entries={c.audit_count()}")
print("    last 5 ops:")
for e in c.audit_tail(5):
    print(f"    [{e['outcome']:8s}] {e['operation']:22s}  agent={e['agent_pid']}  {e['duration_us']}µs")

# 6. Agent lifecycle — terminate approver after audit
pid_a = agents.get("approver", "")
if pid_a:
    c.terminate_agent(pid_a, reason="review complete")
    detail = c.agent_detail(pid_a)
    print(f"\n[6] approver terminated: status={detail['status'] if detail else 'gone'}")

# 7. Full kernel export for compliance archiving
import json
snapshot = c.kernel_export(audit_tail_limit=50)
snap = json.loads(snapshot)
stats = snap.get('stats', snap)
print(f"\n[7] kernel_export: {len(snapshot)} bytes  "
      f"agents={stats.get('total_agents',0)} packets={stats.get('total_packets',0)} "
      f"audit={stats.get('total_audit_entries',0)}")
