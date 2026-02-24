"""Demo 4 — Banking Fraud Detection  (YAML config · firewall · integrity · full audit)

Run:  export OPENAI_API_KEY=sk-...  &&  python demos/python/04_banking_fraud.py
"""
import os, json
from vac_ffi import Connector

HERE = os.path.dirname(__file__)

# 1. YAML config — Tier 1 (LLM), Tier 2 (firewall/behavior/security), Tier 3 (observability)
c = Connector.from_config(os.path.join(HERE, "banking.yaml"))
c.set_compliance(["SOC2"], data_classification="confidential", retention_days=3650)
print(f"[1] loaded from banking.yaml  repr={repr(c)[:80]}")

# 2. Multi-agent fraud pipeline: ingestion → risk_scorer → sanctions → decision
TX = ("Transaction: TXN-20240315-9921. Amount: $47,500 USD. "
      "Sender: Acme Trading LLC (acct: 4421-8833). "
      "Receiver: Offshore Holdings Ltd, Cayman Islands (acct: 9988-2211). "
      "Memo: 'consulting services'. Time: 02:47 UTC. "
      "Sender avg monthly: $12,000. No prior international transfers.")

ingest   = c.agent("ingestion",         "Parse and normalize transaction. Flag missing fields. 1 sentence.")
risk     = c.agent("risk_scorer",       "Score risk 0-100. List top 3 signals. 2 sentences.")
sanction = c.agent("sanctions_checker", "Check OFAC/EU/UN. State CLEAR or FLAGGED with reason. 1 sentence.")
decision = c.agent("decision",          "Final: APPROVE / DECLINE / REVIEW with one-line rationale.")

r_i = ingest.run(TX, "user:system")
r_r = risk.run(f"Transaction: {TX}\nIngestion: {r_i.text}", "user:risk_engine")
r_s = sanction.run(f"Transaction: {TX}\nRisk: {r_r.text}", "user:compliance")
r_d = decision.run(f"Risk: {r_r.text}\nSanctions: {r_s.text}\nTX: {TX}", "user:fraud_officer")

print(f"\n[2] pipeline trust: ingest={r_i.trust} risk={r_r.trust} "
      f"sanctions={r_s.trust} decision={r_d.trust}")
print(f"    risk:     {r_r.text[:100]}...")
print(f"    sanction: {r_s.text[:80]}...")
print(f"    decision: {r_d.text[:80]}...")

# 3. Integrity check — verifies no packets were tampered
ok, errors = c.integrity_check()
print(f"\n[3] integrity_check: ok={ok}  errors={errors}")

# 4. Kernel health — memory pressure, warnings
h = c.kernel_health()
print(f"\n[4] kernel_health: healthy={h['healthy']}  "
      f"memory_pressure={h['memory_pressure']}  warnings={h['warnings']}")

# 5. Namespace listing — all 4 agent namespaces
print("\n[5] namespaces:")
for ns in c.list_namespaces():
    print(f"    {ns['name']:30s}  packets={ns['packet_count']}")

# 6. Session summary — token usage, tier, timing
print("\n[6] sessions:")
for s in c.list_sessions():
    print(f"    {s['session_id'][:20]}  agent={s['agent_id'][:16]}  "
          f"packets={s['packet_count']}  tokens={s['total_tokens']}  tier={s['tier']}")

# 7. Trust breakdown
t = c.trust_breakdown()
print(f"\n[7] trust: total={t['total']} memory={t['memory_integrity']} "
      f"audit={t['audit_completeness']} authz={t['authorization_coverage']} "
      f"provenance={t['decision_provenance']} health={t['operational_health']}")

# 8. Full audit chain — every op logged, integrity verified
ok, errs = c.integrity_check()
print(f"\n[8] audit chain: integrity_ok={ok}  errors={errs}  total_entries={c.audit_count()}")
print("    last 5 ops:")
for e in c.audit_tail(5):
    print(f"    [{e['outcome']:8s}] {e['operation']:22s}  agent={e['agent_pid'][:16]}  {e['duration_us']}µs")

# 9. Kernel stats + export
import json
snapshot = c.kernel_export(audit_tail_limit=20)
snap  = json.loads(snapshot)
stats = snap.get('stats', snap)
print(f"\n[9] kernel_export: {len(snapshot)} bytes  "
      f"agents={stats.get('total_agents',0)} packets={stats.get('total_packets',0)} "
      f"audit={stats.get('total_audit_entries',0)}")
print("    kernel_stats:", c.kernel_stats())
