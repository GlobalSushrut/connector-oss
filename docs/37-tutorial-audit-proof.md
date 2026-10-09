# 37 — Tutorial: Audit and Proof Generation

> Build an audit trail, generate a cryptographic proof bundle, and verify it offline.

---

## What You'll Build

A complete audit cycle:
1. Run an agent session with structured evidence
2. Verify the HMAC chain is intact
3. Generate a cryptographic proof bundle
4. Verify the bundle offline (without the running node)
5. Export the bundle as a compliance report

---

## Step 1 — Set Up the Audit Session

```python
import sys, json, hashlib, time
sys.path.insert(0, "demos/")
from system_data import ConnectorPlatform

p = ConnectorPlatform()

# Register agent for this audit demo
agent = p.register_agent("audit-demo", "Audit proof tutorial", 3)
pid = agent["pid"]
ns  = agent["namespace"]
session_id = f"audit_session_{int(time.time())}"

print(f"PID: {pid}")
print(f"Session: {session_id}")
```

---

## Step 2 — Run Operations That Produce Evidence

```python
# Write initial context
p.write_memory(pid,
    json.dumps({"session": session_id, "purpose": "SOC2 quarterly audit"}),
    ptype="session_init", memory_type="evidence",
    session_id=session_id, tags=["soc2", "audit"])

# Simulate 5 governed operations
for i in range(5):
    # Firewall check
    content = f"Business operation {i+1}: query quarterly report"
    fw = p.firewall_inspect(pid, content, ns)

    # Record decision
    p.record_decision(pid,
        f"operation.{i+1}",
        f"resource_{i+1}",
        "allow",
        rationale=f"Routine business query {i+1}",
        confidence=0.95,
        regulations=["soc2"])

    # Write evidence
    p.write_memory(pid,
        json.dumps({"op": i+1, "fw_blocked": fw["blocked"],
                    "injection_score": fw["injection_score"]}),
        ptype="operation_evidence", memory_type="evidence",
        session_id=session_id)

    print(f"Op {i+1}: fw_blocked={fw['blocked']}, decision recorded")
```

---

## Step 3 — Verify the HMAC Chain

```python
journal  = p.get_books_journal(limit=100)
chain_ok = journal.get("t0_chain_verified", True)

print(f"\nJournal entries: {len(journal['entries'])}")
print(f"Chain verified: {chain_ok}")

if not chain_ok:
    print("⚠ CHAIN BREAK DETECTED — potential tamper")
    # Alert, investigate, do not proceed with proof
else:
    print("✓ HMAC chain intact")

# Show last few entries
for entry in journal["entries"][-3:]:
    print(f"  [{entry['seq_no']:>4}] {entry['action']:<30} {entry['outcome']}")
```

---

## Step 4 — Generate the Proof Bundle

```python
proof = p.generate_proof(pid, title=f"soc2_audit_{session_id}")

print(f"\nProof generated:")
print(f"  proof_id:        {proof['proof_id']}")
print(f"  journal_entries: {proof['journal_entries']}")
print(f"  receipts:        {proof.get('receipts', 0)}")
print(f"  chain_verified:  {proof['chain_verified']}")
print(f"  signature:       {proof['signature'][:40]}...")
print(f"  cid:             {proof['cid']}")
```

```bash
# Via CLI:
connectorctl prove agent <pid> --title "soc2_q1_audit"
```

---

## Step 5 — Formal Verification

```python
verify = p.get_verify_report()
summary = verify.get("executive_summary", {})

print(f"\nFormal verification:")
print(f"  Grade:      {summary.get('grade')}")
print(f"  Invariants: {summary.get('invariants_passed')}")
print(f"  Health:     {summary.get('agent_health_score')}")
print(f"  Verdict:    {summary.get('verdict')}")
```

---

## Step 6 — Generate Regulation-Specific Report

```python
# SOC2 report
soc2 = p.get_regulation_report("soc2")
print(f"\nSOC2 Report: ok={soc2.get('ok')}")

# Check for violations
violations = p.get_policy_violations()
print(f"Policy violations: {violations.get('count', 0)}")
```

---

## Step 7 — Offline Verification

The proof bundle is self-contained. You can verify it without a running Connector node:

```python
import hashlib, hmac as hmac_lib, json

def verify_chain_offline(entries: list, genesis_key: bytes = b"genesis") -> bool:
    """Offline HMAC chain verification."""
    prev = genesis_key
    for entry in entries:
        # Canonical payload (must match server's canonical CBOR)
        payload = json.dumps({
            "seq_no":    entry["seq_no"],
            "action":    entry["action"],
            "outcome":   entry["outcome"],
            "timestamp": entry.get("timestamp", "")
        }, sort_keys=True).encode()

        expected = hmac_lib.new(prev, payload, hashlib.sha256).hexdigest()
        if expected != entry.get("hmac", ""):
            print(f"  Chain break at seq {entry['seq_no']}")
            return False
        prev = expected.encode()
    return True

# Load bundle (in practice, load from exported file)
journal   = p.get_books_journal(limit=1000)
chain_ok  = verify_chain_offline(journal["entries"])
print(f"Offline chain verification: {chain_ok}")
```

Note: The server uses CBOR canonical encoding for HMAC computation. For production offline verification, use the provided `verify_bundle.py` utility.

---

## Step 8 — Export the Proof Bundle

```bash
# Export to files
connectorctl prove agent <pid> \
  --title "soc2_q1_audit" \
  --format json \
  --export ./audit_exports/

# Creates:
# ./audit_exports/proof_prf_uuid.json
# ./audit_exports/proof_prf_uuid.md
# ./audit_exports/proof_prf_uuid.csv
```

```python
# Or via API — save the proof bundle to disk
with open(f"proof_{proof['proof_id']}.json", "w") as f:
    json.dump(proof, f, indent=2)
print(f"Exported: proof_{proof['proof_id']}.json")
```

---

## Step 9 — Build the Full Audit Package

A complete audit package for a compliance reviewer:

```python
def build_audit_package(pid: str, framework: str) -> dict:
    return {
        "framework":    framework,
        "agent_pid":    pid,
        "generated_at": now_iso(),
        "proof":        p.generate_proof(pid, title=f"{framework}_audit"),
        "journal":      p.get_books_journal(limit=1000),
        "violations":   p.get_policy_violations(),
        "regulation":   p.get_regulation_report(framework),
        "verify":       p.get_verify_report(),
        "cost":         p.get_agent_cost(pid),
    }

package = build_audit_package(pid, "soc2")
with open(f"audit_package_soc2_{pid[:8]}.json", "w") as f:
    json.dump(package, f, indent=2)
```

---

## Audit Trail Checklist

Use to confirm a complete audit trail:

```python
def audit_checklist(pid: str) -> dict:
    journal    = p.get_books_journal(limit=1000)
    proof      = p.generate_proof(pid)
    violations = p.get_policy_violations()

    checks = {
        "chain_intact":          journal.get("t0_chain_verified", False),
        "proof_generated":       bool(proof.get("proof_id")),
        "proof_chain_verified":  proof.get("chain_verified", False),
        "no_violations":         violations.get("count", 0) == 0,
        "journal_entries_gt_0":  len(journal.get("entries", [])) > 0,
    }

    passed = sum(checks.values())
    total  = len(checks)
    print(f"\nAudit checklist: {passed}/{total}")
    for check, result in checks.items():
        icon = "✓" if result else "✗"
        print(f"  {icon} {check}")
    return checks

audit_checklist(pid)
```

---

## Next Steps

- **[19 — Ring 8 and 9: Audit and Surface](19-ring-8-9-audit-surface.md)**
- **[31 — API: Audit and Proof](31-api-audit.md)**
- **[40 — Tutorial: HIPAA System](40-tutorial-compliance.md)**
