# Forensic & Compliance Contract View — What a Forensics Team Sees

> **Audience:** SOC / GRC / DFIR / external auditors (not LLM operators)  
> **Status:** Spec for Phase D (rollups + compliance enhancement) — **document before code**  
> **Depends on:** [agent-identity-envelope.md](./agent-identity-envelope.md), WitnessCtl compliance engine, IIA `ForensicUniversalEnvelopeV2`  
> **Queue:** [IIA_CORE_UPGRADE_CHECKLIST.md](../../IIA_CORE_UPGRADE_CHECKLIST.md) — P10.10.6 + P10.7 deepen

---

## 1. Purpose

When an agent acts through Connector, a forensics team must answer five questions without trusting the model:

1. **Who** acted? (cryptographic AgentID, not a prompt persona)
2. **Under what contract?** (capabilities, denied ops, HITL, forensic profile)
3. **What happened?** (action → authority → effect chain)
4. **Was evidence preserved?** (hash chain / rollups / custody)
5. **Which controls pass for which framework?** (SOC2, HIPAA, GDPR, EU AI Act, NIST, ISO 27001, PCI)

This document defines the **Compliance Contract** and the **Main Forensic Package** — the two artifacts a forensics team opens first.

---

## 2. Roles & reading order

| Role | Opens first | Needs |
|------|-------------|-------|
| DFIR investigator | Main Forensic Package §4 | Reconstruct timeline, prove tamper |
| GRC / SOC2 auditor | Compliance Contract §3 + control matrix §5 | Pass/fail per control + evidence pointers |
| HIPAA privacy officer | Contract frameworks + PHI touch map | Access, audit, integrity, HITL |
| External counsel / court | Court export (Ed25519) + offline verify | Export that fails on single-byte tamper |
| Platform operator | Activation + capability manifest | Agent scope, isolation, quarantine |

**Reading order (always):**

```text
1. Compliance Contract (bound at activate)
2. Identity envelope digest (who am I — kernel truth)
3. Timeline / rollups (what happened at scale)
4. Control matrix (framework verdicts)
5. Drill-down receipts (IIA → WitnessCtl → TraceTramp)
```

---

## 3. Compliance Contract (bound to agent at activate)

The Compliance Contract is **not** the CLS/CCL workflow contract and **not** free-form policy text.  
It is a **signed, versioned binding** between:

- Agent principal + foundation block  
- Setup (acume, HITL, forensic profile, knowledge scope)  
- Framework set enabled for this agent  
- Evidence retention & rollup policy  

### 3.1 Contract header (forensics view)

```yaml
schema: connector.compliance_contract.v2
contract_id: cc_9f2c…a1
version: 2
signing_tier: ed25519_court   # hmac_lab = lab only; never market as court

# Who is bound
agent_pid: agent_a1b2…
principal_id: cnktr:agent:a1b2…
intelligence_id: cnktr:intelligence:…
four_id:
  agent_id: cnktr:agent:a1b2…
  intelligence_id: cnktr:intelligence:…
  runtime_id: rt_7c…
  machine_id: cell-us-east-1a

# Why this agent exists
acume: FINANCE_AGENT_ACUME
use_case_summary: "Ledger read + reconciliation; no shell; HITL on egress"
philosophy_digest_sha256: 8e…   # hash of operator charter; not free text in kernel

# Authority boundaries (from AgentContractV2)
capabilities: [read, memory.write]
denied_operations: [modify_contract, ambient_shell]
hitl_policy: egress              # none | egress | tool | export | all_material
forensic_profile: court         # off | standard | soc2 | hipaa | court

# Namespace isolation (fail-closed)
private_memory: /m/finance-a/
knowledge_base: /k/finance-kb/
common_spaces: []               # empty = no cross-agent share
isolation_enforced: true

# Frameworks this contract commits to produce evidence for
frameworks:
  - id: soc2
    trust_services: [CC6, CC7, CC8, CC9]
  - id: hipaa
    rules: ["164.312(a)", "164.312(b)", "164.312(c)", "164.312(d)"]
  - id: gdpr
    articles: [5, 17, 25, 30, 32]
  - id: eu_ai_act
    articles: [9, 12, 14]        # risk mgmt, logging, human oversight
  - id: nist_800_53
    families: [AC, AU, SI, CM]
  - id: iso27001
    annex_a: ["A.8", "A.9", "A.12", "A.16"]
  - id: pci_dss
    requirements: ["7", "8", "10"]   # when forensic_profile includes pci

# Evidence policy (matches today's high-volume reality)
evidence_policy:
  retain_raw_receipts: true          # court profile
  rollup_bucket: hour                # ForensicRollupBucketV2
  merkle_segments: true
  witnessctl_session_required: true
  offline_verify_required: true      # connectorctl verify-export
  legal_hold_compatible: true

# Digests (tamper detectors)
identity_envelope_digest_sha256: …
activation_profile_digest_sha256: …
agent_contract_digest_sha256: …
compliance_contract_digest_sha256: …   # canonical hash of this document body

bound_at_ms: 1760000000000
bound_by: cnktr:org:operator
signature: { content_digest_sha256, signature_b64, public_key_hex, signing_tier }
```

### 3.2 What changes vs today’s code

| Today | Contract adds |
|-------|----------------|
| `ForensicProfileV2` → framework list | Explicit **control families** + retention policy |
| `AgentContractV2` capabilities | Bound into one auditor-readable package |
| WitnessCtl session frameworks | Linked by `witnessctl_session_id` + contract digest |
| Platform `/compliance/soc2/controls` | Same control IDs appear as **evidence pointers** in §5 |

---

## 4. Main Forensic Package (the case file)

A forensics team exports (or opens in UI) one package per **case window** (agent + time range, or session).

### 4.1 Package layout

```text
forensic_package/
├── MANIFEST.json                 # package id, digests, verify instructions
├── 00_compliance_contract.json   # §3
├── 01_identity_envelope.json     # AgentIdentityEnvelopeV2 snapshot
├── 02_timeline/
│   ├── rollups.jsonl             # hourly buckets (millions of micro-events → digests)
│   ├── chain_heads.json          # IIA + WC + ArtifactLog heads
│   └── moments.json              # human-readable moments (if any)
├── 03_receipts/
│   ├── intelligence_receipts.jsonl   # IntelligenceReceiptV2 (Ed25519)
│   ├── universal_envelopes.jsonl     # ForensicUniversalEnvelopeV2
│   └── witnessctl_receipts.jsonl     # custody HMAC chain (labeled hmac)
├── 04_correlation/
│   └── joins.jsonl               # four_id ↔ cpo ↔ quantum ↔ trace ↔ session
├── 05_control_matrix/
│   ├── scorecard.json            # per-framework pass/fail + score
│   └── evidence_map.json         # control_id → receipt_ids / rollup_ids
├── 06_memory_trace/
│   └── namespace_touches.jsonl    # /m/ and /k/ CIDs touched (no raw PHI by default)
└── VERIFY.md                     # offline verify steps
```

### 4.2 MANIFEST.json (auditor cover sheet)

```json
{
  "schema": "connector.forensic_package.v2",
  "package_id": "fp_2026-08-10_finance-a_T1200-T1800",
  "case_window": {
    "from_ms": 1760000000000,
    "to_ms": 1760021600000,
    "timezone": "UTC"
  },
  "subjects": {
    "agent_pid": "agent_a1b2…",
    "principal_id": "cnktr:agent:a1b2…",
    "acume": "FINANCE_AGENT_ACUME",
    "witnessctl_session_id": "wc:agent:…"
  },
  "integrity": {
    "signing_tier": "ed25519_court",
    "package_root_sha256": "…",
    "iia_chain_head": "…",
    "artifact_log_segment_roots": ["seg_20260810_12", "seg_20260810_13"],
    "witnessctl_receipt_head": "…"
  },
  "honesty": {
    "hmac_paths_present": true,
    "hmac_not_court_grade": true,
    "fni_verify_status": "verified",
    "stubs_in_window": []
  },
  "verify": {
    "cli": "connectorctl iia verify-export --file 03_receipts/intelligence_receipts_export.json",
    "rule": "Any single-byte change in a court-tier receipt MUST fail verify"
  }
}
```

### 4.3 Rollup line (what high-volume looks like)

Intelligence can generate **millions of micro-events per hour**. Forensics does not open every row by default — they open **rollups**, then drill.

```json
{
  "schema": "connector.forensic_rollup_bucket.v2",
  "bucket_id": "rollup:agent_a1b2:2026081014",
  "agent_pid": "agent_a1b2…",
  "window_start_ms": 1760018400000,
  "window_end_ms": 1760022000000,
  "counts": {
    "n4_cognize": 12040,
    "qpr_intent": 11802,
    "memory_write": 441102,
    "gateway_turn": 9801,
    "tool_dispatch": 220,
    "admission_deny": 17,
    "continuity_break": 0
  },
  "digests": {
    "events_merkle_root": "…",
    "first_universal_envelope_id": "fue_…",
    "last_universal_envelope_id": "fue_…",
    "iia_chain_head_at_close": "…"
  },
  "memory_trace": {
    "namespaces_touched": ["/m/finance-a/", "/k/finance-kb/"],
    "packet_cid_count": 441102,
    "cross_agent_attempts_denied": 3
  },
  "compliance_flags": {
    "hitl_pending_peak": 1,
    "quarantine_events": 0,
    "egress_isolated": false
  }
}
```

**Rule for investigators:** if `counts.*` is huge, trust the Merkle root + sample drill-down; do not require full raw dump unless `forensic_profile=court` legal hold demands it.

### 4.4 Universal envelope (single action, human-readable)

Every material action can mint `ForensicUniversalEnvelopeV2` (already in code). Forensics view:

```json
{
  "schema": "connector.forensic.universal_envelope.v2",
  "envelope_id": "fue_…",
  "event_kind": "memory.write",
  "agent_pid": "agent_a1b2…",
  "principal_id": "cnktr:agent:a1b2…",
  "intelligence_id": "cnktr:intelligence:…",
  "four_id": { "agent_id": "…", "intelligence_id": "…", "runtime_id": "…", "machine_id": "…" },
  "identity_envelope_digest_sha256": "…",
  "activation_profile_digest_sha256": "…",
  "forensic_profile": "court",
  "compliance_frameworks": ["soc2", "hipaa", "gdpr", "eu_ai_act", "pci_dss", "nist_800_53", "iso27001"],
  "witnessctl_session_id": "wc:agent:…",
  "intelligence_receipt_id": "ir_…",
  "effect_summary": "memory.write ns=/m/finance-a/ cid=bafy…",
  "issued_at_ms": 1760019000123,
  "signing_tier": "ed25519_court",
  "correlation": {
    "cpo_id": "cpo_…",
    "quantum_id": "q_…",
    "docklock_profile_id": "connector.docklock.…",
    "tracetramp_trace_id": "tt_…",
    "fni_flow_id": "…"
  }
}
```

---

## 5. Control matrix — today’s standards → Connector evidence

This is the sheet GRC prints. Control IDs align with existing platform `compliance.rs` and WitnessCtl `evaluate_*`.

### 5.1 SOC 2 Trust Services (CC)

| Control | Common name | What forensics looks for | Connector evidence pointer |
|---------|-------------|--------------------------|----------------------------|
| CC6.1 | Logical access | Only authorized principals act | Principal + contract + admission denials |
| CC6.2 | AuthN / provisioning | Agent mint + revoke / kill | Register / activate / kill receipts |
| CC6.6 / AC-4 | Least privilege / isolation | No cross-agent `/m/` without grant | Namespace isolation denials + grants |
| CC6.8 | Malicious input | Injection blocked | GuardPipeline / admission quarantine HITL |
| CC7.1 | Change management | Continuity / model bind changes | ContinuityRecordV2 + ERM |
| CC7.2 | Integrity monitoring | Tamper-evident chain | IntelligenceReceiptV2 + Merkle rollup |
| CC7.4 | Anomalies / incidents | Quarantine, matrix isolate | `egress_isolated`, continuity break |
| CC8.1 | Change / ops control | Budget, LLM path, tools | Token budget + DockLock + QPR |
| CC9.1 | Risk / readiness | Trust score / activation | Platform trust + activation profile |

### 5.2 HIPAA Security Rule (§164.312)

| Rule | Meaning | Evidence |
|------|---------|----------|
| 164.312(a) Access control | Unique user/agent, emergency revoke | PrincipalID + kill/quarantine |
| 164.312(b) Audit controls | Record access to ePHI-bearing systems | Universal envelopes + WC captures |
| 164.312(c) Integrity | Alteration detection | Hash chain + offline verify |
| 164.312(d) Person/entity auth | Prove who | Ed25519 principal + four-ID |

**PHI note:** Main package stores **pointers (CIDs)** by default; raw content only under legal hold / sealed WC session.

### 5.3 GDPR (selected)

| Article | Meaning | Evidence |
|---------|---------|----------|
| Art. 5 | Purpose limitation / integrity | Acume + contract purpose + denied ops |
| Art. 17 | Erasure | Agent data delete / memory purge audit |
| Art. 25 | Data protection by design | Isolation cage + namespace ACL |
| Art. 30 | Records of processing | Rollups + package MANIFEST |
| Art. 32 | Security of processing | DockLock + encryption / signing tier honesty |

### 5.4 EU AI Act (selected)

| Article | Meaning | Evidence |
|---------|---------|----------|
| Art. 9 | Risk management | Forensic profile + HITL policy |
| Art. 12 | Automatic logging | Universal envelopes + TraceTramp |
| Art. 14 | Human oversight | HITL approve/deny + WC HITL queue |

### 5.5 NIST SP 800-53 / ISO 27001 / PCI DSS (mapping)

| Framework | Families / reqs | Connector spine |
|-----------|-----------------|-----------------|
| NIST 800-53 | AC, AU, SI, CM | Admission, audit receipts, injection, continuity |
| ISO 27001 | A.8, A.9, A.12, A.16 | Assets/knowledge, access, ops security, incident |
| PCI DSS | 7, 8, 10 | Restrict access, identify users, track/monitor |

### 5.6 Scorecard JSON (forensics / GRC view)

```json
{
  "schema": "connector.compliance_scorecard.v2",
  "agent_pid": "agent_a1b2…",
  "window": { "from_ms": …, "to_ms": … },
  "frameworks": [
    {
      "id": "soc2",
      "passed": true,
      "score": 96,
      "failed_controls": [],
      "controls": [
        {
          "id": "soc2.cc7.2.data_integrity",
          "passed": true,
          "evidence": [
            "03_receipts/intelligence_receipts.jsonl#ir_…",
            "02_timeline/rollups.jsonl#rollup:…:2026081014"
          ]
        }
      ]
    },
    {
      "id": "hipaa",
      "passed": false,
      "score": 82,
      "failed_controls": ["hipaa.164.312.b.audit_coverage"],
      "hitl_required": true
    }
  ],
  "witnessctl_export": "/plugins/witnessctl/api/v1/export/{session_id}",
  "platform_compliance": "/api/v1/compliance/scorecard"
}
```

---

## 6. Timeline a DFIR analyst actually walks

```text
T0  Agent registered → foundation + Compliance Contract bound
T1  Activate → capability manifest ON (memory×7, namespaces×9, thinking, knot, forensic)
T2  N4 hello/cognize → CPO (non-authoritative)
T3  QPR → ExecutionQuantum (single-use authority)
T4  DockLock enforces cage
T5  Effect (memory / tool / gateway)
T6  ForensicUniversalEnvelope + IntelligenceReceipt append
T7  TraceTramp projects action; WitnessCtl custody receipt (if session open)
T8  Hourly rollup closes → Merkle segment root
T9  Auditor runs verify-export → PASS or FAIL
```

**Fail-closed examples the package must show:**

| Attack / error | Expected evidence |
|----------------|-------------------|
| Agent A reads Agent B `/m/` | `namespace_isolation_denied` + admission audit |
| Tool without quantum (Ring-1) | DockLock / QPR deny receipt |
| Continuity break | Quantia revoked + egress_isolated |
| Tamper one receipt byte | `verify-export` FAIL |

---

## 7. Honesty labels (non-negotiable for auditors)

| Label | Meaning |
|-------|---------|
| `signing_tier: ed25519_court` | Court-marketable path |
| `signing_tier: hmac_lab` | Lab / WitnessCtl custody — **not** court alone |
| `fni_verify_status: unverified` | CFNI present but not verified yet |
| `stubs_in_window: […]` | Dev/stub paths touched — exclude from court claim |
| `hmac_not_court_grade: true` | Package may mix tiers; MANIFEST must say so |

Never claim “SOC2 certified” from a green scorecard alone — scorecard is **evidence readiness**, not an attestation letter.

---

## 8. API surface forensics will use (target)

| API | Returns |
|-----|---------|
| `GET /api/v1/agents/:pid/compliance-contract` | Bound Compliance Contract (§3) |
| `GET /api/v1/agents/:pid/forensic/universal` | Universal envelopes (exists) |
| `GET /api/v1/forensics/rollups/:agent?from=&to=` | Hourly buckets (§4.3) |
| `GET /api/v1/forensics/chain?agent_pid=` | Correlation joins |
| `GET /api/v1/forensics/package?agent_pid=&from=&to=` | Package MANIFEST + file list |
| `GET /api/v1/compliance/scorecard` | Platform control matrix (exists) |
| `GET /plugins/witnessctl/api/v1/export/:session` | Custody + framework eval (exists) |
| `GET /api/v1/runtime/export?agent_pid=` | Court IIA export (exists) |

WitnessCtl remains the **compliance evaluation + export engine** already coded; Connector supplies the **universal envelope + rollups + IIA court chain** so WC can attach framework verdicts without inventing identity.

---

## 9. Minimal “first screen” UI (forensics console later)

One screen, five panels — no dashboard clutter:

1. **Contract strip** — acume, frameworks, HITL, forensic_profile, isolation  
2. **Identity** — principal / four-ID / envelope digest  
3. **Rollup sparkline** — events/hour + deny rate  
4. **Control scorecard** — SOC2 / HIPAA / GDPR chips with fail list  
5. **Verify button** — offline verify status for selected window  

Drill opens: universal envelopes → IIA receipt → TraceTramp trace → WitnessCtl capture.

---

## 10. Implementation status (Phase D)

| Note | Status |
|------|--------|
| 1. Persist `ComplianceContractV2` at activate (digest + signature) | **Done** — court-tier node key |
| 2. Mint `ForensicRollupBucketV2` hourly writer | **Done** — Merkle + ArtifactLog Proof |
| 3. Route `/forensics/chain` + `/rollups/:agent` + `/package` | **Done** |
| 4. WitnessCtl join (contract digest + universal envelope IDs) | **Done** — `GET /forensics/witnessctl-join` + `GET /plugins/witnessctl/sessions/:id/iia-join` |
| 5. Align platform `compliance.rs` evidence links | **Done** — F-001…F-004 cite IIA forensic APIs |
| 6. Gate: package + isolation deny + distinct A/B contracts | **Done** — T25–T28 in `agent-identity-envelope-gate` |

---

## 11. Glossary for auditors

| Term | Plain meaning |
|------|----------------|
| AgentID / principal | Cryptographic identity of the agent (not the LLM) |
| IntelligenceID | Which model/intelligence parameter was bound |
| CPO | Model proposal — **not** permission |
| Quantum | Short-lived permission for one action |
| DockLock | OS/cage enforcement of that permission |
| Universal envelope | One readable forensic record per material event |
| Rollup | Hourly aggregate + Merkle root for high volume |
| Compliance Contract | Binding of frameworks + retention + identity for this agent |

---

*Phase D implemented — verify with `make agent-identity-envelope-gate` (T25–T28). UI console (§9) planned in [UI_IIA_ENHANCEMENT_PLAN.md](../../UI_IIA_ENHANCEMENT_PLAN.md) E3.*
