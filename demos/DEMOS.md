# Connector OSS — Demo Suite

Four production-grade demos across Python and TypeScript.
Each demo is self-contained and runnable with a real LLM key.

---

## Setup

```bash
# Build the native Rust kernel (required for Python demos)
cd vac/crates/vac-ffi && maturin develop --release

# Start the REST server (required for TypeScript demos)
cd connector && cargo run -p connector-server

# Python deps
pip install pyyaml

# TypeScript deps
cd sdks/typescript && npm install && npx ts-node src/<demo>.ts
```

Set your LLM key:
```bash
export OPENAI_API_KEY=sk-...
# or
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Demo 1 — Hello World (`01_hello_world`)

**Files:** `demos/python/01_hello_world.py` · `demos/typescript/01_hello_world.ts`

The entry-point demo. Shows the 5 core capabilities in ~80 lines.

| # | Capability | What you see |
|---|-----------|-------------|
| 1 | **Agent execution** | `agent.run()` returns structured `PipelineResult` with text, trust score (0-100), trust grade (A/B/C/D/F) |
| 2 | **Kernel memory** | Every run writes tamper-evident `MemPacket`s; `c.packet_count()` grows with each call |
| 3 | **CID provenance** | `c.write_packet()` returns a content-addressed CID; same content → same CID (deterministic) |
| 4 | **Namespace isolation** | Two agents get separate namespaces; `c.namespace_packet_count("ns:alice")` shows per-agent memory |
| 5 | **Audit trail** | `c.audit_tail(5)` returns the last 5 kernel operations with timestamps, outcomes, and durations |

**Key APIs used:**
```python
c = Connector("openai", "gpt-4o", api_key)
agent = c.agent("bot", "You are helpful")
result = agent.run("Hello!", "user:alice")
result.text, result.trust, result.trust_grade, result.ok
c.packet_count(), c.audit_count()
c.write_packet(pid, content, user, pipe)   # → CID string
c.namespace_packet_count("ns:bot")
c.audit_tail(5)                            # → list of audit dicts
```

---

## Demo 2 — Hospital ER (`02_hospital_er`)

**File:** `demos/python/02_hospital_er.py`

Multi-agent clinical pipeline with HIPAA compliance, grounding, claim verification, and trust scoring.

| # | Capability | What you see |
|---|-----------|-------------|
| 1 | **Multi-agent pipeline** | `triage → diagnosis → treatment` — three agents, each sees only its own namespace |
| 2 | **HIPAA compliance** | `set_compliance(["HIPAA"], data_classification="PHI")` tags every packet; audit log records regulation |
| 3 | **Grounding table** | Medical codes (ICD-10, RxNorm) loaded via `load_grounding_json()`; `lookup_code("conditions", "fever")` → `{code, desc, system}` |
| 4 | **Claim verification** | `verify_claims([...], source_text, cid)` returns confirmed / rejected / needs_review with validity ratio |
| 5 | **Trust breakdown** | `trust_breakdown()` shows 5 dimensions: memory_integrity, audit_completeness, authorization_coverage, decision_provenance, operational_health |
| 6 | **Namespace isolation** | Triage agent cannot read diagnosis agent's namespace; `try_read()` returns `DENIED:...` |
| 7 | **Access grant** | `grant_access(owner_pid, namespace, grantee_pid)` allows controlled cross-agent reads |
| 8 | **Kernel stats** | `kernel_stats()` shows total packets, agents, sessions, audit entries, namespaces |

**Key APIs used:**
```python
c.set_compliance(["HIPAA"], data_classification="PHI", retention_days=2555)
c.load_grounding_json(MEDICAL_CODES_JSON)
c.lookup_code("conditions", "fever")
c.verify_claims(claims, source_text, cid)
c.trust_breakdown()
c.try_read(agent_pid, cid)          # → "DENIED:..." or packet text
c.grant_access(owner, ns, grantee)
c.kernel_stats()
```

---

## Demo 3 — Legal Document Review (`03_legal_document`)

**File:** `demos/python/03_legal_document.py`

Contract analysis pipeline with SOC2 + GDPR compliance, judgment engine, session management, and full audit export.

| # | Capability | What you see |
|---|-----------|-------------|
| 1 | **Multi-regulation compliance** | `set_compliance(["SOC2", "GDPR"])` — two frameworks simultaneously enforced |
| 2 | **Pipeline with roles** | `intake → reviewer → approver` — each agent has a distinct role (reader, writer, approver) |
| 3 | **Session lifecycle** | `create_session()` → `close_session()` groups all packets for a contract review into one auditable session |
| 4 | **Judgment / trust scoring** | `trust_breakdown()` after each agent shows how trust evolves as more authorized operations accumulate |
| 5 | **Audit export** | `c.inner.export_audit_json()` dumps the full tamper-evident audit chain as JSON |
| 6 | **Audit chain verification** | `c.inner.verify_audit_chain()` returns chain length; any tampering breaks the HMAC link |
| 7 | **Agent lifecycle** | `list_agents()` shows registered/running/terminated states; `terminate_agent()` with reason |
| 8 | **Kernel export** | `kernel_export(audit_tail_limit=200)` produces a full JSON snapshot for compliance archiving |

**Key APIs used:**
```python
c.set_compliance(["SOC2", "GDPR"], requires_human_review=True)
c.create_session(pid, label="contract-review-2024-001")
c.close_session(pid, session_id)
c.list_agents()
c.audit_by_agent(pid, limit=20)
c.terminate_agent(pid, reason="review complete")
c.kernel_export(audit_tail_limit=200)
c.inner.verify_audit_chain()   # → chain length (int)
c.inner.export_audit_json()    # → JSON string
```

---

## Demo 4 — Banking Fraud Detection (`04_banking_fraud`)

**File:** `demos/python/04_banking_fraud.py`

High-security financial pipeline with full config-driven setup, firewall, behavior monitoring, integrity checks, and military-grade audit.

| # | Capability | What you see |
|---|-----------|-------------|
| 1 | **YAML config loading** | `Connector.from_config("banking.yaml")` — entire setup from file with `${ENV_VAR}` interpolation |
| 2 | **3-tier config** | YAML shows Tier 1 (mandatory LLM), Tier 2 (firewall/behavior/security), Tier 3 (streaming/observability) |
| 3 | **Firewall** | Config sets `block_injection: true`, `pii_types: [ssn, credit_card]`, `max_calls_per_minute: 60` |
| 4 | **Behavior monitoring** | `anomaly_threshold`, `max_actions_per_window`, `detect_contamination` — behavioral guardrails |
| 5 | **Multi-agent fraud pipeline** | `ingestion → risk_scorer → sanctions_checker → decision` — 4 agents, each isolated namespace |
| 6 | **Integrity check** | `integrity_check()` returns `(ok: bool, error_count: int)` — verifies no packets were tampered |
| 7 | **Kernel health** | `kernel_health()` shows memory pressure, warnings, healthy flag |
| 8 | **Full audit chain** | `verify_audit_chain()` + `audit_tail(20)` — every operation cryptographically linked |
| 9 | **Namespace listing** | `list_namespaces()` shows all 4 agent namespaces with packet counts |
| 10 | **Session summary** | `list_sessions()` shows token usage, tier (hot/warm/cold), start/end times per session |

**Key APIs used:**
```python
c = Connector.from_config("demos/python/banking.yaml")
c.integrity_check()             # → (True, 0)
c.kernel_health()               # → {healthy, memory_pressure, warnings}
c.list_namespaces()             # → [{name, packet_count, agents}]
c.list_sessions()               # → [{session_id, tier, total_tokens, ...}]
c.audit_tail(20)                # → last 20 kernel ops
c.inner.verify_audit_chain()    # → chain length
```

---

## Capability Matrix

| Capability | Hello | Hospital | Legal | Banking |
|-----------|:-----:|:--------:|:-----:|:-------:|
| Agent execution | ✅ | ✅ | ✅ | ✅ |
| Kernel memory / packets | ✅ | ✅ | ✅ | ✅ |
| CID provenance | ✅ | ✅ | ✅ | ✅ |
| Namespace isolation | ✅ | ✅ | ✅ | ✅ |
| Audit trail | ✅ | ✅ | ✅ | ✅ |
| HIPAA compliance | | ✅ | | |
| SOC2 / GDPR compliance | | | ✅ | |
| Multi-regulation | | | ✅ | ✅ |
| Grounding table (ICD-10/RxNorm) | | ✅ | | |
| Claim verification | | ✅ | | |
| Trust breakdown (5 dimensions) | | ✅ | ✅ | ✅ |
| Cross-agent access grant | | ✅ | | |
| Session lifecycle | | | ✅ | ✅ |
| Audit chain verification (HMAC) | | | ✅ | ✅ |
| Agent lifecycle (terminate) | | | ✅ | |
| Kernel export (JSON snapshot) | | | ✅ | |
| YAML config loading | | | | ✅ |
| 3-tier config (firewall/behavior) | | | | ✅ |
| Integrity check | | | | ✅ |
| Kernel health report | | | | ✅ |
| Namespace listing | | | | ✅ |
| Session summary (tokens/tier) | | | | ✅ |
| TypeScript (REST) | ✅ | | | |

---

## What Makes This Different

Every demo runs on a **real cryptographic kernel** — not mocked:

- **Tamper-evident memory**: every packet has a content-addressed CID; the audit log is HMAC-chained
- **Zero-fake provenance**: `result.is_verified()` is only `True` when all events come from the kernel audit log
- **Namespace isolation**: agents cannot read each other's memory without an explicit `grant_access()` call
- **Compliance-by-default**: HIPAA/SOC2/GDPR tags flow through every packet and audit entry automatically
- **Trust is computed, not claimed**: the 5-dimension trust score is derived from actual kernel state, not self-reported
