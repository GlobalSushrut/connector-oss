# 58 — Compliance Framework: HIPAA, SOC2, GDPR, EU AI Act

> Compliance is not a feature Connector adds on top. It is what the architecture produces when you run it correctly. Every regulation mapped here is addressed by a specific subsystem — not a policy document, not a configuration flag, but a structural guarantee enforced by the 9 rings and 9 chains.

---

## The Structural Compliance Model

Most AI compliance is aspirational: the company writes a policy, trains employees, and hopes the system follows it. Connector compliance is structural: the system architecture makes the violation physically impossible or immediately detectable.

For each regulation below, the mapping follows this format:
- **What the regulation requires**
- **What Connector does structurally to satisfy it**
- **Which chain records proof of compliance**
- **How to produce the evidence bundle**

---

## HIPAA — Health Insurance Portability and Accountability Act

### Minimum Necessary Standard (§164.502(b))

**Requirement:** Use or disclose only the minimum PHI necessary to accomplish the intended purpose.

**Connector structural implementation:**
- PHI lives in `/p/` namespace with `SecurityLevel::Restricted`
- Firewall (Ring 3) blocks any context construction that includes `/p/` content
- The LLM receives only the minimal abstracted context produced by the selective context engine
- The `maria_redacted` pattern in Demo 5 is the production implementation of §164.502(b)

**Chain proof:** Dehallucination Chain (Chain 3) records what context the LLM received. Isolation Chain (Chain 9) records every `/p/` access. The Proof Bundle shows: LLM context did not include PHI.

**Evidence command:**
```bash
$ connectorctl prove agent <pid> --regulation hipaa
  minimum_necessary: ENFORCED
  phi_in_llm_context: false
  phi_in_llm_output: false
  isolation_chain: intact
  audit_cid: mem1-sha256-a3f7b2...
```

---

### Access Controls (§164.312(a))

**Requirement:** Implement technical security measures to guard against unauthorized access to PHI transmitted over electronic communications.

**Connector structural implementation:**
- Namespace `ContainmentPolicy` enforces per-agent access control at the data layer
- `IsolationChain` records every access attempt — authorized and unauthorized
- Unauthorized access triggers `BlockAndAlert` — logged, blocked, and alerted immediately
- No agent can access `/p/` without declaring the namespace in its CCL contract (audited at compile time)

**Chain proof:** Isolation Chain (Chain 9) is the §164.312(a) audit log. Every access, every block, every authorization decision is recorded.

---

### Audit Controls (§164.312(b))

**Requirement:** Implement hardware, software, and/or procedural mechanisms to record and examine access and other activity in information systems that contain PHI.

**Connector structural implementation:**
- The HMAC Audit Chain (Chain 1) records every system event in tamper-evident sequence
- `books.rs` — the primary journal implementation
- Every journal entry carries `agent_pid`, `event_type`, `namespace`, `timestamp`, `audit_cid`
- 6-year retention: journal entries are archived to cold storage, remain verifiable

**Evidence command:**
```bash
$ POST /api/v1/books/journal?regulation=hipaa&since=2026-01-01
  Returns: All PHI-related journal entries with HMAC chain verification
```

---

### Integrity Controls (§164.312(c))

**Requirement:** Implement security measures to ensure that electronically protected health information is not improperly altered or destroyed.

**Connector structural implementation:**
- CID addressing: once a memory packet is written, its CID is its identity. A modified packet has a different CID — the modification is detectable.
- Memory Chain (Chain 2): every write extends the namespace chain. A deletion or modification breaks the chain.
- `AppendOnly` integrity level on `/p/` namespaces: the system refuses write operations that would modify existing packets

---

### Breach Notification Support (§164.400)

**Requirement:** Notify individuals and HHS within 60 days of discovering a breach.

**Connector structural implementation:**
- Isolation Chain (Chain 9) records the exact time, agent, operation, and namespace of any isolation violation
- `BlockAndAlert` generates an immediate notification
- `generate_proof` produces a complete forensic bundle: what was accessed, by whom, when, and whether it was blocked
- The evidence bundle includes the exact scope of any potential breach

---

## SOC 2 — Trust Service Criteria

SOC 2 has five Trust Service Criteria (TSC). Connector addresses each structurally:

### TSC 1 — Security
*System is protected against unauthorized access.*

| Control | Connector Implementation |
|---------|--------------------------|
| Access control | Namespace `ContainmentPolicy`, CCL contract capability declarations |
| Authentication | Node Ed25519 keypair, API key + agent PID auth |
| Intrusion detection | Firewall Ring 3, isolation chain violation detection |
| Audit logging | HMAC Audit Chain (Chain 1), Isolation Chain (Chain 9) |

### TSC 2 — Availability
*System is available for operation as agreed.*

| Control | Connector Implementation |
|---------|--------------------------|
| Fault tolerance | Cell migration, saga bridge rollback |
| Health monitoring | `/health`, `/health/maturity` endpoints |
| Recovery procedures | 12-stage boot with RESTORE stage |
| Capacity management | Global quota enforcement, budget controls |

### TSC 3 — Processing Integrity
*System processing is complete, valid, accurate, timely, and authorized.*

| Control | Connector Implementation |
|---------|--------------------------|
| Input validation | Firewall Ring 3 (injection detection, schema validation) |
| Processing accuracy | Grounding verification, dehallucination chain |
| Authorized processing | CCL contract governs every step |
| Error handling | Governance chain records every policy violation |

### TSC 4 — Confidentiality
*Information designated as confidential is protected.*

| Control | Connector Implementation |
|---------|--------------------------|
| Data classification | Namespace security levels (`/p/` = Restricted) |
| Access restriction | Namespace policy, contract capability declarations |
| Transmission security | mTLS, CNP over encrypted transport |
| Data disposal | TTL fields on memory packets, CID tombstoning |

### TSC 5 — Privacy
*Personal information is collected, used, retained, disclosed per privacy notice.*

| Control | Connector Implementation |
|---------|--------------------------|
| Collection limitation | `/p/` namespace write restriction |
| Use limitation | Firewall blocks PHI from reaching LLM |
| Disclosure controls | Isolation chain records every disclosure |
| Retention/deletion | TTL fields, right-to-erasure tombstoning |

**SOC 2 Type II Evidence Package:**
```bash
$ POST /api/v1/compliance/export?framework=soc2&period=2026-Q1
  Returns: Complete evidence bundle for SOC 2 Type II assessment
  Includes: Audit logs, access records, processing integrity reports,
            availability metrics, policy enforcement records
```

---

## GDPR — General Data Protection Regulation

### Article 5 — Data Minimization Principle

**Requirement:** Personal data shall be adequate, relevant, and limited to what is necessary.

**Connector implementation:** The selective context construction system — the same mechanism that satisfies HIPAA minimum necessary — directly implements GDPR data minimization. The LLM receives the minimum context needed. The cryptographic proof of minimization (`diff_verified`, `phi_in_llm`) is in the proof bundle.

---

### Article 17 — Right to Erasure

**Requirement:** Data subject has the right to have personal data erased.

**Connector implementation:**
1. Identify all memory packets for the data subject (query by namespace + agent_pid)
2. Remove packets: the CID is tombstoned in the namespace chain
3. Journal entry: `right_to_erasure_executed` with subject identifier and timestamp
4. Knowledge packets referencing the subject are also tombstoned
5. Proof bundle generation: proves erasure was performed and when

**Important:** CID tombstoning does not destroy the chain. The chain records that a packet *existed and was erased* — satisfying both the erasure requirement and the audit trail requirement.

---

### Article 25 — Data Protection by Design

**Requirement:** Implement data protection principles from the outset of system design.

**Connector claim:** The namespace model, the firewall's `/p/` enforcement, the CCL contract's capability declarations, and the selective context construction are data protection by design — not add-ons. The architecture cannot be configured to remove these controls without replacing the core system.

---

### Article 32 — Security of Processing

**Requirement:** Implement appropriate technical measures to ensure security of processing, including pseudonymization and encryption.

**Connector implementation:**
- Pseudonymization: the selective context engine replaces patient names with `Patient-A`, `Patient-B` in LLM context
- Encryption: mTLS for all transport, storage encryption via redb encryption at rest
- HMAC integrity: all journal entries are HMAC-chained
- Ed25519 signatures: all proof bundles are signed

---

### Article 35 — Data Protection Impact Assessment (DPIA)

**Requirement:** Conduct DPIA for high-risk processing.

**Connector contribution:** The compliance chain (Chain 4) and the proof bundle provide the evidence base for DPIA documentation. The CCL contract is machine-readable documentation of the processing purposes and safeguards — directly usable in a DPIA.

---

### Data Residency

**GDPR cross-border restriction:** EU personal data cannot leave EU jurisdiction without appropriate safeguards.

**Connector implementation:** Namespace-to-cell binding. `/p/eu-customers/` is bound to EU-located cells only. The distributed scheduler enforces this binding — even if a cell fails, the scheduler only migrates EU-namespace agents to other EU cells.

---

## EU AI Act

### Article 9 — Risk Management System (High-Risk AI)

**Requirement:** High-risk AI systems must implement a risk management system.

**Connector implementation:** The CCL contract is the machine-readable risk management document. It declares: what the system can do (tool allowlist), what it cannot do (blocked tools), when human review is required (HITL thresholds), what budgets apply (token/cost limits), and what regulations apply (governance tags). The governance chain (Chain 5) proves the risk management system was actually applied to every interaction.

---

### Article 12 — Record-Keeping (High-Risk AI)

**Requirement:** High-risk AI systems shall be capable of logging.

**Connector implementation:** The HMAC Audit Chain (Chain 1) satisfies Article 12 completely. It records every input, every decision, every output, every human oversight event. The logs are tamper-evident, timestamped, and retain the information needed for post-market monitoring.

---

### Article 13 — Transparency (High-Risk AI)

**Requirement:** High-risk AI systems shall be designed to ensure sufficient transparency.

**Connector implementation:** Every LLM response includes `audit_cid` — the content address of the audit entry for that interaction. Any user or regulator can use the `audit_cid` to retrieve the complete record of what happened: what context the LLM saw, what decision was made, which policy was applied, and who approved it (if HITL was involved).

---

### Article 14 — Human Oversight (High-Risk AI)

**Requirement:** High-risk AI systems must be designed to enable effective human oversight.

**Connector implementation:** The HITL system (Ring 5, Governance Chain) implements Article 14 directly. CCL contracts declare confidence thresholds below which human review is mandatory. The HITL queue is the human oversight interface. Every HITL event is recorded in the compliance chain with the reviewer's identity and decision.

---

## Multi-Framework Compliance in One Interaction

A single Connector interaction can simultaneously satisfy multiple frameworks:

```
Governed chat: patient-qa-agent processes cardiac inquiry for Maria Santos

Chain 1 (Audit):      Event logged ✓ (HIPAA §164.312(b), SOC2 TSC1, EU AI Act Art.12)
Chain 2 (Memory):     /p/ read authorized and chained ✓ (HIPAA §164.312(a))
Chain 3 (Dehall):     LLM output grounded ✓ (SOC2 TSC3, EU AI Act Art.13)
Chain 4 (Compliance): hipaa + eu-ai-act tags applied ✓
Chain 5 (Governance): CCL step executed under medical contract ✓ (EU AI Act Art.9)
Chain 9 (Isolation):  /p/ boundary maintained ✓ (HIPAA §164.502(b), GDPR Art.5)

Single proof bundle covers: HIPAA, SOC2 (all 5 TSC), GDPR, EU AI Act
Generation time: < 200ms
```

One `generate_proof` call. One cryptographic bundle. Evidence for every regulation.
