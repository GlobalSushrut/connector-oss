# Compliance Engine

> Standards, Evidence types, ComplianceReport, all 7 frameworks
> Source: `connector/crates/connector-engine/src/compliance.rs`

---

## Design Principle

Every compliance claim is backed by kernel audit evidence — not configuration flags. Compliance is verified against actual agent behavior, not just policy existence.

---

## Standards

```rust
pub enum Standard {
    EuAiAct,       // EU AI Act (effective Aug 2025)
    NistAiRmf,     // NIST AI RMF 1.0
    OwaspLlmTop10, // OWASP LLM Top 10 (2025)
    Maestro,       // MAESTRO 7-layer model
    Hipaa,         // HIPAA Security Rule
    Soc2,          // SOC 2 Type II
    Gdpr,          // GDPR
}
```

---

## Evidence

```rust
pub struct Evidence {
    pub control_id:   String,
    pub description:  String,
    pub satisfied:    bool,
    pub evidence_type: EvidenceType,
    pub detail:       String,
}

pub enum EvidenceType {
    KernelAudit,      // strongest — from actual audit log entries
    FirewallLog,      // from firewall event log
    BehaviorAnalysis, // from behavior analyzer
    Configuration,    // weakest — just shows intent, not proof
    Missing,          // no evidence available
}
```

Evidence strength hierarchy: `KernelAudit > FirewallLog > BehaviorAnalysis > Configuration > Missing`

---

## ComplianceReport

```rust
pub struct ComplianceReport {
    pub standard:   Standard,
    pub score:      f64,       // 0.0–100.0
    pub max_score:  f64,       // 100.0
    pub grade:      String,    // PASS | PARTIAL | FAIL
    pub controls:   Vec<Evidence>,
    pub summary:    String,
}
```

---

## Framework Details

### HIPAA Security Rule

**Controls checked**:

| Control ID | Description | Evidence Source |
|-----------|-------------|-----------------|
| `HIPAA-164.312(a)(1)` | Access control — unique user IDs | KernelAudit: AgentRegister ops |
| `HIPAA-164.312(b)` | Audit controls — hardware/software activity | KernelAudit: all ops logged |
| `HIPAA-164.312(c)(1)` | Integrity — protect PHI from alteration | KernelAudit: CID integrity check |
| `HIPAA-164.312(e)(2)(ii)` | Encryption — PHI in transit | Configuration: signing enabled |
| `HIPAA-164.308(a)(1)` | Risk analysis — threat assessment | FirewallLog: threat scores |
| `HIPAA-164.308(a)(5)` | Security awareness — anomaly detection | BehaviorAnalysis: anomaly events |

**Usage**:
```python
report = output.comply("hipaa")
# report.score = 95.0
# report.grade = "PASS"
# report.controls[0].control_id = "HIPAA-164.312(b)"
# report.controls[0].satisfied = True
# report.controls[0].evidence_type = "KernelAudit"
```

---

### SOC 2 Type II

**Controls checked**:

| Control ID | Description | Evidence Source |
|-----------|-------------|-----------------|
| `CC6.1` | Logical access controls | KernelAudit: AccessGrant/Revoke |
| `CC6.2` | Authentication | KernelAudit: AgentRegister with role |
| `CC6.3` | Authorization | KernelAudit: VAKYA token coverage |
| `CC7.1` | System monitoring | BehaviorAnalysis: anomaly detection |
| `CC7.2` | Security incident detection | FirewallLog: Block verdicts |
| `CC9.2` | Risk mitigation | Configuration: compliance frameworks set |
| `A1.1` | Availability — system capacity | KernelAudit: no Failed ops |

---

### GDPR

**Controls checked**:

| Control ID | Description | Evidence Source |
|-----------|-------------|-----------------|
| `GDPR-Art5(1)(f)` | Integrity and confidentiality | KernelAudit: CID integrity |
| `GDPR-Art17` | Right to erasure | KernelAudit: MemEvict/MemClear ops |
| `GDPR-Art25` | Data protection by design | Configuration: namespace isolation |
| `GDPR-Art30` | Records of processing | KernelAudit: full audit trail |
| `GDPR-Art32` | Security of processing | Configuration: encryption enabled |
| `GDPR-Art35` | DPIA — data impact assessment | FirewallLog: PII detection |

---

### EU AI Act

**Controls checked** (effective Aug 2025, penalties up to €35M):

| Control ID | Description | Evidence Source |
|-----------|-------------|-----------------|
| `EUA-Art9` | Risk management system | FirewallLog + BehaviorAnalysis |
| `EUA-Art10` | Data governance | KernelAudit: namespace isolation |
| `EUA-Art12` | Record keeping | KernelAudit: complete audit trail |
| `EUA-Art13` | Transparency | KernelAudit: decision provenance |
| `EUA-Art14` | Human oversight | KernelAudit: RequireApproval ops |
| `EUA-Art15` | Accuracy and robustness | BehaviorAnalysis: anomaly detection |

---

### NIST AI RMF 1.0

**4 functions**:

| Function | Controls | Evidence Source |
|----------|---------|-----------------|
| GOVERN | Policy existence, roles defined | Configuration |
| MAP | Risk identification, context | FirewallLog |
| MEASURE | Trust score, anomaly metrics | KernelAudit + BehaviorAnalysis |
| MANAGE | Incident response, rollback | KernelAudit: VakyaRollback ops |

---

### OWASP LLM Top 10 (2025)

| Risk | Mitigation | Evidence Source |
|------|-----------|-----------------|
| LLM01: Prompt Injection | Firewall injection detection | FirewallLog |
| LLM02: Insecure Output Handling | ClaimVerifier + GroundingTable | KernelAudit |
| LLM03: Training Data Poisoning | InterferenceEngine contradiction | KernelAudit |
| LLM04: Model Denial of Service | Rate limiting + BudgetTracker | KernelAudit |
| LLM05: Supply Chain | VAKYA token signing | Configuration |
| LLM06: Sensitive Info Disclosure | PII detection + namespace isolation | FirewallLog |
| LLM07: Insecure Plugin Design | InstructionPlane default-deny | KernelAudit |
| LLM08: Excessive Agency | BudgetTracker + RequireApproval | KernelAudit |
| LLM09: Overreliance | JudgmentEngine quality score | KernelAudit |
| LLM10: Model Theft | Namespace isolation + AccessGrant | KernelAudit |

---

### MAESTRO

MAESTRO 7-layer model for AI system security:

| Layer | Description | Connector Coverage |
|-------|-------------|-------------------|
| L1: Foundation Models | LLM provider security | LlmRouter + VAKYA signing |
| L2: Data Operations | Data integrity | CID + EncryptedStore |
| L3: Agent Frameworks | Agent isolation | Namespace + Firewall |
| L4: Deployment | Runtime security | connector-server + Docker |
| L5: Evaluation | Quality assessment | TrustComputer + JudgmentEngine |
| L6: Observability | Monitoring | KernelAudit + Prometheus |
| L7: Governance | Policy enforcement | AAPI MetaRules + FederatedPolicy |

---

## Compliance in YAML

```yaml
connector:
  comply: [hipaa, soc2, gdpr, eu_ai_act]
  security:
    signing: true
    data_classification: PHI
    jurisdiction: US
    retention_days: 2555
  firewall:
    preset: hipaa
```

Setting `comply` activates framework-specific enforcement in `DualDispatcher` — not just reporting.
