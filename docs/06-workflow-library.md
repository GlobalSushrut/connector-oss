# 06 — Workflow Library Index

> Master index of 100 workflow patterns across all domains.

---

## How to Use This Index

Each pattern entry contains:
- **Pattern name** and domain
- **Required rings** (which of the 9 rings are exercised)
- **Contract sketch** (CCL shape)
- **Token cost estimate**
- **Compliance tags**

Full implementations in chapters 07–10.

---

## Domain Summary

| Domain | Chapter | Patterns | Primary Use Case |
|---|---|---|---|
| Governance & Compliance | 07 | 25 | Regulated industries — HIPAA, SOC2, GDPR |
| Data Privacy & PHI | 08 | 25 | Data-sensitive systems — PII, PHI, namespace isolation |
| DevOps & Deterministic Execution | 09 | 25 | Infrastructure automation — deploy, rollback, verify |
| Multi-Agent Coordination | 10 | 25 | Agent networks — delegation, consensus, routing |

---

## Section 1: Governance & Compliance Patterns (01–25)

| # | Pattern | Rings | Token Cost | Compliance Tags |
|---|---|---|---|---|
| GC-01 | HIPAA Minimum Necessary Enforcement | 3,4,5,8 | Low | hipaa |
| GC-02 | SOC2 Audit Trail Generation | 5,8,9 | Low | soc2 |
| GC-03 | GDPR Right-to-Erasure Agent | 4,5,8 | Medium | gdpr |
| GC-04 | EU AI Act Article 13 Transparency | 5,8,9 | Low | eu_ai_act |
| GC-05 | Multi-Jurisdiction Policy Stack | 5,8 | Low | hipaa,soc2,gdpr |
| GC-06 | Automated Compliance Report | 5,8,9 | Medium | all |
| GC-07 | Decision Ledger Attestation | 5,8 | Low | soc2 |
| GC-08 | Regulatory Hold Workflow | 4,5,8 | Low | hipaa,gdpr |
| GC-09 | Incident Response Chain | 5,7,8 | High | soc2 |
| GC-10 | PHI Access Logging | 3,4,5,8 | Low | hipaa |
| GC-11 | Policy Conflict Detection | 5 | Low | all |
| GC-12 | Budget Governance Gate | 5,8 | Low | soc2 |
| GC-13 | HITL Escalation Chain | 5,8 | Medium | all |
| GC-14 | Contract Hot-Swap Audit | 5,8 | Low | soc2 |
| GC-15 | Regulation Tag Propagation | 5,8 | Low | all |
| GC-16 | Proof Bundle Generation | 8,9 | Medium | all |
| GC-17 | Chain Break Detection and Alert | 8 | Low | soc2 |
| GC-18 | Compliance Score Dashboard | 5,8,9 | Medium | all |
| GC-19 | Cross-Framework Evidence Export | 8,9 | High | all |
| GC-20 | Consent Management Workflow | 4,5,8 | Medium | gdpr |
| GC-21 | Data Residency Enforcement | 2,4,5 | Low | gdpr |
| GC-22 | Right-to-Explanation Output | 5,8,9 | Medium | eu_ai_act |
| GC-23 | Human Oversight Gate | 5,8 | Medium | eu_ai_act |
| GC-24 | Audit Response Bundle | 8,9 | High | hipaa,soc2 |
| GC-25 | Formal Verification Report | 5,8,9 | High | all |

---

## Section 2: Data Privacy & PHI Patterns (26–50)

| # | Pattern | Rings | Token Cost | Compliance Tags |
|---|---|---|---|---|
| DP-01 | Selective Context Construction | 4,5,6 | Medium | hipaa |
| DP-02 | PII Detection and Redaction | 3,5,8 | Low | gdpr,hipaa |
| DP-03 | Namespace Isolation (Multi-Tenant) | 4,5 | Low | hipaa,gdpr |
| DP-04 | Identity-Aware Execution | 1,5,8 | Low | all |
| DP-05 | Cryptographic Data Minimization Proof | 5,8 | Medium | hipaa,gdpr |
| DP-06 | PHI Field Classification | 3,5 | Low | hipaa |
| DP-07 | Cross-Border Data Residency | 2,4,5 | Low | gdpr |
| DP-08 | Anonymization Chain | 4,5,8 | High | gdpr |
| DP-09 | De-identification with Re-linkage Prevention | 4,5,8 | High | hipaa |
| DP-10 | PHI Vault Access with Audit | 4,5,8 | Low | hipaa |
| DP-11 | Patient Consent Gate | 5,8 | Low | hipaa,gdpr |
| DP-12 | Data Subject Request Handler | 4,5,8 | Medium | gdpr |
| DP-13 | Namespace Fence Test | 4,5 | Low | hipaa |
| DP-14 | LLM Output PII Scrub | 3,6,8 | Low | gdpr |
| DP-15 | PHI-Safe RAG Pipeline | 4,5,6 | High | hipaa |
| DP-16 | Pseudonymization Workflow | 4,5,8 | Medium | gdpr |
| DP-17 | Secure Multi-Party Context | 4,5 | Medium | hipaa |
| DP-18 | Data Lifecycle Management | 4,5,8 | Medium | gdpr |
| DP-19 | Field-Level Encryption Gate | 4,5 | Low | hipaa |
| DP-20 | Minimum Necessary Field Selector | 4,5,6 | Medium | hipaa |
| DP-21 | PHI Containment Proof | 4,5,8 | Medium | hipaa |
| DP-22 | PII Velocity Check | 3,5,8 | Low | gdpr |
| DP-23 | Sensitive Data Tagging Pipeline | 3,4,5 | Low | all |
| DP-24 | Zero-Knowledge Context Window | 4,5,6 | High | hipaa |
| DP-25 | Differential Privacy Memory Write | 4,5,8 | High | gdpr |

---

## Section 3: DevOps & Execution Patterns (51–75)

| # | Pattern | Rings | Token Cost | Compliance Tags |
|---|---|---|---|---|
| DO-01 | Governed Deployment Pipeline | 5,7,8 | Medium | soc2 |
| DO-02 | Dependency-Ordered Multi-Step Workflow | 5,7 | Medium | soc2 |
| DO-03 | Hash-Verified Deterministic Execution | 5,7,8 | Medium | soc2 |
| DO-04 | Rollback on Failure with Audit | 5,7,8 | Medium | soc2 |
| DO-05 | Cost-Bounded Compute Job | 5,7,8 | Low | soc2 |
| DO-06 | Schema-Validated API Call | 3,7 | Low | soc2 |
| DO-07 | Canary Release Governance | 5,7,8 | High | soc2 |
| DO-08 | Infrastructure Drift Detection | 5,7,8 | Medium | soc2 |
| DO-09 | Execution Replay and Forensic Reconstruction | 7,8,9 | High | soc2 |
| DO-10 | Tool Allowlist Enforcement | 3,5,7 | Low | soc2 |
| DO-11 | Constraint-Checked Tool Invocation | 3,5,7 | Low | soc2 |
| DO-12 | Dry-Run Before Execute | 7,8 | Low | soc2 |
| DO-13 | Two-Phase Commit Pattern | 5,7,8 | Medium | soc2 |
| DO-14 | Circuit Breaker Pattern | 5,7 | Low | soc2 |
| DO-15 | Saga Pattern with Compensation | 5,7,8 | High | soc2 |
| DO-16 | Idempotent Execution Gate | 5,7,8 | Low | soc2 |
| DO-17 | Execution Proof for CI/CD Gate | 7,8,9 | Medium | soc2 |
| DO-18 | Database Migration Governance | 5,7,8 | High | soc2 |
| DO-19 | Secret Rotation Workflow | 1,5,7,8 | Medium | soc2 |
| DO-20 | Container Health Check Chain | 5,7,8 | Low | soc2 |
| DO-21 | Kubernetes Resource Governance | 5,7,8 | Medium | soc2 |
| DO-22 | SSH Command Safety Gate | 3,5,7 | Low | soc2 |
| DO-23 | Package Update Pipeline | 5,7,8 | Medium | soc2 |
| DO-24 | Log Integrity Verification | 8 | Low | soc2 |
| DO-25 | Automated Rollback Decision | 5,7,8 | Medium | soc2 |

---

## Section 4: Multi-Agent Coordination Patterns (76–100)

| # | Pattern | Rings | Token Cost | Compliance Tags |
|---|---|---|---|---|
| MA-01 | Agent Delegation Chain with Proof-of-Authority | 1,5,8 | Medium | all |
| MA-02 | Consensus Voting Workflow | 5,8 | Medium | all |
| MA-03 | Parallel Agent Fan-Out | 5,7 | High | soc2 |
| MA-04 | Specialist Agent Routing (Medical) | 5,6,7 | Medium | hipaa |
| MA-05 | Agent-to-Agent Memory Share | 4,5 | Low | all |
| MA-06 | Conflict Resolution between Agents | 5,8 | Medium | all |
| MA-07 | HITL Escalation Network | 5,8 | Medium | all |
| MA-08 | Peer Agent Trust Negotiation | 1,5,8 | Medium | all |
| MA-09 | Cross-Cell Agent Coordination | 2,5,8 | High | all |
| MA-10 | Coordinator-Specialist-Validator Triad | 5,6,7,8 | High | all |
| MA-11 | Agent Budget Pooling | 5,8 | Low | soc2 |
| MA-12 | Namespace Fencing in Multi-Agent | 4,5 | Low | hipaa |
| MA-13 | Agent Handoff Protocol | 1,5,8 | Medium | all |
| MA-14 | Federated Memory Sync | 4,5,8 | High | all |
| MA-15 | Agent Reputation Gate | 1,5,8 | Low | all |
| MA-16 | Result Aggregation Pipeline | 5,6,7 | High | all |
| MA-17 | Agent-Based A/B Test Governance | 5,7,8 | Medium | soc2 |
| MA-18 | Recursive Agent Delegation | 1,5,8 | High | all |
| MA-19 | Specialist Domain Routing Table | 5,6 | Low | all |
| MA-20 | Cross-Agent Audit Trail Merge | 8,9 | High | all |
| MA-21 | Agent Quorum Decision | 5,8 | Medium | all |
| MA-22 | Blind Relay Pattern | 4,5 | Medium | hipaa |
| MA-23 | Agent Policy Inheritance | 5 | Low | all |
| MA-24 | Multi-Jurisdiction Multi-Agent Stack | 2,4,5,8 | High | all |
| MA-25 | Agent Swarm with Proof Rollup | 5,8,9 | High | all |

---

## Pattern Template

Every pattern in chapters 07–10 follows this structure:

```yaml
pattern: GC-01
name: HIPAA Minimum Necessary Enforcement
domain: Governance & Compliance
rings_required: [3, 4, 5, 8]
token_cost: low
compliance: [hipaa]

ccl_sketch: |
  contract HIPAAMinNec {
    intent: "..."
    memory { read /p/... }
    governance { require namespace_clean: /p/ ; tag hipaa }
  }

python_sequence:
  1. register_agent(name, desc, clearance)
  2. firewall_inspect(pid, content)
  3. invoke_chat(pid, ns, prompt)
  4. record_decision(pid, action, target, outcome)

connectorctl_verify:
  - connectorctl show agent <pid>
  - connectorctl explain <decision_id>
  - connectorctl prove agent <pid>
```

---

## Next Steps

- **[07 — Governance Workflows](07-workflows-governance-compliance.md)**
- **[08 — Data Privacy Workflows](08-workflows-data-privacy.md)**
- **[09 — DevOps Workflows](09-workflows-devops-execution.md)**
- **[10 — Multi-Agent Workflows](10-workflows-multiagent.md)**
