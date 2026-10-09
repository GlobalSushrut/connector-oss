# Connector Final Outcomes

**Status:** Product acceptance SoT (implementation / conformance under the capability standard)  
**Parent:** [CONNECTOR_CAPABILITY_STANDARD.md](CONNECTOR_CAPABILITY_STANDARD.md)  
**Promise:** [CONNECTOR_PRODUCT_PROMISE.md](CONNECTOR_PRODUCT_PROMISE.md)  
**Pass rule:** Capability + honesty bars — **not** a “100% secure” certification. Soft postures must be labeled soft. Harden must fail closed or refuse start.

Companions: [AAPI_BEHAVIOR_RUNTIME.md](AAPI_BEHAVIOR_RUNTIME.md) · [DYNAMIC_INTELLIGENCE_MANIFOLD.md](DYNAMIC_INTELLIGENCE_MANIFOLD.md) · [KNOT_BELIEF_FIELD.md](KNOT_BELIEF_FIELD.md)

**How this relates to the standard:** §§3–20 of the capability standard are the *must-express* model (including already-engineered surfaces in Appendix A). E / A / S below are the *binary pass* checks that the software actually delivers that model with posture honesty.

**Working checklist:** [CONNECTOR_REACH_CHECKLIST.md](CONNECTOR_REACH_CHECKLIST.md)

Three sets:

| Set | Meaning | IDs |
|-----|---------|-----|
| **E** | Engineer freedom — configure and prove | E1–E8 |
| **A** | Agent capabilities — what a hosted agent gains / how limits apply when enabled | A1–A28 |
| **S** | System capabilities — platform working software | S1–S28 |

---

## E — Engineer freedom

| ID | Outcome | Verify hint | Code surface |
|----|---------|-------------|--------------|
| E1 | Profile continuum: playground/pilot/harden; intent vs applied visible | `/substrate/status` or posture API shows LAB vs applied | `playground`, docklock posture |
| E2 | Compose limits: contract, WorldGrant, tier, budgets, tokenization, DIM bands tunable per agent | Change one without rewriting others | `agent_principal`, world_gateway, rgo, dim, broker |
| E3 | Isolation tier choice: T0 → Landlock → container → microVM; applied tier reported | Posture `applied_truth` | docklock, microvm_tool_plane |
| E4 | Dynamic range: widen/tighten Θ/recall/verification without changing NF³ | DIM regulate ≠ admit Allow | `substrate/dim` |
| E5 | Proof export: digests, receipts, journal, DIM journal, DNA for agent/mission window | `GET /proof/export/:agent_pid` | `substrate/proof_export` |
| E6 | Monitor without CoT: regime, Φ, denials, spend, HITL | DIM operator view + operator pulse | `dim/api`, operator |
| E7 | Lab honesty: gates off → LAB/soft-fail labeled | Soft-fail cannot claim production-ready | posture, playground |
| E8 | Escape hatches explicit: named env flags + audit | No hidden admit bypass | env gates, audit |

---

## A — Agent capability outcomes

### Identity & membrane (A1–A8)

| ID | Outcome | When enabled | Code |
|----|---------|--------------|------|
| A1 | Bound identity — no ambient LLM effects | force-pid / harden | gateway, agent_principal |
| A2 | Contract floor — undeclared FS/net/tools denied | contract required | agent_principal, action_binding |
| A3 | Cage / isolation soft-fail loud | DockLock/Landlock/microVM | docklock |
| A4 | Memory namespace `m/{kernel_pid}` | always for new agents | agents, vac |
| A5 | WorldGrant pores for external addresses | world gateway enforce | world_gateway |
| A6 | Packet DNA on outbound effects | DNA required mode | packet_dna, cnp |
| A7 | Continuity Broken → egress cut | matrix enforce | continuity, matrix |
| A8 | Charter change re-individuates | demote path | agent_principal |

### Tokenization & budgets (A9–A14)

| ID | Outcome | When enabled | Code |
|----|---------|--------------|------|
| A9 | Ingress tokenization / seal | broker gate on | llm_broker_gate, data_tokenization |
| A10 | Detokenize only on admitted effects | broker gate on | llm_broker_gate |
| A11 | Token/compute budget exhaustion stops spend | harden + budgets | aapi budgets, VAC |
| A12 | AAPI reserve-execute-commit; overspend refuse | budgets on | aapi, aapi_bridge |
| A13 | Trajectory blast / commitment / exposure caps | mission budgets | trajectory_budget |
| A14 | Playground session reap + agent cap | playground mode | playground, agents |

### Cognition (A15–A20)

| ID | Outcome | Code |
|----|---------|------|
| A15 | Persistent inspectable DIM Z_t | `substrate/dim` |
| A16 | DIM self-maintenance without authority | dim regulate |
| A17 | Durable memory + recall after restart | vac, knot_rebuild, memory_retrieval |
| A18 | Contradiction → interference, not silent overwrite | belief_snapshot, interference |
| A19 | Mission continuity / temporal wake without new prompt | dim, mission_journal |
| A20 | Model-replaceable mind | identity stack + DIM persist |

### Effects & accountability (A21–A28)

| ID | Outcome | Code |
|----|---------|------|
| A21 | Digest-bound HITL | action_binding |
| A22 | Proportional autonomy R0/R1 vs R3 | rgo, pate |
| A23 | Receipt for every admitted effect | aapi_bridge, mission_journal |
| A24 | Compensation when inverse registered | aapi, action footprint |
| A25 | CONP without SIL theater | conp_protocol, microvm |
| A26 | Narrowed child agents + paired receipts | fabric/mission bridge |
| A27 | Operator stop/inspect without raw CoT | dim, operator |
| A28 | No self-authorization (authority-attack) | nf3, pate, dim tests |

---

## S — System outcomes

| Band | IDs | Summary |
|------|-----|---------|
| Worldline | S1–S5 | register→Talk · mission journal · model swap · process restart · fabric child |
| DIM | S6–S10 | inspect · refresh · regulate · idle wake · authority-attack resist |
| Knot | S11–S15 | restart recall · composite+ReadSet · interference · non-destructive consolidate · selective foresight |
| AAPI | S16–S20 | durable ledger · BCR spend · idempotent retry · compensate · CONP DNA |
| Membrane | S21–S24 | R0/R1 proportional · R3 fail-closed · NF³ categorical · effect exclusivity |
| Ops | S25–S28 | health under load · operator view · poison/degrade response · CI on promise+outcomes |

---

## Anti-claims

Never ship language that says Connector makes agents “100% secure,” that Knot-21 authorizes, that lab echo is SIL, that soft-fail equals production membrane, or that DIM/KECS confidence equals permission.
