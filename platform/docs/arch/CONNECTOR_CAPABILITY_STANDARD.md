# Connector — Final Capability, Engineering Control, Evidence, Proof, and Compliance Model

**Status:** Parent product / architecture SoT  
**Audience:** Engineers, architects, operators, auditors  
**Acceptance lists (under this doc):** [CONNECTOR_FINAL_OUTCOMES.md](CONNECTOR_FINAL_OUTCOMES.md) (E1–E8 · A1–A28 · S1–S28)  
**Promise slice:** [CONNECTOR_PRODUCT_PROMISE.md](CONNECTOR_PRODUCT_PROMISE.md)  
**Code encyclopedia:** [CONNECTOR_FULL_ARCHITECTURE.md](CONNECTOR_FULL_ARCHITECTURE.md)

This document is the **Connector standard**: what Connector *is for*, what it *must be able to express*, and how engineer control, evidence, proof, and compliance relate. Implementation/conformance is measured by the E/A/S outcomes underneath — including every part of Connector already engineered.

---

## 1. Purpose

Connector is an **agent operating substrate for engineers building and operating dynamic agents in augmented environments**.

It gives engineers a common execution spine for defining:

* what an agent is,
* what it knows,
* what it remembers,
* how dynamically it may reason,
* what tools and systems it may access,
* what data and addresses it may reach,
* what actions it may perform,
* what quantitative limits apply,
* how strongly it is isolated,
* how automation and workflows execute,
* how effects are admitted,
* how the agent is monitored,
* and what evidence exists afterward.

Central principle:

> **The engineer chooses the operating envelope. The agent may behave dynamically inside that envelope, but cannot silently expand or bypass it.**

Connector does not claim that every deployment is absolutely secure.

Instead, Connector makes the selected posture:

**explicit, applied, observable, enforceable, and reconstructible.**

---

## 2. Product model

```text
TOOLS
+
AUGMENTED ENVIRONMENT
+
CONSTRAINT / ISOLATION
+
MONITORING
+
PROOF
```

### Tools

Talk · MCP · CNP · CONP · model interfaces · databases · APIs · system tools · workflows · automation · VAC memory · mission runtime · AAPI effects

### Environment

Identity · character · knowledge · memory · DIM cognitive state · mission · relationships · namespaces · cognitive parameters · temporal state

### Constraints

Contracts · NF³ · PATE · WorldGrant · HITL · tokenization · budgets · isolation tiers · network restrictions · capability boundaries · ActionBinding

### Monitoring

Agent health · mission state · DIM state · regime · Φ · grants · denials · spend · budgets · HITL · degradation · isolation posture · traces

### Proof

Identity · lineage · configuration · action digests · approvals · Packet DNA · grants · receipts · mission journal · DIM journal · effect ledger · posture evidence · forensic export

---

## 3–20. The 20 fundamental capabilities

| # | Capability | Engineer control (summary) | Proof (summary) |
|---|------------|----------------------------|-----------------|
| **3** | **Agent Identity** — PID, principal, tenant, genome, lineage, charter version, continuity | Force-identity, ownership, child agents, crypto lineage, authority on identity change | Creation, version, lineage, identity-on-effect, charter/continuity transitions |
| **4** | **Character / Charter** — role, obligations, prohibitions, risk, escalation (not a prompt) | Per-workload charters; change → re-individuation | Charter version, activation, authority deltas |
| **5** | **Knowledge Boundary** — permitted / authoritative / prohibited sources, freshness, provenance | Source sets per agent class (research vs regulated) | Source set, retrieval trace, constraints active |
| **6** | **Memory Substrate** — working / episodic / semantic / mission / commitments | Persistence, classes, consolidation, retention, sharing | Writes, reads, namespace, provenance, consolidation |
| **7** | **Memory Constraints** — scoped access; existence ≠ access | R/W, cross-agent, inheritance, sensitive retention | Requested vs admitted memory, denials, grants |
| **8** | **Dynamic Intelligence State (DIM)** — Z_t, regime, Φ; survives idle/restart | Viability bands / ranges, not step micromanagement | Snapshots, regime, regulation, interference, wake |
| **9** | **Intelligence Physics Envelope** — exploration, recall, verification, wake, foresight ranges | Continuum of operating conditions (not only autonomous/blocked) | Active parameter envelope + regulation journal |
| **10** | **Agentic Loop Runtime** — observe→recall→reason→plan→admit→act→verify→update | Duration, wake/stop, HITL, retries, tool/spend limits | Mission journal progression (no raw CoT required) |
| **11** | **Mission / Trajectory** — goals, deadlines, commitments, progress | Trajectory budgets (effects, $, children, data, window) | Mission→step→request→admit→effect→result |
| **12** | **Capability System** — FS/API/MCP/CNP/CONP/tools/models/workflows | Declare what *may* exist | Capability inventory ≠ authorization |
| **13** | **Authority Membrane** — Contract · NF³ · PATE · WorldGrant · HITL · budgets · ActionBinding | Compose gates per profile | Cognition requests authority; never creates it |
| **14** | **World / Address Access** — address as capability pore | Broad playground vs harden allowlists | Grant used; tool switch must not bypass when enforce on |
| **15** | **Data Tokenization** — classify, seal, broker, destination-bound release; SVF progressive disclosure (S0–S5) | Off / selective / mandatory | Class, token state, detokenize auth, disclosure receipts ([CONNECTOR_SVF.md](./CONNECTOR_SVF.md)) |
| **16** | **Isolation** — T0…T5 continuum | Tier for workload | **Requested / Applied / Effective**; harden must refuse start if unmet |
| **17** | **Resource / Spend / Blast** — tokens, $, effects, time, children, exposure | Bounded envelopes (not unlimited “may trade”) | Budget ledger, BCR reserve-commit, trajectory |
| **18** | **Tool / Workflow / Automation** — MCP, CNP, CONP, schedules, missions | Same identity/grants/budgets/evidence follow automation | Background ≠ separate authority |
| **19** | **Effect / Transaction Control** — binding→risk→reserve→admit→HITL→exec→commit→receipt | Digest-bound HITL; compensate when inverse registered | Approve A ≠ execute B |
| **20** | **Monitoring / Evidence / Compliance** — operate as accountable systems | Evidence level, retention, export | Structured worldline, not “more logs” |

### DIM security rule (§8)

```text
DIM → reasoning behavior
DIM ↛ permission
```

### Authority invariant (§13)

> **Cognition can request authority. Cognition cannot create authority.**

Confidence, DIM regime, mission urgency, usefulness, memory, model output, child requests, KECS, and reasoning quality **cannot** independently create permission.

---

## 21–22. Engineer control plane and profiles

Compose an agent from a profile:

```text
Identity · Character · Knowledge · Memory · DIM · Model · WorldGrants · Tools
Autonomy · HITL · Tokenization · Budgets · Trajectory · Isolation · Evidence · Retention
```

| Profile | Intent | Soft-fail |
|---------|--------|-----------|
| **Playground** | Fast experiment; LAB UI mandatory | Allowed |
| **Pilot** | Real integration, bounded consequence | Loud / limited |
| **Harden** | High-consequence; mandatory primitives | **Forbidden** — unmet → **START REFUSED** |

---

## 23–25. Evidence, proof, and export

Evidence answers specific questions — identity, authority, action, data, cognitive (control-relevant only), execution, worldline — **not** raw CoT for control.

Distinguish:

| Kind | Meaning |
|------|---------|
| **Log** | Runtime observation |
| **Evidence** | Structured record tied to identity/execution |
| **Proof artifact** | Independently integrity-verifiable (digest, signed receipt, DNA, linked journal) |
| **Claim** | Statement Connector is entitled to make — **never more than evidence establishes** |

**Proof export** (`GET /proof/export/:agent_pid`, forensic packages): manifest, identity, posture, grants, journals, digests, HITL, AAPI receipts, DNA, budgets, compensation, integrity hashes.

---

## 26–30. Compliance model

Connector does **not** claim “we make an AI compliant.”

Compliance depends on organization, jurisdiction, purpose, process, people, and configuration.

Connector provides **technical controls and evidence** organizations map to their obligations.

| Concern | Connector control / evidence |
|---------|------------------------------|
| Identity | PID, principal, lineage |
| Least privilege | Contracts, capabilities, WorldGrant |
| Access control | PATE / NF³ |
| Data minimization | Tokenization, knowledge boundary |
| Segregation | Namespaces, isolation |
| Human approval | Digest-bound HITL |
| Change control | Charter / profile versions |
| Auditability | Receipts, journals |
| Accountability | Action↔agent lineage |
| Resource limits | Budgets / BCR / trajectory |
| Third-party access | Explicit WorldGrants |
| Investigation | Worldline export |
| Monitoring | Health / operator / DIM |
| Disclosure | Token / detokenize evidence |
| Continuity | Mission + identity journals |

**Conformance** = software matched selected Connector profile.  
**Organizational compliance** = org’s legal bar (Connector supplies evidence).  
**Certification** = external body only — Connector must not self-claim it.

---

## 31–33. Security model and invariants

Convergence of consequence paths (not random API checks):

```text
Agent → Identity → Capability → Authority → Data/world → ActionBinding → Execution → Evidence
```

Under harden, no legitimate Connector-managed path to the same consequence may skip these controls.

**Engineer** may change the envelope. **Agent** may operate dynamically *inside* it — never silently widen it.

### Five core invariants

1. **No self-authorization**
2. **Effect exclusivity** (when gate required, paths converge)
3. **Posture honesty** (requested ≠ applied unless true)
4. **Engineer freedom** (widen/narrow without redesigning runtime)
5. **Reconstructible consequence** (when profile requires evidence)

---

## 34. Linux analogy

| Linux | Connector |
|-------|-----------|
| process / PID / user | agent / agent PID / principal |
| permissions | grants / PATE |
| filesystem | knowledge + memory |
| namespace / cgroups | agent namespace / budgets |
| network namespace | WorldGrant |
| syscalls | tool / effect calls |
| scheduler / systemd | agent loop / mission·workflow |
| seccomp | action admission |
| container / VM | DockLock / microVM |
| IPC / drivers | CNP / CONP·HAL |
| audit / `/proc` | receipts / operator·DIM state |

Linux: which process may access which compute resource?  
Connector: **which intelligence, with which identity, character, knowledge, memory, cognitive state, mission, capabilities, and authority, may interact with which data, address, tool, agent, machine, or workflow, within what quantitative limits, and what consequence may it cause?**

---

## 35. Final product definition

**Connector is an agent operating substrate that gives engineers the primitives required to host dynamic agents as persistent, bounded, observable computational entities.**

It provides identity, character, knowledge boundaries, memory and memory isolation, persistent cognitive state, intelligence parameters, agentic loops, missions, capabilities, authority, address control, data tokenization, isolation, budgets, tools, workflows, automation, effect admission, monitoring, evidence, proof export, and compliance mapping.

The engineer decides how much freedom and constraint the agent receives. Connector’s job is to make that configuration **real rather than aspirational**.

> Give engineers control over the physics of the agent environment, give agents useful freedom inside those physics, force consequential execution through explicit boundaries when configured, and leave enough evidence to prove what the system actually admitted and executed.

Connector does not promise perfect intelligence or absolute security. It promises:

> **A configurable, evidence-producing execution substrate in which engineers can make agent capability, constraint, isolation, autonomy, and consequence explicit—and know whether those controls actually existed at runtime.**

---

# Appendix A — Engineered standard map (what already exists)

Honesty: **Engineered** = code path in this repo; **Partial** = present but soft / lab / incomplete; **Gap** = standard requires more than today’s surface.

| § | Capability | Primary engineered surfaces | Status |
|---|------------|----------------------------|--------|
| 3 | Identity | `kernel/agent_principal`, `identity_stack`, `agent_progeny`, `continuity`, genome/DNA hooks | Engineered (force-pid / harden gated) |
| 4 | Charter | AgentContract / intelligence principal, demote on change | Partial → Engineered path; profile UX incomplete |
| 5 | Knowledge boundary | `substrate/knowledge_boundary` + retrieve filter + `/knowledge/:pid/*` | Engineered |
| 6 | Memory | VAC MemPackets, `agent_memory`, episodic ToolCall/ToolResult, consolidation | Engineered |
| 7 | Memory constraints | `m/{kernel_pid}` namespaces, grants | Engineered (enforce modes vary) |
| 8 | DIM | `substrate/dim/*` Z_t, regime, regulate, journal, wake | Engineered (authority-neutral) |
| 9 | Intel physics envelope | DIM regulation + Θ; profile YAML bands | Partial (bands less productized) |
| 10 | Agentic loop | `dynamic_agent_loop`, `ltl`, CIP/DAL, agent_loop + PATE | Engineered / Partial |
| 11 | Mission / trajectory | `mission_journal`, `trajectory_budget` | Engineered |
| 12 | Capabilities | AAPI caps, tool registry, CLS compile | Partial (discovery ≠ auth — correct) |
| 13 | Authority membrane | `action_binding`, `nf3`, `pate`, `rgo`, HITL digests | Engineered |
| 14 | World / address | WorldGrant, `world_gateway`, address DAC / cage | Engineered when enforce on |
| 15 | Tokenization | `data_tokenization`, `llm_broker_gate`, sealed context | Engineered when broker on |
| 16 | Isolation | DockLock, Landlock, `microvm_tool_plane`, isolation tiers, posture | Partial→Engineered; T4/T5 vary |
| 17 | Budgets / blast | ActionEngine budgets, BCR (`aapi_effect_field`), trajectory | Engineered |
| 18 | Tools / workflow / automation | MCP/tools, CNP/CONP, CLS workflows, playground | Engineered (same-spine rule — close remaining ungated paths) |
| 19 | Effect control | PATE ATU, BCR reserve-commit, compensation receipts, digest HITL | Engineered / Partial compensate |
| 20 | Monitoring / evidence | `/substrate/status`, DIM operator view, `proof_export`, forensics | Engineered (worldline/proof). `/compliance/*` GRC reports exist separately — **not** the capability-standard finish line |

**Docs companions:** [DYNAMIC_INTELLIGENCE_MANIFOLD.md](DYNAMIC_INTELLIGENCE_MANIFOLD.md) · [AAPI_BEHAVIOR_RUNTIME.md](AAPI_BEHAVIOR_RUNTIME.md) · [KNOT_BELIEF_FIELD.md](KNOT_BELIEF_FIELD.md) · [CONNECTOR_SDB_RUNTIME.md](CONNECTOR_SDB_RUNTIME.md) · [NATIVE_PROTOCOL_SDB.md](NATIVE_PROTOCOL_SDB.md)

---

# Appendix B — How acceptance works

| Layer | Doc | Role |
|-------|-----|------|
| **Standard (this file)** | Capability + control + evidence + compliance model | Must-be-able-to-express |
| **Promise** | [CONNECTOR_PRODUCT_PROMISE.md](CONNECTOR_PRODUCT_PROMISE.md) | Guarantee vs non-guarantee |
| **Outcomes** | [CONNECTOR_FINAL_OUTCOMES.md](CONNECTOR_FINAL_OUTCOMES.md) | Binary E/A/S conformance |
| **CI honesty** | `scripts/audit-product-promise.sh` | Docs + symbols + anti-claims |

Closing remaining **Partial/Gap** rows in Appendix A *is* reaching this standard — not inventing a second product.

**Working checklist:** [CONNECTOR_REACH_CHECKLIST.md](CONNECTOR_REACH_CHECKLIST.md) — ordered phases, verify hints, exit criteria.
