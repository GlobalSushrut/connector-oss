# Connector OS — What You Get When IIA Is Complete (On Top of Today)

**Audience:** operators, builders, security/legal, investors, and anyone who will market or evaluate Connector after the **P10 Intelligence Identity Architecture (IIA v2)** upgrade.  
**Rule:** every capability below is labeled **today** (already in code / engineering green), **after IIA** (requires P10.9 `make iia-court-gate`), or **market sign-off** (human Final GO on top of engineering gates).  
**Coding queue:** [IIA_CORE_UPGRADE_CHECKLIST.md](IIA_CORE_UPGRADE_CHECKLIST.md) · [FINAL_REACH.md](FINAL_REACH.md) P10 · **today’s truth:** [docs/CONNECTOR_TRUTH_STORY.md](docs/CONNECTOR_TRUTH_STORY.md)  
**What the node already is (kernel → ACS):** [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) **v3 §0**.

---

## One sentence

**Today:** Connector is a self-hosted AI operating substrate — one governed node where agents, models, tools, workflows, and plugins run under shared identity, admission, isolation, memory, audit, and usage truth, with L5 mesh and custody **engineering foundations** proven on lab soaks.

**After IIA (P10 complete):** The same node becomes a **verifiable intelligence identity and execution system** — every model is admitted through N4, every effect requires a signed execution quantum through QPR, DockLock physically enforces the contract, and TraceTramp/WitnessCtl produce **Ed25519 court-tier evidence** that survives offline verification and tamper detection.

**Not automatic with IIA alone:** Market L4/L5 human sign-off, clean-VM flagship tar, QUIC peer mTLS fabric, or “we replace your cloud IAM.” Those stay on [FINAL_REACH.md](FINAL_REACH.md) P7–P9.

---

## The stack — two layers, one product

```text
┌─────────────────────────────────────────────────────────────────────┐
│  AFTER IIA (P10) — vertical spine (court-grade intelligence)      │
│  Agent Kernel · N4 · QPR · DockLock · ERM · IntelligenceReceipt   │
├─────────────────────────────────────────────────────────────────────┤
│  TODAY (L3–L5 engineering green) — horizontal substrate             │
│  Gateway · Admission · Agents · Memory · Cages · CLS/CNP · TT/WC/DG │
│  CFNI · Moments · Books · Mesh soak · Custody quorum · Dashboard    │
└─────────────────────────────────────────────────────────────────────┘
         ▲
         │  LLMs, SDKs, OpenAI-compatible clients, mesh peers
```

IIA does **not** replace the substrate. It **threads** intelligence identity and execution authority through every path the substrate already governs.

---

## What you already have **today** (do not re-build)

These are **starting points** — real code, engineering gates, or soak evidence. IIA **upgrades** them; it does not throw them away.

| Domain | What works now | Evidence |
|--------|----------------|----------|
| **Sovereign node** | One install: `connector-platform` + `connectorctl` + dashboard | `make package`, `connectorctl start` |
| **Governed gateway** | OpenAI-compatible LLM path with admission, routing, cost posture | Service Map, gateway APIs |
| **Agent lifecycle** | Register agents as PIDs with namespace and principal hooks | `POST /agents`, Ring 1 identity |
| **Effect admission** | HTTP routes mapped to `admission_gate` (Gate-2 *paths*) | [admission-matrix.md](docs/architecture/admission-matrix.md) |
| **Isolation** | Cage / microVM / plugin-runtime with honesty badges | cage smoke, prod preset |
| **Memory & moments** | MemPackets, Object Fabric, content-addressed recall | L4 physiology |
| **Institutions** | TraceTramp, WitnessCtl, DevGuard as apps on the OS | plugin catalog, `/plugin/…` |
| **Programs** | CLS workflows, CNP dispatch tokens | workflow enable/dry-run |
| **Forensics (lab)** | CFNI flow stamps, HMAC audit paths | `forensic_flow.rs` — **upgraded to Ed25519 in IIA** |
| **Short-lived tickets** | Flow lease on hot paths | `flow_lease.rs` — **upgraded to ExecutionQuantum in IIA** |
| **Placement** | SGKE geo×hardware deny, HardwarePlacementV2 seed | `sgke_gate.rs`, `/runtime/mesh` |
| **L5 mesh (engineering)** | Peer mesh ping, governed channel, fabric claim after soak | `.l5-mesh-soak.ok` |
| **Custody (engineering)** | 3-node live WitnessCtl quorum path | `.custody-multinode-soak.ok` |
| **Honesty** | No fake `$0`, no decorative `verified`, failover/mesh flags honest | `make engineering-reach-gate` |

**Operator stories today:** [CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md](CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md) Stories A–D (gateway + TraceTramp + WitnessCtl + DevGuard + workflow catalog).

---

## What IIA **adds** — the delta (after P10.9)

### The constitutional separation (product language)

| Separation | Today (partial) | After IIA |
|------------|-----------------|-----------|
| **Intelligence ≠ Identity** | Agent PID + prompt persona | Cryptographic `cnktr:agent:*` principal; same model → many distinct agents |
| **Identity ≠ Authority** | Policy + admission on routes | Signed **Agent Contract**; model cannot self-grant |
| **Authority ≠ Execution** | Flow lease / admission ticket | **Cognitive Proposal (CPO)** from N4; not executable by itself |
| **Execution ≠ Evidence** | CFNI HMAC, TT/WC partial | **Execution quantum** → DockLock → **IntelligenceReceipt** hash chain |
| **Model ≠ Principal** | Model is wired in gateway | N4 handshake + **IntelligenceProfile** (claimed/observed/attested/accepted) |

### The two gates (every protected effect)

```text
Model output
    → N4 (Gate 1): handshake · qualify · context classes · CPO
    → QPR (Gate 2): polarize → ExecutionQuantum (nonce, expiry, contract-bound)
    → DockLock: cage/fs/net/process enforcement bound to quantum
    → OS/HW → WitnessCtl / TraceTram → signed receipt
```

**After IIA, Connector can:**

1. **Prove who the agent is** — independent of which LLM weights are plugged in (`GET /runtime/self`, signed contract, continuity ledger).
2. **Admit intelligence safely** — unqualified models rejected at N4; prompt injection becomes a labeled CPO, not a shell command.
3. **Quantize authority** — no ambient “the agent has filesystem access”; each effect needs a fresh, single-use quantum.
4. **Enforce physically** — bypass attempts (shell, raw SDK, network side-door) fail at DockLock with adversarial tests.
5. **Witness execution reality** — signed Execution Reality Manifest (node, hardware tier honest: none / TPM / TDX).
6. **Break continuity on tamper** — tool/runtime hash change revokes quanta and isolates egress before damage spreads.
7. **Reconstruct causality** — human intent → CPO → quantum → DockLock → PID → syscall → object in TraceTram.
8. **Export court-tier packages** — Ed25519 receipts; `connectorctl verify-export` offline; tamper one record → verify fails.
9. **Delegate across mesh cells** — four-ID linkage (Agent / Intelligence / Runtime / Machine) on cross-node effects.
10. **Run the flagship demo** — 14-step §23 scenario (two principals, deny inject, bypass fail, tamper detect) on clean VM.

---

## Capabilities by persona (after IIA on today’s node)

### Operators / platform engineers

| Capability | Today | After IIA |
|------------|-------|-----------|
| Run one governed node | Yes | Yes — unchanged install story |
| Point agents at gateway | Yes | Yes — plus N4 intercept on tool calls |
| See agent in catalog | PID + namespace | **Self envelope**: principal, contract digest, continuity state |
| Mesh / HA honesty | Engineering soak green | Same honesty rules + four-ID on cross-cell traffic |
| Backup trust domain | Yes | Export includes intelligence receipt chain |
| Prove node health | `engineering-reach-gate` | + `make iia-court-gate` |

### Builders / agent authors

| Capability | Today | After IIA |
|------------|-------|-----------|
| Register agent, call gateway | Yes | Principal minted at register with signed contract |
| Use tools under admission | Route-level gate | **CPO → quantum required** on every effect path |
| Same model, different agents | Convention / separate PIDs | **Cryptographically distinct** `cnktr:agent:*` + contract |
| Swap model version | Config change | **IntelligenceID** updates; **AgentID** stable; continuity explicit |
| SDK integration | OpenAI-compat HTTP | + `connector.self()`, `/n4/*`, `/qpr/intent` for native apps |

### Security / compliance / legal

| Capability | Today | After IIA |
|------------|-------|-----------|
| Policy on high-risk paths | Workflows + WitnessCtl hooks | Contract + quantum scope = auditable authorization |
| Tamper-evident logs | Keyed HMAC audit | **Ed25519 court tier** + hash-linked receipts |
| Independent verify | Partial recompute | **`connectorctl verify-receipt` / `verify-export`** — no UI trust |
| Prompt injection defense | Admission + policy | N4 context classes; inject → CPO only, QPR deny |
| Bypass resistance | Cage + admission | DockLock adversarial gate; prod deny without quantum |
| Multi-party custody | 3-node soak (engineering) | Custody export on **Ed25519** receipt chain |
| Court admissibility posture | **Not yet** — do not claim | **Target after T24** + human P10.9 sign-off |

### FinOps / SRE

| Capability | Today | After IIA |
|------------|-------|-----------|
| Usage-first books | Yes | Receipts tie spend to **principal + quantum** |
| Trace by agent | TraceTramp | Trace links **CPO → quantum → effect** |
| Placement deny | SGKE gate | ERM + contract + SGKE on schedule/filter |
| Global mesh | Engineering T13/T15 | Delegate API + placement filter by principal |

---

## Stories — today’s A–D **plus** IIA scenarios

### Story E — “Two agents, one model, zero identity collapse”

**Who:** Platform team runs Developer and Finance agents on the **same** LLM endpoint.

**After IIA:** `GET /runtime/self` on each shows distinct `cnktr:agent:*`, contracts, capability sets, and continuity chains. Auditors export both histories; verify offline; tamper fails. **Claim test T19.**

### Story F — “The model tried to steal — the OS said no”

**Who:** Red team prompts Finance data access through Developer agent.

**After IIA:** N4 emits CPO with untrusted context labeled; QPR denies quantum for out-of-contract target. No file read occurs. TraceTram shows deny at polarization, not “model refused nicely.” **Claim tests T20, T21.**

### Story G — “They bypassed the chat UI”

**Who:** Attacker uses shell or raw SDK against the host.

**After IIA:** No valid ExecutionQuantum → DockLock denies process/network/fs. `make docklock-bypass-adversarial` green. **Claim test T22.**

### Story H — “Someone swapped the tool binary”

**Who:** Supply-chain change to a registered tool.

**After IIA:** Continuity evaluator marks BROKEN; new quanta revoked; egress isolated. Manifest and receipt chain show before/after hashes. **Claim test T23.**

### Story I — “The auditor did not trust our dashboard”

**Who:** External counsel receives custody export package.

**After IIA:** `connectorctl verify-export` on air-gapped machine; Ed25519 signatures valid; one flipped byte → fail. Dashboard green is irrelevant. **Claim test T24.**

Stories A–D remain the **horizontal** product finish line; Stories E–I are the **vertical** IIA finish line. Together they describe the full Connector promise.

---

## Runtime APIs you gain (after IIA)

| API | What it answers |
|-----|-----------------|
| `GET /api/v1/runtime/self` | Who am I? Contract? Continuity? Model ref? |
| `GET /api/v1/runtime/contract` | Signed constitution + digest |
| `GET /api/v1/runtime/hardware` | Signed Execution Reality Manifest |
| `GET /api/v1/runtime/permissions` | What quanta could be issued now? |
| `GET /api/v1/runtime/provenance` | CPO / quantum / receipt chain head |
| `POST /api/v1/runtime/delegate` | Bounded cross-agent / cross-cell delegation |
| `POST /api/v1/n4/hello` | Intelligence handshake |
| `POST /api/v1/n4/qualify` | Profile quadrants |
| `POST /api/v1/n4/cognize` | Model turn → **CPO** (not execution) |
| `POST /api/v1/qpr/intent` | CPO → **ExecutionQuantum** |

---

## How you **prove** it (gates)

| Stage | Command | Meaning |
|-------|---------|---------|
| **Today baseline** | `make engineering-reach-gate` | L3–L5 engineering green (mesh + custody soaks) |
| P10.2 Identity | `make iia-p0-gate` | Two principals, `/runtime/self` |
| P10.3 N4 | `make iia-n4-gate` | Handshake, CPO, no raw tool exec |
| P10.4 QPR | `make iia-qpr-gate` | Quantum on all effect paths |
| P10.5 DockLock | `make docklock-bypass-adversarial` | Bypass fails |
| P10.6 Continuity | `make iia-continuity-gate` | Break stops quanta |
| P10.7 Forensics | `make iia-forensics-gate` | TT/WC receipt chain |
| **IIA complete** | `make iia-court-gate` | T19–T24 + §23 flagship |
| **Market L4/L5** | `FINAL_GO_RUNBOOK` + human sign-off | Still required for public “+2 / +3” claims |

---

## Before / after — honest comparison

| Question | Today | After IIA |
|----------|-------|-----------|
| Who is this agent? | PID + namespace + policy hooks | Signed `cnktr:agent:*` + contract + continuity |
| Can the model execute tools directly? | Sometimes via gateway paths | **No** — CPO then quantum required |
| Is CFNI “court-grade”? | HMAC lab tier — **say lab only** | Ed25519 court tier on export path |
| Same LLM, two agents? | Ops convention | Cryptographic separation |
| Prompt injection? | Policy/admission partial | N4 context + QPR deny with receipt |
| Shell bypass? | Cage + admission partial | DockLock + adversarial gate |
| Offline verify export? | Partial | `connectorctl verify-export` |
| Mesh identity on wire? | Peer mesh + channel | Four-ID + delegate |
| Market “court-grade custody”? | Engineering soak only | IIA receipts + P9 human sign-off |

---

## What Connector **still will not** claim (even after IIA)

- Subjective AI “consciousness” or sentience — only **cryptographic self-awareness** via runtime APIs.
- That the model is trustworthy — models stay **untrusted intelligence parameters**.
- Automatic global failover or multi-master SoT without soak + honesty flags.
- QUIC mutual-auth fabric while peer mTLS path remains `fail_closed`.
- Exact cloud provider invoices — usage truth ≠ billing oracle.
- Kubernetes-as-the-product — Connector is the OS for intelligence, not a chart collection.
- Court admissibility in **your** jurisdiction without **your** legal review — we provide verify artifacts; counsel decides admissibility.

---

## Copy blocks (use only after `iia-court-gate` + P10.9 sign-off)

### Elevator (IIA complete)

> Connector OS is the operating system for autonomous intelligence. Every agent has a cryptographic identity and signed contract independent of the LLM. Models are admitted through N4, authorized through short-lived execution quanta, enforced by DockLock, and proven with Ed25519 receipts you can verify offline — on one node or across a governed mesh.

### For security buyers

> Intelligence is not identity. Identity is not authority. Connector separates them in code: cognitive proposals never execute without a contract-bound quantum; bypass paths fail closed; exports verify without trusting our UI.

### Do not use until both IIA court gate **and** market Final GO

> ~~“Fully court-admissible in all jurisdictions”~~ · ~~“Models cannot hallucinate”~~ · ~~“Zero-trust AI”~~ (vague) · ~~“HMAC receipts are court-grade”~~

---

## Where this sits in the doc library

| Need | Document |
|------|----------|
| **This file** — capability vision after IIA | `CONNECTOR_WHEN_IIA_COMPLETE.md` |
| IIA coding checklist | [IIA_CORE_UPGRADE_CHECKLIST.md](IIA_CORE_UPGRADE_CHECKLIST.md) |
| Today’s honest marketing | [docs/CONNECTOR_TRUTH_STORY.md](docs/CONNECTOR_TRUTH_STORY.md) |
| Operator stories (horizontal) | [CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md](CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md) |
| Full product grades A/B/C | [FINAL_OUTCOME.md](FINAL_OUTCOME.md) |
| L3–L5 + P10 coding queue | [FINAL_REACH.md](FINAL_REACH.md) |
| IIA architecture canon | `docs/architecture/intelligence-identity-architecture-v2.md` (import pending) |
| Architecture index | [ARCHITECTURE.md](ARCHITECTURE.md) |

---

## Progress honesty

| Milestone | Status |
|-----------|--------|
| L3–L5 engineering green | **DONE** — `make engineering-reach-gate` |
| IIA P10 canon + types + gates | **OPEN** — [IIA_CORE_UPGRADE_CHECKLIST.md](IIA_CORE_UPGRADE_CHECKLIST.md) |
| IIA court-grade market claim | **OPEN** — requires `make iia-court-gate` + P10.9 human sign-off |
| L4/L5 market claim | **OPEN** — FINAL_REACH P7/P9 human sign-off |

*If this document describes court-tier Ed25519 exports while `signing_tier` is still `hmac_lab` in code, the doc is ahead of reality — fix the doc or ship the gate.*
