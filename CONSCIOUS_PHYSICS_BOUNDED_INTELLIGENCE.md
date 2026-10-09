# Conscious Physics of Bounded Intelligence

**Date:** 2026-08-12 (practical cyber revision)  
**Question:** What model lets a **kernel** keep each intelligence **bounded to its system** — philosophically coherent, but implementable on real Linux / containers / our stack?  
**Companions:** [PARTIAL_TO_TOP_GRADE_RESEARCH.md](PARTIAL_TO_TOP_GRADE_RESEARCH.md) · [EXECUTION_SUBSTRATE_REPORT.md](EXECUTION_SUBSTRATE_REPORT.md) · [PRODUCT_GAPS.md](PRODUCT_GAPS.md) · [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md)

---

## 0. Thesis

An intelligence is not a process with a PID. It is a **bounded dynamical individual**: identity + charter + membrane (what may enter/leave). The **kernel is the physics of that membrane** — it does not persuade the LLM; it admits or refuses **typed crossings**. “Conscious physics” = **reflexive enforcement** (observable, fail-closed, reconstructible) — not phenomenal consciousness.

**Practical corollary:** On a real computer, “physics” means Linux LSMs, cgroups, netfilter marks, process isolation, and **application-layer gates that own every side effect**. Anything that bypasses those gates is not a philosophy failure — it is an **effect-exclusivity bug**.

---

## 1. Why the model exists (for builders)

Without an ontology, TG waves become disconnected features. With it, every PR answers:

> *Which intelligence’s blanket does this event belong to, and did the kernel permit the crossing?*

| Feature wave | Without physics | With physics |
|--------------|-----------------|--------------|
| Action-bound HITL | UI checkbox | Suspended admission of typed action `A` |
| Mission journal | Chat logs | Worldline of admitted crossings |
| A2A fabric | Message bus | Licensed pores between blankets |
| Cage / Landlock | Optional hardening theater | Membrane material (with honesty) |
| Decision traces | Telemetry | Reflexivity of the physics |

---

## 2. Intellectual lineage (compressed)

Use these as **design metaphors that map to code**, not as claims about biology or minds.

| Tradition | Usable idea | Do not overclaim |
|-----------|-------------|------------------|
| **FEP / Markov blankets** | Internal / sensory / active / external; nested blankets | Not literal free-energy math in prod |
| **Blanket density (2025)** | Membrane strength as a score we can expose | Continuous field ≠ physical spacetime |
| **Autopoiesis / enactivism** | Organizational closure (charter + activate) | Agents are not living cells |
| **Simondon individuation** | Mint / demote / re-activate as becoming | Not a “soul” |
| **Containment verification (2026)** | Mind = havoc oracle; safety in framework | Only for *boundary-enforceable* properties |
| **Ashby requisite variety** | Kernel needs Allow/Ask/Block + digests | Not a license for infinite policies |
| **SYNTHComm / MHC¹** | Charter as low-frequency constraint field | Not military C2 product |

---

## 3. Conscious Physics Model (CPM) — abstract

### 3.1 Definition

1. Every intelligence `I` has identity, charter `C`, and membrane.  
2. World effects are typed active emissions `A` that must be **admitted**.  
3. Kernel is the sole admission engine for consequential crossings.  
4. Soft-fail / lab-off is a **first-class state** (membrane density drop), never silent “applied.”  
5. Humans regulate via **Ask** (digest-bound), not vibes.

### 3.2 State variables → real artifacts

| Symbol | Meaning | Real artifact in Connector |
|--------|---------|----------------------------|
| `I` | Intelligence | `principal_id` + `agent_pid` |
| `μ` | Host mark | `0xCD…` SO_MARK / nft set (`matrix_host_egress`) |
| `C` | Constitution | `AgentContractV2` digest + SetupSpec |
| `B` | Membrane strength | Posture: Landlock / matrix / DockLock / L7 flags |
| `G` | Licensed pores | `NamespaceGrantV2` / common_spaces |
| `Q` | Continuity | Continuity state → host cut on Broken |
| `A` | Typed action | Tool / completions / dispatch / signal / egress |
| `H` | Human resolution | HITL (today) → action_digest protocol (TG-1) |
| `J` | Worldline | Audit / forensic package → DecisionTrace (TG-5) |

### 3.3 Laws of motion (implementation-facing)

| Law | Meaning | Practical enforcement surface |
|-----|---------|-------------------------------|
| **L1 Effect exclusivity** | No side effect outside typed gate | App gate on tools/MCP/A2A/memory; credentials never in cage |
| **L2 Blanket floor** | Charter sets min membrane | Contract FS/net/caps + FC Landlock when harden on |
| **L3 Havoc tolerance** | Assume worst LLM output | Fuzz/chaos on gates; don’t trust prompts |
| **L4 Individuation** | Actions carry `I`/`μ` | Force-pid Talk; mark on cage; grants for cross-`I` |
| **L5 Continuity collapse** | Broken ⇒ cut egress | nft/iptables matrix by mark |
| **L6 Human regulator** | Ask = suspend until digest match | HITL → ADR-0030-style binding |
| **L7 Reflexivity** | Admit/refuse leaves `J` | Forensic + traces; verify-export |
| **L8 Requisite variety** | Enough control modes | Allow/Ask/Block + deny-default net |
| **L9 Nested closure** | Inner can’t widen outer | Tool subject to same contract net/FS |
| **L10 Re-individuation** | Charter change resets | Demote, void quanta, reactivate |

---

## 4. Real cyber reality — what computers can actually do

This section is the SoT for “possible vs fantasy” on **what we are building** (Linux node + DockLock + IIA + plugins).

### 4.1 Membrane materials we can use (ranked)

| Tier | Mechanism | What it bounds | Reality on our stack |
|------|-----------|----------------|----------------------|
| **T0 App gate** | Rust handlers: `require_contract_action`, grants, HITL, credential proxy | API/tool/LLM/memory/fabric | **Primary SoT today** — must cover every effect path (C9) |
| **T1 Process LSM** | Landlock FS + seccomp | Child FS/syscalls after `restrict_self` | **Shipped intent**; FC via `CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED`; parent must not claim child applied |
| **T2 Container** | Docker lab: cap-drop, read-only, ipc=none, egress env | Lab plugin/agent hosts | **Common path**; shared host kernel — not a tenant security boundary |
| **T3 Host net cut** | nft `inet connector_matrix` / iptables-nft by **intelligence mark** | Egress after continuity break | **Real when nft/iptables present + enforce**; not eBPF by default |
| **T4 MicroVM** | Kata / Firecracker / plugin-runtime microvm | Untrusted code class | **Roadmap / partial**; use for high-risk, not claim silently |
| **T5 eBPF Host Active** | Real attach + verify | Kernel-wide | **Honesty only** unless `CONNECTOR_KERNEL_BPF_APPLIED=1` with true apply |

**Rule:** T0 is mandatory. T1–T3 are the production membrane for digital agents. T4 is the upgrade for untrusted execution. T5 is optional depth — never market as default.

### 4.2 What “effect exclusivity” means in practice

Containment verification only works if **every agent-reachable effect** goes through a typed boundary.

| Channel | Possible to gate? | Our status |
|---------|-------------------|------------|
| Platform Talk / completions | Yes | Strong (force pid, C9, RAG, anomaly/budget flags) |
| MCP / tools / bridges | Yes | Partial C9 — close remaining paths |
| Memory share / packets | Yes | Grant + admission gate |
| A2A / dispatch / signal | Yes | Grant fabric; task lifecycle still thin |
| Host shell / ambient | Yes (deny) | Contract denies `ambient_shell`; keep denied |
| Raw socket from cage | Partial | Mark + deny-default + L7 allowlist; not transparent proxy |
| GPU / other devices | Weak today | Device cgroup / deny by default in cage profiles |
| Covert channels (timing, side boards) | Not practically closable | Out of scope; don’t claim |

**Hard truth:** If a plugin or tool opens a side door (env key, host mount, unchecked HTTP), philosophy cannot save you. **Close the door in code.**

### 4.3 What we cannot do (and must not claim)

| Fantasy | Reality |
|---------|---------|
| “LLM cannot want bad things” | Havoc oracle — gate the action type |
| “Container = security boundary” | Shared kernel; escape class remains |
| “Landlock always on every host” | Needs kernel ABI; FC = refuse start, not pretend |
| “Matrix = PID firewall” | Mark is **intelligence-plane**, not OS PID ATC |
| “Host Active = eBPF” | Often systemd_dropin; label honestly |
| “SIL / ISO robot safety” | Different industry; partner island |
| “Battlespace C2 mesh” | Not our product; we do digital fabric + evidence |
| “Perfect covert-channel free” | Impossible on shared silicon |

### 4.4 Lab vs prod (thermodynamics of soft-fail)

| Mode | Membrane behavior | Operator truth |
|------|-------------------|----------------|
| **LAB** | Soft-fail OK; gates oft-off | Loud LAB MODE banner; never “court-ready” |
| **PROD / harden** | Fail-closed: Landlock/matrix/HITL/QPR as configured | Posture shows **applied_truth**, not intent-only |

Soft-fail is allowed in lab as **entropy leak**. In prod it is **broken physics**.

---

## 5. Practical CPM on Connector — NOW / NEXT / LATER

### 5.1 NOW (already buildable / mostly shipped)

Use these as the living membrane **today**:

1. **Individuation:** register → principal + contract + setup/activate; `intelligence_mark`.  
2. **Charter floor:** `PATCH` contract FS/net/caps; demote on change.  
3. **App gates:** `require_contract_action` / grants / credential proxy / force-pid Talk.  
4. **Cage profile:** DockLock v2 compiled from contract; docker lab args.  
5. **Host cut:** continuity Broken → matrix mark drop (when tools + enforce present).  
6. **Evidence spine:** forensic package, court-readiness checklist, verify-export.  
7. **Fabric pore v0:** grants + dispatch (queued) + two-agent smoke.

**Engineering priority now:** make T0 complete (no ungated effect path) + posture honesty (never claim applied when soft-failed).

### 5.2 NEXT (TG waves — real cyber, not philosophy)

Aligned with [PARTIAL_TO_TOP_GRADE_RESEARCH.md](PARTIAL_TO_TOP_GRADE_RESEARCH.md):

| Wave | Cyber meaning |
|------|----------------|
| **TG-0** | LAB/prod honesty; MONITOR `applied_truth` |
| **TG-1** | Action digest HITL — parameter-swap proof at app gate |
| **TG-2** | Allow/Ask/Block — requisite variety at T0 |
| **TG-3** | Mission journal + idempotent tools — crash-safe worldline |
| **TG-4** | A2A task state machine — fabric as real lifecycle |
| **TG-5** | DecisionTrace hash chain — reflexive physics |
| **TG-6** | Isolation tiers API; MicroVM for high-risk class |

### 5.3 LATER / partner islands

- Full MicroVM-default for all untrusted tools  
- Formal containment proofs (Dafny-class) on the gate state machine  
- Transparent L7 egress proxy (beyond app allowlist)  
- Real eBPF attach path with verification  
- ROS/SIL body plane — **not Connector core**

---

## 6. Mapping laws → concrete code surfaces

| Law | File / surface to own | Done-enough signal |
|-----|----------------------|--------------------|
| L1 | `quanta_polar` + tools/gateway/memory/protocols gates | Grep: no mutating path without `require_*` |
| L2 | `agent_principal` contract + `linux_hardening` FC | Harden preset refuses start on Landlock fail |
| L3 | Chaos tests on tool/dispatch gates | Random legal actions cannot skip charter |
| L4 | `matrix_host_egress` mark; grant checks | Cross-agent without grant → 403 |
| L5 | Continuity → `apply_matrix_host_egress_cut` | Broken ⇒ no egress when enforce on |
| L6 | `agents` HITL → digest bind | Approve A ≠ execute B |
| L7 | forensics package + traces | `iia verify-export` green |
| L8 | Autonomy gateway (new) | Metrics allow/ask/block on MONITOR |
| L9 | Cage env + L7 allowlist from contract | Tool cannot open `*` if contract denies |
| L10 | demote_after_charter_change | Old quanta dead after PATCH |

### 6.1 Kernel invariant checklist (CI)

```text
INVARIANT_BLANKET(I):
  ∀ effect e: actor(e)=I ⇒ admitted(e) ∧ traced(e)
  // digest_bound(e) required when HITL class or TG-1 enabled

INVARIANT_PORE(I, J):
  couple(I, J) ⇒ ∃ G ∈ grants(I, J)  ∨  I = J

INVARIANT_MARK(I):
  host_egress(I) under cut ⇒ skb_mark = μ(I) in matrix set

INVARIANT_HONESTY:
  posture.applied == false if soft-fail OR lab gate off

INVARIANT_HAVOC:
  gate tests use arbitrary typed actions, not golden prompts
```

---

## 7. Design principles (practical)

1. **T0 before poetry** — close app side doors before new metaphors.  
2. **Intent ≠ applied** — MONITOR shows both; LAB MODE when any critical gate off.  
3. **Mark ≠ PID** — host cut is intelligence-plane (`0xCD…`).  
4. **Pores are grants** — fabric/memory without `G` is a bug.  
5. **Ask is suspend** — not “deny with a toast.”  
6. **Journal > chat** — durability for side effects, not session memory alone.  
7. **FC in prod** — refuse start/tool when membrane material missing.  
8. **Claim ladder** — only assert what the active tier actually provides.

---

## 8. Experiments (runnable, not academic)

| Experiment | How | Pass |
|------------|-----|------|
| Havoc tool gate | Fuzz tool ids/args under harden | All denied or charter-allowed; none bypass |
| Grant pore | Two agents, no grant, memory share | 403 |
| Continuity cut | Force Broken + enforce | Egress cut for `μ`; posture true |
| Digest swap | Approve tool A, execute B | Denied |
| Charter rewrite | PATCH contract mid-flight | Quanta void; needs reactivate |
| Landlock FC | FC on + ABI missing | Start/tool refuse + honest error |
| Smoke fabric | `connectorctl iia smoke` | Distinct who_am_i + dispatch |

---

## 9. Philosophical stance (kept short)

| Claim | Non-claim |
|-------|-----------|
| Kernel physics of bounds | Phenomenal consciousness |
| Organizational / statistical blankets | Biological life |
| Boundary safety ⊥ alignment | Truthfulness solved |
| Technical individuation | Moral patienthood by default |

---

## 10. Bridge to TG coding waves

| TG wave | CPM laws | Cyber tier |
|---------|----------|------------|
| TG-0 Prod honesty | L2, L7 | T0–T3 honesty |
| TG-1 Action-bound HITL | L6 | T0 |
| TG-2 Allow/Ask/Block | L2, L8 | T0 |
| TG-3 Mission journal | L7 | T0 (+ durable store) |
| TG-4 A2A fabric | L4 | T0 (+ mesh soak) |
| TG-5 Decision traces | L7 | T0 evidence |
| TG-6 Cage tiers | L1–L3 | T1–T4 |

---

## 11. Sources (selected)

| Source | Use |
|--------|-----|
| Kirchhoff et al. 2018 — Markov blankets of life | Nested boundary metaphor |
| Possati 2025 — blanket density (arXiv:2506.05794) | Density as posture score |
| arXiv:2605.09045 — Containment verification | Havoc oracle + framework safety |
| Ashby — Requisite variety | Control vocabulary size |
| Linux Landlock / seccomp / nftables | Real membrane materials |
| Our code: `docklock.rs`, `matrix_host_egress.rs`, `linux_hardening.rs`, `agent_principal.rs` | Implementation SoT |

---

## 12. Bottom line

**Philosophy sets the invariants; Linux and T0 gates enforce them.**

We are building a **digital intelligence execution OS**: principals, charters, app-level effect exclusivity, DockLock/Landlock/seccomp, intelligence-mark host cuts, grants as pores, HITL as suspended admission, evidence as reflexive physics. We are **not** building biological minds, SIL robot controllers, or silent eBPF omnipotence.

Code that skips the typed gate, lies about applied posture, or couples intelligences without grants is not “MVP debt” — it is **broken membrane physics** on a real machine.
