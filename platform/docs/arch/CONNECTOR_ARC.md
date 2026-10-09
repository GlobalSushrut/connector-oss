# Connector ARC — Augmented Agency Runtime Architecture

**Status:** Target architecture SoT (next plane on top of engineered substrate)  
**Audience:** Architects, systems engineers, implementers  
**Does not replace:** [CONNECTOR_CAPABILITY_STANDARD.md](CONNECTOR_CAPABILITY_STANDARD.md) · [CONNECTOR_PRODUCT_PROMISE.md](CONNECTOR_PRODUCT_PROMISE.md) · [CONNECTOR_AGENT_ISOLATION.md](CONNECTOR_AGENT_ISOLATION.md)  
**Implementation plan:** [CONNECTOR_ARC_IMPLEMENTATION_PLAN.md](CONNECTOR_ARC_IMPLEMENTATION_PLAN.md)  
**Companions:** [EFFECT_EXCLUSIVITY.md](EFFECT_EXCLUSIVITY.md) · [DYNAMIC_INTELLIGENCE_MANIFOLD.md](DYNAMIC_INTELLIGENCE_MANIFOLD.md) · [CONSCIOUS_PHYSICS_BOUNDED_INTELLIGENCE.md](../../../CONSCIOUS_PHYSICS_BOUNDED_INTELLIGENCE.md) · [arch.pdf](arch.pdf)

---

## Outcome triad (what ARC must read as when done)

ARC is successful only when an engineer can operate a **usable, securely governed, augmented** environment — not when the prose is deep.

| Outcome | Means in practice | Fail if… |
|---------|-------------------|----------|
| **Usable** | Register → start → Talk/tools → promote/quarantine → proof export works on one spine; playground stays soft; APIs/flags/docs match behavior | Architecture exists but operators cannot run a day-2 agent without tribal knowledge |
| **Secure (governed)** | Consequences mediated (lease/exclusivity); \(\mathcal{A}\) non-expanding; cognition ≠ Allow; quarantine → zero agency; LAB vs Effective honest | Soft-fail sold as harden; DIM confidence mints permission; alternate effect paths open |
| **Augmented** | `CONNECTOR_AUGMENTED_ENV=1` node: refuse-start when Requested unmet; agency digests + worldline on live path; MicroCell Effective when claimed | “Augmented” means only a flag with no membrane, or KVM theater without agency governance |

**One sentence:** *Usable* so engineers ship agents; *secure* so reachable consequences stay inside the engineer envelope; *augmented* so the live node is a real agency environment, not a lab demo.

### LLM access through Connector (not a brick wall)

The product is an **access fabric with mediation**, not a deny-everything firewall.

```text
WRONG (BCR-as-brick-wall / block-first theater)
  LLM → blocked from tools/memory/world by default
  “security” = nothing works

RIGHT (Connector augmented outcome)
  LLM → proposes inside engineer envelope
       → Γ admits when in contract ∩ grants ∩ budgets ∩ posture
       → ConsequenceLease enables the effect
       → Connector realizes Talk / tools / memory / world
```

| Law | Meaning |
|-----|---------|
| **Access is the point** | Inside \(\mathcal{A}\), Talk and declared tools **must succeed** (lease minted, sink redeems, effect settles). Denial outside the envelope is success; denial inside is a product bug. |
| **Lease enables, does not smother** | `NoLease⇒NoEffect` closes *bypass* paths. It must not become “no lease ever minted.” In-envelope proposals mint leases by design. |
| **BCR meters, does not ban Connector** | Budgets (B) refuse *overspend*. They are not a substitute for a capability lattice (C). A zeroed exploratory budget in playground is fine; harden agents ship with engineer-sized \(B\) so work proceeds. |
| **Proportional autonomy** | R0/R1 stay usable (admit with evidence); R3 is HITL/fail-closed for high consequence — not global lockout. |
| **Same spine** | Playground soft-fail and augmented harden differ by **posture**, not by removing LLM access to Connector surfaces. |

**Anti-read:** “Secure” here means **governed + reconstructible + fail-closed when configured** — not absolute security, SIL, org certification, or making the LLM unable to use Connector.

---

## Center of mass

```text
AgencyState → AgencyTransaction → ConsequenceLease → WorldlineCommit
```

ARC is a **state-transition runtime for agency**. NF³, BCR, IFC, A-VSOCK, KVM, quarantine, and the scheduler are inputs to or enforcement of that transaction — not competing admit stacks.

---

## 0. Positioning

Connector already has machine isolation (MicroCell/Firecracker/KVM), Linux isolation (AgentCell), semantic authority (contract · WorldGrant · NF³/PATE · BCR · HITL), lifecycle, and worldline evidence.

What is missing as a **first-class operating abstraction** is the plane between **stochastic intelligence** and the **deterministic Unix/Linux execution world**.

ARC names that plane. It is **not** “better KVM.” KVM virtualizes machines. Connector ARC virtualizes **agency**.

> **Linux schedules execution. KVM bounds machines. ARC commits governed transitions of autonomous agency into the real world.**
>
> (Companion form: Unix gave computation a process; KVM gave machines a virtualization boundary; Connector ARC gives autonomous stochastic agency an operating abstraction.)

**Honesty:** ARC is the target architecture. Large parts of L1–L2 and fragments of L4–L5 are engineered today. L3 fabric (A-VSOCK, consequence leases as typed objects, AgencyState as `task_struct`-grade) is the coding frontier. This doc does not claim ARC is fully shipped.

---

## 1. Core thesis

Classical OS subject:

```text
user → process → syscall → resource → effect
```

Autonomous agent subject:

```text
observation → probabilistic state → belief/goals → intent
  → possible actions → consequence → new world → new cognition
```

Linux / containers / hypervisors isolate the **execution body**. They do not natively isolate agency, intent evolution, delegation, reachable future consequences, commitments, or autonomy.

**Primitive:**

> Agency is the persistent principal. Process, container, and VM are temporary execution bodies.

This strengthens the already-engineered law:

\[
\text{Agent} \neq \text{ExecutionBody}
\]

(same `agent_pid` across AgentCell ↔ MicroCell promote).

---

## 2. Layer stack (L0–L6)

```text
L6  INTELLIGENCE          — LLM / planner; proposes only
L5  AGENCY VIRTUALIZATION — identity, epochs, autonomy volume, worldline
L4  CONSEQUENCE VIRTUALIZATION — Γ admit, IFC, lease, BCR, HITL
L3  AGENT VIRTUALIZATION FABRIC — Agent ABI, A-VSOCK, scheduler, memory classes, body bind
L2  EXECUTION ISOLATION   — AgentCell / ns / cgroup / Landlock / DockLock
L1  MACHINE VIRTUALIZATION — Firecracker / KVM / jailer / vsock
L0  PHYSICAL COMPUTE
```

| Layer | Connector today | ARC target |
|-------|-----------------|------------|
| L6 | Model routers, Talk, agent-loop | Unchanged role: propose |
| L5 | `agent_pid`, DIM \(\hat Z\)/operator_view, Knot, mission journal, ancestry (partial) | `AgencyState`, cognitive epoch, **facet** \(\mathcal{A}\) digest, STM head |
| L4 | `governed_effect`, PATE, NF³, WorldGrant, ActionBinding, BCR, HITL, effect exclusivity | Typed `EffectProposal` → `ConsequenceLease` → redeem/settle; IFC labels on payloads |
| L3 | microVM channels, vsock bytes, lifecycle HTTP | A-VSOCK framed IPC, epoch fencing, agency scheduler, memory class ABI |
| L2 | AgentCell / DockLock / Landlock | Same; body remains disposable |
| L1 | CVR MicroCell / microd / Firecracker | Same; MicroCell = embodiment, not identity owner |
| L0 | Host | Unchanged |

**Rule:** Extend these modules. Do not invent a parallel admit path or a second agent identity.

---

## 3. Three governing planes

```text
COGNITIVE PLANE     — DIM · Knot · VAC · model   — NO DIRECT AUTHORITY
        │ propose
        ▼
AGENCY PLANE        — AgencyState · Γ · autonomy · epochs · IFC · worldline
        │ lease
        ▼
EXECUTION PLANE     — Effect broker · AgentCell · A-VSOCK · MicroCell · KVM
```

\[
\boxed{\text{Cognition proposes}} \quad
\boxed{\text{Agency authorizes}} \quad
\boxed{\text{Execution realizes}}
\]

No plane may impersonate another (maps to existing DIM-INV / authority-attack CI).

---

## 4. AgencyState (higher-order `task_struct`)

```text
AgencyState {
  AgentID
  identity, ancestry, mission, commitments
  observable_hat_z, belief_digest, uncertainty_est, policy_entropy_est  // hat Z only — non-authority
  // NEVER stores claimed complete latent LLM state as authority input
  capabilities, world_grants, authority_epoch
  autonomy_facets { C, G, D, I, T, Q, P, N }, autonomy_volume_digest
  memory_namespaces, confidentiality, integrity, provenance
  compute/memory/network/effect/exposure budgets
  body_id, body_type, isolation_profile
  cognitive_epoch, worldline_head
  transition_fsm_head   // current AgencyTransition id/state if any
}
```

**Persistence / failure rule:**

- **WorldlineCommit is authoritative.**
- After connectord or MicroCell death: reconstruct `AgencyState` from the last COMMITTED epoch + deterministic replay of the durable AgencyTransaction log; rebind body via CVR.
- Never treat an ephemeral in-memory AgencyState snapshot as truth over worldline.
- `AgencyState` survives body promote/destroy; body death alone does not destroy Agency.

**Today’s seeds:** agent meta + DIM folder + Knot + grants + BCR + CVR body bind + proof export.

---

## 5. Agency Transition (basic unit)

Unix: \(process \rightarrow syscall \rightarrow object\).

ARC:

\[
S_t \rightarrow a_t^{\text{propose}} \rightarrow \Gamma(\hat{Z}_t, A_t, \ldots, a_t) \rightarrow S_{t+1}
\]

\[
S_t = (X_t, \hat{Z}_t, A_t, M_t, C_t, R_t, W_t)
\]

Stochastic policy \(a_t \sim \pi(a\mid S_t^{\text{latent}})\) does **not** imply effect. Environment changes only if \(\Gamma = \text{Admit}\). Connector never evaluates \(\Gamma\) on unobserved latent cognition — see §5.2.

**Today’s Γ:** `ops_runtime` preflight → PATE / NF³ → ActionBinding → BCR → DNA → `governed_effect`.  
**ARC Γ:** same spine, plus explicit transition STM (§5.1), autonomy-volume membership (§6), IFC gate, lease mint.

### 5.1 Agency Transaction state machine (kernel of ARC)

A consequential effect is an **AgencyTransaction** — the runtime kernel (not “just another module”). Four center primitives:

```text
AgencyState → AgencyTransaction → ConsequenceLease → WorldlineCommit
```

Happy path:

```text
PROPOSED → VALIDATED → RESERVED → LEASED → REDEEMING
  → EFFECT_STARTED → SETTLED → COMMITTED
```

Branches / terminals:

```text
DENIED | WAITING_HITL | REVOKED | EXPIRED | FAILED
EFFECT_UNKNOWN | COMPENSATING | QUARANTINED | ABORTED
```

| State | Meaning | Who may enter | \(E_A\) | Budget \(B\) | Lease | Worldline | Body |
|-------|---------|---------------|---------|--------------|-------|-----------|------|
| PROPOSED | `EffectProposal` recorded | cognition → agency | unchanged | none | none | proposal digest | running |
| VALIDATED | Γ membership + gates OK | governor | unchanged | none | none | validate edge | running |
| RESERVED | BCR reserve + ActionBinding locked | governor | unchanged | reserve held | none | reserve receipt | running |
| WAITING_HITL | Obligation unmet | governor / HITL | unchanged | hold/release per policy | none | HITL wait | may pause |
| LEASED | `ConsequenceLease` minted | governor Admit | binds **current** \(E_A\) | reservation bound | **minted** | lease digest | running |
| REDEEMING | Sink verifies epoch + begins redeem | **sink** | **must match current** | held | redeem_begin | redeem edge | bound |
| EFFECT_STARTED | Real-world side effect may have begun | sink | match | held | in-flight | effect start | bound |
| SETTLED | Result known; BCR commit/release | broker/sink | unchanged unless revoke | commit/release | consumed | result digest | running |
| COMMITTED | WorldlineCommit; \(S_{t+1}\) advanced | runtime | unchanged | settled | dead | **required** | running |
| DENIED | Reject before lease | governor | unchanged | release if any | none | denial | running |
| EXPIRED | Lease TTL | sweeper/sink | unchanged | release | dead | expire | running |
| REVOKED | Epoch bump / explicit | operator / quarantine | **bump** | release | dead | revoke | freeze possible |
| FAILED | Known failure after start | sink | unchanged | compensate path | consumed | failure | running |
| EFFECT_UNKNOWN | Crash/loss after EFFECT_STARTED before SETTLED | recovery | unchanged | fence; **no blind retry** | fenced | unknown edge | running |
| COMPENSATING | Inverse effect (new tx) | AAPI | match rules | new reserve/lease | new lease | compensate link | running |
| QUARANTINED | Unreachable-consequence agency op | operator | **bump** | freeze | all revoked | QC receipt | freeze + VMM pause |
| ABORTED | Cancel before EFFECT_STARTED | operator | optional bump | release | revoke if any | abort | optional pause |

**Kernel invariants**

1. No PROPOSED → REDEEMING shortcut.  
2. REDEEMING requires `lease.authority_epoch == authority_epoch::current(agent)` at the **sink** (epoch is part of sink protocol, not only connectord RAM).  
3. Crash after EFFECT_STARTED before SETTLED → **EFFECT_UNKNOWN** (never silent COMMITTED; never blind retry).  
4. COMMITTED only after SETTLED; **WorldlineCommit is authoritative** for AgencyState reconstruct.  
5. Quarantine may preempt → REVOKED/QUARANTINED from any non-terminal.  
6. Soft/playground may collapse RESERVED+LEASED only if LAB labeled — never under ARC_LEASE harden.

**Edge table:** every legal edge encodes who, epoch_rule, budget_rule, lease_rule, body_rule, worldline_rule, crash_recovery, rollback — implementation plan Phase **B0**.

**Prior art:** Late-bound saga; AgentLedger reserve + fencing; Wharfie UNCERTAIN; Connector BCR + ActionBinding.

### 5.2 Observable vs latent cognition (scientific boundary)

The runtime **cannot** know the LLM’s full latent state.

\[
Z_t^{\text{latent}} \quad\text{(unobservable)} \qquad\neq\qquad \hat{Z}_t^{\text{observable}}
\]

Connector governs **only** with \(\hat{Z}_t\):

```text
model outputs / tool proposals
memory mutations + retrieved knowledge digests
policy entropy estimates (when available)
commitments / mission journal heads
effect history + denials
budget / posture / grant / body ids
IFC provenance on held objects
DIM operator_view / Knot digests (control-relevant only — not raw CoT for Allow)
```

Therefore:

\[
\Gamma = \Gamma(\hat{Z}_t, A_t, M_t, \mathcal{A}_t, a_t^{\text{proposal}}, \ldots)
\]

never \(\Gamma(Z_t^{\text{latent}})\).

| Signal class | May influence | Must not |
|--------------|---------------|----------|
| \(\hat Z\) entropy, DIM Φ, Knot interference | verification pressure, trajectory width, HITL threshold, posture *recommend* | DENY→ALLOW, expand \(\mathcal{A}\) |
| Unobserved latent intent | — | Any authority decision |

**Type-level rule:** `GovernorInput` is a closed struct of typed observations only. The governor API **must not** accept unrestricted DIM/model-private blobs. DIM feeds `ObservableState` → `GovernorInput` through an explicit assembler; raw latent fields are unrepresentable in Γ.

**Prior art:** “govern what you cannot observe”; MI9 agentic telemetry; metacognition as advisor not governor; Connector DIM-INV.  
**Discipline:** No phenomenal-consciousness claims; CPM/DIM remain membrane/cognitive-condition metaphors.

---

## 6. Autonomy Volume \(\mathcal{A}_t\) — computational definition

Not “may access X.” Conceptually the reachable consequence region — **but implementations must not enumerate LLM futures.**

### 6.1 Finite representation (product / meet of facets)

\[
\mathcal{A}_t \;=\; C_t \,\sqcap\, G_t \,\sqcap\, D_t \,\sqcap\, I_t \,\sqcap\, T_t \,\sqcap\, Q_t \,\sqcap\, P_t \,\sqcap\, N_t
\]

Each facet is a **bounded lattice** (or meet-semilattice). Meet \(\sqcap\) never amplifies. `AutonomyVolumeDigest` = hash of the **canonical encoding** of the tuple.

**Enforcement grade per facet:** `Observed` | `Enforced` | `Effective`.

- **Effective \(\mathcal{A}\)** = meet over facets with grade ≥ `Enforced` (prefer `Effective` when host-bound).
- An `Observed`-only facet **must not** shrink a marketed Effective reachable-set claim — label LAB / partial instead.
- Status reports grades explicitly (same honesty as CVR R/A/E).

| Facet | Symbol | Meaning | Connector encoding today / target |
|-------|--------|---------|-----------------------------------|
| Capability region | \(C\) | Declared tools / ops partial order | AgentContract tool surface |
| Grant / address region | \(G\) | WorldGrant pores, net/FS names | `world_gateway` grants |
| Data / IFC region | \(D\) | Max conf/integ labels possessable + egressable | Tokenize + IFC lattice (target) |
| Irreversibility / exposure | \(I\) | Caps on irreversible / high-blast ops | RGO class + trajectory exposure |
| Temporal horizon | \(T\) | Wall / mission / lease TTL envelope | session reap, lease exp, mission window |
| Quantitative budgets | \(Q\) | Remaining BCR / effect / child counts | BCR + trajectory + agent caps |
| Posture requirement | \(P\) | Min isolation profile for effects in region | V0–V4 / CVR applied |
| Topology / progeny | \(N\) | Max delegation depth + child \(\mathcal{A}\) ceiling | A26 narrowing + depth counter |

**Membership test (what Γ actually computes):**

\[
a \in \mathcal{A}_t \iff
\bigwedge_{\text{facets } F}
\text{proj}_F(a) \sqsubseteq F_t
\]

Denial diagnostics name **which facet failed** (faceted narrowing prior art).

### 6.2 Laws on the finite object

\[
\boxed{\mathcal{A}_{t+1} \not\supset \mathcal{A}_t}
\]

i.e. componentwise \(F_{t+1} \sqsubseteq F_t\) unless an **external authorized principal** expands a facet (engineer grant, HITL-approved expansion, charter change with re-individuation).

Learning, \(\hat Z\) confidence, model swap, memory growth, child spawn — alone — must yield \(\mathcal{A}' \sqsubseteq \mathcal{A}\).

**Ceiling vs active:** Engineer may fix ceiling \(B_{\max}\) at grant; active \(\mathcal{A}_t \sqsubseteq B_{\max}\). Agent evidence may shrink active authority, never raise ceiling (fixed-ceiling earned-authority prior art).

### 6.3 Agency conservation / non-creation

\[
\mathcal{A}_C \sqsubseteq \mathcal{A}_P, \quad
\mathcal{A}_{\text{delegated}} \sqsubseteq \mathcal{A}_{\text{source}}
\]

\[
\boxed{\text{Agency cannot create new agency}}
\]

Child mint = meet of parent \(\mathcal{A}\) with child caveats; refuse amplification.

### 6.4 Quarantine target — unreachable consequence

Successful quarantine is **not** “empty data structures.” It proves **unreachable consequence**:

1. Facets at bottom where meaningful (\(C=\emptyset\), \(G=\emptyset\), \(Q\) frozen, \(N\) progeny QC'd).
2. No valid external leases; redeem fails at every sink.
3. No broker work in `REDEEMING` / `EFFECT_STARTED` / `EFFECT_UNKNOWN` without fence.
4. No deferred/dispatched action that can still COMMIT later.
5. No direct egress / alternate consequence path.
6. Child \(\mathcal{A}=\varnothing\).
7. **Then** freeze AgentCell / pause VMM.

Else `QUARANTINE_FAILED`. Target: \(\mathcal{A}=\varnothing\) **and** no latent commit capability.

**Prior art alignment:** product-lattice / faceted attenuation; OCap caveats meet-semilattice; MAD narrowing; ChainCaps; blast-radius as reachability facets; Connector contract ∩ grant ∩ trajectory ∩ posture.

## 6b. Status: ARC not frozen

These three closures (§5.1 STM, §5.2 \(\hat Z\), §6 finite \(\mathcal{A}\)) are **required** before claiming ARC is implementation-complete theory. Until digests and STM are in code, treat Autonomy Volume language in status APIs as **best-effort facet compile**, not omniscient future-set enumeration.

## 7. \(\Omega_a\) — keep axes mathematically distinct

\[
\Omega_a = \langle C, B, L, E, O, R, P, W \rangle
\]

| Symbol | Meaning | Connector today | Must not collapse into |
|--------|---------|-----------------|------------------------|
| \(C\) | Capability lattice (partial order) | Contract / tool surface | Token credits |
| \(B\) | Resource vector | BCR reserve→commit | Permission |
| \(L\) | IFC (conf / integ / provenance) | Tokenization + knowledge boundary (partial) | Capability alone |
| \(E\) | Authority epoch | Continuity / demote / quarantine (partial) | Soft flags |
| \(O\) | Obligations | HITL digests, R3 | Confidence |
| \(R\) | Risk/exposure | DIM / RGO pressure (sensor) | Allow |
| \(P\) | Execution posture | V0–V4 / CVR | Authority |
| \(W\) | Worldline | Proof export / journals | CoT |

**ARC-6:** compute, confidence, entropy, money, reputation **cannot** mint \(C\) or expand \(\mathcal{A}\).

---

## 8. Viability region \(\mathcal{V}\)

Admitted transitions should keep \(S_t \in \mathcal{V} \Rightarrow S_{t+1} \in \mathcal{V}\) (or high-probability form for soft bands).

**Probability does not authorize.** It may raise verification, shrink autonomy radius, demand HITL, or require posture promote. Categorical NF³ remains hard.

Maps to DIM viability bands + Φ homeodynamics — already non-authoritative.

---

## 9. NF³ as boundary geometry

\(NF^3(S,a)\) asks whether the proposed transition lies inside the permitted region. Inputs may include consequence magnitude, irreversibility, information sensitivity, delegation depth — **separately** from uncertainty and confidence.

\[
\text{uncertainty} \neq \text{risk} \neq \text{authority}, \quad
\text{confidence} \neq \text{permission}
\]

---

## 10. Entropy as cognitive signal only

\(H(\pi)\) may feed the Agency State Estimator (trajectory width, verification depth) — never `DENY→ALLOW`. Compatible with DIM-INV-12 / DIM-EVAL-10.

---

## 11. Cognitive Epoch

Agency clock \(E_0, E_1, \ldots\) — one meaningful transition cycle (observe → update → propose → Γ → effect/receipt → worldline).

Epoch record digests: state, memory, authority epoch, autonomy volume, body, proposal, effect, result, worldline parent.

**Today:** mission journal + DNA + receipts + AACR epochs (partial).  
**Target:** every admitted consequence is an epoch edge on the worldline graph.

---

## 12–14. Consequence virtualization & lease

Hard posture: agent does not hold raw net/FS/secret/shell. It proposes `effect://…` **EffectProposal**s.

On Admit, Connector mints a **ConsequenceLease** (single-use, epoch-bound, digest-bound, not a bearer ambient token):

```text
propose → Γ → ConsequenceLease → EffectBroker redeem → world → settle → worldline
```

\[
\boxed{\text{No valid consequence lease} \Rightarrow \text{No consequential effect}}
\]

**Prior art:** ACP Execution Token; Macaroon/capability leasing; OCap caretakers; FIDES/MVAR sink mediation; LATTICE complete mediation; Connector EFFECT_EXCLUSIVITY.

**Today’s approximation:** ActionBinding digest + BCR reservation + governed_effect + exclusivity inventory.  
**Coding target:** promote that approximation to an explicit lease object redeemed only at lease-aware sinks (tool plane, world gateway, CONP, memory mutate, spawn).

---

## 15. A-VSOCK (Agency-aware IPC)

Ordinary vsock: CID, port, bytes.  
A-VSOCK frame adds: AgentID, BodyID, cognitive/authority epochs, message class, capability/transition ids, digests, nonce, integrity tag.

Classes: OBSERVATION, TRANSITION_PROPOSAL, LEASE_ISSUE/REDEEM, EFFECT_RESULT, MEMORY_*, SPAWN_*, FREEZE, QUARANTINE, REVOKE, PROMOTE, …

**Role:** nervous system between stochastic guest work and host agency governor — a **protocol**, not the security boundary.

Security boundary = MicroCell has **no alternate consequence-capable path** (no raw virtio-net effects, host mounts, second tool daemons, ungated vsock). Phase F acceptance requires a **host bypass inventory**, not only framed-message tests.

---

## 16–17. KVM and MicroCell under ARC

KVM must **not** learn belief/goal/authority. It stays CPU/memory/device isolation.

MicroCell = **disposable physical embodiment** of persistent Agency. Receives AgentID, BodyID, epochs, digests, A-VSOCK endpoint. Destroying the guest does not destroy Agency.

---

## 18–19. Authority epoch & quarantine

Authority-changing events increment \(E_A\). Sinks require `lease.epoch == currentEpoch` (ARC-8).

Quarantine is an **agency operation** ending at \(\mathcal{A}=\varnothing\) + body suspended (extends ordered quarantine already in CVR):

deny transitions → bump epoch → revoke leases/grants → invalidate A-VSOCK → stop redemption → settle inflight → freeze cell → pause VMM → progeny → verify zero reachable consequence.

---

## 20–21. Dynamic isolation & Agency Scheduler

Posture \(P\) may be **derived** from agency state (consequence radius, sensitivity, irreversibility) while AgentID persists — promote/demote body only.

Agency Scheduler inputs include autonomy volume, HITL wait, isolation need, child topology — outputs **ScheduleHint only**: RUN / DEFER / FREEZE / PROMOTE / DEMOTE / REQUEST_HITL / CONTRACT_AUTONOMY / QUARANTINE. **Hard rule:** scheduler never Admits; only `arc::governor` authorizes consequence / mints leases.

**Today:** `isolation: auto` + risk table + promote API.  
**Target:** auto policy fed by live \(\Omega\) sensors without letting sensors mint \(C\).

---

## 22–23. Agency memory & IFC lineage

Expand `m/{pid}` / VAC into typed domains (Working, Persistent, Knowledge, Shared, Secret, Mission, Evidence, ModelContext, Scratch) with owner/IFC/share/destroy policies.

Every object carries three **independent** components:

\[
L = \langle L_{\mathrm{conf}},\, L_{\mathrm{integ}},\, L_{\mathrm{prov}} \rangle
\]

| Component | Algebra | Typical rule |
|-----------|---------|--------------|
| Confidentiality | lattice (no write-down without declass) | High-conf data must not flow to low-conf sinks |
| Integrity | lattice (opposite trust direction) | Low-integ (untrusted) must not write-up into high-integ decisions without quarantine/summary |
| Provenance | lineage / digests | Derived values retain parents; gate checks acceptable provenance |

**Do not** collapse to one “most restrictive” scalar across all three — conf and integ move differently. The IFC gate runs **three** checks before lease mint.

**Today:** tokenization broker + knowledge boundary (partial). Full three-algebra IFC is Phase D.

## 24. Constitutional invariants (ARC-1…10)

| ID | Law | Engineered seed |
|----|-----|-----------------|
| ARC-1 | Agency ≠ ExecutionBody | CVR promote same pid |
| ARC-2 | Cognition ⇏ Permission | DIM authority-attack CI; \(\hat Z\) only |
| ARC-3 | \(\mathcal{A}\) non-expanding without external auth | Facet meet \(C{\sqcap}G{\sqcap}\ldots\); digest |
| ARC-4 | Delegation attenuation | Child narrowing A26 |
| ARC-5 | NoLease ⇒ NoEffect | Effect exclusivity + governed_effect |
| ARC-6 | Authority non-fungible | BCR ≠ Allow; DIM ≠ Allow |
| ARC-7 | Information follows consequence | Tokenize/detok + knowledge (partial) |
| ARC-8 | Stale epoch denied | Continuity cut / demote (extend to leases) |
| ARC-9 | Quarantine ⇒ \(\mathcal{A}=\varnothing\) | Ordered quarantine (strengthen verify) |
| ARC-10 | Worldline continuity | Proof export / DNA / receipts |

---

## 25. Prior art (research map — Connector-worthy, not cargo-cult)

| Body of work | What ARC borrows | What ARC must not copy blindly |
|--------------|------------------|--------------------------------|
| Reference monitor / complete mediation (Anderson, Saltzer–Schroeder) | Single mediated consequence path | Claiming unconditional safety if sandbox broken |
| Object capabilities / attenuation / caveat lattices | Non-amplifying meet \(\sqcap\); child ⊑ parent | Pure userspace caps without L1/L2 body |
| Faceted / product-lattice authority | Finite \(\mathcal{A}\) as facet meet + denial diagnostics | Omniscient enumeration of LLM futures |
| Fixed-ceiling earned authority | Agent evidence cannot raise ceiling | Soft “earned” expansion without engineer/HITL |
| IFC (FIDES, SafeFlow, MVAR, Jif lineage) | Labels on data before tool sinks | IFC alone without body isolation / exclusivity |
| Capability / execution tokens (ACP, Macaroons, leases) | Single-use epoch-bound lease | Long-lived bearer ambient tokens |
| Late-bound saga / AgentLedger / fencing | Propose→ledger→execute STM; reserve before side effect; fence stale workers | Equating durable workflow with agency law |
| MAD / ChainCaps narrowing | Child \(\subseteq\) parent | Protocol without host enforcement |
| LATTICE / five-plane governance | Plan vs control separation; stop-anywhere | Theater without fail-closed start |
| Blast radius / reachability | Facets of \(\mathcal{A}\) | Scoring spreadsheets as enforcement |
| Observable-only governance / MI9 telemetry | \(\hat Z\) boundary; govern what you can observe | Pretending full latent cognition is known |
| Metacognition-as-advisor | Estimators advise verification only | Meta-LLM as Allow authority |
| CPM / DIM (Connector) | Membrane physics; cognition non-authority | Phenomenal-consciousness claims |

**Connector differentiator:** one stack that binds **agency governance + consequence mediation + Linux/KVM embodiment + reconstructible worldline**, with posture honesty (LAB vs Effective). Most IFC/agent papers stop at planner middleware; most VMM work stops at machines.

---

## 26. What Connector becomes (target one-liner)

> **Connector is an agency virtualization substrate for augmented environments.** It separates stochastic intelligence from authority and physical consequence, represents an agent as persistent `AgencyState` rather than a Unix process, constrains reachable consequence space \(\mathcal{A}\), and maps admitted agency transitions onto disposable AgentCell/MicroCell bodies with lease-mediated effects and worldline evidence.

Current product promise (tools · env · isolation · monitoring · proof) remains the **shipped slice**. ARC is the **deepening** of that slice into an OS-grade agency plane.

---

## 27. Explicit non-goals

- Teaching KVM about beliefs or missions  
- Claiming 100% secure / SIL / org compliance by architecture text  
- Replacing enterprise IAM, SIEM, or GRC platforms  
- Letting DIM/entropy/confidence expand \(\mathcal{A}\)  
- A second effect path “for performance” under harden  

---

## Related

- Coding plan: [CONNECTOR_ARC_IMPLEMENTATION_PLAN.md](CONNECTOR_ARC_IMPLEMENTATION_PLAN.md)  
- Isolation body plane: [CONNECTOR_AGENT_ISOLATION.md](CONNECTOR_AGENT_ISOLATION.md) · [CONNECTOR_ISOLATION_IMPLEMENTATION_PLAN.md](CONNECTOR_ISOLATION_IMPLEMENTATION_PLAN.md)  
- Record PDF: [arch.pdf](arch.pdf)
