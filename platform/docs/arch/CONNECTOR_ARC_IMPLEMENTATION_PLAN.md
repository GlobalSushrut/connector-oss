# Connector ARC — Implementation Plan

**Status:** Coding plan under [CONNECTOR_ARC.md](CONNECTOR_ARC.md)  
**Rule:** Extend existing surfaces (`governed_effect`, ActionBinding, BCR, CVR, DIM, microvm channels, proof_export). **No parallel admit stack. No second agent identity.**  
**Pass rule:** Capability + honesty (LAB labeled; harden refuse-closed) — same as FINAL_OUTCOMES.  
**Product outcome:** Usable + securely governed + augmented-ready — LLM gets **mediated access** to Connector (Talk/tools/memory/world inside \(\mathcal{A}\)). ARC must not ship as BCR-brick-wall / deny-all theater. See ARC “LLM access through Connector.”

---

## Center of mass (do not lose this)

ARC is **not** primarily “another authorization checklist.” It is a **state-transition runtime for agency**:

```text
AgencyState  →  AgencyTransaction  →  ConsequenceLease  →  WorldlineCommit
```

| Primitive | Role |
|-----------|------|
| **AgencyState** | Persistent principal (reconstructed from worldline) |
| **AgencyTransaction** | Kernel FSM for one governed effect (the center) |
| **ConsequenceLease** | Single-use, epoch-bound permission to realize one transition |
| **WorldlineCommit** | Authoritative evidence; AgencyState is derived from it |

Everything else — NF³, BCR, IFC, A-VSOCK, KVM, quarantine, scheduler — is an **input to** or **enforcement of** that transaction.

> Linux schedules execution. KVM bounds machines. **ARC commits governed transitions of autonomous agency into the real world.**

---

## Outcome acceptance (every phase)

Every phase exit must preserve **in-envelope success**:

| Check | Pass |
|-------|------|
| U1 In-envelope Talk | Bound agent Talk returns model output under playground and under ARC flags with non-zero BCR |
| U2 In-envelope tool | Declared contract tool + WorldGrant → Admit → lease mint → redeem → settle → commit (when lease flag on) |
| U3 Bypass closed | Undeclared / ungated path still denied (exclusivity + host bypass inventory when MicroCell) |
| U4 BCR meter ≠ ban | Exhausted budget refuses spend with clear error; restoring budget restores access — not permanent Connector lockout |
| U5 Augmented usable | `CONNECTOR_AUGMENTED_ENV=1` with gates met: start succeeds; Talk/tools work; unmet gate → START_REFUSED (honest), not silent empty agent |

Phases that only add Deny paths without U1/U2 green are **rejected**.

---

## 0. Standing (what already exists)

| ARC noun | Exists today as | Gap |
|----------|-----------------|-----|
| Agency ≠ body | CVR promote / `agent_pid` | No first-class `AgencyState`; no worldline-authoritative reconstruct |
| AgencyTransaction | implicit path through `governed_effect` | No kernel STM + crash/settlement algebra |
| Finite \(\mathcal{A}\) | contract ∩ grants ∩ trajectory ∩ posture (implicit) | Facets + **enforcement grades** (Observed/Enforced/Effective) |
| \(\hat Z\) vs latent | DIM operator_view | Type-level `GovernorInput` (no latent/private in Γ) |
| Lease / exclusivity | ActionBinding + exclusivity inventory | Typed lease + sink epoch check + atomic settlement |
| IFC (partial) | Tokenize / knowledge boundary | **Separate** conf / integ / provenance algebras |
| Quarantine | Ordered CVR lifecycle | Prove **unreachable consequence**, not only empty tables |
| A-VSOCK | vsock bytes | Protocol only; bypass inventory is the security claim |
| Scheduler | auto_policy / promote | Hints only — never Admit |

---

## 1. Module map (target tree)

```text
platform/server/src/substrate/
├── arc/                            NEW — agency transaction runtime
│   ├── agency_state.rs             AgencyState + reconstruct-from-worldline
│   ├── governor_input.rs           typed GovernorInput (hat Z only) — compile-time fence
│   ├── observable.rs               assemble ObservableState → GovernorInput
│   ├── autonomy_volume.rs          facets + EnforcementGrade + Effective meet
│   ├── transaction.rs              AgencyTransaction kernel + edge table
│   ├── transaction_store.rs        durable tx log (crash recovery)
│   ├── proposal.rs                 EffectProposal
│   ├── governor.rs                 Γ(GovernorInput, …) → calls pate/nf3/binding/bcr/ifc
│   ├── consequence_lease.rs        mint / redeem / epoch bind / settle hooks
│   ├── authority_epoch.rs          counter + sink-verifiable current-epoch API
│   ├── cognitive_epoch.rs          cognitive clock ↔ worldline
│   ├── worldline_commit.rs         authoritative commit / reconstruct
│   ├── ifc/
│   │   ├── confidentiality.rs     lattice (no write-down without declass)
│   │   ├── integrity.rs           lattice (no write-up of untrusted)
│   │   ├── provenance.rs          lineage DAG / digests
│   │   └── gate.rs                compose three relations (not one “most restrictive”)
│   ├── scheduler.rs                hints only — returns ScheduleHint, never Admit
│   └── avsock.rs                   protocol codec (not the security boundary)
├── governed_effect.rs              EXISTING — lease redeem + epoch verify hook
├── effect_exclusivity.rs           EXISTING — sink inventory + bypass inventory
├── effect_intent.rs                EXISTING — seed for EffectProposal
├── affordance_envelope.rs          EXISTING — seed for facet C
├── aapi_bridge.rs / BCR            EXISTING — RESERVED / settle budget
├── cvr/                            EXISTING — body; quarantine → unreachable proof
├── dim/                            EXISTING — feeds ObservableState only
└── …

guest: connector-vm-agent avsock codec (Phase F) — still no raw consequence path
```

**Ownership:** `arc::governor` is the **only** Admit authority. Scheduler returns `ScheduleHint`. DIM never appears inside `GovernorInput` as free-form private state.

---

## 2. Phased delivery

### Phase A — Vocabulary + digests (honesty first)

| ID | Work | Acceptance |
|----|------|------------|
| A1 | Land ARC docs + this plan; links from OPERATIONAL / REACH / ARCHITECTURE | Linked |
| A2 | `AgencyState` + `ObservableState`; **`GovernorInput` type excludes latent/private DIM blobs** | **DONE** — `substrate/arc/`; governor takes `GovernorInput` only |
| A3 | Facets v0 \(C{\sqcap}G{\sqcap}Q{\sqcap}P{\sqcap}N\) with `EnforcementGrade::{Observed,Enforced,Effective}` per facet; digests label grade | **DONE** — lab_partial Observed; Effective claim false |
| A4 | `/substrate/status` → `arc` block (digests, epoch, body, facet grades, LAB if partial) | **DONE** — `arc` key on status |
| A5 | Product-promise / anti-claim audit | CI pass |

**Exit:** Digests visible; no default behavior change.

---

### Phase B0 — ARC Transaction Semantics (**before leases**)

**Purpose:** Make `AgencyTransaction` the **kernel** of ARC — analogous to process state or DB transaction state — **before** minting leases or A-VSOCK.

Canonical happy path:

```text
PROPOSED → VALIDATED → RESERVED → LEASED → REDEEMING
  → EFFECT_STARTED → SETTLED → COMMITTED
```

Branches: `DENIED | WAITING_HITL | REVOKED | EXPIRED | FAILED | EFFECT_UNKNOWN | COMPENSATING | QUARANTINED | ABORTED`

| ID | Work | Acceptance |
|----|------|------------|
| B0.1 | Durable `AgencyTransaction` record + edge table in code/docs (who, epoch, budget, lease, body, worldline, rollback, crash rule) — see §2.1 | Doc + Rust enum + illegal-edge tests — **DONE** `transaction.rs` |
| B0.2 | `transaction_store`: append-only transitions; crash mid-edge leaves explicit state | Unit: recover after kill — **DONE** in-process DashMap |
| B0.3 | **Crash after EFFECT_STARTED before SETTLED → `EFFECT_UNKNOWN`** (no silent COMMITTED; no blind retry) | Property test — **DONE** |
| B0.4 | Idempotency key on proposal; compensate path hooks to existing AAPI inverse where registered | **DONE** — `idempotency_key` on tx; `lease::compensate_tx` on settle_failed (AAPI inverse when registered) |
| B0.5 | Worldline write rules per edge; **WorldlineCommit is authoritative** | Export stub — edges recorded on tx; commit module Phase E |
| B0.6 | Illegal: PROPOSED→REDEEMING, LEASED→COMMITTED skipping SETTLED, etc. | Exhaustive edge tests — **DONE** |

**Exit:** Transaction algebra frozen in tests; **no production lease enforcement yet**. Do not start Phase C until B0 green.

#### 2.1 Edge algebra (authoritative — implement as data)

For **every** legal edge, the implementation must encode:

| Field | Required |
|-------|----------|
| `from` / `to` | states |
| `who` | cognition / governor / sink / operator / sweeper |
| `epoch_rule` | unchanged \| must_match_current \| bump |
| `budget_rule` | none \| reserve \| commit \| release \| freeze |
| `lease_rule` | none \| mint \| redeem_begin \| consume \| revoke |
| `body_rule` | none \| require_bound \| freeze \| pause_vmm |
| `worldline_rule` | optional \| required append |
| `crash_recovery` | restart-safe rule (esp. EFFECT_UNKNOWN) |
| `rollback` | release reserve / revoke lease / compensate / none |

Sinks **must** call `authority_epoch::current(agent)` at redeem begin; `lease.epoch != current` → deny (epoch is part of sink protocol, not only connectord memory).

---

### Phase B — Governor + epoch wiring (on top of B0)

| ID | Work | Acceptance |
|----|------|------------|
| B1 | `AuthorityEpoch` bump on grant/charter demote/quarantine/revoke; sink-readable API | **DONE** — bumps with `CellRegistry::bump_epoch`; `arc::runtime::authority_epoch` |
| B2 | Drive STM: PROPOSED→VALIDATED→RESERVED (or DENIED/WAITING_HITL) via governor | **DONE** — `governor::record_pate_admit` under `CONNECTOR_ARC_GOVERNOR=1` |
| B3 | Governor uses **only** `GovernorInput` + facets + existing PATE/NF³/binding/BCR | **DONE** — hooks on `pate::admit_{talk,tool,conp}`; NF³ in `mint_atu`; BCR before RESERVED |
| B4 | Soft: log-only; Harden: skip governor → deny | **DONE** — Soft no-op; `CONNECTOR_ARC_HARDEN=1` requires GOVERNOR (ops preflight) |
| B5 | Proof export includes epoch + transaction id/state | **DONE** — `AgencyTransaction::proof_export` (`connector.arc.admit_proof.v1`) |

**Exit:** Γ façade live; Allow semantics match baseline gates for in-envelope (U1/U2).

---

### Phase C — ConsequenceLease + atomic settlement (ARC-5)

| ID | Work | Acceptance |
|----|------|------------|
| C1 | Lease struct: agent, body, tx_id, cognitive_epoch, **authority_epoch**, digests, IFC triple, BCR reservation, nbf/exp, nonce, approval, MAC | **DONE** — `arc/lease.rs` |
| C2 | Mint only on VALIDATED→…→LEASED; store durable with tx | **DONE** — `mint_on_reserved` once per tx |
| C3 | Sink protocol: verify epoch → REDEEMING → EFFECT_STARTED → SETTLED → COMMITTED | **DONE** — `redeem` / `settle_committed` |
| C3b | Crash between EFFECT_STARTED and SETTLED → EFFECT_UNKNOWN; operator/reconcile/compensate — **never auto COMMITTED** | **DONE** — `mark_effect_unknown` + unit |
| C3c | **Usability:** in-envelope path always mints+redeems+commits under flag (U2) | **DONE** — `LeaseSinkGuard` on tool.dispatch |
| C4 | First **one** real sink lease-only (prefer tool/HTTP via `governed_effect` / world_gateway); exclusivity lists it | **DONE** — `tool.dispatch` + exclusivity mediator inventory |
| C5 | Quarantine: bump epoch → revoke leases → fail redeem → unreachable proof (§G) | **DONE** — `CellRegistry::bump_epoch` → `revoke_agent_leases` |
| C6 | Replay / cross-agent / expired lease adversarial | **DONE** — unit tests in `lease.rs` |

**Exit:** Under `CONNECTOR_ARC_LEASE=1`, that sink cannot effect without lease; settlement honest under crash.

---

### Phase D — IFC as three algebras (ARC-7)

| ID | Work | Acceptance |
|----|------|------------|
| D1 | Separate modules: confidentiality lattice, integrity lattice, provenance lineage | **DONE** — `arc/ifc/{confidentiality,integrity,provenance}.rs` |
| D2 | Gate composes **three** checks — **not** a single “most restrictive” scalar across all three | **DONE** — `ifc::check_flow` + counterexample tests |
| D3 | Broker tokenize/detok respects conf; detok only post-Admit | **DONE** — `assert_detokenize_post_admit` in `detokenize_for_world` |
| D4 | Optional Dual-LLM quarantine summary — never expands \(\mathcal{A}\) | **DONE** — `ifc/dual_llm.rs` LAB Observed stub |

**Exit:** PII→external denied; integrity write-up denied; allowed flows still work (U2).

---

### Phase E — WorldlineCommit + AgencyState reconstruct

| ID | Work | Acceptance |
|----|------|------------|
| E1 | `WorldlineCommit` on SETTLED→COMMITTED; cognitive epoch linked | **DONE** — `worldline::commit_from_tx` monotonic seq |
| E2 | **Authoritative rule:** after restart, AgencyState = last COMMITTED epoch + deterministic replay of durable tx log; body rebind via CVR | **DONE** — `reconstruct_agency_state` |
| E3 | Export graph: proposal→lease→effect→settle→commit | **DONE** — `worldline::export_graph` |
| E4 | AACR compat layer — no double-write corruption | **DONE** — `aacr.rs` single-writer fence |

**Exit:** MicroCell death before snapshot does not invent a divergent AgencyState; worldline wins.

---

### Phase F — A-VSOCK protocol (**not** the security boundary)

| ID | Work | Acceptance |
|----|------|------------|
| F1 | Host/guest frame codec + integrity tag | **DONE** — `arc/avsock.rs` encode/decode round-trip |
| F2 | Guest rejects effect without LEASE_REDEEM class | **DONE** — `guest_assert_effect_class` |
| F3 | Epoch fencing on frames | **DONE** — `accept_host_frame` epoch fence |
| F4 | **Host bypass inventory** (required): no raw virtio-net consequence, no host mount, no second tool daemon, no ungated vsock effect — extend exclusivity adversarial under MicroCell | **DONE** — `bypass_inventory.rs` (closed or LAB) |
| F5 | Soft fallback when `ARC_AVSOCK=0` labeled LAB | **DONE** — status `f5_soft` |

**Exit:** Framed redeem works **and** alternate host/guest consequence paths inventoried closed. Perfect A-VSOCK auth without F4 is **not** a pass.

---

### Phase G — Effective Autonomy Volume + quarantine reachability + scheduler

| ID | Work | Acceptance |
|----|------|------------|
| G1 | Facets D/I/T filled; **Effective \(\mathcal{A}\)** = meet of facets with grade ≥ Enforced (Observed-only cannot shrink claim) | **DONE** — `with_dit_enforced` + `effective_meet` |
| G2 | Child meet \(\mathcal{A}_C=\mathcal{A}_P\sqcap\text{caveats}\); refuse amplify | **DONE** — existing `meet_child` |
| G3 | Faceted denial diagnostics | **DONE** — `FacetDenial` |
| G4 | Scheduler: `ScheduleHint` only (`PROMOTE|DEFER|FREEZE|…`); **cannot call Admit** | **DONE** — `assert_cannot_admit` fence |
| G5 | Dynamic isolation recommend; same AgentID | **DONE** — `IsolationRecommend` + `recommend` |
| G6 | Quarantine **unreachable consequence proof**: no live leases, no broker in REDEEMING/EFFECT_STARTED/EFFECT_UNKNOWN without fence, no child \(\mathcal{A}>\bot\), no direct egress, no deferred commit capable of succeeding — else `QUARANTINE_FAILED` | **DONE** — `quarantine_proof.rs` |

**Exit:** Conservation + unreachable QC; scheduler outside authority.

---

### Phase H — Memory classes

| ID | Work | Acceptance |
|----|------|------------|
| H1 | Class map: Working/Persistent/Knowledge/Shared/Secret/Mission/Evidence/ModelContext/Scratch + owner/share/destroy | **DONE** — `arc/memory.rs` class map |
| H2 | IFC per class (three algebras) | **DONE** — `default_ifc` + `assert_ifc_for_write` |
| H3 | SecretMemory tokenize | **DONE** — `requires_tokenize` / put refuses plaintext |
| H4 | EvidenceMemory append-only | **DONE** — `append_evidence` + overwrite denied |

**Exit:** Class deny without identity change; Secret tokenize; Evidence append-only.

---

## 3. Feature flags (honesty)

| Flag | Default | Role |
|------|---------|------|
| `CONNECTOR_ARC_GOVERNOR` | 0 | Governor + transaction drive |
| `CONNECTOR_ARC_HARDEN` | 0 | Soft→Harden: require GOVERNOR or deny (B4) |
| `CONNECTOR_ARC_LEASE` | 0 | Lease required at wired sinks |
| `CONNECTOR_ARC_IFC` | 0 | Three-algebra IFC gate |
| `CONNECTOR_ARC_AVSOCK` | 0 | Framed agency IPC |
| `CONNECTOR_ARC_SCHEDULER` | 0 | ScheduleHint only |
| `CONNECTOR_ARC_MEMORY` | 0 | Memory class ABI enforcement |
| `CONNECTOR_ARC_DURABLE` | 0 | Persist worldline + tx (JSONL or COPG) |
| `CONNECTOR_ARC_STORE` | `jsonl` | `jsonl` \| `copg` (redb operation graph) |
| `CONNECTOR_ARC_STORE_MAC_KEY` | (none) | HMAC integrity chain for COPG |

Turn GOVERNOR+LEASE on under augmented/production **only after B0+C green**. AVSOCK only with MicroCell Effective **and** F4 bypass inventory.

Escape hatches → `/substrate/status` → `escape_hatches` (E8).

---

## 4. Test & CI gates

| Gate | When |
|------|------|
| Exhaustive STM illegal edges + EFFECT_UNKNOWN recovery | B0 |
| GovernorInput cannot construct from raw DIM private | A/B |
| Facet grade honesty (Observed ⇏ Effective shrink) | A/G |
| Lease replay + epoch mismatch at sink | C |
| Crash after EFFECT_STARTED | C |
| AgencyState reconstruct from worldline | E |
| Host bypass inventory under MicroCell | F |
| Quarantine unreachable proof | G |
| `audit-authority-attack.sh` | Every phase |
| `audit-product-promise.sh` | A1+ |
| U1–U5 | Every phase exit |

---

## 5. Coding order (revised)

```text
 0  B0 AgencyTransaction semantics + durable store + EFFECT_UNKNOWN   ← before leases
 1  AgencyState + GovernorInput (hat Z typed)
 2  Authority epoch (sink-verifiable)
 3  Governor drive to RESERVED / DENIED / HITL
 4  ConsequenceLease + one lease-only sink + settlement
 5  Bypass adversarial on that sink
 6  WorldlineCommit + AgencyState reconstruct
 7  A-VSOCK protocol + host bypass inventory
 8  Delegation facet meet
 9  IFC three algebras
10  Effective AutonomyVolumeDigest (grades)
11  Scheduler hints (never Admit)
12  Memory classes
```

**Hard stops:** No C before B0. No F before C. No “\(\mathcal{A}\) Effective complete” while facets are Observed-only stubs. No scheduler Admit path ever.

---

## 6. Acceptance demos (engineer-facing)

**Usability:** 0 / 0b as before (access + BCR meter).

**Governance:**

1. Ceiling: high DIM confidence cannot expand tools.  
2. Lease: missing/stale/replay denied; valid path commits.  
3. Epoch: quarantine bumps epoch → previously issued lease fails at sink.  
4. Crash: EFFECT_STARTED then kill → EFFECT_UNKNOWN, not false COMMITTED.  
5. Attenuate: child cannot hold parent pore.  
6. Quarantine: unreachable consequence proof (not only empty lease map).  
7. Promote: same AgentID; Talk works; worldline continuous.  
8. IFC: conf and integ fail independently; allowed flow works.  
9. Reconstruct: restart → AgencyState matches worldline replay.  
10. A-VSOCK: framed redeem works **and** bypass inventory closed.  
11. Scheduler cannot Admit (type/API).  
12. Honesty + augmented ready (U5).

---

## 7. Explicit non-work

- Parallel admit stack / second agent identity  
- Compliance UIs as ARC finish line  
- Teaching KVM about missions  
- Single fungible “authority token” replacing \(C,B,L,\ldots\)  
- Deny-all defaults / BCR as permanent ban  
- Treating A-VSOCK auth as sufficient security without bypass inventory  
- Claiming Effective \(\mathcal{A}\) from Observed-only facets  
- Scheduler or DIM as Allow authority  
- Blind retry of EFFECT_UNKNOWN  

---

## 8. Definition of done (ARC plane reached)

| # | Criterion | Status (honesty) |
|---|-----------|------------------|
| 1 | Four primitives live | **DONE** — AgencyState / AgencyTransaction / ConsequenceLease / WorldlineCommit |
| 2 | B0 edge algebra + EFFECT_UNKNOWN | **DONE** — tested; crash → EFFECT_UNKNOWN |
| 3 | `NoLease⇒NoEffect` on inventoried sinks | **DONE Soft** — sinks: `tool.dispatch`, `llm.chat`, `conp.command` under `CONNECTOR_ARC_LEASE` |
| 4 | AgencyState reconstructible after death | **DONE Soft** — `reconstruct_agency_state` + JSONL or **COPG** (`CONNECTOR_ARC_STORE=copg`) |
| 5 | Effective A = Enforced/Effective only | **DONE Soft** — C/G/D/I/T/Q/P Enforced; **N Observed** (topology) labeled |
| 6 | Quarantine unreachable proof | **DONE** — `quarantine_proof` / `QUARANTINE_FAILED` |
| 7 | MicroCell body-only; A-VSOCK protocol | **Partial** — codec + bypass inventory; live wire still LAB |
| 8 | IFC three algebras; GovernorInput; scheduler outside authority | **DONE Soft** — flags off = Soft no-op |
| 9 | Product promise / anti-claims CI | **DONE** — existing hygiene |
| 10 | Usable triad U1–U5 on augmented node | **Operator verify** — not auto-green; run on real node |

**Not claimed:** full distributed COPG, live A-VSOCK security boundary, F4 all closed, U1–U5 CI demos, refreshed `arch.pdf`.  
**Durable standard:** [CONNECTOR_COPG.md](CONNECTOR_COPG.md) — redb graph+SQL-ish (not SQLite).

When Soft→Harden green on a node: mark REACH **Phase ARC** rows `[x]`/`[~]` accordingly + refresh `arch.pdf` / `arch.html`.

---

## 9. Soft vs Harden (flags)

See §3 feature flags. Default Soft: DashMap + optional JSONL. Harden: `CONNECTOR_ARC_HARDEN` + governor/lease as documented.
