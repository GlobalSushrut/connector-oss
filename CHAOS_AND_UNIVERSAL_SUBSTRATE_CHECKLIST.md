# Chaos Inventory & Universal DI Substrate Checklist

**Purpose:** Name the **chaotic problems** that stop Connector OS from being what the world will need when agents and augmented AI hit production — then give a **timeless checklist** to become a **universal operating substrate for distributed intelligence**, no matter which model, framework, or cloud wins.

**North star:** [FINAL_OUTCOME.md](FINAL_OUTCOME.md) (full ~2-year OS + next grade)  
**Honesty today:** [IMP_1000.md](IMP_1000.md)  
**Evidence base:** [CONNECTOR_OS_CODE_REALITY_AND_SECURITY_REPORT.md](CONNECTOR_OS_CODE_REALITY_AND_SECURITY_REPORT.md), [docs/architecture/substrate-map.md](docs/architecture/substrate-map.md), [docs/00-constitutional-preamble.md](docs/00-constitutional-preamble.md), [MASTER_ISSUES.md](MASTER_ISSUES.md)

**How to use**

1. Read **§1 Chaos** — agree these are the real blockers (not “missing another agent feature”).  
2. Accept **§2 Timeless requirements** — these do not expire when GPT/Claude/local models change.  
3. Execute **§3 Phased checklist** (P0→P5) with Core / Backend / UI where listed.  
4. Cross-check Grade B ([WHEN_DONE](CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md), [PRODUCTION_READINESS](PRODUCTION_READINESS_CHECKLIST.md)) and Grade C ([MATURITY_CHECKLIST_30.md](MATURITY_CHECKLIST_30.md)).  
5. Only then tell the next person: *universal DI substrate, production-ready.*

---

## 0. Verdict

The chaos is not “we need more features.”  
It is **multiple truths** for the same facts — identity, admission, memory, evidence, meters, isolation — so when agents mature in production they **bypass**, **fork**, or **believe false green**.

A top-grade Connector must be the OS that remains necessary **after** agents are everywhere: the place identity, memory, authority, execution, isolation, evidence, and usage are *one physiology*.

---

## 1. Chaotic problems (inventory)

Mark `[x]` only when the chaos is **closed in code + UI + docs**, not when a plan exists.

### 1.1 Ontology chaos — many names, no single pipeline

| ID | Chaos | Why it breaks when agents mature |
|----|--------|----------------------------------|
| O1 | Nine rings are language, not one unavoidable typed pipeline | Ops assume every ring always ran; silent skips look like compliance |
| O2 | Admission is a library call on some routes, absent on others | Tools/knowledge/debug become the real surface; effects escape the gate |
| O3 | Firewall inspect ≠ admission enforce; empty policy can allow | “Firewall green” does not mean deny |
| O4 | Audit called “HMAC” but is unkeyed hash-link | Store compromise can rewrite “custody” |
| O5 | Proof / custody / compliance / SCITT conflated in UI | Court asks for independent verify; issuer verifies itself |
| O6 | Institutions bleed into kernel roles (parallel products) | New WFs copy “own DB + own identity” |
| O7 | Boot readiness models disagree (7-bit vs 12-stage UI) | Operators trust decorative complete |

- [ ] O1 closed — request object / inventory proves which gates ran  
- [ ] O2 closed — admission before every external effect (matrix + tests)  
- [ ] O3 closed — inspect never marketed as enforce  
- [ ] O4 closed — keyed integrity + recompute, or honest rename  
- [ ] O5 closed — verification_status only after independent recompute  
- [ ] O6 closed — TT/WC/DG consume `connector-trust`; no parallel trust root  
- [ ] O7 closed — one readiness model in API + UI  

### 1.2 Identity chaos

| ID | Chaos | Why it breaks |
|----|--------|---------------|
| I1 | Tenant via spoofable header when token lacks tenant | Cross-tenant memory/tools/export |
| I2 | Workflows mint local sessions ≠ `PrincipalContextV2` | Revocation/delegation cannot span TT↔WC↔gateway |
| I3 | Cage DNS / path treated as identity | Spoofed names look like federation |
| I4 | Ambient god admin tokens for plugin planes | Blast radius = whole estate |
| I5 | Open-auth / free presets can escape loopback | Lab posture ships to prod |
| I6 | DevGuard static keys ≠ minted session | Coding agents look governed but aren’t bound |

- [ ] I1–I6 closed with adversarial HTTP tests green  

### 1.3 Storage / data-plane chaos

| ID | Chaos | Why it breaks |
|----|--------|---------------|
| S1 | Own Postgres per WF as SoT | N products × N DBs; incident correlation dies |
| S2 | Dual kernel stores + ~60s flush window | Crash → memory/audit disagree |
| S3 | Knot RAM-only / rebuild gap | Multi-agent graphs thin after restart |
| S4 | Moment/multimodal live path incomplete | Images/IoT → fake “memory OS” via RAG only |
| S5 | Knowledge ingest without admission | Agents poison each other’s context |
| S6 | Asymmetric evidence (hash vs fat trees) | Cannot replay what the agent saw |

- [ ] S1 closed — ArtifactLog/CAS + projections; no new SoT DB  
- [ ] S2 closed — WAL/checkpoint; loss ≤ configured window  
- [ ] S3 closed — Knot rebuild/persist on boot  
- [ ] S4 closed — Moment + Object Fabric on live MemWrite  
- [x] S5 closed — ingest requires admission *(graph + mesh grant/revoke + memory mutators wired)*
- [ ] S6 closed — lean moment + single CAS body; no junk duplication  

### 1.4 Network / forensics chaos

| ID | Chaos | Why it breaks |
|----|--------|---------------|
| N1 | Security = intended routing; soft header correlation | Agents skip proxy → “no evidence” ≠ blocked |
| N2 | Management plane ≠ data plane (ops confuse them) | Hub proxy thought to govern LLM traffic |
| N3 | TT→WC handoff best-effort | Peak load drops custody silently |
| N4 | Async firewall / fail-open policy | “Always evidenced” is a race |
| N5 | Protocol bridges uneven; each invents forensics | Mesh of MCP/A2A without shared stamp |
| N6 | Topology / ports tribal | Wrong plane bindings in multi-plugin stacks |

- [ ] N1 closed — CFNI + fail-closed egress *(partial: gateway + pipeline LLM admission + kerneld lease)*
- [ ] N2 closed — docs/UI make data plane explicit  
- [ ] N3 closed — durable handoff or evidence-required mode *(platform: `CONNECTOR_HANDOFF_REQUIRED` + pending cap blocks TT mutating proxy; plugin TT→WC path open)*  
- [ ] N4 closed — fail-closed production defaults  
- [ ] N5 closed — CNP edge + shared stamp for external protocols  
- [ ] N6 closed — Service Map = real topology; compose conflict-free  

### 1.5 Workflow / plugin sprawl

| ID | Chaos | Why it breaks |
|----|--------|---------------|
| W1 | Secondary WFs named like peers while incomplete | Buyers expect false maturity |
| W2 | New WF = new SoT temptation | Domain teams fork the OS |
| W3 | CLS dry-run ≠ full governed runtime | “Enabled” ≠ enforced fleet behavior |
| W4 | cpkg signatures optional in prod | Unsigned plugins at scale |
| W5 | Boundary violations (logic in wrong product) | Duplicate features; 404→502 governance |
| W6 | DevGuard routes/hooks incomplete | Coding agents become ungoverned change agents |

- [ ] W1–W6 closed; secondary WFs deferred in messaging until primary truth holds  

### 1.6 UI / claim honesty chaos

| ID | Chaos | Why it breaks |
|----|--------|---------------|
| U1 | `verified: true` without recompute | Dashboard becomes false auditor |
| U2 | Unavailable shown as `0`; fake `$` leadership | FinOps automates on lies |
| U3 | Framework badges ≠ certified controls | Enterprises confuse UI with attestation |
| U4 | Huge UI surface, uneven depth | Every pane expected equal |
| U5 | DevGuard sold as bypass-impossible | Cooperative cage treated as absolute |

- [ ] U1–U5 closed; IMP-1000 tags match every public claim  

### 1.7 Isolation / fail-open chaos

| ID | Chaos | Why it breaks |
|----|--------|---------------|
| X1 | Silent isolation downgrade (microVM→Docker→subprocess) | Untrusted plugins run “fake prod” |
| X2 | TT policy fail-open on Connector outage | Kernel down = open season |
| X3 | DevGuard allow when hooks missing | Agents detect gap and proceed |
| X4 | Unsigned packages / default secrets | First boot insecure |
| X5 | TT management auth not attached | Remote control of quarantine/policy |
| X6 | WitnessCtl session IDOR | Cross-session evidence leak |

- [ ] X1–X6 closed; production profile fail-closed by default  

### 1.8 Metering / books chaos

| ID | Chaos | Why it breaks |
|----|--------|---------------|
| M1 | Stream/view token gaps | Streaming agents hide spend |
| M2 | Budgets not atomic with admission | Race unbounded economics |
| M3 | Invented provider `$` as product truth | Kills trust or freedom |
| M4 | Nested agent tokens without peer receipt | Multi-agent graphs hide cost |
| M5 | Fake `$` inside evidence UIs | Auditors discard whole packs |

- [ ] M1–M5 closed — usage-first; company rate card optional; unavailable ≠ 0  

### 1.9 Distributed / clustering chaos

| ID | Chaos | Why it breaks |
|----|--------|---------------|
| D1 | Helm replicas ≠ kernel HA; SQLite/redb single-node | Split-brain identity/memory |
| D2 | k8s mental model as product scale-out | Wrong SoT; federation chaos |
| D3 | Plugin DB HA ≠ kernel HA | Partial survival looks like DR |
| D4 | Multi-store backup/restore unproven | Cannot restore one trust domain |
| D5 | Naming without placement×identity mesh | Names that are not trust-bound |

- [ ] D1–D5 closed or honestly scoped (HA API never lies)  

### 1.10 Docs vs code chaos

| ID | Chaos | Why it breaks |
|----|--------|---------------|
| C1 | Marketing broader than enforcement | Security review fails claim gap |
| C2 | MASTER “final state” vs IMP honesty tags | Plans treated as shipped |
| C3 | Domain guides look equal to enforcement | Regulated agents follow advisory text |
| C4 | Trust crates exist; wiring incomplete | Looks unified, runs as four products |
| C5 | Grade B vs Grade C conflated | CFNI marketed while Stories A–D open |

- [ ] C1–C5 closed — claims follow executable gates (preamble law 12)  

---

## 2. Timeless requirements — universal DI OS

These must remain true **no matter what** model, agent framework, or cloud wins.  
Check when **mechanism + test + UI honesty** exist.

### 2.1 Constitutional mechanisms

- [ ] **T1** Ten primitives are *mechanisms*, not brand pages — identity, memory, authority, execution, isolation, naming/comms, resources, causality/audit, proof/custody, lifecycle  
- [ ] **T2** Mechanisms below, institutions above — workflows project; they do not mint parallel kernels  
- [ ] **T3** Verified identity before authority — no header/query/path creates trust  
- [ ] **T4** Admission before every external effect — model, tool, memory write, egress, workflow step  
- [ ] **T5** Isolation is factual — declared = effective; no silent prod downgrade  
- [ ] **T6** One causal envelope — principal → policy → decision → execution → evidence  
- [ ] **T7** Evidence independently verifiable — issuer is not final verifier; properties never conflated  
- [ ] **T8** Memory is governed state — CID/namespaced/permissioned/attributable  
- [ ] **T9** Resources metered from observation — unavailable ≠ 0; $ only via customer rates  
- [ ] **T10** No ambient plugin power — short-lived scoped caps + declared egress  
- [ ] **T11** Lifecycle observable — install/start/pause/upgrade/rollback/revoke/terminate  
- [ ] **T12** Governed path easier than bypass — if builders must skip the OS, design failed  
- [ ] **T13** Local sovereignty — one node without mandatory cloud control plane  
- [ ] **T14** Claims follow proofs — public language expands only after gates  

### 2.2 Distributed-intelligence physiology (vendor-independent)

- [ ] **P1** Transit correlation without hoping headers — cryptographic flow identity **or** fail-closed egress  
- [ ] **P2** Log + CAS + rebuildable projections — N WF DBs never N sources of truth  
- [ ] **P3** Placement under identity — where work runs is part of trust (not “replicas = OS”)  
- [ ] **P4** Moment continuity — lean multimodal manifests; recall and forensics share one physiology  
- [ ] **P5** Protocol universality — external protocols enter one fabric (CNP or successor) with shared stamps  
- [ ] **P6** Institutions composable — control (live), custody (evidence), host cage (dev) share envelopes  
- [ ] **P7** Multi-agent economics — peer/nested usage only when observed or attested; else unavailable  

### 2.3 Constitutional success test (operator can *prove*)

An independent operator proves — not is told — that:

- [ ] Each intelligence has verifiable identity  
- [ ] Each action authorized under known policy/delegation  
- [ ] Each memory access respected namespace/provenance  
- [ ] Each external effect crossed admission  
- [ ] Each workload stayed in declared isolation/resources  
- [ ] Each causal event committed to verifiable evidence  
- [ ] Each artifact independently checkable  
- [ ] Each workflow uses the same substrate without privileged exceptions  
- [ ] Node operates locally and can federate without surrendering sovereignty  

---

## 3. Phased checklist to top-grade universal substrate

Complete phases in order. Each phase lists **chaos IDs** closed and **timeless IDs** satisfied.

### Phase P0 — Stop the bleeding (fail-closed truth)

**Closes:** I1, I5, X2, X4, X5, X6, U1 (partial), C1 (partial)

- [x] **Core:** Tenant never from unverified header; open-auth loopback-bound  
- [x] **Backend:** TT mgmt auth attached; WC session ownership enforced; TT fail-open → explicit/fail-closed in prod  
- [ ] **UI:** No decorative `verified: true`; defense-strict defaults documented  
- **Verify:** Adversarial HTTP suite + prod preset smoke  

### Phase P1 — One identity, one admission, one envelope

**Closes:** O2, O6, I2, I3, I4, I6, T3, T4, T6

- [x] **Core:** `PrincipalContextV2` + `AdmissionTicketV2` + `CausalEnvelopeV2` on all mutating effect paths (inventory matrix 100%)  
- [x] **Backend:** TT/WC/DG consume platform principal; cage principal binding + scoped cap; cage name ≠ authz  
- [ ] **UI:** Session/user shows principal source; denied-without-admission visible  
- **Verify:** Route inventory CI; architecture_claims tests  

### Phase P2 — Data physiology (memory that survives agents)

**Closes:** S1–S6, P2, P4, T8

- [ ] **Core:** WAL/checkpoint MemWrite; Knot durable; ArtifactLog; Moment + Object Fabric  
- [ ] **Backend:** Knowledge ingest admitted; TT/WC dual-write as projections  
- [ ] **UI:** Moments / Vector Box / lag; no base64 dumps as product memory  
- **Verify:** Kill -9 soak; restart Knot; multimodal round-trip  

### Phase P3 — Transit forensics (needed when agents bypass “the proxy”)

**Closes:** N1–N5, P1, P5, X1

- [x] **Core:** CFNI partial + kerneld flow lease deny (`flow_lease` on `GET /api/v1/kernel/status`; `connector-kerneld` → `IPAddressDeny=any` when enforced + zero leases)  
- [x] **Backend:** Gateway/TT/WC/CNP stamp partial; fail-closed egress partial; handoff backpressure mode  
- [ ] **UI:** FNI status; enforce on/off honesty; data plane vs mgmt plane clear  
- **Verify:** Bypass proxy without stamp → denied; with stamp → correlated DI export  

### Phase P4 — Usage & freedom (econ without fake money)

**Closes:** M1–M5, T9, P7

- [ ] **Core:** UsageEvent SoT; token_source enum  
- [ ] **Backend:** Stream/view fixed; peer UsageReceipt; budgets atomic with admission  
- [ ] **UI:** Books = usage first; optional company rate card; unavailable ≠ 0  
- **Verify:** Streamed chat metered or unavailable; nested agent unmetered panel  

### Phase P5 — OS generative (workflows cannot fork the kernel)

**Closes:** W1–W6, O1, O5, O7, U2–U5, D1–D5, C2–C5, T1–T2, T5, T7, T10–T14, P3, P6

- [ ] **Core:** Claim/gate inventory; secondary WFs deferred in ABI messaging  
- [ ] **Backend:** Sample thin WF (no SoT DB); cpkg signatures required in prod; CLS runtime honesty; backup/restore one trust domain documented/tested  
- [ ] **UI:** Surface depth badges; DevGuard honesty; HA never claims automatic failover; Grade B stories green  
- **Verify:** Constitutional success test (§2.3) runnable as scripted demo; IMP-1000 + FINAL_OUTCOME aligned; prod-readiness-gate green  

---

## 4. Progress tracker

| Phase | Status | Date | Notes |
|-------|--------|------|-------|
| P0 Stop bleeding | ☑ backend | 2026-08 | tenant/auth/proxy fail-closed |
| P1 Identity + admission + envelope | ☑ backend | 2026-08 | 78/78 admission + cage binding |
| P2 Data physiology | ☑ backend | 2026-08 | WAL soak + artifact log |
| P3 Transit forensics | ☑ backend partial | 2026-08 | CFNI mesh + kerneld lease |
| P4 Usage & freedom | ☐ | | |
| P5 OS generative | ☐ | | |
| §2 Timeless all checked | ☐ | | |
| §2.3 Success test demo | ☐ | | |
| Handoff to next person | ☐ | | |

---

## 5. Relationship to other checklists

| Document | Role |
|----------|------|
| This file | **Chaos → universal DI OS** (why + timeless + phases) |
| [FINAL_OUTCOME.md](FINAL_OUTCOME.md) | What users get (Grade A/B/C) |
| [MATURITY_CHECKLIST_30.md](MATURITY_CHECKLIST_30.md) | Detailed Grade C iterations (maps into P2–P4) |
| [PRODUCTION_READINESS_CHECKLIST.md](PRODUCTION_READINESS_CHECKLIST.md) | Release hardening gate |
| [CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md](CONNECTOR_OS_WHEN_DONE_HOW_PEOPLE_USE_IT.md) | Stories A–D (Grade B) |
| [IMP_1000.md](IMP_1000.md) | Honest capability map |
| [UI_MAKEOVER_PLAN.md](UI_MAKEOVER_PLAN.md) | Operator dashboard page-by-page makeover (chosen UI) |
| [BACKEND_UNIVERSAL_CHECKLIST.md](BACKEND_UNIVERSAL_CHECKLIST.md) | Universal operator backend — registries + merge APIs before UI |

**Rule:** Do not add another institution until **P0–P1** are closed. More plugins on a chaotic substrate multiplies chaos.

---

## 6. One sentence for the next person

> The chaos is **multiple truths**; the product is a **universal DI operating substrate** — one identity, one admission, one memory/evidence physiology, one usage meter, fail-closed isolation, institutions as projections — so when agents and augmented AI hit production, Connector remains necessary regardless of which model wins.

---

*Update §4 as phases close. Prefer closing chaos over shipping the next named workflow.*
