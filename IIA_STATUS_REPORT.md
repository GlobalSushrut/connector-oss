# Connector IIA — Status Report

**Date:** 2026-08-13  
**Product framing:** **Distributed intelligence OS** — not process-only firewalling, not ATC-only UI.  
**Architecture plan:** [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) **v3** — kernel → ACS / 3 layers / world grants / share portals. Picture: **§0**.  
**Operator create:** [INTELLIGENCE_5MIN.md](INTELLIGENCE_5MIN.md) · **World:** [OPERATOR_WORLD_AGENTS.md](OPERATOR_WORLD_AGENTS.md) · **Now possible:** [AGENTIC_INFRA_NOW_POSSIBLE.md](AGENTIC_INFRA_NOW_POSSIBLE.md) · **Court:** [COURT_DEFENSIBLE_CHECKLIST.md](COURT_DEFENSIBLE_CHECKLIST.md)  
**Research:** [EXECUTION_SUBSTRATE_REPORT.md](EXECUTION_SUBSTRATE_REPORT.md) · [PARTIAL_TO_TOP_GRADE_RESEARCH.md](PARTIAL_TO_TOP_GRADE_RESEARCH.md) · [CONSCIOUS_PHYSICS_BOUNDED_INTELLIGENCE.md](CONSCIOUS_PHYSICS_BOUNDED_INTELLIGENCE.md)  
**Companions:** [PRODUCT_GAPS.md](PRODUCT_GAPS.md) · [BACKEND_IIA_COMPLETION_BACKLOG.md](BACKEND_IIA_COMPLETION_BACKLOG.md) · [UI_IIA_ENHANCEMENT_PLAN.md](UI_IIA_ENHANCEMENT_PLAN.md) · [CODEBASE_PROBLEMS_AUDIT.md](CODEBASE_PROBLEMS_AUDIT.md)

---

## 1. Where we are now

Connector has crossed from “IIA types + documentary policy” into a **working intelligence execution spine**:

| Layer | Maturity |
|-------|----------|
| **Backend IIA backlog (B1–B40)** | **All listed B-items Done** (Waves 0–5 + OS deepen B38–B40) |
| **Honesty / court claims** | S0 audit defects fixed; court tier only after real node sign; continuity starts `Unknown` |
| **Cage / host cut** | Contract-bound DockLock + docker-grade volatile intelligence cage; matrix host egress by **intelligence mark** (nft / iptables-nft) |
| **Operator UI** | Execution workbench + full-page Charter Studio; Evidence iia-join; Control activity/traces |
| **Production defaults** | Still **lab-friendly off** for many gates; prod hardening preset turns them on via `set_if_absent` |

**One-line verdict:** The TG membrane is **in code** — 5-min create, ACS + NS FS, three admission layers, world grants per `(pid × address)`, share only via contract/portal, DockLock + light_ns. Remaining work is **ops honesty** (court only with WC+CFNI, mesh only with soak), not a missing spine.

**General-purpose stance:** A cnktr agent is for **any work the operator asks that the charter allows**. Purpose/acume is identity, not a topic ban. Defaults are HITL=`none`, forensic=`off`, caps include `chat/tool/memory/network`; only `ambient_shell` / `modify_contract` stay denied. Cage network is still deny-default until the operator widens it (Talk uses the platform LLM proxy either way).

This is **not** “court-ready out of the box.” It is **constitution + cage + Talk + institutions** that work when you turn the right env/presets on and run the required migrations/plugins.

---

## 2. What the software can do today

### 2.1 Agent constitution (Charter)

- Register / list / lifecycle agents (`pause` / `resume` / `kill`, etc.).
- **Write SetupSpec:** name, acume, HITL policy, forensic profile, memory types, KB id, common-space grants (`POST /agents/:pid/setup`).
- **Write AgentContract cage:** purpose, capabilities, denied ops, FS read/write, network allow/default, receipt_required (`PATCH /agents/:pid/contract`).
- Charter change **demotes Active → SetupReady**, voids quanta, returns `needs_reactivate`.
- **Activate** mints / binds ComplianceContractV2, aligns WitnessCtl frameworks from forensic profile (opens session when WC is configured).
- **UI:** drawer Charter tab (S1–S6 + Activate) and full-page **Charter Studio** at `/agents/:pid/charter` (S1–S6, S9 institutions, S10–S11 review/activate).

### 2.2 Talk as a real principal

- `POST /agents/:pid/completions` forces path pid (no anonymous Talk façade).
- Gateway / Anthropic inject **who_am_i** + shared RAG; quantum header; prod/gate bans anon / `gateway-*`.
- Chat **threads** list/create/get; completions accept `thread_id`.
- MCP tool `connector_who_am_i`; multiagent / experiments paths inject identity.

### 2.3 Volatile intelligence cage (DockLock)

- Schema `connector.docklock.intelligence.v2`: OS brokered, hardware deny, isolation, network deny-default.
- Cage compiled from **contract** (not duplicate hardcode when contract present).
- Docker lab args: cap-drop, read-only, ipc=none, egress allowlist from cage env.
- Linux pre_exec: Landlock FS (soft-fail), seccomp intent, **SO_MARK** for intelligence mark.
- Continuity break → host cut via **nftables** `inet connector_matrix` / iptables-nft `CONNECTOR_MATRIX_INTEL` (mark `0xCD…` from agent_pid) — intelligence plane, not OS-PID firewalling.

### 2.4 HITL, compliance, institutions

- HITL create / pending / approve / deny; policy enforceable when `CONNECTOR_IIA_HITL_ENFORCE=1`.
- Compliance contract GET with WC alignment + framework mismatch honesty.
- Forensic universals + forensic package paths; signing tier honesty (HmacLab → Ed25519Court after node sign).
- TraceTramp policies scoped by `agent_pid` (migration required).
- WC session proxy + **`GET …/sessions/:id/iia-join`** (platform join digests).
- UI Evidence: compliance, alignment, iia-join, TT bind, WC sessions, forensic universals.

### 2.5 Memory, grants, knot

- Memory list/tree/search/import/compact/purge; packet pin/unpin routed.
- Grants: grant/revoke syncs setup `common_spaces` + grant folder; `GET /agents/:pid/grants`.
- Knot summary for Manage peek.
- **Share portals:** isolated by default. Human+root sharing contract (what / where / how much / why) mints `/share/{portal_id}`. No contract → no portal → A cannot see B.

### 2.6 Membrane (ACS · layers · world)

- **ACS** (`GET /runtime/acs/:pid`) — character + isolation + NS FS + world grants at the top of the workbench. Agent header cannot read another pid.
- **NS FS** — `{DATA}/nsfs/{pid}/` trees: `/workspace` `/m` `/k` `/p` `/v` `/out` `/share`. `/p` never LLM. Created on intelligence apply.
- **Three admission layers** — Root HITL · Cone (default, AI suggests) · App Allow (human+root + justification). Fold: Block > Ask > App Allow. App cannot downgrade Ask/Block.
- **World gateway** — grant per `(agent_pid × CNP address)`. Kernel root passcode. Missing grant under harden = Cone Ask, not silent Allow.
- **Isolation density** — `light_ns` (docker-grade materials, shared kernel). MicroVM is high-risk only.

### 2.6 Operator cockpit (UI)

| Surface | Can do |
|---------|--------|
| **RUN workbench** | Control · Talk · Identity · Charter · Manage · Evidence |
| **Control** | Start / pause / resume / kill + cage logs + crumbs + traces |
| **Talk** | Forced-pid chat with server threads |
| **Identity** | who_am_i / envelope |
| **Manage** | HITL · **grant/revoke** · **sharing contract** · **task dispatch** · knot |
| **ACS strip** | Character + isolation + NS FS + world grants (top of workbench) |
| **Setup / Power · world** | Gateway form: this pid × this address + layer + kernel root |
| **Evidence** | Compliance, WC iia-join, TT bind, **forensic package download** |
| **MONITOR** | Intelligence posture chips + **fleet charter drift** table |
| **WATCH** | Live stream + fleet intelligence crumb strip |
| **Charter Studio** | Full-page stage rail → setup/contract/activate |
| **WC / TT consoles** | Still the deep institution UIs (`/plugins/witnessctl`, `/plugins/tracetramp`) |

### 2.8 Host / kernel honesty

- Host attach → **Simulated**; kerneld drop-in + `confirm-host-apply` → **Active** (systemd_dropin honesty, not silent eBPF claim).
- Optional `CONNECTOR_KERNEL_BPF_APPLIED=1` for honest BPF Active note when truly applied.

---

## 3. Done — completed work (summary)

### Backend waves (all Done)

| Wave | Items | Theme |
|------|-------|--------|
| 0 | B33–B37 | Crash / integrity lies |
| 1 | B1, B4, B6, B9, B14 | Charter unblocked + Talk gate |
| 2 | B5, B7, B8, B17, B23, B24, B29, B30, B38–B40 | Cage = reality + OS deepen |
| 3 | B2, B3, B11, B12, B15, B25–B28, B31–B32 | Talk honesty + continuity/host |
| 4 | B16, B18, B19 | WC / TT / Art.14 |
| 5 | B10, B13, B20–B22 | Hardening apply + memory/grants polish |

### UI shipped

- E0 workbench shell with execution tabs  
- Charter S1–S6 + Activate (drawer)  
- Full-page Charter Studio (S1–S6, S9, S10–S11)  
- Talk + threads  
- Manage (HITL / grants / knot)  
- Evidence + **iia-join**  
- Control **WATCH/TT recorder** (activity + traces)

### Audit S0

- C1–C5 fixed (recursion, QPR taxonomy, books chain, VAC plaintext, stub sig labeling).

---

## 4. Work still left (small remaining set)

**Biggest remaining holes (ops / depth, not missing APIs):** live WC+CFNI court soak verification, multi-cell fabric soak (`make l5-mesh-soak`), optional full L7 transparent proxy. DI-0…DI-5 + TG membrane (ACS, 3 layers, world grants, share portals) are **in code** — see [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) §0.

| # | Item | Why it remains | Suggested owner |
|---|------|----------------|-----------------|
| **R1** | ~~Forensic package download UX~~ | **Shipped** | — |
| **R2** | Fuller **WATCH surface** depth | Crumbs shipped; richer event lens / principal filter still thinner | UI E4 |
| **R3** | ~~Charter Studio S7 / S8~~ | **Shipped**; S0 register polish optional | — |
| **R4** | ~~**Two-agent smoke** (charter → grant → dispatch → distinct who_am_i)~~ | **Shipped** — `connectorctl iia smoke` / `platform/scripts/iia-two-agent-smoke.sh` | — |
| **R5** | Run **TT `agent_pid` migration** on deployed nodes | Code Done; ops must apply | Ops |
| **R6** | Turn **prod hardening** on for real deployments | Lab defaults leave Ring-1 / HITL / anon-ban off | Ops |
| **R7** | ~~OpenAI gateway **memory inject parity** with Anthropic RAG~~ | **Shipped** — `inject_connector_rag` on stream + non-stream | — |
| **R8** | ~~C9 on Talk / fabric / knowledge / share~~ | **Shipped** (gateway + A2A/signal/share/ingest); notebook/plugins still deepen | — |
| **R9** | Real **eBPF Active** path (beyond drop-in honesty) | B32 honesty landed; full BPF attach still Phase A | Kernel |
| **R10** | UI GAP banners / honesty labels cleanup | Many banners still say “gap” language though B-items are Done | UI cleanup |
| **R11** | ~~Anomaly-gated inference~~ | **Shipped** — `CONNECTOR_IIA_ANOMALY_GATE=1` HIGH_DENY_RATE on Talk | — |
| **R12** | ~~Landlock fail-closed + L7 app allowlist~~ | **Shipped** (`CONNECTOR_L7_EGRESS_PROXY`); full transparent proxy optional later | — |
| **R13** | ~~Court readiness checklist~~ / live soak | Checklist API+UI shipped; WC+CFNI ops soak not claimed Done | Ops |
| **R14** | Multi-cell fabric soak | Cells/mesh honesty synced; run `make l5-mesh-soak` | Ops |

**Not claiming Done until verified:** court package end-to-end with live WC + CFNI secret; Landlock on kernels that lack it (soft-fail by design).

---

## 5. How to run it for real (ops cheat-sheet)

| Concern | Knob / action |
|---------|----------------|
| Prod-like gates | Production hardening preset (Ring-1, QPR, DockLock, HITL, setup-gate) |
| HITL at admission | `CONNECTOR_IIA_HITL_ENFORCE=1` |
| Ban anon Talk | Gate/prod or `CONNECTOR_GATEWAY_BAN_ANON` |
| WC activate open | `CONNECTOR_WITNESSCTL_MANAGEMENT_URL` + admin token |
| TT agent bind | Migration `20260811000000_policies_agent_pid` |
| Matrix host cut | `nft` or `iptables-nft`; cage SO_MARK on runtimes |
| VAC secrets | `CONNECTOR_VAC_KEK_SECRET`; never leave plaintext allow in prod |
| BPF Active claim | Only with real apply + `CONNECTOR_KERNEL_BPF_APPLIED=1` if asserting BPF |

Lab tip: leave Ring-1 / gateway ban unset unless testing prodish behavior.

---

## 6. Capability map (operator journey)

```text
Create (5-min apply or Charter Studio)
    → ACS + NS FS minted (isolated)
    → Link LLM · Start
    → Talk / tools under Cone (Ask) unless App Allow justified
    → World: gateway form + kernel root for this pid × this address
    → Share: human+root contract → portal (else A cannot see B)
    → Evidence: compliance + iia-join + forensic
    → Control: start/pause/kill + cage logs + traces
    → Runtime: DockLock + light_ns + matrix mark on continuity break
```

---

## 7. Honest limits

- **Default lab config is permissive** — features exist; production posture requires presets/env.
- **Court-grade** is a pipeline (sign + WC + evidence + no stubs), not a checkbox. No court-green without WC+CFNI soak.
- **Host Active ≠ eBPF** unless you actually applied BPF. **light_ns ≠ MicroVM.**
- **CONP taxonomy ≠ SIL** / certified robot safety.
- **WATCH** is started in Control; full recorder UX is still thin.

---

## 8. Recommended next sprint (short)

Membrane is shipped. Next is **ops honesty**, not another spine:

1. Deploy checklist: TT migration + WC URL + hardening preset (R5 + R6).  
2. Court soak only when WC+CFNI are live — do not market green.  
3. Multi-cell claim only after `make l5-mesh-soak`.  
4. Never claim MicroVM / eBPF unless those backends are actually applied.

---

*Report reflects DI-0…5 + TG membrane (ACS, 3 layers, world grants, share portals) as of 2026-08-13. Court / mesh / MicroVM / eBPF remain ops-honesty claims — see plan §0.*
