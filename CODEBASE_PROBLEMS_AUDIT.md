# Codebase Problems Audit (deep sweep)

**Date:** 2026-08-10  
**Scope:** `platform/server`, `oss/connector`, `oss/vac`, `platform/ui-leptos`, `plugins/{tracetramp,witnessctl,devguard}`, plus checklist honesty.  
**Companion:** [BACKEND_IIA_COMPLETION_BACKLOG.md](BACKEND_IIA_COMPLETION_BACKLOG.md) (B-ids) · [UI_IIA_ENHANCEMENT_PLAN.md](UI_IIA_ENHANCEMENT_PLAN.md)

**Method:** Pattern search (TODO/FIXME/stub/hardcoded/gateway-*), IIA enforcement audit vs types, UI/plugin surface audit, manual verification of critical paths.

**Verdict:** Court/flagship **gates** prove a thin spine. Much of the product still has **hardcoded cages**, **env-off enforcement**, **documentary policies**, **bypass LLM paths**, and **UI that does not expose charter**. Several items **over-claim** (Verified continuity at mint, court tier stamps, books `chain_verified: true`, QPR `capabilities: ["read"]` ⇒ allow-all).

---

## Severity legend

| Sev | Meaning |
|-----|---------|
| **S0** | Crash / recursion / false integrity claim — fix before trusting prod |
| **S1** | Security / isolation / court honesty — blocks real charter & Talk claims |
| **S2** | Feature incomplete but honesty usually labeled |
| **S3** | Polish, UX redirects, stubs with banners |

---

## S0 — Critical defects

| ID | Problem | Evidence | Fix later |
|----|---------|----------|-----------|
| **C1** | ~~ring1↔qpr recursion~~ | **FIXED** (B33) — leaf env flags | — |
| **C2** | ~~QPR read allows all~~ | **FIXED** (B34) — capability taxonomy | — |
| **C3** | ~~Books chain_verified lie~~ | **FIXED** (B35) — hash-chain check | — |
| **C4** | ~~VAC plaintext encrypt silent~~ | **FIXED** (B36) — fail closed unless lab flag | Real AEAD still future |
| **C5** | ~~VAC audit stub as platform sig~~ | **FIXED** (B37) — `unverified_digest:` / fail-closed | — |

---

## S1 — IIA / security / court honesty

### S1.A Contract cage (Charter S2)

| ID | Problem | Where | Backlog |
|----|---------|-------|---------|
| **C6** | Contract FS/network/denied hardcoded at mint; **no PATCH** | `kernel/agent_principal.rs` `compile_contract`; `services/agents.rs` caps=`["read"]` | **B1**, **B9** |
| **C7** | DockLock cage **ignores** loaded contract (duplicate hardcode) | `kernel/docklock.rs` `compile_cage_profile` | **B7** |
| **C8** | ~~cage_env never injected~~ | **FIXED** (B23) — persist + notebook/plugin apply | — |
| **C9** | Contract not checked in admission / gateway / memory / tools | effect paths use NS + optional Ring-1 only | **B1** enforcement wave |
| **C10** | ~~receipt_required never gates~~ | **FIXED** (B24) — signed receipt required when set | — |

### S1.B HITL / forensic / compliance (documentary)

| ID | Problem | Where | Backlog |
|----|---------|-------|---------|
| **C11** | `HitlPolicyV2` **not read by admission** | setup + compliance store only | **B5** |
| **C12** | `hitl_posture.pending_count` hardcoded **0** | `agent_identity_envelope.rs` ~241–253 | **B17** |
| **C13** | ~~HITL passed ≈ policy≠None~~ | **FIXED** (B19) — decisions in window required | — |
| **C14** | ~~WC frameworks not aligned on activate~~ | **FIXED** (B16) — `witnessctl_align` opens/pending + mismatch on compliance-contract | — |
| **C15** | ~~Continuity minted Verified~~ | **FIXED** (B25) — minted `Unknown` | — |
| **C16** | ~~Hardcoded Ed25519Court~~ | **FIXED** (B26) — court only after node sign | — |
| **C17** | ~~ephemeral CPO/quantum court sigs~~ | **FIXED** (B27) — node-sign + consume verify | — |
| **C18** | ~~stubs_in_window always empty~~ | **FIXED** (B28) — env + unsigned/hmac scan | — |

### S1.C Isolation / continuity / Talk

| ID | Problem | Where | Backlog |
|----|---------|-------|---------|
| **C19** | ~~No setup → NS allow~~ | **FIXED** (B29) — fail-closed when setup gate on | — |
| **C20** | ~~is_owner always true~~ | **FIXED** (B30) — namespace owner check | — |
| **C21** | Ring-1 / QPR / DockLock / setup-gate **off by default** | env flags; only prodish/`DEFENSE_STRICT` turns on | **B4**, **B8** |
| **C22** | Continuity break still Ring-1/meta-gated; gateway anon Talk banned under gate/prod (B4). | `enforce_real_agent_talk` | Lab leave ban unset |
| **C23** | ~~unquarantine leaves egress/continuity~~ | **FIXED** (B31) — clears egress + Broken→Unknown | — |
| **C24** | Gateway default pid **`gateway-agent`**; Anthropic **`gateway-anthropic` + builder** | `gateway.rs`, `anthropic_gateway.rs` | **B2**, **B3** |
| **C25** | ~~Anthropic: no who_am_i inject / RAG~~ | **FIXED** (B3) — who_am_i + shared RAG | — |
| **C26** | Multiagent + experiments LLM **bypass** admission/envelope | `multiagent.rs`, `experiments.rs` | **B11** |
| **C27** | Setup gate off → auto-activate (lab OK); gate on → draft setup (B14). | `agent_identity_envelope.rs` | Lab leave gate off |
| **C28** | Setup always `setup_complete: true` | `agent_identity.rs` | **B13** |
| **C29** | MCP `connector_who_am_i` unwired | protocols / envelope D4 | **B12** |
| **C30** | ~~Active simulates attach~~ | **FIXED** (B32) — Simulated ≠ Active; enforce denies | — |

### S1.D Crypto / glue / transport (lab footguns)

| ID | Problem | Where |
|----|---------|-------|
| **C31** | CNP mTLS stub (`CONNECTOR_CNP_ALLOW_MTLS_STUB`) | `cnp/stack.rs` |
| **C32** | Distributed insecure TLS skip-verify flag | `distributed/transport.rs` |
| **C33** | Glue `ContractExecutor::stub` (prod blocked unless allow) | `connector-glue` |
| **C34** | Caps mock runners (`CONNECTOR_CAPS_ALLOW_MOCK`) | `connector-caps` |
| **C35** | MicroVM / Firecracker host stub until 5.3.x | `runtime_control.rs`, `main.rs` |
| **C36** | Federation deny-overrides `implemented: false` | `federation_policy.rs` |
| **C37** | `connector-api` `delegate_to` / `send_to` fake success | `connector-api/src/agent.rs` |

---

## S2 — Incomplete product (often labeled)

| ID | Area | Problem | Path hints |
|----|------|---------|------------|
| **C38** | Retention | Cold-tier job stub; UI run-stub | `substrate/retention.rs`, settings_panel |
| **C39** | Object fabric | Range hydrate FS CAS seek stub | `object_fabric.rs` |
| **C40** | Artifact log | Projection rebuild = recount | `artifact_log.rs` |
| **C41** | Hub publish | `implemented: false` | `hub_workflow_publish.rs` |
| **C42** | Workflow CNP | Synthetic enable-token / partial builder | `workflow_runtime.rs`, `workflow_cnp.rs` |
| **C43** | HA peer | `add_peer_ui: stub` | `ha_federation.rs`, settings_panel |
| **C44** | Portal | Pilot stub subscriptions | `router.rs` portal_pilot_stub |
| **C45** | Embeddings | Hash pseudo-embeddings MiniLM stub | `connector-engine/src/embedding.rs` |
| **C46** | Knot | Semantic retrieval channel commented out | `vac-core/src/knot.rs` |
| **C47** | Memory API | Some recall/query ignore; ~~packet pin unwired~~ **FIXED** (B20) pin/unpin routed | memory services / router |
| **C48** | Books | Trust components hardcoded 100; token/merkle TODOs | `connector-engine/src/books.rs` |
| **C49** | Billing | Stub heuristic costs | `services/billing.rs` |
| **C50** | LLM stub mode | `CONNECTOR_LLM_STUB` canned — CI/airgap presets | gateway, `connector_profile.rs` |
| **C51** | Flow lease | Deny stub (not full FNI product) | `flow_lease.rs` |
| **C52** | KernelStore | Sqlite/Postgres backends not implemented | `connector-api` |
| **C53** | TT product | Decision-tree stub, budget hard-enforce, admin auth — see `plugins/BACKLOG.md` | tracetramp |
| **C54** | Soak / FINAL_REACH | Hub SLO, CAS blob, cluster store, TT/WC/DG same-id E2E still open | `FINAL_REACH.md`, `KNOWN_LIMITATIONS.md` |

---

## S3 — UI / plugins incomplete

| ID | Problem | Path |
|----|---------|------|
| **C55** | Charter workbench tabs live (Talk/Charter/Manage/Evidence); full Studio wizard still deepening | `agent_workbench.rs` | E2a–E2d |
| **C56** | GAP banners in Charter/Evidence workbench; not every stage labeled yet | `agent_workbench.rs` GapBanner | deepen |
| **C57** | WC sessions listed in Evidence; **iia-join deep panel still thin** | Evidence tab + `/plugins/witnessctl` | join UI |
| **C58** | TT/WC **admin-ui = static HTML stubs** | `plugins/*/admin-ui/dashboard.html` |
| **C59** | FNI verify endpoints not callable from operator UI | TT/WC admin routes vs badge-only |
| **C60** | Legacy redirects **drop drawer state** (`/memory`→watch, `/agents`→run, …) | `dashboard/src/lib.rs` |
| **C61** | `OpAgentTree` gallery-only | `agent_tree.rs` |
| **C62** | Memory panel = counts/moments only | `topic_panels.rs` |
| **C63** | TT light console ≪ backend (tenants/providers/budgets/fni-verify) | `light_consoles.rs`, `rules_panels.rs` |
| **C64** | DevGuard no admin-ui | plugin commands only |
| **C65** | P10.9.4 human sign-off still open | `IIA_CORE_UPGRADE_CHECKLIST.md` |

---

## Env flags that hide the holes (default OFF)

| Flag | Default | Risk if unset |
|------|---------|----------------|
| `CONNECTOR_IIA_RING1` | off | No quantum on effects (+ **C1** recursion footgun) |
| `CONNECTOR_IIA_QPR_ENFORCE` | off | same family |
| `CONNECTOR_IIA_DOCKLOCK_ENFORCE` | off | same family |
| `CONNECTOR_IIA_RING1_STRICT` | off | weaker bind |
| `CONNECTOR_AGENT_SETUP_GATE` | off | auto-activate skips Charter |
| `CONNECTOR_MATRIX_HW_ENFORCE` | off | HW reality optional |
| `CONNECTOR_KERNEL_FAIL_CLOSED` | often 0 | admit without real kernel attach |
| `CONNECTOR_DEFENSE_STRICT` / prodish env | turns Ring-1 on | laptop/dev looks “open” |

---

## Hardcoded cheat-sheet (expand anytime)

| Value | Location |
|-------|----------|
| `capabilities: ["read"]` | `services/agents.rs` |
| denied_ops / FS / network lists | `compile_contract` + `compile_cage_profile` |
| Continuity `Verified` at mint | `agent_principal.rs` |
| `runtime_hash_placeholder` | `agent_principal.rs` |
| SigningTier `Ed25519Court` stamps | envelope, forensics, compliance, foundation, continuity |
| HITL default Egress, forensic Soc2, all memory types | `mint_default_setup` |
| `gateway-agent` / `gateway-anthropic` | gateways |
| `hitl pending_count: 0` | envelope builder |
| `stubs_in_window: []` | forensic package |
| books `chain_verified: true` | connector-engine books |
| DockLock process_allow list | `compile_cage_profile` |

---

## Recommended fix waves (entire codebase)

```text
Wave 0 — Stop the bleeding (S0)
  C1 recursion · C2 QPR read-allows-all · C3 books lie · C4/C5 vac crypto honesty

Wave 1 — Charter real (S1.A + setup)
  B1 contract PATCH · B9 capabilities · B6 remint · B14 no fake bootstrap · B4 setup gate
  B7 DockLock←contract · B23 wire cage_env · B24 receipt_required

Wave 2 — Policy real (S1.B)
  B5 HITL enforce · B17 HITL submit · B16 WC bind · B19 scorecard honesty
  B25 continuity truth · B26 signing_tier honesty · B27 CPO/quantum node key or tier label
  B28 stubs_in_window

Wave 3 — Talk + bypasses (S1.C)
  B2 completions · B3 Anthropic · B11 multiagent/experiments · B12 MCP who_am_i
  B8 Ring-1 prod default · B29/B30 isolation · B31 unquarantine · B32 kernel_host honesty

Wave 4 — UI surfaces
  Charter Studio + GAP banners · iia-join · redirects→drawers · OpAgentTree · Manage memory
  TT/WC deepen / deprecate stub admin-ui

Wave 5 — Platform debt (S2)
  Retention · embeddings · hub publish · HA · soak items · plugin BACKLOG
```

---

## Mapping to existing B-ids

| New C-id | Existing B / action |
|----------|---------------------|
| C1 | **NEW B33** — ring1/qpr recursion |
| C2 | fold into **B9** or **B34** — capability matching |
| C3–C5 | **NEW B35–B37** — books/vac honesty |
| C6–C10 | B1, B7, B9, B23, B24 |
| C11–C18 | B5, B16–B19, B25–B28 |
| C19–C30 | B2–B4, B8, B11–B14, B29–B32 |
| C55–C65 | UI plan E0–E6 |

Update [BACKEND_IIA_COMPLETION_BACKLOG.md](BACKEND_IIA_COMPLETION_BACKLOG.md) with B23+ when scheduling work.

---

## What is *not* a silent lie (filtered noise)

- HTML `placeholder=` attributes  
- Test `fake_*` / adversarial fixtures  
- Honesty APIs that correctly return `implemented: false`  
- Intentional lab stubs behind allow-env flags (still footguns if mis-set in prod)  
- Engineering-green gates (court/flagship) — they prove **paths**, not full cage productization  

---

## How to use this doc

1. Do **not** market court-grade / full charter until Wave 0–2 close.  
2. UI Charter forms: show GAP for every Open B/C affecting that stage.  
3. When fixing: mark row Done here + backlog + add a gate/test.  
4. Re-run sweep after major merges (`rg` stub/TODO + re-read `contract_allows_action` / ring1 helpers).

*This audit is a snapshot. Append new findings; do not delete Open rows — mark Done.*
