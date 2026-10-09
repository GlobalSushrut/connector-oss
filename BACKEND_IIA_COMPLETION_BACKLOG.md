# Backend IIA Completion Backlog

**Status:** Living backlog — **B1–B40 listed items are Done** (2026-08-11). Remaining polish lives in [IIA_STATUS_REPORT.md](IIA_STATUS_REPORT.md) §4 (R1–R10).  
**Full codebase sweep (C1–C65):** [CODEBASE_PROBLEMS_AUDIT.md](CODEBASE_PROBLEMS_AUDIT.md)  
**UI plan:** [UI_IIA_ENHANCEMENT_PLAN.md](UI_IIA_ENHANCEMENT_PLAN.md)  
**Rule:** UI must not fake saves against open gaps. Stale GAP banners should be cleared now that matching B-items are Done.  
**When closing an item:** flip Status → Done, cite PR/gate, update UI plan §8 + audit row.

Legend: `Hardcoded` = fixed values in code · `No write API` · `Partial` · `Doc-only` (stored but not enforced) · `Bypass` (unsafe default path)

---

## Priority P0 — blocks Charter Studio / real-agent Talk

| ID | Status | Kind | Gap | Where today | Target completion |
|----|--------|------|-----|-------------|-------------------|
| **B1** | **Done** | Was no write API | **PATCH `/agents/:pid/contract`** + `update_contract` recompute digest. | `agent_principal.rs`, `agent_identity.rs`, `router.rs` | Re-activate note returned; full remint protocol → B6. |
| **B2** | **Done** | Was missing API | **`POST /agents/:pid/completions`** forces path pid; rejects unknown principal. | `agent_identity.rs` `post_agent_completions` | Gateway anon default still exists for raw `/v1` — tighten under B4. |
| **B3** | **Done** | Was no inject | Anthropic who_am_i + **shared RAG** (`build_agent_rag_context`); quantum header; no anon builder; `x-connector-agent-pid`. | `anthropic_gateway`, `gateway` | Parity with OpenAI memory inject. |
| **B4** | **Done** | Was bypass | Raw `/v1` + Anthropic ban anon/`gateway-*` when gate/prod; stub LLM banned in prodish. | `enforce_real_agent_talk`, stream path | Lab: leave `CONNECTOR_GATEWAY_BAN_ANON` unset. |
| **B5** | **Done** | Was doc-only | HITL policy enforced when **`CONNECTOR_IIA_HITL_ENFORCE=1`**; submits HITL request on deny. | `admission.rs` Step 1.22 | Default still off (lab); turn on in prod preset. |
| **B6** | **Done** | Was missing rules | Patch/setup demotes Active→SetupReady, voids quanta, returns `needs_reactivate`. | `update_contract`, `demote_after_charter_change`, setup POST | Re-activate binds new ComplianceContractV2. |

---

## Priority P1 — cage / DockLock / quantum honesty

| ID | Status | Kind | Gap | Where today | Target completion |
|----|--------|------|-----|-------------|-------------------|
| **B7** | **Done** | Was hardcoded | `compile_cage_profile(quantum, contract)` loads FS/network from contract; `contract_bound` flag. | `docklock.rs` + unit test | Fallback hardcode only when contract missing. |
| **B8** | **Done** | Was partial | Prod hardening preset sets Ring-1 / QPR / DockLock / HITL / setup-gate via `set_if_absent`. | `apply_production_hardening_defaults` | Lab: leave unset. |
| **B9** | **Done** | Was partial | Default mint caps: read/write/llm/chat/tool/memory; QPR matching is real (not read⇒all). | `agents.rs`, `quanta_polar` | Further custom caps via B1 patch. |
| **B10** | **Done** | Was missing | Profile bind + cage env sets seccomp intent; supervisor `pre_exec` applies Linux hardening. | `docklock`, `process_group` | Host nft/BPF still Phase A. |
| **B39** | **Done** | Was stamp-only | DockLock = **volatile intelligence** docker-grade cage: OS brokered, HW deny, isolation, network deny-default → docker_lab caps/read-only/ipc + egress. | `docklock.rs`, `docker.rs`, `connectorctl` | Schema `connector.docklock.intelligence.v2`; not process jail. |

---

## Priority P2 — identity / gateway / MCP parity

| ID | Status | Kind | Gap | Where today | Target completion |
|----|--------|------|-----|-------------|-------------------|
| **B11** | **Done** | Was bypass | Multiagent + experiments inject who_am_i via `iia_llm_inject`. | `kernel/iia_llm_inject.rs` | — |
| **B12** | **Done** | Was missing | MCP tool `connector_who_am_i` registered + handled. | `protocols.rs` | — |
| **B13** | **Done** | Was partial | Setup POST accepts `setup_complete`; activate refuses incomplete when gate on. | `AgentSetupBody`, `activate_agent` | — |
| **B14** | **Done** | Was partial | Gate on → `mint_draft_setup` (HITL=None, forensic=Off, `setup_complete=false`). | `bootstrap_agent_identity` | Explicit POST setup required before activate. |
| **B15** | **Done** | Was missing | Chat threads folder + list/create/get; completions optional `thread_id`. | `agent_chat.rs`, `agent_identity`, router | UI can still use localStorage as cache. |

---

## Priority P3 — compliance / HITL / institutions

| ID | Status | Kind | Gap | Where today | Target completion |
|----|--------|------|-----|-------------|-------------------|
| **B16** | **Done** | Was partial | Activate aligns WC frameworks from forensic_profile; opens session when WC configured; mismatch surfaced on compliance-contract. | `witnessctl_align.rs`, activate | Status `pending_wc_unavailable` / `open_failed` when WC down. |
| **B17** | **Done** | Was partial | **`POST /agents/:pid/hitl`** creates pending request. | `agents::hitl_create`, `router.rs` | — |
| **B18** | **Done** | Was partial | TT policies `agent_pid` column + create/list `?agent_pid=`; also embedded in rules. | `tracetramp` admin + migration | Run migration `20260811000000_policies_agent_pid`. |
| **B19** | **Done** | Was doc-only risk | Art.14 passed only when policy on **and** ≥1 HITL decision in window. | `hitl_decisions_in_window` + scorecard | — |

---

## Priority P4 — memory / knowledge / grants polish

| ID | Status | Kind | Gap | Where today | Target completion |
|----|--------|------|-----|-------------|-------------------|
| **B20** | **Done** | Was unwired | `POST …/packets/:cid/pin` + `unpin` routed. | `router.rs`, `memory2` | `packet_seal` remains alias of seal route. |
| **B21** | **Done** | Was undocumented | `GET /agents/:pid/knot/summary` + graph route map; explicit non-goals (no DELETE CRUD). | `agent_identity` | Manage peek SoT. |
| **B22** | **Done** | Was dual-path | grant/revoke syncs setup `common_spaces` + grant folder; `GET /agents/:pid/grants` union. | `multiagent.rs`, router | Isolation UI SoT. |
| **B40** | **Done** | Was optional | Landlock FS from DockLock cage (`CONNECTOR_DOCKLOCK_FS_*`) in plugin pre_exec; SO_MARK probe + helper for new sockets. | `linux_hardening.rs`, `docklock` | Soft-fail if kernel lacks Landlock. |

---

## Priority P0b — from deep audit (fix first)

| ID | Status | Kind | Gap | Where today | Target completion |
|----|--------|------|-----|-------------|-------------------|
| **B33** | **Done** | Was crash | Leaf env flags only in `ring1_enforce_enabled`; no recursion through qpr/docklock helpers. | `docklock.rs`, `quanta_polar` | Audit **C1**. |
| **B34** | **Done** | Was logic bug | Capability taxonomy; empty caps deny; `"read"` does not allow shell/tool. | `quanta_polar::contract_allows_action` | Audit **C2**. |
| **B23** | **Done** | Was dead code | Persist on Ring-1 bind; `apply_cage_env_to_command` on notebook + plugin run. | `docklock.rs`, `notebook.rs`, `connectorctl` | — |
| **B24** | **Done** | Was doc-only | `receipt_required` mints signed receipt (Ring-1 on/off); deny if unsigned. | `docklock::enforce_ring1` | Audit **C10**. |
| **B25** | **Done** | Was over-claim | Continuity minted as **`Unknown`** until evaluate → Verified/Broken. | `agent_principal.rs` | Audit **C15**. |
| **B26** | **Done** | Was over-claim | Tier starts HmacLab; Ed25519Court only after node sign; package aligns with stubs. | forensics, compliance, package, runtime_self | Audit **C16**. |
| **B27** | **Done** | Was partial | CPO/quantum node-signed; consume verifies node pubkey when QPR on. | `intelligence_admission`, `quanta_polar` | Audit **C17**. |
| **B28** | **Done** | Was incomplete | `scan_stubs_in_window` — env stubs + unsigned/hmac receipts/universals. | `forensic_package.rs` | Audit **C18**. |
| **B29** | **Done** | Was bypass | No setup + gate on → NS isolation deny; lab gate off still legacy allow. | `agent_may_access_namespace` | Audit **C19**. |
| **B30** | **Done** | Was weaken | `is_owner` from namespace owner vs agent setup. | `agent_owns_guard_namespace` | Audit **C20**. |
| **B31** | **Done** | Was partial | Unquarantine clears egress/matrix + demotes Broken→Unknown. | `unquarantine_agent` | Audit **C23**. |
| **B32** | **Done** | Was stub | Attach → Simulated; kerneld drop-in → `POST …/confirm-host-apply` → Active. | `kernel_host`, `connector-kerneld` | Active = systemd_dropin honesty, not eBPF. Audit **C30**. |
| **B36b** | **Done** | Was lab-only | VAC envelope **AES-256-GCM** (v2) with random nonce + wrapped DEK. | `vac-core/secrets.rs` | Set `CONNECTOR_VAC_KEK_SECRET` in prod. |
| **B38** | **Done** | Was stamp-only | Continuity break → **nftables `inet connector_matrix`** (`intel_isolated` mark DROP) for **intelligence execution** plane; **iptables-nft** / modern iptables fallback (`CONNECTOR_MATRIX_INTEL`). | `matrix_host_egress.rs`, `linux_hardening.rs` | Mark = `0xCD…` from agent_pid in cage env; pre_exec applies SO_MARK to open sockets. Not process-PID firewalling. |
| **B35** | **Done** | Was lie | `verify_journal_hash_chain` — missing hashes ⇒ unverified. | connector-engine books.rs | Audit **C3**. |
| **B36** | **Done** | Was lie | Encrypt/decrypt fail closed unless `CONNECTOR_VAC_ALLOW_PLAINTEXT_SECRETS=1` (or cfg test). | vac-core secrets.rs | Real AEAD still open; audit **C4**. |
| **B37** | **Done** | Was lie | Stub sig labeled `unverified_digest:…` (or empty fail-closed); tests use stub allow. | `vac-core/audit_export.rs` | Real key path unchanged; audit **C5**. |

---

## Hardcoded values cheat-sheet (fix later)

| Value | Location | Should become |
|-------|----------|---------------|
| `capabilities: ["read"]` | `services/agents.rs` register | From charter / contract patch |
| `denied_operations: modify_contract, ambient_shell` | `compile_contract` | Editable denylist |
| `filesystem_read` namespace-scoped / env | `compile_contract` (`CONNECTOR_CONTRACT_FS_*`) | Charter PATCH still SoT after mint |
| `filesystem_write` namespace-scoped / env | same | Charter PATCH |
| `network_allow` / `network_default` via env | `CONNECTOR_CONTRACT_NETWORK_*` | Charter PATCH |
| `receipt_required` via env | `CONNECTOR_CONTRACT_RECEIPT_REQUIRED` | Charter PATCH |
| `hitl_policy: None` default (was Egress) | `mint_default_setup` | Tighten via Charter for regulated use |
| `forensic_profile: Off` default (was Soc2) | `mint_default_setup` | Soc2/HIPAA/Court via Charter |
| `memory enabled_types` = all 7 | `mint_default_setup` | Checkboxes |
| `gateway-agent` / `gateway-anthropic` | gateway / anthropic_gateway | Reject in product Talk |
| DockLock `process_allow`, syscall_filter strings | `compile_cage_profile` | Profile/policy later |
| Quantum TTL 90s | QPR module | Config / contract overlay later |

---

## Suggested completion waves (backend)

```text
Wave 0 (bleed):              B33, B34, B35, B36, B37
Wave 1 (Charter unblocked):  B1, B9, B6, B14, B4
Wave 2 (Cage = reality):     B7, B23, B24, B8, B5, B17, B29, B30, B38, B39, B40
Wave 3 (Talk honesty):       B2, B3, B11, B12, B25–B28, B31–B32, B15
Wave 4 (Institutions):       B16, B18, B19
Wave 5 (Polish):             B10, B13, B20–B22
```
(Optional OS deepen folded into Wave 2 as B38–B40.)

UI Charter Studio mapping:

| Studio stage | Needs |
|--------------|-------|
| S2 Contract cage | **B1**, B9, B6, B7 |
| S3 HITL policy | **B5**, B17 |
| S4 Forensic | B16 (WC align) |
| S10–S11 Activate | B4, B14 |
| Talk | **B2**, B3, B8, B11 |

---

## Honesty labels for UI while Open

| Label | When to show |
|-------|----------------|
| `backend_gap: contract_write` | S2 save disabled |
| `backend_gap: hitl_policy_unenforced` | S3 — “stored on compliance contract; admission enforcement pending B5” |
| `backend_gap: docklock_cage_hardcoded` | Show contract FS vs DockLock status diverge until B7 |
| `backend_gap: gateway_anonymous` | Talk disabled unless B2 or forced pid client-only with warning |
| `signing_tier` / `hmac_lab` | Existing honesty — never claim court from UI alone |

---

## Done criteria (per item)

1. Write path or enforcement exists and is tested (unit or gate script).  
2. UI GAP banner removed for that stage.  
3. This file row → **Done** + evidence path (`.ok` or test name).  
4. Mention in `IIA_CORE_UPGRADE_CHECKLIST.md` if it closes a P10 UI/API column.

---

*Seeded 2026-08-10 from Phase E UI planning. Extend freely; do not delete Open rows — mark Done.*
