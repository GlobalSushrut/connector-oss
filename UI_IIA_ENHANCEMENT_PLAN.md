# IIA UI Enhancement Plan (Phase E) — Execution + Full Agent Charter

**Status:** Plan v4.2 — execution cockpit + Charter forms; aligned to **distributed intelligence** (not process UI).  
**Stack:** Leptos/WASM `platform/ui-leptos/dashboard` only.  
**Shell:** Keep RUN/WATCH/FIX/MONITOR/SETUP geometry; gravity = **execute with a real intelligence**; instruments secondary ([§0](#0-why-the-ui-feels-like-airplane-control-and-why-thats-wrong-for-us)).  
**Architecture SoT:** [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) · gaps: [PRODUCT_GAPS.md](PRODUCT_GAPS.md) · status: [IIA_STATUS_REPORT.md](IIA_STATUS_REPORT.md).  
**Backend:** [BACKEND_IIA_COMPLETION_BACKLOG.md](BACKEND_IIA_COMPLETION_BACKLOG.md) (B1–B40 Done) · **full sweep:** [CODEBASE_PROBLEMS_AUDIT.md](CODEBASE_PROBLEMS_AUDIT.md) (C1–C65).  
**Types SoT:** `oss/connector/crates/connector-trust/src/iia/types.rs`  
**Related:** [UI_OPERATOR_SHELL.md](UI_OPERATOR_SHELL.md) · [agent-identity-envelope.md](docs/architecture/agent-identity-envelope.md) · [forensic-compliance-contract-view.md](docs/architecture/forensic-compliance-contract-view.md) · [IIA_CORE_UPGRADE_CHECKLIST.md](IIA_CORE_UPGRADE_CHECKLIST.md)

**One sentence:** The UI must give operators **places and forms** for every charter — purpose, allow/deny, FS/network cage, HITL, forensic, memory/KB, grants, tools, budgets, WC/TT — then **Talk/execute** as that **intelligence principal** with a recorder of principal · quantum · DockLock · receipt (not PID babysitting).

---

## 0. Why the UI feels like airplane control (and why that’s wrong)

Early shell docs chose **air-traffic control** to kill 40-page sprawl. That fixed navigation and accidentally made the product feel like a **control plane**.

Connector is a **distributed intelligence execution system** (process isolation is substrate only):

```text
INTELLIGENCE PRINCIPAL → AUTHORITY (contract/quantum/grants)
  → EXECUTION PLANE (Talk/tools/DockLock/CNP) → EVIDENCE → FLEET
```

| Wrong center | Right center |
|--------------|--------------|
| Radar of workflows + approve queues | **Intelligence charter → activate → Talk/execute** |
| Process firewall / PID ops | **Principal · quantum · intelligence-mark cage** |
| Instruments as the product | Instruments as the glass around intelligence execution |

Pulse/WATCH/FIX stay. They are not the home.

---

## 1. The narrowness problem (why v3 was not enough)

Backend already has a full **agent constitution**. UI today only has **register name/model/instructions** + pause/kill + thin HITL.

| Backend domain | Types / APIs | UI today |
|----------------|--------------|----------|
| Setup charter | `AgentSetupSpecV2` `POST /agents/:pid/setup` | **None** |
| Authority cage | `AgentContractV2` (capabilities, denied_ops, FS, network) | **None** (read APIs only; **no PATCH** — GAP) |
| HITL policy | `HitlPolicyV2` on setup | **None** (queue only, thin) |
| Forensic / evidence | `ForensicProfileV2` → `EvidencePolicyV2` + frameworks | **None** |
| Compliance bind | `ComplianceContractV2` at activate | **None** |
| Memory profile | `MemoryProfileV2` + region/eviction | **None** |
| Common spaces / grants | `NamespaceGrantV2` + `/multiagent/grant` | **None** |
| Tools / AAPI / clearance | scoped bindings, UCAN, clearance | **None** / DEV JSON |
| Budgets / adaptive / HIPAA | register + PATCH + adaptive + BAA | Partial chips |
| WC session policy | frameworks, hosts, PII, clearance | WC console only |
| TT policies | content/tool/rate/PII rules | TT console only |
| Talk | gateway completions | **None** |

**This plan’s centerpiece is the Agent Charter Studio** — multi-step forms that write the constitution — not only Talk and Identity viewers.

---

## 2. Philosophy

```text
INTELLIGENCE ≠ IDENTITY ≠ AUTHORITY ≠ EXECUTION ≠ EVIDENCE
```

| Rule | UI |
|------|-----|
| Charter before Talk | Cannot Talk until setup complete + activated (when `CONNECTOR_AGENT_SETUP_GATE=1`; otherwise show honesty that auto-activate skipped forms) |
| Contract = allow/deny truth | Forms for capabilities, denied_operations, FS/network, receipt_required |
| HITL policy ≠ HITL queue | Policy picker at setup; queue in FIX + Manage |
| Forensic profile drives evidence | Picker shows **derived** EvidencePolicy + frameworks (read-only preview) |
| Isolation fail-closed | Grants explicit; never implied shared memory |
| UI ≠ crypto verifier | Package download + `connectorctl iia verify-export` |
| Execution-first | After charter, home = Talk/workbench |

---

## 3. Information architecture

```text
SETUP ── Agent Charter Studio (create / edit constitution) ───── forms ★
RUN   ── Execution cockpit: Talk · Manage · Charter · Identity · Evidence · Control
WATCH ── Recorder (principal · quantum · docklock · receipt)
FIX   ── Unblock (agent HITL + TT + WC) with crumbs
MONITOR ── Instruments
TT/WC ── Institution consoles + agent join
```

### Agent workbench tabs (RUN)

| Tab | Role |
|-----|------|
| **Talk** | Execute conversation as principal (hero after activate) |
| **Charter** | Edit/view constitution forms (same as Studio, agent-scoped) |
| **Manage** | Runtime ops: memory packets, KB ingest, tools invoke, live grants, HITL queue |
| **Identity** | Read-only who_am_i / four-ID / envelope / capability manifest |
| **Evidence** | Compliance contract, receipts, package, TT/WC join |
| **Control** | Pause/resume/freeze/kill/signal/budget/trust |

**Charter** = *what the agent is allowed to be*. **Manage** = *operate that plane after bind*. Do not collapse them.

---

## 4. Agent Charter Studio — full forms catalog

**Entry points**

1. SETUP → **Create agent** → Charter Studio wizard  
2. RUN → agent → **Charter** tab (reconfigure where APIs allow; remint/re-activate honesty when digest changes)  
3. Deep-link from Identity “Edit charter”

**Wizard stages** (map 1:1 to backend lifecycle). Each stage is a **real form**, not a JSON dump.

```text
S0 Register → S1 Purpose & philosophy → S2 Authority contract (allow/deny/cage)
  → S3 HITL policy → S4 Forensic & compliance posture → S5 Memory & knowledge
  → S6 Isolation & grants → S7 Tools & clearance → S8 Budgets & risk
  → S9 Institution bind (WC/TT) → S10 Review digests → S11 Activate → Talk
```

Enable `CONNECTOR_AGENT_SETUP_GATE=1` in product/demo so activate is explicit after forms.

---

### S0 — Register

**API:** `POST /api/v1/agents`

| Field | Backend | Form control |
|-------|---------|--------------|
| `name` | required | text |
| `namespace` | isolation root | text + preview `/m/…` |
| `role` | writer/admin/… | select |
| `model` | continuity / intelligence seed | model picker |
| `instructions` | prompt charter (≠ IIA contract) | textarea — labeled “LLM instructions (not authority)” |
| `purpose` | IIA purpose / acume seed | tags / textarea |
| `token_budget` | default 16000 | number |
| `hipaa` | `agent_hipaa_flags` | toggle + BAA warning |
| `parent_pid` | progeny | optional agent picker |
| `geo_id`, `master_agent_id`, `knowledge_base_id` | foundation seeds | optional |
| `tags` | meta | chips |

**Also show cell limits:** `GET /runtime/policy` (slot honesty).

---

### S1 — Purpose, acume, use case

**API:** fields on `POST /agents/:pid/setup` → `AgentSetupSpecV2`

| Field | Control |
|-------|---------|
| `name` | confirm/edit |
| `acume` | **required** plain-language purpose (Finance ≠ Developer) |
| `use_case_def` | structured form → JSON (domain, data classes, success criteria) |
| `philosophy_digest` | auto from acume/charter hash; show hex; optional recompute |
| `contract_ref` | digest or CLS template id (link S2) |

---

### S2 — Authority contract (what’s allowed / not) ★

**Type:** `AgentContractV2`  
**Read today:** `GET /runtime/contract?agent_pid=`, `/runtime/permissions`, envelope  
**Write today:** **GAP** — minted only at register via `compile_contract` with hardcoded defaults

| Field | Default today | Form |
|-------|---------------|------|
| `purpose[]` | from register | editable list |
| `capabilities[]` | `["read"]` only | multi-select / tags (read, write, tool, network, …) |
| `denied_operations[]` | `modify_contract`, `ambient_shell` | denylist editor + presets |
| `filesystem_read[]` | `/workspace/**` | glob list |
| `filesystem_write[]` | `/workspace/out/**` | glob list |
| `network_allow[]` | `[]` | host/CIDR list |
| `network_default` | `deny` | deny \| allow (default deny) |
| `receipt_required` | `true` | toggle |

**Presets (UI):** `readonly_analyst`, `workspace_builder`, `finance_locked`, `court_strict` — fill lists, still editable.

**Backend work required (plan dependency B1):**

```text
PUT|PATCH /api/v1/agents/:pid/contract
  body: AgentContractV2 fields (or ContractPatchV2)
  → recompute contract_digest_sha256, resign if needed
  → may require continuity evaluate / re-activate if already active
```

Optional: CLS path `GET /contracts/templates`, `POST /agents/:id/contract/from-template` as **import**, then land in this form.

**Honesty in UI:** Until B1 ships, form is **preview of mint defaults** + “Save disabled — contract write API pending”; do not fake saves.

---

### S3 — HITL policy

**Type:** `HitlPolicyV2` on setup  
**Values:** `none` | `egress` | `tool` | `export` | `all_material`  
**API:** `POST /agents/:pid/setup` `hitl_policy` string  
**Default:** `egress`

| Control | Copy |
|---------|------|
| Radio cards | When must a human approve before material effect? |
| Preview | Maps to capability `hitl` bool on activate |
| Link | “Pending requests” → Manage/FIX (runtime queue — separate) |

**Runtime queue (not this form):**  
`GET /agents/:pid/hitl/pending`, approve/deny — FIX + Manage.

**Note for builders:** Policy is SoT in compliance contract; admission may not yet branch on every enum — UI still collects truth; gate work can follow.

---

### S4 — Forensic profile & compliance posture

**Type:** `ForensicProfileV2` — `off` | `standard` | `soc2` | `hipaa` | `court`  
**API:** setup `forensic_profile`  
**Default:** `soc2`

**Form:** profile picker + **read-only derived panel**:

| Derived | From |
|---------|------|
| `EvidencePolicyV2` | retain_raw_receipts, rollup_bucket, merkle_segments, witnessctl_session_required, offline_verify_required, legal_hold_compatible |
| `frameworks[]` | SOC2 / HIPAA / GDPR / EU AI Act / … via `framework_bindings()` |
| WC session required | if profile demands |

**Post-activate (Evidence tab):** `GET /agents/:pid/compliance-contract` shows bound signed contract (not re-edited casually — change profile → re-setup/re-activate flow).

---

### S5 — Memory & knowledge profiles

**Types:** `MemoryProfileV2`, KB fields on setup

| Field | Control |
|-------|---------|
| `default_memory_type` | select: working, episodic, semantic, procedural, relational, reflective, evidentiary |
| `enabled_types[]` | 7 checkboxes (cognitive types) |
| `quota_tier` | standard / … |
| `knowledge_base_id` | text + suggest `kb:{acume}` |
| `knowledge_base_address` | preview `/k/…` |

**Optional advanced (still Charter-adjacent):**  
`POST /memory/region/configure`, eviction policy, tier change — under “Advanced memory plane”.

**Runtime ingest/query** stays in **Manage** (not Charter).

---

### S6 — Isolation & common spaces

**Type:** `NamespaceGrantV2[]` as `common_spaces` on setup  
**Also:** `POST /multiagent/grant|revoke` at runtime (Manage)

| Field | Control |
|-------|---------|
| Private paths | read-only preview `/m/…`, `/a/…` |
| Common space path | e.g. `/k/shared/…` |
| `readable_by[]` / `writable_by[]` | agent pickers |
| `expires_at_ms` | optional datetime |
| Isolation proof | “Test: Agent B recall A’s `/m/` → expect 403” (lab) |

Default message: **No shared space unless you add a grant.**

---

### S7 — Tools, clearance, AAPI

| Form block | API |
|------------|-----|
| Clearance level | `POST /agents/:pid/clearance` — public → kernel |
| Scoped tool bindings | `POST /tools/bindings/scoped` — tool_id, allowed_operations[], allowed_paths[] |
| MCP bridges (pick) | list + attach |
| UCAN / AAPI caps | `POST /aapi/capabilities/issue` — actions, resources, ttl |
| Policy packs | HIPAA/financial `POST /aapi/policies/hipaa` etc. |
| Policy dry-run | `POST /agents/:pid/policy/check` |

Show linkage: **contract cage (S2) ∩ tool bindings (S7) ∩ DockLock** = what can actually run.

---

### S8 — Budgets, trust, HIPAA risk

| Field | API |
|-------|-----|
| Token budget | register / `PATCH /agents/:pid/budget` |
| AAPI resource budgets | `POST /aapi/budgets` |
| Adaptive routing | `PUT /adaptive/agents/:pid/config` — ceiling USD, providers, strategy |
| Trust override | `POST /agents/:pid/trust` |
| HIPAA flag + BAA | register hipaa + `POST /compliance/baa/accept` honesty |
| Residency | `GET /agents/:pid/residency` |

---

### S9 — Institution bind (WitnessCtl / TraceTramp)

Not a replacement for TT/WC consoles — **bind this agent** into them.

**WitnessCtl**

| Field | API |
|-------|-----|
| Open/link session | `POST /plugins/witnessctl/sessions` |
| `frameworks[]` | hipaa, soc2, gdpr, eu_ai_act, iso_27001, pci_dss, nist_800_53 |
| Session policy | clearance, denied_hosts, allowed_hosts, pii_action, require_admission, risk_level |
| Preview iia-join | after activate |

**TraceTramp**

| Field | API |
|-------|-----|
| Attach/create policy | `POST /plugins/tracetramp/admin/policies` — type content_filter \| tool_permission \| rate_limit \| pii_redact; enforcement monitor\|block\|alert |
| Tenant / agent filter | form fields + later WATCH filter |

---

### S10 — Review (digests before activate)

Single scroll of truth:

1. who_am_i preview (`GET` envelope dry or setup-derived)  
2. Contract digest + allow/deny summary  
3. HITL + forensic + evidence policy  
4. Memory types + KB path  
5. Grants table  
6. Tools/clearance summary  
7. WC/TT bind summary  
8. Capability manifest **preview** (`GET /capabilities` if setup_ready)

**Activate** button → `POST /agents/:pid/activate` → show `ComplianceContractV2` digest + receipt id → **Start Talk**.

---

### S11 — Activate & start

| Action | API |
|--------|-----|
| Activate | `POST /agents/:pid/activate` |
| Start (if gated) | `POST /agents/:pid/start` |
| Confirm | Identity + Compliance contract panels |

If setup incomplete: block with field-level errors (name, acume, KB, contract_ref).

---

## 5. Manage tab (runtime ops — after charter)

Charter sets the constitution. Manage operates it.

| Section | Forms / actions | APIs |
|---------|-----------------|------|
| Memory | tree, search, write, purge, compact, sessions | `/agents/:pid/memory*` |
| Knowledge | ingest, query | `/memory/knowledge/*` |
| Knot | summary + neighbor peek | graph APIs + envelope |
| Grants (live) | grant/revoke | `/multiagent/grant\|revoke` |
| Tools | invoke-scoped (quantum), approvals | tools + FIX |
| HITL queue | approve/deny | `/hitl/*` |
| Budget tune | patch/reset | budget APIs |

---

## 6. Talk — execute as the chartered agent

(See prior deep design; unchanged intent.)

1. Require activated principal + who_am_i strip  
2. Forced `POST /api/v1/agents/:pid/completions` (B2)  
3. Optional N4 → QPR when enforce/tools  
4. Receipt footer → Evidence/WATCH  
5. Continuity BROKEN → Talk disabled  
6. Anthropic inject parity (B3)

Talk **never** invents allow/deny — it obeys S2/S3 charter.

---

## 7. WATCH / FIX / MONITOR / TT / WC

| Surface | Role vs Charter |
|---------|-----------------|
| WATCH | Recorder of effects under that contract; crumbs principal/quantum/DockLock/receipt; Chat lens |
| FIX | HITL queue + TT + WC items; link back to Charter HITL policy |
| MONITOR | Continuity, DockLock, deny rate, capability health |
| Evidence | Bound compliance contract, package, verify CLI |
| WC console | Session ops + **iia-join**; frameworks may differ from forensic_profile — show both |
| TT console | Policy/trace detail + agent filter; causal link to envelopes |

---

## 8. Backend incomplete / hardcoded — complete later

**Full living backlog:** [BACKEND_IIA_COMPLETION_BACKLOG.md](BACKEND_IIA_COMPLETION_BACKLOG.md) (B1–B22).

UI **must not fake** writes against Open items. Show honesty labels from that doc (`backend_gap: …`).

### 8.1 P0 summary (blocks Charter / Talk)

| ID | Kind | Incomplete today | Complete later |
|----|------|------------------|----------------|
| **B1** | Hardcoded + no write API | `compile_contract` fixes denied_ops, FS, network; register capabilities=`["read"]` only | `PATCH /agents/:pid/contract` + persist digest |
| **B2** | Missing API | No `/agents/:pid/completions`; gateway falls back to `gateway-agent` | Forced-pid completions façade |
| **B3** | Partial | Anthropic path: `gateway-anthropic`, no who_am_i/RAG | Parity with OpenAI gateway inject |
| **B4** | Bypass | `CONNECTOR_AGENT_SETUP_GATE` default off; silent bootstrap setup | Gate on + refuse Talk until Active |
| **B5** | Doc-only | `HitlPolicyV2` on setup/compliance; **admission does not read it** | Enforce per effect class + HITL submit |
| **B6** | Missing rules | No re-activate / continuity protocol after contract edit | Spec + implement remint |

### 8.2 Other hardcodes UI must disclose

| Hardcode | File | Until |
|----------|------|-------|
| DockLock cage FS/network **not from contract** | `kernel/docklock.rs` `compile_cage_profile` | **B7** |
| Ring-1 / QPR / DockLock env-optional | docklock / admission env flags | **B8** |
| Default setup HITL=None, forensic=Off, all memory types (general-purpose) | `mint_default_setup` | **B14**; tighten via Charter |
| Multiagent/experiments LLM bypass envelope | `multiagent.rs`, `experiments.rs` | **B11** |
| MCP `connector_who_am_i` unwired | protocols / envelope D4 | **B12** |
| WC frameworks not auto-bound from forensic_profile | activate + WC sessions | **B16** |
| Package “HITL passed” ≈ policy≠None | `forensic_package.rs` | **B19** |

### 8.3 Backend waves (for later sprints)

```text
Wave 1: B1 B9 B6 B14 B4   → Charter S2/S3/S11 real
Wave 2: B7 B8 B5 B17      → Cage + HITL real
Wave 3: B2 B3 B11 B12     → Talk real agent
Wave 4: B16 B18 B19       → WC/TT/evidence honesty
Wave 5: B10 B13 B15 B20–22 → polish
```

Until B1: Charter **S2 save disabled** + `backend_gap: contract_write` banner.

---

## 9. Gap matrix (forms vs backend)

| Form / place | Backend | UI target |
|--------------|---------|-----------|
| Register | `POST /agents` | S0 |
| SetupSpec | `POST …/setup` | S1,S3–S6 |
| Contract cage | type + read; **write GAP** | S2 + B1 |
| HITL policy | setup enum | S3 radio cards |
| HITL queue | hitl pending | Manage + FIX |
| Forensic profile | setup enum | S4 + derived evidence |
| Compliance contract | activate mint | Review + Evidence |
| Memory profile | setup | S5 |
| KB bind | setup | S5 |
| Common spaces | setup grants | S6 |
| Live grants | multiagent | Manage |
| Tools/clearance/AAPI | tools/aapi/clearance | S7 |
| Budgets/adaptive/HIPAA | budget/adaptive/compliance | S8 |
| WC session policy | witnessctl sessions | S9 + WC console |
| TT policies | tracetramp admin | S9 + TT console |
| Activate | `POST …/activate` | S10–S11 |
| Talk | gateway / completions | Talk tab |
| Identity view | envelope/self | Identity tab |
| Forensics package | forensics/* | Evidence |

---

## 10. Phased delivery

### E0 — Foundations

- API clients: setup, contract (read), capabilities, envelope, hitl, forensics, grants  
- Workbench tabs: Talk · **Charter** · Manage · Identity · Evidence · Control  
- Form primitives: `OpFormSection`, `OpTagList`, `OpGlobList`, `OpPolicyRadio`, `OpDigestBar`, `OpDerivedPanel`

### E1 — Identity + RUN agents + MONITOR instruments

- Agents lens; Identity read-only; pulse chips  

### E2 — **Charter Studio (forms)** ★ widest slice

| Ship | Stages |
|------|--------|
| E2a | S0 Register + S1 Purpose + S3 HITL + S4 Forensic + S5 Memory/KB + S6 Grants → `POST …/setup` |
| E2b | S10 Review + S11 Activate + compliance-contract panel |
| E2c | S2 Contract cage UI + **B1 write API** |
| E2d | S7 Tools/clearance + S8 Budgets/HIPAA + S9 WC/TT bind |

**Acceptance E2:** Operator can create Finance vs Developer agents with **different acume, HITL, forensic profile, memory types, grants** and see distinct envelopes — without curl.

### E3 — Evidence + forensics console + WC iia-join

### E4 — WATCH/FIX spine + TT deepen

### E5 — Talk (real-agent chat) + B2/B3

### E6 — Manage runtime depth (memory write/KB ingest/knot/live grants)

**Recommended order**

```text
E0 → E1 → E2a/b (charter without contract write)
  → B1 + E2c (allow/deny cage)
  → E5 Talk MVP
  → E2d + E6 Manage
  → E3 Evidence → E4 recorder/TT
```

Demo bar: **two agents, two charters, two Talks** — not a pretty radar.

---

## 11. Component & file targets

| Piece | Path |
|-------|------|
| Charter Studio wizard | `pages/setup_wizards/agent_charter_studio.rs` (replace/extend create_agent) |
| Charter tab | `overlays/agent_charter/{mod,contract,hitl,forensic,memory,grants,tools,budgets,institutions,review}.rs` |
| Form primitives | `components/operator/forms/*` |
| Contract API (server) | `services/agent_identity.rs` / `agents.rs` + `router.rs` — B1 |
| Completions façade | gateway + agents — B2 |
| Workbench shell | `topic_panels.rs` / `agent_workbench.rs` |
| TT/WC bind panels | light_consoles + charter S9 |

---

## 12. UX rules for forms

- One stage, one job; plain-language labels over type names (show type names in Advanced).  
- Always show **digest** after save (contract / setup / compliance).  
- Derived panels (evidence policy) are not editable — change parent profile.  
- Dangerous lists (network allow, denied_ops) use presets + confirm.  
- HIPAA / court profiles show stronger warnings.  
- Never call instructions field “the contract.”  
- Mobile: stage stepper; desktop: left stage rail + form canvas.

---

## 13. What we will not do

- JSON-only “Advanced setup” as the only charter UX.  
- Fake contract save without B1.  
- Collapse Charter into Talk.  
- Revive 40 sidebar pages (Charter is wizard + tab).  
- Claim court-grade from a green form checkbox.  
- Imply HITL policy == WC HITL queue without linking both.

---

## 14. Success criteria

| # | Criterion |
|---|-----------|
| 1 | Charter Studio covers S0–S11 with real controls for every SetupSpec field |
| 2 | HITL + forensic profile choices persist and appear on compliance-contract after activate |
| 3 | After B1: capabilities / denied_operations / FS / network editable and reflected in `/runtime/permissions` |
| 4 | Two agents differ on acume, HITL, forensic, grants in Identity without curl |
| 5 | Talk only as activated principal; receipts in WATCH |
| 6 | WC/TT bind visible from Charter S9 + Evidence join |
| 7 | Manage can operate memory/KB/grants post-charter |

---

## 15. Decision log

| ID | Decision | Rationale |
|----|----------|-----------|
| U11 | Execution-first | Product is execution system |
| U12 | RUN = workbench | Not radar-only |
| U13 | **Charter tab + Studio** | Backend constitution needs forms |
| U14 | Contract write API (B1) is in-scope | Cage fields otherwise dead |
| U15 | HITL policy form ≠ queue UI | Two layers in backend |
| U16 | Forensic picker + derived evidence | Matches ComplianceContract mint |
| U17 | S9 binds TT/WC, doesn’t replace consoles | Institution depth preserved |
| U18 | Manage ≠ Charter | Configure vs operate |

---

## 16. Immediate next step

**Full status report:** [IIA_STATUS_REPORT.md](IIA_STATUS_REPORT.md)

**Shipped in workbench:** E0 shell; Charter S1–S6 (purpose, cage FS/network, HITL, forensic, memory types, grants) + Activate; Talk + threads; Manage grants/knot/HITL; Evidence (compliance, WC alignment, forensic universals, TT bind, WC session list, **iia-join**); Control **activity + traces** recorder.

**Shipped full-page:** Charter Studio at `/agents/:pid/charter` (`agent_charter_studio.rs`) — stage rail S1–S6, S9 institutions, S10–S11 review/activate; linked from Charter tab.

**Still next:** follow **DI-0…DI-5** in [DISTRIBUTED_INTELLIGENCE_PLAN.md](DISTRIBUTED_INTELLIGENCE_PLAN.md) and [PRODUCT_GAPS.md](PRODUCT_GAPS.md):
1. DI-0 LAB MODE + intelligence-named WATCH/MONITOR.  
2. DI-1 LLM paste / `llm link` (keys out of cage).  
3. DI-2 Charter S7/S8 + Manage grants; E3 package UX; two-agent smoke.
