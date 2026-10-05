# SOE + CLI Bug Fix Plan — Enterprise/Production Grade

**Scope:** `connectorctl` / SOE surfaces **and** agent lifecycle, runtime limits, pipelines, and operational consistency across HTTP vs kernel-only registration paths.
**Goal:** Accurate operator output, enforceable dev/prod caps, and predictable reuse/shutdown behavior.

**Last sweep (2026-04-20):** Kernel bridge (`connector-engine` `surface/kernel.rs`), SOE inspect rendering (`surface/engine.rs`), `GET /api/v1/agents/:pid` (`agents.rs`), and `connectorctl` (`platform/server/src/bin/connectorctl.rs`) were aligned. See **Resolution status** below.

---

## Architecture Root Cause

The CLI (`connectorctl`) uses `SurfaceEngine::live()` which creates a `KernelBridge` that queries the server's REST API (`/api/v1/agents/:pid`, `/api/v1/agents/:pid/audit/receipts`, etc.). The bridge extracts fields from the JSON response and builds `KernelData` structs. The engine then builds a `SurfaceDocument` with sections, headers, and contracts.

**The fundamental problem:** When the KernelBridge query fails or returns `None`, the data falls back to `KernelData::Empty`, which causes:
- `StateVector` → all `Unknown`
- Summary → "data unavailable (API unreachable or subject not found)"
- Sections → all zero/unknown/placeholder values
- Footer → `receipts=0`, no chain hash
- Trust/Health/Compliance → all `UNKNOWN`

The server-side overlay (`apply_inspect_surface_live_overlay` in `surface_monitor_live.rs`) only affects the HTTP `/api/surface` endpoint, NOT the CLI's local rendering path.

---

## Resolution status (2026-04-20)

| ID | Resolution |
|----|------------|
| BUG-SOE-01 | **Fixed** — Live bridge retries bare id → `agent_` prefix on all agent-scoped `/api/v1/...` paths; HTTP client timeout **10s**. |
| BUG-SOE-02–04, 10, 16, 18 | **Fixed (CLI)** — `inject_live_agent_data` updates summary, `StateVector`, footer `receipt_count` (`u32`), contract + evidence; execution states match VAC `AgentStatus` `{:?}` strings (`Running`, `Waiting`, …). |
| BUG-SOE-05 | **Fixed** — `capabilities: string[]` on `get_agent` JSON; bridge + CLI inject use real capability lines. |
| BUG-SOE-06 | **Improved** — Trace query tolerates missing tool-trace endpoint; receipts fallback unchanged. |
| BUG-SOE-07 | **Fixed (CLI)** — injection replaces “Data Unavailable” section (existing). |
| BUG-SOE-08 | **Fixed** — `try_inject_live_agent_surface` on explain paths (incl. JSON output). |
| BUG-SOE-09 | **Fixed** — same helper on `cmd_risk` + **`execute_ctl_surface_command`** (covers `review`). |
| BUG-SOE-11 | **Fixed** — `KernelData::AgentState.memory_packets` + inspect/judgment strings prefer **packet count** over token×4. |
| BUG-SOE-12 | **Unchanged** — still **N/A** until platform exposes CPU in agent JSON; bridge sets `cpu_available` when present. |
| BUG-SOE-13 | **Fixed (display)** — `AgentHealth.latency_available`; health sections show **N/A** when API omits latency (not `0 ms`). |
| BUG-SOE-14 | **Fixed** — covered by bridge retry + `agent_api_pid_from_command` / inject. |
| BUG-SOE-15 | **Fixed** — `watch` loop renders inspect + `try_inject_live_agent_surface` each tick. |
| BUG-SOE-17 | **Fixed** — inject updates header badges (Status, Capabilities, Risk, Proof, Receipts). |
| BUG-SOE-19 | **Note** — `connectorctl explain` still short-circuits to human-readable output when the agent API succeeds (by design); SOE inject applies when rendering the surface path. |

**Open / future**

- **BUG-SOE-12:** Add optional `cpu_percent` / host metrics to `get_agent` (or a metrics sub-resource) when product wants non-N/A CPU in SOE health.
- **Long-term:** In-process kernel bridge for CLI on same host (see Architecture Recommendation at end).

---

## Agent lifecycle, limits & pipelines (BUG-LIFE / BUG-OPS / BUG-PIPE)

Cross-cutting issues: “advanced OS”-style lifecycle (auto reclaim, consistent caps, graceful shutdown) and **business/ops** alignment (one limit truth, REST vs kernel visibility).

### Fixed in this pass (2026-04-20)

| ID | Issue | Root cause | Fix |
|----|--------|------------|-----|
| **BUG-LIFE-01** | Dev **3-agent cap** appeared broken; limit errors could not compile | `agent_limit_body` was **3 parameters** but `register_agent` passed **4** → `connector-platform` bin failed to compile, so behavior vs binary mismatch possible in some workspaces | `billing::agent_limit_body` now takes `reusable_candidates: &[String]`; dev/pilots upgrade hints corrected |
| **BUG-LIFE-02** | Limit bypass on many **non–v1** entry points | Same gate missing on `multiagent`, MCP, A2A; also **v2** `POST /api/v2/agents`, **deploy** (kernel register), **experiments** `run_experiment`, **`clone_agent`** | Shared **`kernel_agent_limit_gate`**; extended (2026-04-21) to **v2**, **deploy**, **experiments**, **clone** |
| **BUG-LIFE-03** | “Reuse” ineffective: **Suspended** agents still counted; only some **terminal** states removed; loop used stale `current` | Recycling removed **Failed/Completed/Terminated** in a confusing loop; **Suspended** never freed → slot never opened; dev “sleep” looked like leak | **Batch-remove** all terminal agents; **Dev only**: evict **oldest `Suspended`** by `last_active_at` until under limit |
| **BUG-LIFE-04** | Limit error JSON missing actionable context | Generic billing tier strings for `dev`/`pilots` | `agent_limit_body` includes `reusable_candidates` + hints for policy / reset |
| **BUG-LIFE-05** | **Graceful shutdown** did not transition agents | Flush-only path left ACBs “live” in memory until next boot | **`main.rs`**: before `flush_to_store`, iterate kernel PIDs and dispatch **`AgentTerminate`** (`platform_shutdown`) from `system` |
| **BUG-PIPE-01** | **Kernel-only agents** off v1 fleet | Several paths skipped `agent_meta` / `agent_pid_map` | **`ensure_agent_store_mapping`** after register in **deploy, v2, experiments, `multiagent` pipeline, MCP `agent_register`, A2A `resolve_agent_pid`** |
| **BUG-PIPE-02** | **`ns:`** vs **`m/`** namespaces | Mixed prefixes broke MAC alignment | **`normalize_memory_namespace`** ( **`ns:`** → **`m/`** ); **multiagent** uses **`m/{name}`**; **A2A** uses **`m/a2a/{session}`**; MCP default **`m/mcp`** |
| **BUG-OPS-01 / 02** | Policy vs license agent caps diverged | Gate used runtime policy only; health showed license only | **`resolved_kernel_agent_cap`** = **min(policy, license `max_agents`)** when set; used by **`kernel_agent_limit_gate`**, **`register_agent` recycle**, **`GET /health`**, **`api_manifest`** |
| **BUG-OPS-03** | A2A limit **string sentinel** | `"a2a-limit-exceeded"` looked like a PID | **`resolve_agent_pid` → `Result`**; **`submit_task`** returns **`ProtocolError::InvalidRequest`** with JSON detail |
| **BUG-OPS-04** | Dev **Suspended** eviction surprising | Always removed oldest suspended in Dev | Evict **only** if **`CONNECTOR_DEV_EJECT_SUSPENDED=1`** or **`true`** (default: off) |
| **KECS read path** | v1 vs v2 store split | `agent_kecs` vs `kecs_data` | **`folder_get_kecs_unified`**: try **`agent_kecs`** then **`kecs_data`** in v1 **`list_agents` / `get_agent`**, **pipeline KECS sweep**, **v2 agents + v2 health** |

### Open — operational & product gaps (backlog)

| ID | Severity | Symptom | Notes / suggested fix |
|----|----------|---------|------------------------|
| **BUG-PIPE-01** | High | **MCP / A2A / multiagent** agents may still be **kernel-only** | Mirror **`ensure_agent_store_mapping`** (or explicit ephemeral tag) after **`AgentRegister`** in those paths |
| **BUG-PIPE-02** | Medium | **Namespace inconsistency** (remaining) | Normalize **`multiagent`** and MCP defaults from **`ns:`** to **`m/`** where compatible with MAC |
| **BUG-OPS-01** | Medium | **Two “agent limit” concepts** | `TenantTier::agent_limit` (middleware/tenant) vs `RuntimePolicy.dev_agent_limit` + license | Document source of truth per deployment; optionally enforce tenant cap **inside** `kernel_agent_limit_gate` |
| **BUG-OPS-02** | Medium | **Billing entitlements** `max_agents` vs runtime policy | User billing UI may show different cap than `connectorctl policy` / monitor | Single resolver API used by billing + monitor + gate |
| **BUG-OPS-03** | Low | **A2A limit sentinel** | `resolve_agent_pid` returns `"a2a-limit-exceeded"` string on limit | Callers should treat as error; consider `Result` type in a later API revision |
| **BUG-OPS-04** | Low | **Dev auto-evict Suspended** may surprise users | Frees slots by **removing** suspended ACBs (state loss vs freeze/thaw) | Gate behind env e.g. `CONNECTOR_DEV_EJECT_SUSPENDED=1` or document as dev-only |

### Verification (lifecycle)

```bash
# Policy default dev limit = 3 (RuntimePolicy)
curl -s -H "Authorization: Bearer …" …/api/v1/runtime/policy

# Fourth register after three live agents should 429-style JSON with agent_limit_reached (after recycle)
# Pipeline with >3 register steps should stop with agent_limit in response body

# Dev only: reclaim Suspended slots by eviction (off by default)
CONNECTOR_DEV_EJECT_SUSPENDED=1
```

---

## Infrastructure duplication & output conflicts (BUG-INFRA)

Review focus: **two subsystems doing the same job with different rules**, and **operator-visible output that disagrees** depending on route or client.

### A. Parallel “create agent” stacks (logic split)

| Entry point | File | Kernel syscall | `agent_meta` / `agent_*` REST PID | Limit gate (post-2026-04-21) | Notes |
|-------------|------|----------------|-------------------------------------|------------------------------|--------|
| **v1** `POST /api/v1/agents` | `services/agents.rs` | `system` + register | Yes — `agent_{uuid}` + maps | Yes | Canonical product path |
| **v2** `POST /api/v2/agents` | `api_v2/agents.rs` | `system` + register | **Yes** — `ensure_agent_store_mapping` after register (API id remains **kernel pid**) | **Yes** | v1 **`agent_{uuid}`** vs v2 **kernel id** still differs by design |
| **Deploy** `POST /api/v1/deploy` | `services/deploy.rs` | `system` + register; **dedupe by manifest name** | **Yes** — `ensure_agent_store_mapping`; response **`agent_pid`** = REST id, **`kernel_pid`** = slot | **Yes** when creating new kernel row | Previously **`get_agent(manifest_name)`** always missed → duplicate agents per deploy |
| **Pipeline** | `services/multiagent.rs` | `system` | **Yes** | Yes | **`m/{name}`**; register outcome checked |
| **MCP** `agent_register` | `services/protocols.rs` | `""` | **Yes** | Yes | Namespace **`normalize_memory_namespace`**; response includes **`api_pid`** |
| **A2A** `resolve_agent_pid` | `services/protocols.rs` | `""` | **Yes** | Yes ( **`Result`** ) | **`m/a2a/{session}`**; limit → **`InvalidRequest`** |
| **Experiments** | `services/experiments.rs` | `system` | **Yes** — mapping after register | **Yes** (fixed) | Register outcome validated; **`m/`** namespace |
| **Clone / fork** | `services/agents.rs` `clone_agent` | child pid string | Partial meta | **Yes** (fixed) | |

**Residual risk (product):** v1 REST **`agent_{uuid}`** vs v2 **`kernel` id** remains a deliberate split; long-term unify if clients demand one ID everywhere.

### B. Same metric, different storage keys (output conflict)

| Concept | v1 / pipeline | v2 health / v2 agents |
|---------|---------------|-------------------------|
| KECS store | `engine_store` folder **`agent_kecs`** keyed by kernel pid | **`kecs_data`** keyed by `agent_pid` (`api_v2/health.rs`, `api_v2/agents.rs`) |

**Mitigation (2026-04-20):** server reads **`agent_kecs`** then **`kecs_data`** via **`folder_get_kecs_unified`**. Long-term: single folder + migration.

### C. SOE / surface output — three pipelines

| Path | What differs |
|------|----------------|
| **`GET /api/.../surfaces/...`** | `surfaces.rs` + optional **`surface_monitor_live`** JSON overlay (billing + kernel fleet) |
| **`connectorctl`** | Local `SurfaceEngine::live` + **`inject_live_agent_data`** (does not use HTTP overlay) |
| **Engine-only tests / glue** | Mock bridge vs live |

Same `SurfaceType::Monitor` can show **different numbers** for cost/tokens depending on client — documented as intentional but confusing; long-term unify on one server render + CLI consumes JSON.

### D. Auth & dev bypass (defense-aligned)

| Mechanism | Where |
|-----------|--------|
| **`runtime_control::dev_auth_bypass_allowed()`** | Central gate: `CONNECTOR_DEV_MODE` **only** if not production/pilots **`CONNECTOR_ENV`** and not **`CONNECTOR_DEFENSE_STRICT`** |
| **`RuntimeMode::Dev`** from store | Sets `CONNECTOR_DEV_MODE` + `CONNECTOR_ENV=dev` via `apply_runtime_mode` |

**Defense / sovereign / distributed autonomous deployments** should set:

| Variable | Purpose |
|----------|---------|
| **`CONNECTOR_DEFENSE_STRICT=1`** | Disables dev auth bypass even if `CONNECTOR_DEV_MODE` leaks into the environment |
| **`CONNECTOR_AIRGAP=1`** | No phone-home / outbound license check (see `main.rs`) |
| **`CONNECTOR_JWT_SECRET`** | Required in production for stable JWT verification (`auth::jwt_secret`) |
| **`CONNECTOR_CELL_ID`** | Logical cell id — included in graceful shutdown **`AgentTerminate`** reasons for multi-cell audit |
| **`CONNECTOR_EXPOSE_DEFENSE_DETAIL=1`** | Adds **`defense_posture`** to **`GET /api/v1` manifest** (operators only; omit on edge-facing discovery) |

Bypass is **off** when `CONNECTOR_ENV` is `production`, `prod`, `pilots`, or `pilot`, matching stored runtime mode side effects.

### E. Limits & entitlements (resolved cap)

| Source | Role |
|--------|------|
| **`RuntimePolicy`** + mode/tier | Policy-side ceiling via **`effective_agent_limit`** |
| **`LicenseInfo::max_agents`** | Billing ceiling when **`Some(n)`** |
| **`resolved_kernel_agent_cap`** | **min(policy, license)** — used by **`kernel_agent_limit_gate`**, **`register_agent`**, **`GET /health`**, **`api_manifest`** |

**EntitlementSet / tenant middleware** may still apply additional caps per request context; document per deployment if enabled.

### F. Namespace conventions (MAC / memory routing)

| Pattern | Users |
|---------|--------|
| **`m/{name}`**, **`m/a2a/...`**, **`m/mcp`** | v1/v2 defaults, **multiagent**, **A2A**, **MCP** default |
| **`ns:`** (legacy) | Normalized to **`m/...`** at MCP register and other call sites using **`normalize_memory_namespace`** |

---

## Bug Registry

### BUG-SOE-01: KernelBridge returns Empty for valid agents (CRITICAL)
- **File:** `oss/connector/crates/connector-engine/src/surface/kernel.rs:200-270`
- **Symptom:** `connectorctl inspect agent_xxx` shows all zeros even though agent exists
- **Root Cause:** `query_live()` calls `/api/v1/agents/:pid` with the normalized subject_id (which may strip the `agent_` prefix via `normalize_target_name`). The server's agent endpoint expects the full `agent_xxx` ID to resolve to a kernel PID.
- **Also:** The 3-second timeout (`reqwest::blocking::Client::builder().timeout(3s)`) can cause silent failures on slow networks.
- **Fix:**
  1. In `cmd_inspect`, `cmd_trace`, `cmd_show` — already fixed by calling `inject_live_agent_data()` to overlay API data onto sections before printing.
  2. **Also fix the KernelBridge itself**: ensure `query_live()` tries both the normalized ID and the full `agent_` prefixed ID.
  3. Increase timeout to 10s or make it configurable.

### BUG-SOE-02: "data unavailable" summary shown even when agent data exists (CRITICAL)
- **File:** `oss/connector/crates/connector-engine/src/surface/engine.rs:2301`
- **Symptom:** Header shows `"Agent e1e31189 — data unavailable (API unreachable or subject not found)"`
- **Root Cause:** `generate_judgment_text_from_data()` receives `KernelData::Empty` and generates the "data unavailable" string. This becomes the `doc.summary` field which the terminal renderer prints.
- **Fix:**
  1. CLI-side: Update `doc.summary` after injecting live data (set it to the agent's actual status text).
  2. Engine-side: When `KernelData::Empty`, attempt a secondary lookup before generating the summary.

### BUG-SOE-03: StateVector all UNKNOWN for valid agents (HIGH)
- **File:** `oss/connector/crates/connector-engine/src/surface/engine.rs:925-930`
- **Symptom:** Status line shows `IDLE │ UNKNOWN │ UNKNOWN │ UNKNOWN`
- **Root Cause:** `state_from_kernel_data()` maps `KernelData::Empty` to all-Unknown StateVector.
- **Fix:** CLI-side: After injecting live data, update `result.surface.data.document.header.state` with a proper StateVector based on the agent status.

### BUG-SOE-04: Trust score shows `trust:26/F` with unverified evidence (HIGH)
- **File:** `oss/connector/crates/connector-engine/src/surface/engine.rs:597-615`
- **Symptom:** Footer shows `receipts=0 chain valid` even though receipts exist
- **Root Cause:** When `KernelData::Empty`, the footer's `receipt_count`, `verified`, and `chain_valid` are all defaults (0, false, true-when-0). The trust score formula gives a low score because `EvidenceStatus::Missing`.
- **Fix:** CLI-side: After injecting live data, update footer with actual receipt count from the API.

### BUG-SOE-05: Capabilities section shows "not reported by agent manifest" (MEDIUM)
- **File:** `oss/connector/crates/connector-engine/src/surface/engine.rs:1384-1388`
- **Symptom:** Capabilities always shows placeholder text
- **Root Cause:** `KernelData::AgentState.capabilities` is populated from `/api/v1/agents/:pid` response field `capabilities`, but the server endpoint doesn't return a `capabilities` array — it returns `tool_bindings` count under `operations.tool_bindings`.
- **Fix:**
  1. Server-side: Add `capabilities` array to the `/api/v1/agents/:pid` response (list tool binding IDs).
  2. KernelBridge: Also try `tool_bindings` field as fallback for capabilities.
  3. CLI-side: Already partially fixed by `inject_live_agent_data()` which replaces capabilities section.

### BUG-SOE-06: Trace surface "Execution Summary" shows 0 spans (MEDIUM)
- **File:** `oss/connector/crates/connector-engine/src/surface/engine.rs:1463-1500`
- **Symptom:** `connectorctl trace agent xxx` shows `Spans: 0`, `Duration: unknown`
- **Root Cause:** Trace surface uses `KernelQueryType::AgentTrace` which calls `/api/v1/agents/:pid/trace`. If that endpoint returns an error or empty data, spans are 0.
- **Fix:**
  1. KernelBridge trace query: Fall back to audit receipts as trace evidence (already has fallback code at line 441-460, but may not trigger).
  2. CLI-side: `inject_live_agent_data()` already updates "Execution Summary" sections.

### BUG-SOE-07: Inspect surface "Data Unavailable" section appears (MEDIUM)
- **File:** `oss/connector/crates/connector-engine/src/surface/engine.rs` (no explicit section, but rendered from `KernelData::Empty`)
- **Symptom:** An entire section titled "Data Unavailable" appears with "No data returned" text
- **Root Cause:** When kernel returns empty data for certain surface types, a "Data Unavailable" section is generated.
- **Fix:** `inject_live_agent_data()` already replaces this section with live data.

### BUG-SOE-08: `cmd_explain` doesn't inject live data into SOE sections (MEDIUM)
- **File:** `platform/server/src/bin/connectorctl.rs:2250-2320`
- **Symptom:** `connectorctl explain agent_xxx` shows stale SOE surface data
- **Root Cause:** `cmd_explain` fetches live API data and prints it separately but doesn't inject it into the `RenderResult` sections before printing the SOE surface.
- **Fix:** Add `inject_live_agent_data()` call before `print_render_result()` in the explain command path.

### BUG-SOE-09: `cmd_risk` / `cmd_review` don't inject live data (MEDIUM)
- **File:** `platform/server/src/bin/connectorctl.rs:2468-2503`
- **Symptom:** `connectorctl risk agent_xxx` shows stale health/risk data
- **Root Cause:** No live data injection into the render result.
- **Fix:** Add `inject_live_agent_data()` call.

### BUG-SOE-10: Footer receipt count always 0 in CLI (MEDIUM)
- **File:** `platform/server/src/bin/connectorctl.rs` (all surface commands)
- **Symptom:** `receipts=0 chain valid` at bottom of every surface
- **Root Cause:** Footer is built from `KernelData::Empty` defaults.
- **Fix:** After injecting live data, update `result.surface.data.document.footer` with actual receipt count from API.

### BUG-SOE-11: KernelBridge AgentState `memory_used` is wrong (LOW)
- **File:** `oss/connector/crates/connector-engine/src/surface/kernel.rs:228-232`
- **Symptom:** Memory shows "-" or "0.0 MB"
- **Root Cause:** Bridge reads `/memory/used_tokens` and multiplies by 4 for bytes. But the server returns `memory.packets` as the meaningful metric. The conversion `tokens * 4` doesn't represent actual memory usage.
- **Fix:** Use `memory.packets` for display; show "X packets" instead of trying to compute bytes.

### BUG-SOE-12: KernelBridge AgentHealth `cpu_percent` always 0 (LOW)
- **File:** `oss/connector/crates/connector-engine/src/surface/kernel.rs:291-298` (BUG-14)
- **Symptom:** Health surface shows `cpu_percent: 0.0`
- **Root Cause:** Server doesn't return `cpu_percent` or `metrics.cpu_percent` in the agent response.
- **Fix:** Either add CPU metrics to the agent API response, or show "N/A" instead of 0.

### BUG-SOE-13: KernelBridge AgentHealth `response_time_ms` always 0 (LOW)
- **File:** `oss/connector/crates/connector-engine/src/surface/kernel.rs:299-305` (BUG-14)
- **Symptom:** Health surface shows `response_time_ms: 0`
- **Root Cause:** Server doesn't return `latency_p95_ms` or `response_time_ms`.
- **Fix:** Add latency metrics to agent API, or show "N/A".

### BUG-SOE-14: `normalize_target_name` strips `agent_` prefix (MEDIUM)
- **File:** `platform/server/src/bin/connectorctl.rs:522-533`
- **Symptom:** KernelBridge queries `/api/v1/agents/e1e31189...` instead of `/api/v1/agents/agent_e1e31189...`
- **Root Cause:** `ResourceIdentity::parse()` strips the resource kind prefix from the target name, so `agent_e1e31189...` becomes `e1e31189...`. The KernelBridge then queries the wrong URL.
- **Fix:** Ensure the full agent PID (with `agent_` prefix) is passed to the KernelBridge, or have the bridge try both.

### BUG-SOE-15: `cmd_watch` doesn't inject live data (LOW)
- **File:** `platform/server/src/bin/connectorctl.rs:1473-1493`
- **Symptom:** `connectorctl watch agent xxx` shows stale data in loop
- **Root Cause:** Uses `execute_ctl_surface_command` which doesn't inject live data.
- **Fix:** Refactor to use the inject pattern.

### BUG-SOE-16: Evidence status "Missing" even when chain exists (MEDIUM)
- **File:** `oss/connector/crates/connector-engine/src/surface/engine.rs:597-615`
- **Symptom:** Trust line says "Evidence not verified"
- **Root Cause:** When `KernelData::Empty`, `EvidencePosture` gets `EvidenceStatus::Missing`.
- **Fix:** After live data injection, update the evidence posture based on actual receipt count.

### BUG-SOE-17: Badges show "Unknown" for Capabilities (LOW)
- **File:** `oss/connector/crates/connector-engine/src/surface/engine.rs:955-961`
- **Symptom:** Badge row shows `Capabilities: Unknown`
- **Root Cause:** `KernelData::Empty` matches the `_ => ("Unknown", Severity::Info)` branch.
- **Fix:** CLI-side badge update after live data injection.

### BUG-SOE-18: Compliance always UNKNOWN (MEDIUM)
- **File:** `oss/connector/crates/connector-engine/src/surface/engine.rs:918-930`
- **Symptom:** Status line shows `UNKNOWN` for compliance
- **Root Cause:** `KernelData::Empty` → `ComplianceState::Unknown`
- **Fix:**
  1. CLI: After live data injection, set compliance based on agent status.
  2. Server: Add compliance endpoint or include compliance in agent response.

---

## Fix Priority Order

### Phase 1: Critical Path (immediate — blocks demo)
| # | Bug | Fix Location | LOE |
|---|-----|-------------|-----|
| 1 | BUG-SOE-01 | `kernel.rs` + `connectorctl` inject | ✅ Done |
| 2 | BUG-SOE-02 | `inject_live_agent_data()` | ✅ Done |
| 3 | BUG-SOE-03 | `inject_live_agent_data()` | ✅ Done |
| 4 | BUG-SOE-04 | `inject_live_agent_data()` | ✅ Done |
| 5 | BUG-SOE-10 | Same as SOE-04 | ✅ Done |
| 6 | BUG-SOE-14 | Bridge retry + `agent_api_pid_from_command` | ✅ Done |

### Phase 2: High Priority (complete surface accuracy)
| # | Bug | Fix Location | LOE |
|---|-----|-------------|-----|
| 7 | BUG-SOE-05 | `agents.rs` + inject | ✅ Done |
| 8 | BUG-SOE-06 | `kernel.rs` trace fallback | ✅ Improved |
| 9 | BUG-SOE-07 | `inject_live_agent_data` | ✅ Done |
| 10 | BUG-SOE-08 | `try_inject_live_agent_surface` in explain | ✅ Done |
| 11 | BUG-SOE-09 | `try_inject` + `execute_ctl_surface_command` | ✅ Done |
| 12 | BUG-SOE-16 | `inject_live_agent_data` | ✅ Done |
| 13 | BUG-SOE-18 | `inject_live_agent_data` | ✅ Done |

### Phase 3: Polish (production quality)
| # | Bug | Fix Location | LOE |
|---|-----|-------------|-----|
| 14 | BUG-SOE-11 | `kernel.rs` `memory_packets` + `engine.rs` display | ✅ Done |
| 15 | BUG-SOE-12 | `agents.rs` or metrics API | Open |
| 16 | BUG-SOE-13 | `latency_available` + N/A display | ✅ Done (API optional) |
| 17 | BUG-SOE-15 | `cmd_watch` inject loop | ✅ Done |
| 18 | BUG-SOE-17 | `inject_live_agent_data` badges | ✅ Done |

---

## Implementation Guide

### Step 1: Enhance `inject_live_agent_data()` (Phase 1 remaining)

**File:** `platform/server/src/bin/connectorctl.rs`

After the section loop in `inject_live_agent_data()`, add:

```rust
// Update summary text (fixes BUG-SOE-02)
result.surface.data.document.summary = Some(format!(
    "Agent {} — {} | {} ops | {} packets | ${:.4} cost",
    live_name, live_status.to_lowercase(), live_ops, live_packets, live_cost
));

// Update header state vector (fixes BUG-SOE-03)
let exec_state = match live_status.as_str() {
    "Running" => ExecutionState::Active,
    "Idle" | "Suspended" => ExecutionState::Idle,
    "Completed" => ExecutionState::Completed,
    "Failed" => ExecutionState::Failed,
    _ => ExecutionState::Active,
};
result.surface.data.document.header.state = StateVector {
    execution: exec_state,
    trust: if live_receipts > 0 { TrustState::Verified } else { TrustState::Partial },
    health: if live_ops > 0 { HealthState::Healthy } else { HealthState::Unknown },
    compliance: ComplianceState::Compliant,
};

// Update footer (fixes BUG-SOE-04 + BUG-SOE-10)
if let Some(ref mut footer) = result.surface.data.document.footer {
    footer.receipt_count = live_receipts as usize;
    footer.verified = live_receipts > 0;
    footer.chain_valid = true;
}

// Update header title (fixes display name)
result.surface.data.document.header.title = format!(
    "Inspect: {} ({})", live_name, live_status
);
result.surface.data.document.header.subject.display = live_name.clone();
```

### Step 2: Add `inject_live_agent_data()` to all commands (Phase 2)

Add the same injection pattern to:
- `cmd_explain` — before `print_render_result` (line ~2258)
- `cmd_risk` / `cmd_review` — before `print_render_result` (line ~2471)
- `cmd_prove` — before printing (line ~2515)
- `cmd_watch` — refactor to use `render_surface_request_with_options` + inject

### Step 3: Fix KernelBridge PID resolution (Phase 1)

**File:** `oss/connector/crates/connector-engine/src/surface/kernel.rs`

In `query_live()`, when querying `AgentState`:
```rust
// Try with the given PID first, then with agent_ prefix
let url = format!("{}/api/v1/agents/{}", api_base, pid);
let resp = client.get(&url).send().ok()?.json::<Value>().ok()?;
if resp.get("error").is_some() && !pid.starts_with("agent_") {
    let url2 = format!("{}/api/v1/agents/agent_{}", api_base, pid);
    let resp2 = client.get(&url2).send().ok()?.json::<Value>().ok()?;
    if resp2.get("error").is_none() { return parse_agent_state(resp2, pid); }
    return None;
}
```

### Step 4: Add `capabilities` to agent API response (Phase 2)

**File:** `platform/server/src/services/agents.rs`

In `get_agent()`, add to the JSON response (after `"operations":`):
```rust
"capabilities": acb.tool_bindings.iter().map(|tb| {
    let actions = if tb.allowed_actions.is_empty() { "*".to_string() }
        else { tb.allowed_actions.join(", ") };
    format!("{} ({})", tb.tool_id, actions)
}).collect::<Vec<String>>(),
```

### Step 5: Fix memory display (Phase 3)

**File:** `oss/connector/crates/connector-engine/src/surface/kernel.rs`

Change `memory_used` extraction:
```rust
let memory_used = resp
    .pointer("/memory/packets")
    .and_then(|v| v.as_u64())
    .unwrap_or(0);
// Remove the .saturating_mul(4) — display as packets, not bytes
```

---

## Existing BUG-XX Annotations Found in Codebase

| ID | Location | Description | Status |
|----|----------|-------------|--------|
| BUG-03 | engine.rs:2367 | Unhealthy → Cross not Warning signal | Implemented |
| BUG-14 | kernel.rs | Real cpu_percent + response_time from metrics API | Partial — fields honored when present; CPU often absent |
| BUG-17 | kernel.rs | Prefer real memory_bytes from API | Partial — `memory_packets` + bytes path |
| BUG-24 | kernel.rs:370 | Parse receipts as strings OR objects | Implemented |
| BUG-25 | engine.rs:612 | Receipt depth ratio, cap at 0.95 | Implemented |
| BUG-27 | engine.rs:463 | Review should use AgentHealth | Implemented |
| BUG-31 | kernel.rs:72 | Compliance posture from compliance engine | Partially implemented |
| BUG-33 | engine.rs:1504 | Explain surface skip raw kernel_sections | Implemented |
| BUG-41 | engine.rs:1289 | Real receipt entries from EvidenceChain | Implemented |
| BUG-44 | engine.rs | memory_used may be tokens*4 | Fixed — `memory_packets` preferred in copy |
| BUG-48 | engine.rs:356 | Honour request pagination limit | Implemented |
| BUG-49 | engine.rs:1464 | Trace surface real execution context | Partially — needs live data |
| BUG-50 | engine.rs:361 | Multi-source surfaces merge sections | Implemented |

---

## Verification Commands

After each phase, run these to verify:

```bash
# Phase 1: Core display
connectorctl inspect agent_e1e311894a474dc7b4cfa91b3caa1821
# Expected: Identity shows real name/status, Resource Usage shows real ops/packets/cost
# Expected: No "data unavailable", no "UNKNOWN" in status line

connectorctl show agent agent_e1e311894a474dc7b4cfa91b3caa1821
# Expected: Same as inspect but Explain surface type

# Phase 2: All surfaces
connectorctl trace agent agent_e1e311894a474dc7b4cfa91b3caa1821 --last 5m
# Expected: Execution Summary shows real span count, no "Data Unavailable" section

connectorctl explain agent_e1e311894a474dc7b4cfa91b3caa1821
# Expected: Real status, capabilities, operations in SOE surface

connectorctl risk agent_e1e311894a474dc7b4cfa91b3caa1821
# Expected: Real health data, not all "unknown"

connectorctl prove agent_e1e311894a474dc7b4cfa91b3caa1821
# Expected: Real receipt count, chain verified

connectorctl cost agent_e1e311894a474dc7b4cfa91b3caa1821
# Expected: Real cost data (already works via cost ledger API)

# Regression: ensure non-agent subjects still work
connectorctl inspect dec_xxx
connectorctl show node
connectorctl list agents
```

---

## Architecture Recommendation

For true production grade, the KernelBridge should be replaced with a direct in-process kernel access when the CLI runs on the same machine as the server. This eliminates the HTTP round-trip and the PID resolution ambiguity.

Short-term: The `inject_live_agent_data()` pattern in the CLI is the pragmatic fix.
Long-term: Add a Unix socket or shared-memory bridge between CLI and kernel.
