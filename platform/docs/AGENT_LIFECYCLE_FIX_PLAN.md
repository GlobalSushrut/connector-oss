# Agent Lifecycle & Human Interaction — Fix Plan

> Status: **draft for implementation**  
> Scope: Connector Platform agent registry + SOE kernel + `connectorctl`  
> Audience: engineers fixing cap enforcement, CLI UX, and telemetry parity

This document establishes the canonical **agent lifecycle**, compares it to the Linux process lifecycle, identifies every place our implementation deviates, and lists the fixes in the correct dependency order.

---

## 1. Canonical Agent Lifecycle (and Linux analogue)

The code already calls the ACB "task_struct equivalent" — we must make every layer honor that contract.

### 1.1 State model

| Agent state        | Linux analogue              | Meaning                                                      |
|--------------------|-----------------------------|--------------------------------------------------------------|
| `Registered`       | `TASK_NEW` (fork done)      | ACB created, not yet dispatching syscalls                    |
| `Running`          | `TASK_RUNNING`              | Actively executing operations                                |
| `Waiting`          | `TASK_INTERRUPTIBLE`        | Awaiting external event (human, tool, LLM)                   |
| `Suspended`        | `TASK_STOPPED` (SIGSTOP)    | Paused, context preserved, resumable                         |
| `Completed`        | `EXIT_ZOMBIE` (success)     | Task finished normally; waiting to be reaped                 |
| `Failed`           | `EXIT_ZOMBIE` (error)       | Terminal error; waiting to be reaped                         |
| `Terminated`       | `EXIT_DEAD` (post-wait)     | Reaped by operator/system, archived                          |

Reference: `@/home/umesh/Documents/connector-private/oss/vac/crates/vac-core/src/types.rs:1300-1332`.

### 1.2 Lifecycle transitions (must be single-writer through kernel)

```
          register                   start                 work
   ∅ ───────────────▶ Registered ─────────▶ Running ◀──────────► Waiting
                         │                   │   │                   │
                         │                   │   │ suspend           │ event
                         │                   │   ▼                   │
                         │                   │ Suspended ────────────┘
                         │                   │   │ resume
                         │                   ▼   ▼
                         │                Completed / Failed    (zombie)
                         │                       │
                         ▼                       ▼
                       (evict)                Terminated  (reaped)
```

### 1.3 Linux-style invariants we must honour

1. **Single parent/owner**: every agent has a creator (user id or parent agent) — analogue of `parent` in `task_struct`. Today we persist `created_by` but don't enforce parent/child tree semantics.
2. **Signals are one-way**: `Suspend`, `Resume`, `Terminate`, `Kill` map to `SIGSTOP`, `SIGCONT`, `SIGTERM`, `SIGKILL`. All must flow through `AgentSignal` syscall — not direct state mutation in handlers.
3. **Reaper**: zombies (`Completed`/`Failed`) must be reaped automatically when cap pressure exists, like `init` reaping orphans.
4. **Cap is a hard limit**: Linux enforces `RLIMIT_NPROC` at every `fork()`. Our `kernel_agent_limit_gate` must be called on **every** `AgentRegister` path — no exceptions.
5. **PID uniqueness**: kernel PID is the primary key. Names are aliases resolved by the platform (like `/proc/<pid>/comm`).

---

## 2. Human Interaction Surface (CLI ⇄ kernel)

Canonical `connectorctl` verb → syscall mapping (must be 1:1).

| CLI verb              | HTTP method + path                            | Kernel syscall         | Linux analogue             |
|-----------------------|-----------------------------------------------|------------------------|----------------------------|
| `connectorctl spawn`  | `POST /agents`                                | `AgentRegister`        | `fork() + exec()`          |
| `connectorctl list`   | `GET /agents`                                 | read ACB table         | `ps aux`                   |
| `connectorctl inspect`| `GET /agents/:id`                             | read ACB + audit       | `cat /proc/<pid>/status`   |
| `connectorctl pause`  | `POST /agents/:id/signal {Suspend}`           | `AgentSignal(SIGSTOP)` | `kill -STOP`               |
| `connectorctl resume` | `POST /agents/:id/signal {Resume}`            | `AgentSignal(SIGCONT)` | `kill -CONT`               |
| `connectorctl stop`   | `DELETE /agents/:id`                          | `AgentTerminate`       | `kill -TERM`               |
| `connectorctl kill`   | `POST /agents/:id/kill`                       | `AgentKill`            | `kill -KILL`               |
| `connectorctl clean`  | `DELETE /agents` (**new**, admin-only)        | bulk `AgentTerminate`  | `killall`                  |
| `connectorctl top`    | `GET /agents?live=1` (SSE)                    | stream ACB deltas      | `top`                      |
| `connectorctl logs`   | `GET /agents/:id/activity`                    | audit tail             | `journalctl -u <unit>`     |

All other CLI commands (`explain`, `risk`, `prove`, etc.) are **observers** — they must never mutate agent state.

---

## 3. Current Deviations (root causes of observed bugs)

### 3.1 Cap (3 in dev) is not enforced after the fact
**Observed:** `/health` reports `agents: "19/3"`.  
**Cause:** `kernel_agent_limit_gate()` only runs inside `register_agent`. The recycler (`recycle_kernel_agents_for_new_registration`) only harvests `Terminated | Completed | Failed`. `Running` and `Waiting` agents can accumulate past the cap because:
- Some registration paths bypass the gate (see below).
- Restart of the node re-hydrates agents from `agent_meta` without re-applying the cap.
- There is no periodic reconciler.

**Registration paths audit:**
| Path                                                              | Calls gate?         |
|-------------------------------------------------------------------|---------------------|
| `@/home/umesh/Documents/connector-private/platform/server/src/services/agents.rs` `register_agent` | ✅ yes              |
| `@/home/umesh/Documents/connector-private/platform/server/src/services/multiagent.rs:186` | ✅ yes              |
| `@/home/umesh/Documents/connector-private/platform/server/src/services/deploy.rs:160`    | ✅ yes              |
| `@/home/umesh/Documents/connector-private/platform/server/src/services/protocols.rs:451` | ✅ yes              |
| `@/home/umesh/Documents/connector-private/platform/server/src/services/protocols.rs:464` (MCP direct) | ❌ **bypass**       |
| `@/home/umesh/Documents/connector-private/platform/server/src/services/protocols.rs:1228` (ANP)    | ❌ **bypass**       |
| boot rehydration from `agent_meta`                                 | ❌ **bypass**       |

### 3.2 Bulk clean was missing
**Observed:** `connectorctl clean agents` did not exist until now.  
**Cause:** no `DELETE /agents` route. Fixed in current patch; see §4 step 2.

### 3.3 Name → PID resolution inconsistent
**Observed:** `connectorctl inspect agent_a2a-agent` shows zeros.  
**Cause:** The CLI and backend disagreed on the primary key. Backend indexes by `kernel_pid` (`pid:NNNNNN`), some folders by `api_pid`, the UI by logical `name`. A single resolver is now added (`resolve_kernel_pid`) but callers are incomplete.

### 3.4 Duplicate logical names
**Observed:** 13 agents named `a2a-agent` in the list.  
**Cause:** `RegisterAgentRequest` doesn't enforce per-namespace name uniqueness. Linux allows duplicate `comm` but each still has a distinct PID — we accept that, but the CLI must show the PID to disambiguate.

### 3.5 No reaper / no heartbeat eviction
**Observed:** Stale agents linger forever.  
**Cause:** No background task periodically:
- Reaps zombies
- Suspends idle agents past KECS threshold
- Evicts agents whose last heartbeat exceeds TTL

### 3.6 Licensing vs runtime cap not wired for non-dev
**Observed:** User expects dev=3, pilots/prod to require a real licence.  
**Cause:** The logic exists (`resolved_kernel_agent_cap` respects `license.max_agents`), but registration paths that bypass the gate (see §3.1) make the cap advisory. License check is only done when the gate is invoked.

---

## 4. Fix plan (dependency-ordered)

Each step should be a single PR. Do them in order — later steps assume earlier ones hold.

### Step 1 — Single source of truth for registration
**Goal:** every `AgentRegister` syscall dispatch goes through one helper that calls the gate.

1. Create `services::agents::register_agent_gated(state, tenant, req) -> Result<(kernel_pid, api_pid), Value>`.
2. Replace every `k.dispatch(... AgentRegister ...)` occurrence listed in §3.1 with a call to this helper.
3. Boot rehydration must re-apply the gate and refuse to load agents beyond cap (spill them to `terminated_agents` with reason `"cap_exceeded_on_boot"`).

### Step 2 — Bulk clean (done in current patch, verify)
1. `DELETE /agents` admin-only → terminate kernel agents + clear `agent_meta`/`agent_cost_ledger`.
2. `connectorctl clean agents [--force]` calls it.
3. Test: after cleanup, `/health` must show `agents: "0/3"`.

### Step 3 — Name/PID resolver everywhere
1. Make `resolve_kernel_pid_pub` the only way handlers turn a URL path into `(kernel_pid, api_pid)`.
2. Audit endpoints that still key by raw `pid`:
   - `@/home/umesh/Documents/connector-private/platform/server/src/services/agents.rs` — `update_agent`, `pause_agent`, `resume_agent`, `terminate_agent`, `kill_agent`, `freeze_agent`, `thaw_agent`, `send_agent_signal`, `reset_budget`, `update_budget`, `reflect`, `trust`.
   - `@/home/umesh/Documents/connector-private/platform/server/src/services/audit_receipts.rs`
   - `@/home/umesh/Documents/connector-private/platform/server/src/services/history.rs`
3. Every handler must early-return `404` via the resolver's "fallback" branch.

### Step 4 — CLI output parity
1. `connectorctl inspect <name|pid>` must always show:
   - Kernel PID (for disambiguation)
   - Namespace, status, ops, memory, cost, receipts — from live API, never zeros when API data exists.
2. Remove the debug `[DEBUG]` prints once flow is verified.
3. `list agents` must display the kernel PID column (so `a2a-agent` duplicates are distinguishable).

### Step 5 — Background reaper & reconciler
Implement `services::agent_reaper::run_periodically(state, interval=30s)`:
1. Reap zombies: remove `Completed|Failed|Terminated` older than 5 min.
2. Suspend idle: `Running` with `last_active_at` older than policy TTL and low KECS.
3. Enforce cap: if `agents().len() > cap`, suspend oldest idle until within cap; then terminate oldest suspended if still over.
4. Record each action in the audit log (reason = `reaper:<action>`).

### Step 6 — Licence-aware caps for pilots/production
1. In non-dev modes, require `state.license.max_agents` to be set; otherwise refuse to leave dev.
2. Activation flow (`POST /runtime/activation`) must fail without a valid `lic_*` key for production.
3. Document: dev=3, pilot=30 (free tier API key), growth=50, business=100, enterprise≥500 — matches the defaults in `runtime_control.rs`.

### Step 7 — Signal plumbing (SIGSTOP/SIGCONT/SIGTERM/SIGKILL)
1. All signal endpoints (`pause`, `resume`, `stop`, `kill`) must dispatch a single `AgentSignal` syscall variant — no direct mutation.
2. Kernel is the only place that transitions `AgentStatus`.
3. The CLI verbs must map 1:1 per the table in §2.

### Step 8 — Heartbeat contract
1. Running agents must emit a heartbeat (`AgentHeartbeat` syscall) at least every N seconds.
2. Missing heartbeat → reaper downgrades state: `Running → Waiting → Suspended → Terminated`.
3. Expose last heartbeat in `GET /agents/:id` and CLI `inspect` footer.

### Step 9b — CLI live-data parity across **all** verbs

**Problem (observed):** `explain`, `risk`, `prove`, `show agent`, `trace`, `watch`, `events`, `top`, `review`, `verify`, etc. still render zeros or `"?"` for status/ops/cost/receipts even when the backend has the data.

**Root cause:** Two non-resolver code paths short-circuit live injection:
1. `try_inject_live_agent_surface` (shared by `explain`, `risk`, `prove`, `review`, `show`) blindly prefixed `agent_` and never resolved names to kernel PIDs.
2. Ad-hoc per-command blocks in `cmd_show`, `cmd_trace` duplicated the same broken logic.

**Fix (partial done in current patch, needs verification):**
- `try_inject_live_agent_surface` now calls `resolve_agent_pid_opt` → `/api/v1/agents/pid:NNNNNN` → `inject_live_agent_data`.
- `cmd_show`/`cmd_trace` rewritten to use the resolver.
- `cmd_inspect` already on the resolver path.

**Remaining CLI verbs to audit (each must use the resolver + inject live data):**
- `cmd_watch` — streams surface, must refresh from API, not cached bridge.
- `cmd_events` — should pull `/api/v1/agents/:pid/activity`, not just audit log.
- `cmd_top` / `cmd_top_render` — already fetches `/api/v1/agents` list; verify it resolves kernel PID column correctly.
- `cmd_stats` / `cmd_metrics` — must read from `/metrics` + `agents` endpoints.
- `cmd_cost` — must call `/api/v1/agents/:pid/cost` via resolver.
- `cmd_verify` — must call `/api/v1/agents/:pid/audit/receipts` via resolver for chain check.
- `cmd_prove` — same as `verify` plus signed receipt display.
- `cmd_chain` — audit chain verification path.
- `cmd_risk` — merge KECS + cost + operations live.
- Memory commands (`cmd_top` memory mode, `cmd_trace --memory`) — query `/api/v1/books/journal` with `agent_pid` filter.

**Acceptance:** For every command in §2 (and in this list), running it against a known agent must display **non-zero, real** values for: status, namespace, ops, memory packets, cost, receipt count. No `"?"` placeholders when the API has data.

**Golden smoke script** (run after Step 1–3):
```bash
pid=$(connectorctl list agents --json | jq -r '.agents[0].pid')
for verb in inspect show explain risk prove review verify cost trace watch events; do
  echo "─── $verb $pid ───"
  connectorctl $verb $pid 2>&1 | head -15
done
```
Every section must show the same non-zero state.

### Step 9 — Tests (regression guard)
- Unit: `resolve_kernel_pid` for all 4 input forms.
- Integration: register 4 agents in dev mode, expect 4th to 429.
- Integration: bulk `DELETE /agents` drops to zero.
- Integration: reaper harvests a `Completed` agent within 30s.
- CLI smoke: `connectorctl spawn → list → inspect → pause → resume → stop → list` golden output.

---

## 5. Immediate verification checklist (after Step 1 + 2)

Run in order, paste the output back:

```bash
# 1. Restart node to pick up new binary
pkill -f connector-platform
connectorctl start --foreground &

# 2. Confirm cap
curl -s http://localhost:9091/health | jq .agents

# 3. Clean everything
connectorctl clean agents --force

# 4. Should be 0/3
curl -s http://localhost:9091/health | jq .agents

# 5. Register 4 agents; 4th must fail with 429
for i in 1 2 3 4; do
  curl -s -X POST -H 'Authorization: Bearer dev-token' \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"test-$i\",\"namespace\":\"ns:test\"}" \
    http://localhost:9091/api/v1/agents
  echo
done
```

Success criteria:
- Step 2 returns `"0/3"` or shows live count after cleanup.
- Step 5 shows 3 successful registrations and the 4th has `"error": "agent_limit_reached"`.

---

## 6. Out-of-scope / future work

- Parent/child agent tree (pgrp, sessions).
- Resource accounting per agent (cgroups analogue) — partially exists in `services/agent_resource_manager.rs`.
- cgroup v2-style delegation for multi-tenant hierarchical caps.
- `/proc/<pid>`-style filesystem view in UI.

---

## 7. Capabilities unlocked by this plan

Completing steps 1–9 turns the agent registry from a loose collection of records into a **real kernel-grade process table**. Concretely:

### 7.1 Platform capabilities
- **Deterministic capacity planning** — dev=3, pilot=30, prod=licence-driven; enforced on every path including MCP, ANP, boot rehydration, and multi-agent pipelines.
- **Bulk lifecycle operations** — `connectorctl clean agents`, `stop-all`, `pause-all`, `resume-all` at the fleet level.
- **Name- or PID-based addressing** — operators can use either logical name, API PID, or kernel PID interchangeably; resolver handles disambiguation.
- **Licence-gated runtime tiers** — cannot leave dev mode without a valid `lic_*` key; prevents accidental production overruns.
- **Tenant-scoped caps** — multi-tenant deployments inherit per-tenant `agent_limit` from `TenantContext`, never exceed platform max.

### 7.2 Reliability & governance
- **Automatic zombie reaping** — `Completed|Failed` agents don't accumulate; reaper sweeps every 30s.
- **Cap pressure relief** — when over-cap (e.g. after crash recovery), oldest idle agents get suspended/terminated in a documented priority order instead of silently overflowing.
- **Heartbeat-driven health** — missing heartbeat demotes `Running → Waiting → Suspended → Terminated`, exactly like Linux `TASK_UNINTERRUPTIBLE` detection.
- **Audit-complete state transitions** — every lifecycle change goes through a kernel syscall, producing a signed audit receipt. No more "agent vanished with no trace".
- **Crash-safe boot** — rehydration re-applies the cap and moves spillover to `terminated_agents` with reason `cap_exceeded_on_boot`.

### 7.3 Operator UX (CLI)
- **1:1 verb ↔ signal mapping** — `pause/resume/stop/kill` behave exactly like `SIGSTOP/SIGCONT/SIGTERM/SIGKILL`, no surprises.
- **Linux-familiar mental model** — operators who know `ps`, `top`, `kill`, `killall` get productive immediately.
- **Honest telemetry** — `inspect` never shows `"?"` or zeroed-out fields when live API data exists; every displayed number is traceable to a kernel ACB field.
- **Disambiguation by PID** — duplicate logical names (e.g. 13× `a2a-agent`) are distinguishable in `list` output via the kernel PID column.
- **Safe destructive ops** — `clean agents` requires explicit `yes` confirmation unless `--force`; admin-only role enforcement.

### 7.4 Developer / API surface
- **Single registration contract** — `register_agent_gated` is the only way to create agents; removes hidden code paths that cause drift.
- **Stable public resolver** — `resolve_kernel_pid_pub` lets plugins and external services resolve agents without reimplementing the PID/name/api_pid trinity.
- **Signal syscall uniformity** — all state transitions flow through `AgentSignal`/`AgentTerminate`/`AgentKill` kernel ops; simpler to reason about, easier to trace.
- **Regression guard** — unit + integration + CLI-smoke tests protect the lifecycle contract going forward.

### 7.5 Product / business outcomes
- **Pilot and production tiers become sellable** — licence enforcement actually works, so billing tiers are defensible.
- **Predictable demo behaviour** — free/dev users never unexpectedly exceed 3 agents, eliminating "works on my laptop but crashes in pilot" confusion.
- **Compliance posture** — every agent creation, signal, and termination is auditable and signed, supporting SOC2/ISO controls.
- **Foundation for next-gen features** — parent/child trees, cgroup-style resource quotas, `/proc`-like agent filesystem, and hierarchical tenant delegation all build on top of this contract.

---

## 8. Glossary

- **ACB**: Agent Control Block — `AgentControlBlock` in `vac-core`. Equivalent to Linux `task_struct`.
- **Kernel PID**: `pid:NNNNNN` — primary key assigned by the SOE kernel.
- **API PID**: `agent_<uuid>` — external opaque identifier stored in `agent_meta`.
- **Logical name**: human-chosen string (e.g. `a2a-agent`), not unique.
- **Gate**: the registration cap check (`kernel_agent_limit_gate`).
- **Reaper**: background task that collects zombies and enforces caps.
