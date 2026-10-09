# Partial Layers → Top Grade — Research for Coding

**Date:** 2026-08-12  
**Purpose:** Deep research on Connector’s **partial** substrate layers so engineering can close them to what production / regulated / “military-grade digital” buyers expect.  
**Companions:** [EXECUTION_SUBSTRATE_REPORT.md](EXECUTION_SUBSTRATE_REPORT.md) · [PRODUCT_GAPS.md](PRODUCT_GAPS.md) · [IIA_STATUS_REPORT.md](IIA_STATUS_REPORT.md) · canvas `connector-vs-substrate.canvas.tsx`

---

## 0. Scope (what “partial” means here)

| Workstream | Substrate layer | Connector today | Top-grade bar (research) |
|------------|-----------------|-----------------|--------------------------|
| **W1 Durable missions** | L6 | HITL + queued dispatch; chat threads | Execution journal + replay-safe tools + durable HITL |
| **W2 Action-bound HITL** | L6/L7 | Approve/deny on request id | Digest-bound, fail-closed, consumable approvals |
| **W3 Fabric task lifecycle** | L5 | Dispatch → `queued` folder | Full A2A task state machine + contextId |
| **W4 Cage fail-closed** | L2 | DockLock/Landlock/matrix; lab soft-fail | Tiered isolation; apply-or-refuse; honesty UI |
| **W5 Progressive autonomy** | L7 policy | Static HITL policy tiers | allow / ask / block gateway (+ later learned) |
| **W6 Decision evidence** | Evidence | Forensic package + court checklist | Decision traces ≠ logs; hash-chain; export verify |
| **W7 Ops control plane** | Ops UX | MONITOR chips / WATCH crumbs / thin Control | Observe · gate · start/stop · cage stdout |
| **W8 Prod defaults** | Cross-cutting | Lab-friendly off | Hardening-on path + loud LAB MODE |

**Out of scope for this doc (honest):** SIL/ISO robot controllers, ROS body HAL, battlespace C2 mesh. Those are L0–L1 physical — partner islands, not Connector MVP.

---

## 1. W1 — Durable mission orchestration (L6)

### What the real world wants

Industry consensus 2025–2026: **session memory ≠ durable execution**. Chat history does not prove which tool ran, whether a retry would double-send, or whether an approval survived a crash ([Zylos — Durable Execution for AI Agent Runtimes, 2026](https://zylos.ai/research/2026-04-24-durable-execution-agent-runtimes/); [DBOS](https://www.dbos.dev/blog/durable-execution-crashproof-ai-agents); Temporal + agent SDK guides).

**Required primitives:**

| Primitive | Why |
|-----------|-----|
| Execution journal / event history | Reconstruct after crash |
| Durable step result | Skip completed LLM/tool on replay |
| External event wait | HITL for hours/days without holding a thread |
| Idempotency key per mutating tool | At-least-once safe |
| Retry policy | Transient fails without losing mission |
| Compensation / saga hooks | Undo reversible steps; escalate irreversible |
| Pivot late | Irreversible effect after reversible prep |

**Architectural rule:** Model *proposes*; orchestrator *commits*. Compensations and state transitions live outside the LLM ([Temporal/Claude production guides](https://claudelab.net/en/articles/api-sdk/claude-agent-sdk-temporal-durable-ai-workflows-production-guide)).

### Connector delta

| Have | Lack |
|------|------|
| Multiagent pipelines; HITL queue; `a2a_tasks` folder with `queued` | No step journal; no replay skip; no durable wait; no tool idempotency SoT; no saga registry |
| Chat threads | Thread ≠ mission journal |

### Code target (implementable)

1. **`MissionV1` / `ExecutionJournalV1`** in engine_store (append-only steps).  
2. Step kinds: `llm`, `tool`, `hitl_wait`, `fabric_task`, `compensate`.  
3. Every mutating tool wrapper: `(mission_id, step_id, idempotency_key) → receipt`.  
4. Resume API: `POST /missions/:id/resume` reconstructs from journal; never re-fires completed side effects.  
5. Crash-injection tests: kill mid-tool after success, assert no duplicate.

**Acceptance**

- [ ] Crash after successful tool, before ack → resume does not re-invoke tool  
- [ ] HITL wait survives process restart  
- [ ] Journal reconstructs who/what/when for every completed step  
- [ ] Irreversible tools require HITL or explicit `no_compensate` flag in charter

---

## 2. W2 — Action-bound, fail-closed HITL (L6/L7)

### What the real world wants

Top-grade approvals are **not** “boolean on a request row.” They are a **protocol**:

- Outcomes: `allow` | `deny` | `require_approval` (suspended — not deny-with-hint)  
- **Action digest** over canonical JSON (RFC 8785 JCS) of exact executable binding  
- Revalidate digest + policy version **immediately before execute**  
- Timeout / restart / malformed → **fail closed** (never auto-allow)  
- One-time consume under concurrency  
- Approver identity authenticated — not a free-text `approver` field  

References: [Microsoft Agent Governance Toolkit ADR-0030](https://microsoft.github.io/agent-governance-toolkit/adr/0030-action-bound-approval-protocol/); [Tenuo SignedApproval](https://tenuo.ai/approvals); [HAP / AT1C receipt-before-execute](https://www.humanagencyprotocol.org/protocol).

### Connector delta

| Have | Lack |
|------|------|
| HITL create/pending/approve/deny; enforce flag | No `action_digest`; approve doesn’t rebind parameters; timeout fail-open possible depending on path; no consume-once; no policy_version pin |

### Code target

```text
ActionBinding {
  schema_version, agent_pid, principal_id, operation,
  target { tool, schema_version, resource },
  parameters (JCS),
  contract_digest, policy_version
}
action_digest = sha256(jcs(ActionBinding))
```

Flow:

1. Policy → `require_approval` + persist `ApprovalRequest{action_digest, expires_at, fail_closed}`  
2. Human decide → `ApprovalResolution` (allow/deny) with authenticated identity  
3. Pre-exec: recompute digest; match resolution; mark consumed atomically with tool start  
4. Emit linked audit: decision → request → resolution → consumed → execution

**Acceptance** (copy ADR-0030 tests)

- [ ] Approval for digest A cannot execute digest B (param swap)  
- [ ] Policy/contract version change invalidates pending approval  
- [ ] Timeout fails closed  
- [ ] Concurrent double-consume impossible  
- [ ] LLM advisory cannot create resolution  

---

## 3. W3 — Fabric task lifecycle (L5)

### What the real world wants

**A2A Protocol** is the industry task fabric ([spec](https://a2a-protocol.org/latest/specification/); [Life of a Task](https://a2a-protocol.org/latest/topics/life-of-a-task/)):

| State | Category |
|-------|----------|
| `SUBMITTED`, `WORKING` | Active |
| `INPUT_REQUIRED`, `AUTH_REQUIRED` | Interrupted (resumable) |
| `COMPLETED`, `FAILED`, `CANCELED`, `REJECTED` | Terminal (immutable) |

Also required:

- `contextId` groups related tasks/messages  
- Terminal tasks never restart — refinements = **new task**, same context  
- Subscribe/stream for active tasks  
- AgentCard: identity, skills, auth, capabilities  
- Grant/authority metadata travels with the task (our PC-C6 lesson)

Field C2 analogue: track must carry identity, confidence, geo, timing, **authority** before effects ([SwarmOS @ PC-C6](https://indefencemag.com/swarmos-links-mixed-drones-into-army-command-network/)).

### Connector delta

| Have | Lack |
|------|------|
| `POST /multiagent/tasks/dispatch` → `queued`; grant gate; A2A protocol surface partial | Full state machine; INPUT_REQUIRED; Get/Cancel/Subscribe parity; contextId; AgentCard from charter; delivery beyond folder_put |

### Code target

1. Map `a2a_tasks` records to A2A `TaskState` enum (aliased honesty labels OK).  
2. APIs: get / cancel / list-by-context / subscribe (SSE already used elsewhere).  
3. Dispatch creates `SUBMITTED` → worker → `WORKING` → terminal or `INPUT_REQUIRED`.  
4. Embed on every task: `from_principal`, `to_principal`, `intelligence_mark`, `grant_id`, `contract_digest`, `namespace`.  
5. Align protocols A2A handler with same SoT (one journal).

**Acceptance**

- [ ] Smoke: dispatch → WORKING → COMPLETED (or FAILED with reason)  
- [ ] Terminal immutability enforced  
- [ ] INPUT_REQUIRED + resume with same taskId  
- [ ] Two agents + grant: unauthorized dispatch 403; authorized completes  
- [ ] Multi-cell: task visible/routable when `CONNECTOR_MESH_FABRIC=1` (soak script)

---

## 4. W4 — Cage fail-closed & isolation tiers (L2)

### What the real world wants

For **untrusted / agent** workloads, 2026 consensus:

1. **Containers ≠ sandbox** (shared kernel) ([Northflank](https://northflank.com/blog/your-containers-arent-isolated-heres-why-thats-a-problem-micro-vms-vmms-and-container-isolation); [MicroVM 2026 survey](https://emirb.github.io/blog/microvm-2026/)).  
2. **Tiered isolation:**  
   - Hot path: Landlock + seccomp (+ egress deny-default / proxy) — Codex/Claude Code style ([Zylos LSM stacking](https://zylos.ai/research/2026-06-23-mandatory-access-control-lsm-stacking-ai-agent-runtimes/))  
   - High risk: MicroVM (Kata / Firecracker / Cloud Hypervisor)  
3. **Fail-closed:** if sandbox apply fails → **refuse start**, don’t soft-run.  
4. Defense in depth still applies inside the guest.  
5. Host Active claims must match mechanism (systemd drop-in ≠ eBPF).

### Connector delta

| Have | Lack |
|------|------|
| DockLock v2; Landlock FC flag; matrix mark; docker lab; L7 app allowlist | Default-on prod path; unify “applied vs claimed” posture; MicroVM as first-class high-risk tier; process_allow as real engine |

### Code target

1. **IsolationTier enum:** `ProcessLandlock` | `DockerLab` | `MicroVm` | `HostSimulated`.  
2. Prod/harden preset: Landlock FC + matrix required unless tier=MicroVm.  
3. `GET /runtime/isolation/:agent_pid` → `{tier, landlock, matrix, soft_fail, applied_truth}`.  
4. Refuse agent tool/runtime start when FC required and apply failed.  
5. Keep eBPF Host Active behind explicit applied flag (honesty already started).

**Acceptance**

- [ ] With FC on + Landlock unavailable → agent start/tool path denied + honest error  
- [ ] Posture API never claims matrix applied when nft/iptables insert failed  
- [ ] LAB MODE banner when any critical gate off  
- [ ] Document MicroVM as next tier (plugin-runtime path), not silent claim

---

## 5. W5 — Progressive autonomy / continuous authority (L7)

### What the real world wants

Static “HITL=all” or “HITL=none” is not top grade. Research formalizes a **three-way gateway**:

- **allow** — auto-execute  
- **ask** — escalate (the missing primitive vs hard deny)  
- **block** — hard deny  

Escalate where human preference is uncertain; learn boundary from approve/deny history ([arXiv:2605.19151 Progressive Autonomy](https://doi.org/10.48550/arxiv.2605.19151); [trustcalib](https://github.com/changkun/trustcalib)).

Military analogue: SYNTHComm — encode intent as persistent constraints, not only last-click veto ([Breaking Defense 2026](https://breakingdefense.com/2026/05/synthesized-command-control-a-new-way-human-choices-can-guide-ai-warfighting/)).

Control plane sits **above** agents: policy, attestation, audit ([Trezalabs AI control plane](https://www.trezalabs.com/blog/what-is-an-ai-control-plane)).

### Connector delta

| Have | Lack |
|------|------|
| HITL policy enum; contract caps; anomaly/budget gates | No allow/ask/block gateway object; no feedback-driven tiering; ask often collapses to deny |

### Code target (phased)

**Phase A (ship first — deterministic):**

```text
AutonomyGateway.decide(action) -> Allow | Ask(hitl) | Block(reason)
inputs: contract caps, denied_ops, HITL policy, risk class, anomaly, budget
```

**Phase B (later):** persist approve/deny features; optional learned threshold (GP/preference) behind flag.

**Acceptance (Phase A)**

- [ ] High-risk tool with HITL=tool → Ask, not silent Allow  
- [ ] Denied op → Block (not Ask)  
- [ ] Ask creates action-bound HITL (W2)  
- [ ] Metrics: allow/ask/block rates on MONITOR  

---

## 6. W6 — Decision evidence & court grade (Evidence)

### What the real world wants

**Logs ≠ audit trails ≠ decision traces.**

Court/regulator grade needs ([Collibra](https://www.collibra.com/blog/ai-audit-trails-what-to-log-for-models-and-agents-and-how-a-command-center-captures-it); [OriginStamp](https://originstamp.com/en/blog/reader/ai-agent-audit-trails-vs-application-logs); [ElixirData decision traces](https://www.elixirdata.co/blog/ai-agent-decision-traces-vs-logs-audit-trail-compliance); EU AI Act Art. 12 framing via [Cockroach/DORA notes](https://www.cockroachlabs.com/blog/dora-database-requirements-ai-agents/)):

Per consequential action, reconstruct:

1. Trigger / input (prompt or event)  
2. Model + config version  
3. Retrieved context (RAG ids/hashes)  
4. Policy evaluation (allow/ask/block + rule ids)  
5. Tool call + params digest + receipt  
6. Human authorization (if any) — W2 objects  
7. Outcome  
8. Principal / session — not shared service account  
9. Tamper-evidence: hash chain and/or external timestamp; portable export  

### Connector delta

| Have | Lack |
|------|------|
| Forensic universals; package download; court-readiness checklist; Ed25519 court tier after node sign; `iia verify-export` | Full decision-trace schema on every Talk/tool; chain covering policy+HITL+exec; live WC+CFNI soak; independent verify UX |

### Code target

1. **`DecisionTraceV1`** emitted on completions + tool + fabric transitions.  
2. Package builder includes traces + approval resolutions + contract digests.  
3. Offline verify: signature + hash chain + optional WC join digests.  
4. Soak runbook: WC session + CFNI secret + signed package → green checklist.

**Acceptance**

- [ ] Export package verifies with `connectorctl iia verify-export`  
- [ ] Trace answers who/what/why for a sample irreversible tool  
- [ ] Court-readiness fails closed when WC/CFNI missing  
- [ ] Traces attributable to `principal_id`, not `gateway-*`  

---

## 7. W7 — Ops control plane UX

### What the real world wants

Control plane = observe + route/govern + intervene ([Opper](https://opper.ai/ai-control-plane); NIST AI RMF Govern/Map/Measure/Manage).

Minimum operator loop:

| Surface | Top-grade |
|---------|-----------|
| MONITOR | Posture truth (cage/matrix/HITL/lab), deny rate, allow/ask/block, fleet drift |
| WATCH | Principal-filtered event lens; continuity breaks |
| Control | Start / pause / kill; **cage stdout** (not only audit); continuity FIX |

### Connector delta

Crumbs/chips shipped; Control still thin (pause meta; logs = activity).

### Code target

1. Control Start wired to runtime admit.  
2. Log stream from cage/runtime (SSE), labeled vs audit.  
3. MONITOR: isolation applied_truth + autonomy gateway rates.  
4. WATCH: filter by `principal_id` / `intelligence_mark`.

**Acceptance**

- [ ] Operator can start→talk→pause→kill without CLI  
- [ ] Cage log line visible within 2s of tool stderr  
- [ ] LAB MODE impossible to miss when gates off  

---

## 8. W8 — Production defaults

### What the real world wants

Buyers assume fail-closed. Lab-permissive defaults without a loud banner destroy trust (NIST: define human–AI configurations explicitly).

### Code target

1. `connectorctl harden` / enable-hardening remains one-shot.  
2. Preset `prod` | `gate`: Ring-1, QPR, DockLock FC, HITL enforce, ban anon, Landlock FC.  
3. UI: LAB MODE banner + one-click enable (DI-0 — verify shipped end-to-end).  
4. Docs/ops cheat-sheet: never claim court-ready without checklist green.

---

## 9. Recommended coding waves (use this order)

```text
Wave TG-0  Prod honesty      W8 + W7 LAB/MONITOR truth
Wave TG-1  Action-bound HITL W2  (unblocks trustworthy Ask)
Wave TG-2  Autonomy gateway  W5 Phase A  (Allow/Ask/Block)
Wave TG-3  Mission journal    W1  (durable steps + idempotent tools)
Wave TG-4  A2A task machine   W3  (fabric = real lifecycle)
Wave TG-5  Decision traces    W6  (package = court-shaped)
Wave TG-6  Cage tiers         W4  (FC default + MicroVM path)
Wave TG-7  Progressive learn  W5 Phase B  (optional)
```

**Why this order:** binding approvals before durable missions prevents “durable wrong action.” Gateway before fabric scales Ask. Traces after journal so the journal is the SoT.

---

## 10. Minimal shared schemas (start coding here)

### 10.1 ActionBinding + digest

See W2. Store hex SHA-256 of JCS bytes. Recompute at execute.

### 10.2 Mission step

```json
{
  "schema": "connector.mission.step.v1",
  "mission_id": "msn_…",
  "step_id": "stp_…",
  "kind": "tool|llm|hitl_wait|fabric|compensate",
  "idempotency_key": "…",
  "input_digest": "sha256:…",
  "output_receipt_id": "…",
  "status": "completed|failed|waiting",
  "agent_pid": "agent_…",
  "principal_id": "cnktr:agent:…"
}
```

### 10.3 Fabric task (A2A-aligned)

```json
{
  "schema": "connector.fabric.task.v2",
  "task_id": "task_…",
  "context_id": "ctx_…",
  "state": "SUBMITTED|WORKING|INPUT_REQUIRED|COMPLETED|FAILED|CANCELED|REJECTED",
  "from_pid": "agent_…",
  "to_pid": "agent_…",
  "grant_id": "ng_…",
  "authority": { "principal_id": "…", "intelligence_mark": "0xcd…", "contract_digest": "…" }
}
```

### 10.4 DecisionTrace

```json
{
  "schema": "connector.decision.trace.v1",
  "trace_id": "dt_…",
  "prev_hash": "…",
  "record_hash": "…",
  "principal_id": "…",
  "gateway": "allow|ask|block",
  "policy_version": "…",
  "action_digest": "…",
  "approval_resolution_id": null,
  "model_ref": "…",
  "rag_context_hashes": [],
  "outcome": "…"
}
```

---

## 11. Test gates (CI / smoke)

| Gate | Command / test |
|------|----------------|
| Two-agent fabric | `connectorctl iia smoke` (extend for COMPLETED state) |
| Approval binding | unit: digest mismatch deny |
| Journal crash | integration: kill after tool OK |
| Court package | `iia verify-export` on generated package |
| Isolation FC | unit/integration: Landlock fail → refuse |
| Lab honesty | API: lab-mode true when harden off |

---

## 12. Sources (selected)

| Source | Use |
|--------|-----|
| [Zylos durable agent runtimes (2026)](https://zylos.ai/research/2026-04-24-durable-execution-agent-runtimes/) | Journal vs session memory |
| [DBOS crashproof agents](https://www.dbos.dev/blog/durable-execution-crashproof-ai-agents) | Durable tools |
| [A2A Life of a Task](https://a2a-protocol.org/latest/topics/life-of-a-task/) | Fabric state machine |
| [A2A specification](https://a2a-protocol.org/latest/specification/) | AgentCard, TaskState |
| [AGT ADR-0030](https://microsoft.github.io/agent-governance-toolkit/adr/0030-action-bound-approval-protocol/) | Action-bound HITL |
| [Tenuo approvals](https://tenuo.ai/approvals) | SignedApproval / request_hash |
| [HAP protocol](https://www.humanagencyprotocol.org/protocol) | Receipt before execute |
| [arXiv:2605.19151](https://doi.org/10.48550/arxiv.2605.19151) | Progressive autonomy |
| [Zylos MAC/LSM agents (2026)](https://zylos.ai/research/2026-06-23-mandatory-access-control-lsm-stacking-ai-agent-runtimes/) | Landlock+seccomp tiers |
| [MicroVM 2026](https://emirb.github.io/blog/microvm-2026/) | When containers aren’t enough |
| [Collibra / OriginStamp / ElixirData](https://www.collibra.com/blog/ai-audit-trails-what-to-log-for-models-and-agents-and-how-a-command-center-captures-it) | Decision traces |
| [DoDD 3000.09](https://media.defense.gov/2023/Jan/25/2003149928/-1/-1/0/DOD-DIRECTIVE-3000.09-AUTONOMY-IN-WEAPON-SYSTEMS.PDF) | Appropriate human judgment |
| [SYNTHComm](https://breakingdefense.com/2026/05/synthesized-command-control-a-new-way-human-choices-can-guide-ai-warfighting/) | Continuous authority |

---

## 13. Bottom line for coding

Top grade for Connector’s partial layers is not “more LLM.” It is:

1. **Digest-bound HITL** that cannot be param-swapped  
2. **Mission journals** that survive crash without double effects  
3. **A2A-complete fabric** with authority metadata  
4. **Fail-closed cages** with tier honesty  
5. **Allow/Ask/Block** gateway feeding MONITOR  
6. **Decision traces** inside court packages  

Implement in waves **TG-0 → TG-6**; treat physical SIL/ROS/C2 as partner islands, not fake completeness.
