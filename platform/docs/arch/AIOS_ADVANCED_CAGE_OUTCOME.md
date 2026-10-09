# Advanced caged environment — final outcome (AI OS & orchestration)

This document is the **outcome definition** for a production-style **cage**: any **AI OS** (e.g. OpenFang-style daemons, agent runtimes), **orchestrator** (Temporal, custom schedulers, CI agents), or **IDE-embedded agent** is **controlled**, **managed**, and **provably governed** *as long as it remains inside the cage*. It ties together platform kernel docs, TraceTramp, WitnessCtl, and the advanced lab.

---

## 1. What “final outcome” means

| Pillar | Meaning in this stack |
|--------|------------------------|
| **Controlled** | No model call, tool invocation, or egress-bearing path that matters for policy **skips** the Connector + TraceTramp **control pipeline** when Control mode is the contract for that tenant. |
| **Managed** | Policy, budgets, blocks, quarantine, HITL holds, and releases are **explicit operator / API commands** — not silent in-memory flips. Configuration is **preset- or GitOps-driven** where you require it ([`CONNECTOR_CAGE_NODE_AND_PLUGINS.md`](../CONNECTOR_CAGE_NODE_AND_PLUGINS.md)). |
| **Proved** | Every material decision leaves **append-only** evidence (`trace_events` + ledger guard), **structured holds** (`hold_metadata`), optional **WitnessCtl** capture/handoff, and **decision exports** (`ledger_contract` in decision envelopes, `/decision/:trace_id`). |
| **“Impossible to bypass”** | **Inside the contractual cage only:** bypass is **not** a normal API or app bug; it requires **violating deployment assumptions** (see §5). Software cannot forbid alternate physics; it **can** forbid alternate *paths while still claiming to use the cage*. |

---

## 2. Who sits inside the cage

Treat these as **caged subjects** (same logical role: “thing that wants to act”):

- **AI OS** — long-lived agent OS processes (Hands, MCP hosts, multi-tool daemons).
- **Orchestration** — workflow engines, runners, lab agents (`advanced-lab/runner`), batch schedulers.
- **Human-driven clients** — IDEs, CLIs, chat UIs pointed at the **governed base URL**.

**Rule:** If the subject holds **only** a TraceTramp/Connector-scoped key and **only** reaches the LLM/provider **through** the governed ingress, it is **in-cage**. If it also holds a **raw provider key** or talks **directly** to `api.*.com`, that traffic is **out-of-cage** by construction — not “bypass of TraceTramp,” **non-participation** in the cage.

---

## 3. Layered cage (defense in depth)

Think **onion** — inner layers do not replace outer layers. **Order of gravity:** host **kernel cage** (egress, attach, `policy_revision`) is the **outer shell** that makes app-layer proof meaningful; TraceTramp and WitnessCtl sit **inside** that shell for ingress and wire-level proof respectively — see **[`CONNECTOR_KERNEL_CAGE_AND_LEDGER.md`](./CONNECTOR_KERNEL_CAGE_AND_LEDGER.md)**.

| Layer | Mechanism (repo / product) | Stops |
|-------|----------------------------|-------|
| **L0 — Identity & tenancy** | Connector admission, tenant keys, agent `pid` binding | Anonymous or wrong-tenant abuse of the plane. |
| **L1 — Control ingress** | TraceTramp **Control** default; optional View **explicitly** gated ([`plugins/tracetramp/src/gateway.rs`](../../../plugins/tracetramp/src/gateway.rs)) | “Silent observe-only” pretending to be enforced traffic. |
| **L2 — Policy / risk / tool / budget** | Connector policy, TraceTramp risk + tool gates, budgets, PII gates | Unapproved models, tools, spend, and sensitive content without review. |
| **L3 — Blocks & HITL** | `operation_blocks`, quarantine, soft policy/tool holds, default HITL, approval queue | High-impact or denied work unless a **real command** approves or policy is revised. |
| **L4 — Append-only ledger** | `trace_events` + DB trigger ([`plugins/tracetramp/migrations/20260503160000_trace_events_ledger_guard.sql`](../../../plugins/tracetramp/migrations/20260503160000_trace_events_ledger_guard.sql)) | Rewriting history of “what the plane decided” via normal SQL. |
| **L5 — Witness & kernel (optional hardening)** | WitnessCtl proxy/capture/handoff; `connector-kerneld` / host egress policy ([`CONNECTOR_KERNEL_CONTROLS.md`](./CONNECTOR_KERNEL_CONTROLS.md)) | **Egress bypass** of the app layer (direct sockets from worker to internet). |

**Git-like behavior:** policy and scoped blocks **supersede** older state through **new commits** (API/TUI/GitOps), not by mutating past `trace_events` rows. Releases and revokes are **commands** recorded like the rest of governance.

---

## 4. Proof pack (what you show an auditor or second team)

Minimum **evidence bundle** for a trace or incident:

1. **`GET …/decision/:trace_id`** (or TraceTramp admin equivalent) — `action_trace_cumulative`, `block_flags_cumulative`, policy/budget slices.
2. **`trace_events`** timeline — immutable cells; `metadata` may only grow (e.g. response preview).
3. **`metadata.decision.ledger_contract`** — `tracetramp_append_only_ledger_v1` declares the integrity model on each envelope.
4. **Approval rows** — `hold_metadata` (lane, `block.class`, `evidence.refs`) + resolution actor (`resolved_by` / approver id).
5. **WitnessCtl** (when deployed) — capture / receipt / handoff rows correlated by `trace_id`.

The **advanced lab** ([`advanced-lab/docs/LAB_FINAL_PLAN.md`](../../../advanced-lab/docs/LAB_FINAL_PLAN.md)) is the repeatable place to **generate** those bundles under benign + attack scenarios.

---

## 5. When bypass is “impossible” vs “deployment failure”

**Impossible (product + DB contract):**

- Rewriting or deleting **past** `trace_events` through the application role (trigger blocks it).
- Getting **Control enforcement** while sending **`X-TraceTramp-Pipeline: view`** unless the server explicitly allows View (config + tenant default).

**Not impossible without the outer shell (you must deploy the shell):**

- Agents with **provider API keys on disk** calling OpenAI/Anthropic **directly**.
- Hosts with **unrestricted egress** from the same cgroup as the agent (kernel / nft / corporate proxy not aligned).
- **Compromised DB superuser** or someone who **drops triggers** — same class as any ledger host compromise.

**Operational definition of success:** *No governed workload has network or secret access that allows a cheaper path than the cage.* That is **CISO + platform + network** joint ownership, documented in kernel runbooks.

---

## 6. One-page operator contract

1. **Single ingress URL** for LLM-shaped traffic from caged workloads.  
2. **No long-lived provider keys** on agent hosts; use **scoped** Connector/TraceTramp credentials.  
3. **Egress allow-list** from agent netns/cgroup to **only** Connector, TraceTramp, and approved tool endpoints ([`CONNECTOR_KERNEL_CAPS.md`](./CONNECTOR_KERNEL_CAPS.md)).  
4. **Control mode** default; **View** only for break-glass roles.  
5. **Migrations applied** — including `hold_metadata` and `trace_events_ledger_guard`.  
6. **WitnessCtl** (if required by compliance) wired with matching handoff secrets.  
7. **Run advanced lab** before production promotion; archive manifests under `advanced-lab/outputs/lab-runs/`.

---

## 7. Related documents

| Document | Role |
|----------|------|
| [`CONNECTOR_KERNEL_CONTROLS.md`](./CONNECTOR_KERNEL_CONTROLS.md) | Where quarantine, op-blocks, HITL, and kernel egress sit. |
| [`CONNECTOR_KERNEL_CAPS.md`](./CONNECTOR_KERNEL_CAPS.md) | Capability vocabulary for host enforcement. |
| [`CONNECTOR_KERNEL_RUNBOOK.md`](./CONNECTOR_KERNEL_RUNBOOK.md) | Operational steps. |
| [`../CONNECTOR_CAGE_NODE_AND_PLUGINS.md`](../CONNECTOR_CAGE_NODE_AND_PLUGINS.md) | Cage topology, presets, plugins. |
| [`plugins/tracetramp/checklist.md`](../../../plugins/tracetramp/checklist.md) | TraceTramp HITL + ledger checklist. |
| [`advanced-lab/docs/LAB_FINAL_PLAN.md`](../../../advanced-lab/docs/LAB_FINAL_PLAN.md) | Runnable proof lab (OpenFang path, attacks, evidence). |
| [`CONNECTOR_KERNEL_CAGE_AND_LEDGER.md`](./CONNECTOR_KERNEL_CAGE_AND_LEDGER.md) | Kernel-first cage + ledger; TraceTramp vs WitnessCtl; custom plugins |

---

## 8. Summary sentence (for exec / RFP)

**Any AI OS or orchestration system that is wired only through the Connector–TraceTramp cage, with host egress and secrets aligned to that cage, is controlled, managed, and cryptographically / procedurally provable from append-only traces and optional witness artifacts; bypass then reduces to non-participation or infrastructure compromise, which explicit runbooks and presets are designed to prevent.**
