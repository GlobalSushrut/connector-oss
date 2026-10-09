# Connector Kernel — cage infrastructure & blockchain-like ledger (strategy)

This document is the **deeper architectural stance** for the cage: **where** “cage infra” and **blockchain-like** (append-only, command-only, tamper-evident) behavior should **anchor** first, then how **TraceTramp**, **WitnessCtl**, **DevGuard**, and **future custom plugins** plug in without diluting the model.

**Implementation order (recommended):**  
**1) Connector Kernel / host contract** → **2) Connector OS APIs & presets** → **3) TraceTramp (ingress ledger)** → **4) WitnessCtl (witness / wire ledger)** → **5) DevGuard & other plugins** (signals + UX, not the sole proof).

---

## 1. Why the kernel comes first

| Problem | If you only fix TraceTramp | If you anchor the **kernel cage** |
|---------|------------------------------|-------------------------------------|
| Agent opens a socket **straight to** `api.openai.com` | TT never sees the traffic → **no proof**, no block | **Egress allow-list** (systemd `IPAddressAllow=`, nft, eBPF) denies the path → bypass is **expensive** |
| Plugin adds a “helper” HTTP client | Policy in TT is irrelevant | Host profile still binds **allow_hostnames** to what the **process** may connect to |
| “We have logs” | Logs can lie if DB rows are mutable | Kernel materialization is **out-of-band** from app DB; combine with **append-only app ledgers** |

**Blockchain-like** here means **product semantics**, not a chain on GPU:

- **Append-only evidence** where decisions are recorded (TraceTramp `trace_events` today; future **kernel attestation log** for reconcile cycles).
- **Explicit commands** for state change (approve, release quarantine, deactivate `operation_blocks`, bump `policy_revision`).
- **Separation of duties**: app ledger (TT DB) vs host effect (kerneld) vs witness store (WitnessCtl) — an auditor wants **two** independent surfaces where possible.

See: [`connector-kerneld/README.md`](../../connector-kerneld/README.md), [`CONNECTOR_KERNEL_CAPS.md`](./CONNECTOR_KERNEL_CAPS.md), [`CONNECTOR_KERNEL_RUNBOOK.md`](./CONNECTOR_KERNEL_RUNBOOK.md).

---

## 2. Specific use cases — TraceTramp vs WitnessCtl (do not merge mentally)

They are **complementary**, not duplicates.

| Dimension | **TraceTramp** (plugin) | **WitnessCtl** (plugin) |
|-----------|-------------------------|-------------------------|
| **Primary job** | **Synchronous ingress control** for LLM-shaped traffic: meter, policy, risk, tools, PII, HITL **before** the upstream model runs. | **Async witness & capture**: proxy path, **wire truth**, receipts, custody/compliance depth, handoffs from TraceTramp, HITL/capture queues aligned with governance. |
| **Best question it answers** | “**Should this request proceed**, on this tenant, with these tools/models, right now?” | “**What actually crossed the wire**, can we **receipt** it, and can we **replay** it for audit / regulator / customer DD?” |
| **Proof shape** | `trace_events` + `/decision/:trace_id` + `approval_queue` / `hold_metadata` on the **TraceTramp DB** (ingress ledger segment). | Captures, proxy metadata, **witness** tables, enforcement packets, optional TSA / custody flows (see WitnessCtl migrations & docs). |
| **Latency sensitivity** | **Hot path** — adds ms–low hundreds ms budget awareness. | **Off path** — async handoff, batch export, human queues. |
| **Bypass if missing** | Policy-only on host — **app-layer** bypass still possible via raw keys. | TT-only — **no** proof of bytes on wire; weaker **non-repudiation** for “what left the building.” |

**Rule of thumb:** TraceTramp = **control plane at the door**. WitnessCtl = **court stenographer + vault** for what happened and what you retain.

---

## 3. Connector OS + plugin constellation (DevGuard, TT, Wctl, custom)

| Component | Role in the cage | Must not pretend to be |
|-----------|------------------|-------------------------|
| **Connector OS (platform)** | Admission, kernel **attach** API, policy bundles, presets, routing to plugins | A single plugin’s database |
| **TraceTramp** | Ingress gate + **request-scoped** append-only ledger | Full wire capture (that’s WitnessCtl) |
| **WitnessCtl** | Wire / custody / extended compliance | Synchronous chat gate (that’s TraceTramp) |
| **DevGuard** | **Client-side** discipline (IDE, local policy hints, operator UX) — increases odds traffic **hits** TT | Host egress enforcement or sole source of truth |
| **Future custom plugins** | Extend **observability**, **tool registries**, **vertical policy** — must **register** with the cage node and respect **kernel profiles** for any workload they spawn | A shadow path that skips Connector admission or kernel attach |

**Custom plugin contract (design target):**

1. **Admission**: all elevated paths go through Connector **same as first-party plugins**.  
2. **Egress**: if a plugin runs workers on-host, those workers must be **kernel-attached** with a profile that lists only the hostnames that plugin + TT + Connector need.  
3. **Events**: structured events toward **one** operator model (trace_id, tenant, actor) — merge into TT trace stream **or** WitnessCtl ingest, not a third silo without linkage.  
4. **Ledger**: mutations = **commands** (HTTP + auth), same as TT approvals / Wctl queues.

---

## 4. Blockchain-like behavior — split across layers (intentional)

| Layer | Mechanism today / next | “Chain” meaning |
|-------|-------------------------|-----------------|
| **Kernel** | `policy_revision` + materialized systemd/BPF allowlists ([`connector-kerneld`](../../connector-kerneld)); future: append-only **reconcile log** on host | Changing allow egress requires a **new revision**, not silent drift |
| **TraceTramp** | `trace_events` ledger guard + `ledger_contract` on decision envelopes | Per-trace **ordered** decisions; no delete; metadata-only growth |
| **WitnessCtl** | Immutable capture rows + signed export / handoff patterns (per WitnessCtl design) | **Wire-level** evidence chain correlated to `trace_id` |
| **Connector** | Strict presets, `CONNECTOR_CONFIG_STRICT`, production preset enforcement | **Config** is committed policy, not accidental env |

Nothing here replaces **legal** non-repudiation unless you add HSMs / TSA / W3C signatures — the goal is **defensible engineering** and **clear accountability**.

---

## 5. Work plan (kernel → TT → Wctl)

| Phase | Focus | Outcome |
|-------|--------|---------|
| **K1** | Document + enforce **kernel profile ↔ plugin surface** mapping in runbooks | Operators know which hostnames each plugin class needs |
| **K2** | Harden `connector-kerneld watch` + platform `kernel_host` snapshot contract | Egress cage **tracks** `policy_revision` |
| **K3** | Connector API: **`GET /api/v1/kernel/cage-manifest`** — JSON listing `ledger_contracts`, first-party plugins, full `kernel_host_snapshot`, preset/env, doc hints | Single artifact for security review ([`kernel_host.rs`](../../../platform/server/src/services/kernel_host.rs) `cage_manifest_json`) |
| **T1** | TraceTramp: HITL `hold_metadata.evidence.kernel_host_at_hold` carries Connector kernel snapshot at enqueue time; ingress `ledger_contract` unchanged | One story: “door decision + host posture” |
| **W1** | WitnessCtl: handoff payload auto-tags `witness_ledger_contract` + `ingress_ledger_contract`; correlate captures ↔ TT `trace_id` (existing `/integrations/tracetramp/...` paths) | Auditor sees two independent proofs |

**Cage manifest regression check (K3):** from the repo root, run the Connector platform unit test that asserts `cage_manifest_schema` and ledger contract fields:

```bash
cd platform/server && cargo test kernel_host::tests::cage_manifest
```

GitHub Actions runs the same filter when pull requests or pushes touch `platform/server` or the listed OSS path dependencies (workflow `.github/workflows/connector-platform-kernel.yml`).

DevGuard runs in **parallel** as developer experience — it should **default** to pointing at the same TraceTramp base URL and surface pending approvals, not alternate provider URLs.

---

## 6. Related documents

| Document | Role |
|----------|------|
| [`AIOS_ADVANCED_CAGE_OUTCOME.md`](./AIOS_ADVANCED_CAGE_OUTCOME.md) | End-state outcome for AI OS + orchestration in the cage |
| [`../CONNECTOR_CAGE_NODE_AND_PLUGINS.md`](../CONNECTOR_CAGE_NODE_AND_PLUGINS.md) | Cage topology, presets, twelve modes |
| [`CONNECTOR_KERNEL_CONTROLS.md`](./CONNECTOR_KERNEL_CONTROLS.md) | Quarantine vs op-block vs kernel |
| [`plugins/tracetramp/checklist.md`](../../../plugins/tracetramp/checklist.md) | TT HITL + ingress ledger checklist |
| [`advanced-lab/docs/LAB_FINAL_PLAN.md`](../../../advanced-lab/docs/LAB_FINAL_PLAN.md) | Runnable lab for proof bundles |

---

## 7. One-line summary

**Anchor cage infra and ledger discipline at the Connector Kernel + OS boundary first; use TraceTramp for synchronous ingress proof and WitnessCtl for wire-level witness proof; treat DevGuard and custom plugins as satellites that must not create unrouted egress or unrouted model calls.**
