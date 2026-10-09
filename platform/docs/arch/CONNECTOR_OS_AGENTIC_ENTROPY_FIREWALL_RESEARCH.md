# Connector Kernel Standard: **nftables + eBPF** for OS-Level Agent Stability

**Version 5.1** — **Connector first, plugins second.** TraceTramp, WitnessCtl, DevGuard-style apps, and other `plugins/*` are **consumers** of Connector HTTP/API and policy; they are not the place to prove the host kernel story until **`oss/connector` + `platform/server`** expose a solid kernel profile, admission hooks, audit, and `connector-kerneld` contract. This doc’s **active engineering track** is Connector core only; plugin rows below are **deferred** (consume APIs once stable).

**Version 4.0** reframed the work as default Connector kernel behavior at the Linux boundary. v5.0 sequences delivery: solid Connector → then revisit plugins.

This is not replacing the existing Connector/VAC kernel. It is making the existing kernel decisions hard to bypass at the process/socket layer.

---

## 0. Delivery phases (non-negotiable order)

| Phase | Scope | Done when |
|-------|--------|-----------|
| **A — Connector core** | `oss/vac`, `oss/connector`, `platform/server`: `MemoryKernel`, `DualDispatcher`, `admission`, sandbox intent → host profile API, `connector-kerneld`, runtime status in platform, tests | Egress-capable paths fail closed without active host profile; attach/status/release proven under restart |
| **B — Plugins** | `plugins/tracetramp`, `plugins/witnessctl`, etc.: propagate `kernel_policy_revision`, enrich captures/traces, lab demos | Plugins only read Connector APIs; no duplicate host loaders in plugins |

Do not block Phase A on TraceTramp/WitnessCtl UI or schema work.

---

## 1. Kernel Standard Outcomes

1. **Connector action control becomes host-backed** — `DualDispatcher`, `AgentFirewall`, AAPI/admission, and platform quarantine semantics keep authority; host kernel policy blocks direct raw egress when a worker bypasses the proxy.
2. **Agent lifecycle becomes OS lifecycle** — agent/session/cgroup registration must bind to a Linux cgroup, service scope, or container cgroup before risky tools run.
3. **AAPI gains a kernel projection** — every allow/deny intent that affects egress emits a policy revision that can be applied to nftables sets and eBPF maps.
4. **Connector orchestration becomes OS-real** — Conductor-style claims move from logical orchestration to real process, cgroup, socket, and namespace orchestration.
5. **Low-level stability is default** — kernel rules survive restarts and ephemeral workers through a controller, not hand-loaded nft rules.
6. **(*Phase B*)** TraceTramp/WitnessCtl read the same `kernel_policy_revision` / status from Connector — optional evidence enrichment after Phase A ships.

---

## 2. Codebase Reality: What Already Exists

The repo already has multiple layers of control **inside Connector**. The missing piece is the **Linux host executor** that translates Connector kernel intent into nftables/eBPF.

### 2.1 Connector core (Phase A — build here first)

| Layer | Existing code | What it does today | Kernel-standard consequence |
|------|---------------|--------------------|-----------------------------|
| **VAC kernel syscall runtime** | `oss/vac/crates/vac-core/src/kernel.rs` | `MemoryKernel::dispatch()` validates requests, executes operations, audits, and has `SyscallRequest`, `AgentRegister`, `AgentBoot`, `RegisterCgroup`, MCP, memory, session, and tool-related ops. | Host controller should subscribe to agent/cgroup lifecycle and bind logical agent IDs to real cgroup paths. |
| **VAC cgroup model** | `oss/vac/crates/vac-core/src/cgroup_controllers.rs` | Software cgroup v2-style hierarchy for packets, bytes, tokens, ops/sec, and agent counts. | Treat this as the policy/accounting model; do not confuse it with Linux cgroup attachment. |
| **VAC eBPF-style hooks** | `oss/vac/crates/vac-core/src/extensions.rs` | Bounded `PreSyscall`, `PostSyscall`, `OnAgentRegister`, `OnAgentTerminate`, etc. hooks. This is a strong **analogy**, not Linux eBPF. | These hooks are the right semantic source for projecting policy to host eBPF, but they do not load BPF programs. |
| **Connector dispatcher** | `oss/connector/crates/connector-engine/src/dispatcher.rs` | `DualDispatcher` owns `AgentFirewall`, guard pipeline, policy engine, action engine, watchdog, quotas, orchestrator, context manager, and `gate_and_execute_tool()`. | Tool execution should not start until its worker is in the correct cgroup/netns and the host profile is active. |
| **Agent firewall** | `oss/connector/crates/connector-engine/src/firewall.rs` | Userland threat scoring and verdicts for PII, injection, anomaly, policy, rate pressure, and boundary crossing. | Keep this as semantic scoring; host eBPF should block socket operations, not parse prompts. |
| **Sandbox intent** | `oss/connector/crates/connector-caps/src/sandbox.rs` | `SandboxConfig` has `allowed_domains`, `network_disabled`, CPU/memory/pids/io hints, nsjail/native backends. | This is the natural input contract for kernel projection: domains/CIDRs/ports become maps and nft sets. |
| **Platform admission** | `platform/server/src/services/admission.rs` | `admission::check()` is intended as the central pre-exec gate for LLM, memory, tools, pipelines, and MCP. | Admission should issue or require a `kernel_policy_revision` for egress-capable actions. |
| **Runtime enforcement API** | `platform/server/src/services/runtime_enforcement.rs` | Currently states the EVM model is logical and says OS isolation is deployment-level/optional. | Revise after kernel controller lands: report real host attachment state, cgroup, BPF link, nft set, and last apply status. |
| **DevGuard network fence spec** | `platform/docs/arch/devguard-plan.md` | Describes netns + nftables/iptables and sandbox/network APIs as architecture. | Implement as **Connector** primitives; apps (including DevGuard) call them, they do not own the loader. |

### 2.2 Plugins (Phase B — after Connector is solid)

| Layer | Path | Note |
|------|------|------|
| TraceTramp | `plugins/tracetramp/src/control.rs` | L7 gateway; may call Connector for policy — **do not** embed host nft/eBPF here. |
| WitnessCtl | `plugins/witnessctl/src/capture.rs`, `…/connector.rs` | Audit proxy; consumes Connector APIs — enrich with `kernel_policy_revision` **after** platform exposes it. |
| Firewall HTTP | `platform/server` + WitnessCtl client | Platform canonical route `POST /api/v1/firewall/inspect`; legacy alias `POST /api/v1/guard/firewall` kept on platform for old callers. |

**Bottom line:** the Connector “kernel” is **`oss/vac` + `oss/connector` + `platform/server`**. Plugins sit on top. The new work for Phase A is **`connector-kerneld` + platform kernel APIs + admission/runtime truth** — not TraceTramp schema churn.

---

## 3. Web Research: Linux Kernel Enforcement Lessons

| Topic | Finding | Design impact |
|------|---------|---------------|
| **nftables + cgroup v2** | `socket cgroupv2` rules resolve cgroup paths to **numeric cgroup IDs** when rules are loaded. If a service cgroup does not exist yet, rules fail. If the cgroup is recreated on restart, old rules no longer match. | Static nft rules are not enough. Connector needs a controller that watches unit/container lifecycle and refreshes nft sets/rules. |
| **systemd `NFTSet=`** | systemd 255 introduced `NFTSet=` to insert cgroup IDs into prepared nft sets when units are realized; rules/sets still must exist separately and user managers have limits. | Prefer nft **sets** over per-agent rule churn. If relying on systemd, support `NFTSet=` where available and provide fallback controller mode. |
| **eBPF cgroup socket hooks** | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` with `cgroup/connect4` and `connect6` runs on socket connect; returning `0` denies with `EPERM`, returning `1` allows. Programs attach to cgroups via BPF link or `bpf_program__attach_cgroup`. | This is the right primitive for per-agent egress allow/deny before traffic leaves the worker. Use BPF maps for policy revision, allowlist CIDRs/ports, and audit counters. |
| **Tetragon / Cilium model** | Modern runtime enforcement pushes filtering/actions into eBPF to avoid user-space race windows; policies can scope by workload identity and enforce network/file/process behavior. | Connector should not invent a toy story. The standard should follow the industry shape: in-kernel filtering for enforcement, userland for policy compilation and evidence. |
| **Socket cgroup caveat** | Sockets belong to the cgroup where they were created. Moving a task after socket creation may not move existing sockets into the desired policy boundary. | Worker launch order matters: create/enter cgroup/netns and attach policy **before** any network-capable code starts. |

References used for implementation framing:

- eBPF docs: `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`, `BPF_CGROUP_INET4_CONNECT`, `BPF_CGROUP_INET6_CONNECT` — https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/
- Linux kernel docs: cgroup socket option program behavior — https://docs.kernel.org/bpf/prog_cgroup_sockopt.html
- nftables cgroup v2 lifecycle discussion — https://blog.fraggod.net/2021/08/31/easy-control-over-applications-network-access-using-nftables-and-systemd-cgroup-v2-tree.html
- systemd resource control `NFTSet=` — https://man7.org/linux/man-pages/man5/systemd.resource-control.5.html
- Tetragon enforcement model — https://tetragon.io/docs/getting-started/enforcement/

---

## 4. Connector Kernel Standard Behavior

### 4.1 Default Host Policy

Every egress-capable Connector worker should run under a managed execution boundary:

- **Linux cgroup v2** for identity and attachment.
- **Optional netns** when the worker needs hard route separation.
- **nftables** for host-visible default-deny egress, nft sets, coarse L3/L4 policy, and ops-readable rules.
- **eBPF cgroup socket hooks** for per-agent `connect4` / `connect6` allow/deny and atomic map updates.
- **Connector policy revision** as the join key across AAPI, engine audit, nft sets, and BPF maps (plugins join **after** Phase A).

Default posture:

1. New agent or worker starts in **deny egress**.
2. Connector admission computes allowed destinations and host profile.
3. Kernel controller applies BPF map + nft set updates.
4. Worker starts only after the controller reports `active`.
5. **Connector** records `kernel_policy_revision` in audit / runtime status (plugins may copy later).

### 4.2 Action Control Impact

`DualDispatcher::gate_and_execute_tool()` currently gates through ACL/firewall/behavior and then executes. With kernel standard behavior:

1. Gate semantic action intent as today.
2. Resolve the action’s `SandboxConfig` / egress contract.
3. Ask the kernel controller for an active profile:
   - `agent_pid`
   - `tenant_id`
   - `operation`
   - `allowed_domains` / resolved CIDRs / ports
   - `network_disabled`
   - `policy_revision`
4. Execute only inside a worker cgroup/netns with that revision active.
5. Include kernel status in action audit.

### 4.3 AAPI / Admission Impact

`admission::check()` is the correct semantic front door. It should not load nft rules directly. It should require or emit:

- `kernel_required: bool`
- `kernel_profile_id`
- `kernel_policy_revision`
- `egress_mode: disabled | proxy_only | allowlist | unrestricted`
- `host_apply_state: pending | active | failed`

If a tool/LLM path is egress-capable and kernel enforcement is required, admission must fail closed when `host_apply_state != active`.

### 4.4 Agentic Lifecycle Impact

VAC already has `AgentRegister`, `AgentBoot`, `OnAgentRegister`, `OnAgentTerminate`, and `RegisterCgroup`. The host controller should bind them to Linux:

1. `AgentRegister` creates the logical identity.
2. `AgentBoot` requests sandbox/capability requirements.
3. Kernel controller creates or finds a systemd scope/container cgroup.
4. eBPF is attached and nft set membership is active.
5. Agent transitions to runnable.
6. `OnAgentTerminate` tears down BPF links, map entries, nft set members, and evidence state.

This turns “agent lifecycle” into a real OS lifecycle rather than only an in-memory registry.

---

## 5. Required New Component: Connector Kernel Controller

Working name: **`connector-kerneld`**.

Responsibilities:

- Watch Connector lifecycle events: agent register, agent boot, tool worker spawn, terminate.
- Watch system lifecycle events: systemd unit/scope changes, container cgroup creation/removal, nft reload.
- Compile Connector policy into:
  - pinned BPF maps under `/sys/fs/bpf/connector/...`
  - BPF links attached to cgroups
  - nftables tables/sets/chains
- Fail closed for required profiles.
- Emit evidence:
  - `policy_revision`
  - `cgroup_path`
  - `cgroup_id` where available
  - BPF program/link IDs
  - nft table/set names
  - last apply result
  - denied connect counters

Non-responsibilities:

- Do not parse prompts in eBPF.
- Do not duplicate `AgentFirewall` scoring in nft rules.
- Do not duplicate plugin-specific evidence stores; emit enough in **Connector audit/API** that plugins can ingest later.
- Do not make DevGuard-specific policy part of the Connector kernel; DevGuard submits intent like any app.

---

## 6. API Contract Sketch

The exact route names can change, but the shape should be Connector-generic:

```text
POST /api/v1/kernel/profiles
  -> create/update host kernel profile from Connector policy intent

POST /api/v1/kernel/agents/:pid/attach
  -> bind agent/session/worker to cgroup/netns and activate policy revision

GET /api/v1/kernel/agents/:pid/status
  -> report active revision, nft/eBPF status, counters, last error

POST /api/v1/kernel/agents/:pid/release
  -> remove BPF links/map entries/nft set membership
```

Plugins (TraceTramp, WitnessCtl, …) should **consume** Connector kernel status APIs only after Phase A; they must not own host enforcement or duplicate `connector-kerneld`.

---

## 7. Military-Grade / CISO-Worthy Evidence Bar

### 7.1 Phase A — Connector-only (required first)

1. **Fail-closed proof** — If `connector-kerneld` is down, required egress-capable actions do not start.
2. **Bypass proof** — Direct `curl` from an agent worker to a blocked provider/IP fails with kernel-level denial while approved proxy egress still works.
3. **Restart proof** — Restart agent scope/container; policy is still active after recreation.
4. **Socket-order proof** — Worker starts inside the cgroup before any outbound socket can be created.
5. **API truth** — `GET …/kernel/agents/:pid/status` (or equivalent) returns cgroup path/id, BPF/nft linkage, `policy_revision`, denied-connect counters, last error.

### 7.2 Phase B — Plugins (after Connector is solid)

6. **End-to-end evidence** — WitnessCtl exports (and TraceTramp traces, if desired) **correlate** with Connector’s `policy_revision` and status — no second source of truth for host state.

---

## 8. Implementation Slices

| Slice | Deliverable | Acceptance |
|------|-------------|------------|
| **K1: reference host profile** | nftables table/sets + one `cgroup/connect4`/`connect6` BPF program with allowlist map. | Lab worker can reach approved proxy and cannot reach blocked raw provider IP. |
| **K2: lifecycle controller** | `connector-kerneld` watches a test systemd scope or container cgroup and reapplies policy on restart. | Restart test worker; direct blocked egress remains blocked. |
| **K3: Connector API integration** | **Platform + OSS** expose kernel profile attach/status/release; admission can require active host profile; runtime API reports host truth. | Egress-capable tool fails closed when profile is missing. |
| **K4: Conductor orchestration** | Agent lifecycle in Connector creates managed execution cells with policy before runnable state. | Multi-agent workflow shows per-agent host boundaries and controlled egress. |
| **K5: (*deferred*) Plugin correlation** | TraceTramp / WitnessCtl read Connector status only; optional DB columns. | Demo export shows same `policy_revision` as `GET …/kernel/.../status`. |

---

## 9. In-Repo Anchors

**Phase A (Connector core)**

| Topic | Path |
|-------|------|
| VAC kernel dispatch / lifecycle | `oss/vac/crates/vac-core/src/kernel.rs` |
| VAC cgroup model | `oss/vac/crates/vac-core/src/cgroup_controllers.rs` |
| VAC eBPF-style hook model | `oss/vac/crates/vac-core/src/extensions.rs` |
| Connector dispatcher / action execution | `oss/connector/crates/connector-engine/src/dispatcher.rs` |
| Connector logical firewall | `oss/connector/crates/connector-engine/src/firewall.rs` |
| Sandbox policy input | `oss/connector/crates/connector-caps/src/sandbox.rs` |
| Platform admission | `platform/server/src/services/admission.rs` |
| Runtime enforcement response | `platform/server/src/services/runtime_enforcement.rs` |
| Platform router (firewall + alias) | `platform/server/src/router.rs` |
| Net fence spec to implement on Connector | `platform/docs/arch/devguard-plan.md` |

**Phase B (plugins — revisit after A)**

| Topic | Path |
|-------|------|
| TraceTramp enforcement | `plugins/tracetramp/src/control.rs` |
| WitnessCtl capture / Connector client | `plugins/witnessctl/src/capture.rs`, `plugins/witnessctl/src/connector.rs` |

---

## Document Control

| Version | Change |
|---------|--------|
| 2.0 | Outcome bullets + compressed external stack. |
| 3.0 | Codebase inventory; nft + eBPF as required stability layer; explicit implementation gap. |
| **4.0** | Promoted nftables + eBPF to **default Connector kernel standard behavior**; tied to action control, AAPI, agent lifecycle, TraceTramp, WitnessCtl, and Conductor OS orchestration; added current Linux kernel research and acceptance bar. |
| **5.0** | **Connector-first sequencing**: Phase A = core only; plugins deferred to Phase B; slices and evidence bar split accordingly. |
| **5.1** | **§10 checklist implementation (Phase A stub):** `kernel_host` APIs, admission step 1.5, metrics, runtime `host_kernel`, connector-caps `egress_policy`, docs (`CONNECTOR_KERNEL_*`), tests, e2e smoke script. |
| **5.2** | **Phase B evidence:** TraceTramp `trace_events.metadata` + WitnessCtl `witness_captures.kernel_host` + receipt payload; lab scripts `connector-kernel-restart-check.sh`, `connector-kernel-bypass-lab.sh`; `kernel_host.rs` `release_agent` restored. |
| **5.3** | **Default host reconciler:** `platform/connector-kerneld` (Rust) — systemd **`IPAddressAllow=`** drop-ins from `GET /api/v1/kernel/status`; `systemd/connector-kerneld.service` template; runbook **Default prod stack** section. |

*Next: wire **`denied_connect_total`** to real kernel counters; optional **bpfman** on K8s nodes for cgroup BPF lifecycle; platform persistence for in-memory `kernel_host` across restarts if desired.*

---

## 10. Production coding checklist (ship-grade)

Use **§10 Phase A** before merging host kernel or platform admission/runtime work. Use **§10 Phase B** only after Connector kernel APIs and `connector-kerneld` are stable.

**Companion docs (Connector-first):** `CONNECTOR_KERNEL_CONTROLS.md`, `CONNECTOR_KERNEL_CAPS.md`, `CONNECTOR_KERNEL_RUNBOOK.md` (same directory as this file).

### Phase A — Connector core only

### 10.1 Correctness and scope

- [x] **Separate controls** — `admission.rs` documents step 1 vs 1.5 vs 2; **`CONNECTOR_KERNEL_CONTROLS.md`** maps quarantine vs scoped deny vs host attachment.
- [x] **Fail-closed defaults** — `CONNECTOR_KERNEL_ENFORCE=1` + default `CONNECTOR_KERNEL_FAIL_CLOSED` denies egress-capable ops without **Active** attachment; `CONNECTOR_KERNEL_FAIL_CLOSED=0` audits **degraded allow**.
- [x] **Idempotency** — `kernel_host::KernelHostState::attach_agent` / `release_agent` / `upsert_profile` (stub simulates stable attachment; real BPF link dedup lands in `connector-kerneld`).
- [x] **API contract** — `POST /api/v1/kernel/*` JSON handlers; `InspectRequest` ignores extra JSON keys (unit test); `AdmissionTicket` carries optional `kernel_policy_revision` / `kernel_host_apply_state`.

### 10.2 Security and trust

- [x] **Capabilities** — **`CONNECTOR_KERNEL_CAPS.md`** (`CAP_NET_ADMIN`, `CAP_BPF`; avoid `CAP_SYS_ADMIN`).
- [x] **Pinned maps / links** — contract path `/sys/fs/bpf/connector/…` in `kernel_host` snapshot + caps doc (permissions enforced when daemon exists).
- [x] **Policy provenance** — profile upsert stores `policy_revision`, `intent_hash` (SHA-256 of canonical JSON), `source`, timestamps.
- [ ] **No silent bypass (full bar)** — **lab** proof: raw `curl` from worker cgroup to a **non-allowlisted** IP must fail when **nft/eBPF + default-deny** path is active; platform stub still does not count real drops. **Script:** `platform/scripts/connector-kernel-bypass-lab.sh`.
- [x] **No silent bypass (systemd default)** — worker unit uses **`IPAddressAllow=`** materialized by **`connector-kerneld`** from Connector profile hostnames (`platform/connector-kerneld/`); egress outside the allowlist is blocked by systemd for that cgroup (resolver/DNS trust is in scope).

### 10.3 Lifecycle and races

- [x] **Cgroup before sockets** — **`CONNECTOR_KERNEL_RUNBOOK.md`** startup order.
- [ ] **Restart tests (full)** — **CI/lab** with persisted policy when `connector-kerneld` + state store exist (scope restart + policy still **Active** / nft refill). **Script:** `platform/scripts/connector-kernel-restart-check.sh` (attach + optional `CONNECTOR_KERNEL_RESTART_CMD`; strict mode via `CONNECTOR_KERNEL_RESTART_EXPECT_PERSISTENT=1`).
- [x] **nft cgroup ID churn** — runbook: sets + `NFTSet=` / controller refill (no static-only rules).
- [x] **Teardown (stub)** — `POST /api/v1/kernel/agents/:pid/release` removes attachment row; **real** map/link teardown in daemon.

### 10.4 Observability and evidence (Connector)

- [x] **Platform runtime** — `GET /api/v1/runtime/enforcement` includes **`host_kernel`** snapshot (`kernel_host::snapshot_json`).
- [x] **Admission ticket** — `kernel_policy_revision`, `kernel_host_apply_state` on pass.
- [x] **Metrics** — `connector_kernel_host_admission_denied_total`, `connector_kernel_profile_upserts_total`, attach success/fail, release, `last_apply_latency_us` in snapshot counters.

### Phase B — Plugins (after A)

- [x] **TraceTramp** — `GET /api/v1/kernel/agents/:pid/status` per chat request (unless `TRACETRAMP_KERNEL_SNAPSHOT=0`); `trace_events.metadata` includes `kernel_policy_revision`, `host_enforcement_status`, `kernel_host` (`plugins/tracetramp/src/gateway.rs`, `control.rs`).
- [x] **WitnessCtl** — `witness_captures.kernel_host` JSONB (`20260502000015_kernel_host_capture.sql`); ingest binds Connector snapshot; receipt payload includes `kernel_host` (`plugins/witnessctl/src/capture.rs`).

### 10.5 Ops and rollback

- [x] **Feature flag** — `CONNECTOR_KERNEL_ENFORCE`, `CONNECTOR_KERNEL_FAIL_CLOSED`, `CONNECTOR_KERNEL_SIMULATE_ATTACH_FAIL` (env, no rebuild).
- [x] **Runbook** — **`CONNECTOR_KERNEL_RUNBOOK.md`** (nft reload, rollback, `NFTSet` refill).
- [x] **SLO** — runbook + metrics names for alert wiring (`kernel_host` counters / `last_apply_latency_us`).

### 10.6 Tests (minimum)

- [x] **Unit** — `connector-caps` **`compile_sandbox_egress`** + revision/dedup tests; platform **`kernel_host`** idempotency tests; **`firewall_config`** JSON contract test.
- [x] **Integration (local)** — `cargo test -p connector-platform kernel_host::tests::` and `… inspect_request_deserializes` (no live HTTP server required).
- [x] **E2E lab (conditional)** — `platform/scripts/connector-kernel-e2e-smoke.sh` (preflight always; HTTP checks if `CONNECTOR_TEST_URL` + `CONNECTOR_TEST_API_KEY` set). **Host reconciler:** `cargo build --manifest-path platform/connector-kerneld/Cargo.toml` + `connector-kerneld print-snapshot|render-dropin|watch` against the same URL/key.

### 10.7 Client alignment (minor cross-layer fix; plugins still secondary)

- [x] WitnessCtl `firewall_inspect` calls **`POST /api/v1/firewall/inspect`**; `FirewallResponse` tolerates minimal JSON from inspect.
- [x] Platform registers **`POST /api/v1/guard/firewall`** as an alias to the same handler for legacy callers.

Further plugin work waits on Phase A kernel status API stability.

**Preflight script:** run `platform/scripts/connector-kernel-prod-preflight.sh` on hosts before enabling enforcement (cgroup v2, nft, optional bpftool).
