# Connector Agent Isolation — Implementation Plan

**Status:** Architecture / implementation source of truth  
**Companion:** Agent Isolation Architecture (user SoT §§1–39) · [CONNECTOR_REACH_CHECKLIST](CONNECTOR_REACH_CHECKLIST.md) · [MICROVM_CHANNELS](MICROVM_CHANNELS.md) · [CONNECTOR_OPERATIONAL_SOFTWARE](CONNECTOR_OPERATIONAL_SOFTWARE.md)  
**Goal:** Make AgentCell + MicroCell + CVR + OS-grade lifecycle **real** inside Connector, with **Firecracker as default MicroVmBackend**, without inventing a second agent model.

---

## 0. Standing (what is already real)

| Target noun | Exists today as | Gap |
|-------------|-----------------|-----|
| Layer 3 semantic isolation | PATE, ActionBinding, WorldGrant, NF³, budgets, DNA, memory ns, harden triad | Needs **ExecutionBody** binding in evidence |
| Layer 2 Linux isolation | DockLock cage, Landlock, cgroups, nsfs, matrix mark, seccomp (plugin path) | No named **AgentCell** lifecycle object |
| Layer 1 microVM | `platform/microvm` Firecracker host, `MicrovmPluginBackend`, vendor FC/kernel/rootfs, `connector-vm-agent`, microvm_tool_plane | No **MicroCell**, jailer orchestration, clean-snapshot pool, **connector-microd** |
| Posture R/A/E | `harden_posture`, `membrane_posture` | Not yet on **lifecycle** transitions |
| Lifecycle HTTP | pause / quarantine / stop / kill via `agent_lifecycle_gate` | Does not always reach VMM pause/stop; no LC receipt triad |
| Profiles | presets + T2/T3/T4 | Map to **V0–V4** engineer intent |

**Rule:** Extend these surfaces. Do not greenfield a parallel isolation stack.

---

## 1. Product contract (non-negotiable)

1. **Agent ≠ body** — `agent_pid` persists across AgentCell ↔ MicroCell promotion.  
2. **Engineer selects posture** (`auto` | `linux-cell` | `hardened-linux-cell` | `shared-microvm` | `dedicated-microvm`) — never Firecracker knobs.  
3. **Firecracker = default backend** behind `MicroVmBackend`; MicroCell is the primitive.  
4. **Requested / Applied / Effective** on isolation **and** lifecycle; harden → **START_REFUSED** / **QUARANTINE_FAILED** when required ops fail.  
5. **No silent fallback** on required MicroCell.  
6. **Effect exclusivity** — shell/curl/child/CONP cannot bypass the same consequence gate.  
7. **Evidence** binds body ids, runtime bundle digests, isolation + lifecycle receipts to worldline.

---

## 2. Target modules (map onto tree)

```text
connectord (platform/server)
├── ExecutionBodyManager          NEW thin façade
│   ├── AgentCell                 NEW type wrapping DockLock+cgroup+ns+Landlock
│   └── MicroCell                 NEW type wrapping MicroVmBackend slot
├── CVR (virtualization runtime)  NEW package folder under substrate/cvr/
│   ├── HostProbe
│   ├── RuntimeBundle
│   ├── MicroVmBackend trait
│   ├── FirecrackerBackend        wraps platform/microvm + jailer
│   ├── SnapshotManager
│   ├── NetworkAttach (World Gateway)
│   └── Evidence
├── connector-microd              NEW binary (Phase 3) — privileged VMM ops
└── Authority spine               EXISTING (unchanged ownership)
```

| New type | Wraps / calls |
|----------|----------------|
| `AgentCell` | `docklock` + `agent_cgroup` + `linux_hardening` + network mark + lifecycle gate |
| `MicroCell` | `MicrovmHost` / `MicrovmPluginBackend` + jailer + vsock + GuestD |
| `HostProbe` | extract from `microvm_tool_plane::host_available`, Landlock ABI, matrix tools, `/dev/kvm` |
| `RuntimeBundle` | vendor paths + digests from `isolation_manifest` measured assets |
| `MicroVmBackend` | thin trait; `FirecrackerBackend` implements via `connector_microvm` |
| V0–V4 | compile from `agent.isolation` + risk → existing T2/T3/T4 + presets |

---

## 3. Phased delivery (Connector-standard)

### Phase A — Vocabulary + posture (1–2 weeks)

**Outcome:** Engineers and APIs speak AgentCell / MicroCell / V0–V4; honesty is complete even before full FC apply.

| Work item | Deliverable | Acceptance |
|-----------|-------------|------------|
| A1 | Doc this plan as SoT; link from ARCHITECTURE.md | Linked |
| A2 | `IsolationProfile` enum V0–V4 + `resolve_isolation(agent)` | Unit tests for auto map |
| A3 | `ExecutionBodyKind { AgentCell, MicroCell { shared\|dedicated } }` on agent meta + `/substrate/status` | Visible R/A/E |
| A4 | Extend `membrane_posture` with `agentcell` / `microcell` blocks | Never claim Applied FC without probe |
| A5 | Map V4 required → START_REFUSED when `HostProbe` incomplete | Harden refuse demo |

**Reuse:** `harden_posture`, `membrane_posture`, `isolation_tiers`, `connector_profile`.

---

### Phase B — AgentCell as first-class body (2–4 weeks)

**Outcome:** High-density Linux isolation is a managed lifecycle object, not only env flags.

| Work item | Deliverable | Acceptance (§31 AgentCell) |
|-----------|-------------|------------------------------|
| B1 | `AgentCell` create/bind/run/freeze/stop/reap | Cell id in evidence |
| B2 | Bind: PID/mount/IPC ns + cgroup v2 + Landlock + seccomp + caps | Cross-agent PID/FS deny tests |
| B3 | Network mark + World Gateway only path | Forbidden destination deny |
| B4 | Resource envelope classes `small` / `compute` → cgroup | Limits enforced |
| B5 | Lifecycle pause/quarantine/stop → cgroup freeze + effect deny + mark cut | LC R/A/E |
| B6 | LifecycleReceipt folder + proof_export | Digest present |

**Reuse:** `docklock`, `agent_cgroup`, `linux_hardening`, `matrix_host_egress`, `agent_lifecycle_gate`, `operator_stop`.

**Do not** wait for Firecracker to ship AgentCell — this is the density path.

---

### Phase C — CVR + FirecrackerBackend (true default) (4–6 weeks)

**Outcome:** Real Firecracker MicroCells behind Connector APIs; engineer never touches FC.

| Work item | Deliverable | Acceptance |
|-----------|-------------|------------|
| C1 | `MicroVmBackend` trait (`probe/prepare/create/start/pause/resume/snapshot/restore/stop/destroy/measure`) | Trait + mock backend tests |
| C2 | `FirecrackerBackend` wrapping `platform/microvm::MicrovmHost` | Start/stop real VM on KVM host |
| C3 | **Jailer** required under harden V3/V4 | Jailer fail → START_REFUSED |
| C4 | `RuntimeBundle` pin: FC + jailer + kernel + rootfs digests | Tamper → refuse |
| C5 | Clean snapshot + fresh overlay; **no authority in base snapshot** | Clone rebinds agent_pid/grants/nonces |
| C6 | vsock ↔ `connector-vm-agent` / GuestD control | Identity handshake |
| C7 | MicroCell network → World Gateway only | Direct world deny under harden |
| C8 | Tool plane: `microvm_tool_plane` uses MicroCell ids | Evidence fields filled |
| C9 | Status: `microcell.backend.requested/available/applied/effective` | Posture honesty |

**Assets:** `vendor/firecracker/`, `vendor/microvm/`, env `CONNECTOR_MICROVM_KERNEL` / `ROOTFS` → migrate to bundle paths under `/var/lib/connector/microvm/`.

**Default:** `FirecrackerBackend` is the only production backend in Phase C; trait keeps Dragonball/CH slots empty stubs.

---

### Phase D — connector-microd + boot readiness (2–3 weeks)

**Outcome:** Install once → boot → MicroCell runtime READY (no VM fleet).

| Work item | Deliverable | Acceptance (§37) |
|-----------|-------------|------------------|
| D1 | `connector-microd` privileged supervisor (IPC from connectord) | connectord not root for KVM |
| D2 | systemd: `connector-microd.service` + HostProbe on start | Boot READY without 1 VM/agent |
| D3 | `connector install` / package path stages RuntimeBundle | No manual FC download |
| D4 | Optional warm pool (N clean clones) | Configurable, default 0–2 |
| D5 | First-use acquire fallback only if install skipped; still pin+verify | Unverified refuse |

**Reuse:** patterns from `connector-kerneld` (privileged helper, systemd). Keep kerneld = egress; microd = VMM.

---

### Phase E — Combined density + auto profile (2–3 weeks)

| Work item | Deliverable |
|-----------|-------------|
| E1 | Shared MicroCell (V3): N AgentCells in one guest |
| E2 | Dedicated MicroCell (V4): 1:1 |
| E3 | `isolation: auto` policy table (R0→V1, R1→V2, untrusted→V3, R3→V4) — **configurable**, never grants authority |
| E4 | Resource profiles documented from first benchmarks (no “100 agents” claim) |

---

### Phase F — Promotion + OS lifecycle complete (3–4 weeks)

| Work item | Deliverable | Acceptance (§34 / §31 lifecycle) |
|-----------|-------------|----------------------------------|
| F1 | Promote AgentCell → MicroCell without new `agent_pid` | Identity/DIM/mission/grants persist |
| F2 | Quarantine ordering: deny effects → cut grants/net → freeze cell → pause VMM → verify | QUARANTINE_FAILED if any required miss |
| F3 | No supervisor auto-revival of QUARANTINED / STOPPED_BY_OPERATOR | Explicit policy |
| F4 | Child propagation default quarantine/stop | Stale child authority impossible |
| F5 | In-flight AAPI effect classification on interrupt | Truthful committed/indeterminate |
| F6 | Full §31 + §34.21 test suites in CI (KVM job + soft LAB job) | Gate merge |

---

## 4. Engineer-facing surface (ship early)

```yaml
agent:
  isolation: auto   # or linux-cell | hardened-linux-cell | shared-microvm | dedicated-microvm
  # optional:
  # isolation_required: true   # fail closed
  # allow_degraded: false
  # resources: small | compute
```

APIs:

| API | Purpose |
|-----|---------|
| `GET /substrate/status` → `cvr`, `execution_bodies` | Runtime READY + escape hatches |
| `GET /agents/:pid/isolation` | R/A/E for this agent |
| `POST /agents/:pid/operator-stop` | Already exists — extend to MicroCell |
| `POST /agents/:pid/quarantine` | Propagate to VMM |
| `GET /proof/export/:pid` | + microcell_id, bundle digests, lifecycle receipts |

CLI:

```text
connector run <agent>
connector quarantine <agent>
connector stop <agent>
connectorctl isolation status
```

---

## 5. Firecracker default — concrete ownership

| Concern | Owner |
|---------|--------|
| Binary pin + jailer | RuntimeBundle / microd |
| API socket / VM dir | `/var/lib/connector/microvm/instances/<id>/` |
| Guest kernel/rootfs | Bundle; measured in isolation_manifest |
| Guest control | vsock → GuestD (`connector-vm-agent` evolved) |
| Network | microd creates attachment; **only** World Gateway egress |
| Pause/stop | `FirecrackerBackend::pause/stop` via microd IPC |
| Evidence | CVR Evidence Manager → proof_export / worldline |

**Anti-patterns (reject in review):**

- App code calling `firecracker` CLI ad hoc outside backend  
- Downloading “latest” FC on boot  
- Claiming MicroCell Applied when HostProbe failed  
- Soft AgentCell fallback labeled as V4  

---

## 6. Test matrix (CI)

| Suite | Runner | Gate |
|-------|--------|------|
| AgentCell semantic + Linux | Linux CI (no KVM) | Always — `make cvr-soft-acceptance` |
| Posture honesty / refuse-start | Linux CI | Always — soft suite |
| FirecrackerBackend smoke | KVM self-hosted / `kvm-effective` label | Required for “Effective V3/V4” — `make cvr-kvm-acceptance` |
| Lifecycle quarantine/pause/stop | Soft always; VMM on KVM | Soft + KVM suites |
| Effect exclusivity alternate path | Linux CI | Always |
| Anti-claims / promise | `audit-product-promise.sh` | Always |

**Workflow:** `.github/workflows/cvr-kvm-acceptance.yml`  
**Artifacts:** `artifacts/cvr-acceptance/cvr-{soft,kvm}-acceptance.json`  
Until KVM artifact has `effective_claim=true`, REACH marks V3/V4 **Effective** as `[LAB]`.

```bash
# Always (merge gate)
make cvr-soft-acceptance

# On a KVM box with pinned FC + kernel + rootfs
export CONNECTOR_FIRECRACKER_BIN=...
export CONNECTOR_MICROVM_KERNEL=...
export CONNECTOR_MICROVM_ROOTFS=...
# optional: CONNECTOR_FETCH_FIRECRACKER=1 CONNECTOR_KVM_REQUIRED=1
make cvr-kvm-acceptance
```

---

## 7. Suggested milestone order (shortest path to “real”)

1. **A** vocabulary + refuse-start for required MicroCell  
2. **B** AgentCell (density + lifecycle freeze that is real on Linux)  
3. **C2–C4** FirecrackerBackend + jailer + RuntimeBundle on a KVM box  
4. **C5–C8** clean snapshot, vsock GuestD, World Gateway-only net  
5. **D** microd + systemd READY-at-boot  
6. **E** shared/dedicated + auto  
7. **F** promotion + full LC invariants  

Do **not** block AgentCell on Firecracker.  
Do **not** ship Firecracker UX to engineers.  
Do **not** treat plugin microVM smoke as MicroCell Effective without HostProbe + jailer + evidence.

---

## 8. Definition of done (architecture §§33 + 39)

- [x] Same `agent_pid` can run on AgentCell then promote to dedicated MicroCell  
- [x] `isolation: auto` resolves; `dedicated-microvm` + missing KVM → START_REFUSED  
- [x] Firecracker used only via `FirecrackerBackend` / microd  
- [x] Quarantine freezes VMM and cuts network; agent cannot self-resume  
- [ ] Proof export reconstructs isolation + lifecycle for one consequential effect  
- [x] No density marketing numbers without benchmark artifact  
- [x] REACH checklist V3/V4 Effective after KVM acceptance suite green (`effective_claim=true`)

---

## Slice 0 / Phase A–B status (coded)

| Item | Status |
|------|--------|
| `substrate/cvr/` module | **Done** — profile, HostProbe, RuntimeBundle, ExecutionBody, FirecrackerBackend probe, AgentCell freeze, lifecycle R/A/E |
| `GET /cvr/status` · `GET\|PATCH /agents/:pid/isolation` | **Done** |
| Start binds ExecutionBody | **Done** — refuse MicroCell when HostProbe incomplete |
| Pause / quarantine / operator-stop | **Done** — CVR lifecycle receipts + AgentCell freeze + egress cut |
| Effect hold on frozen/quarantined | **Done** — `ops_runtime::preflight` |
| Phase C Firecracker create/start/jailer/snapshot | **Done** — `micro_cell::create_and_start` via `MicrovmHost`; pause/resume/stop live |
| Phase D connector-microd | **Done** — `platform/connector-microd` + systemd unit; server `microd_client` routes VMM ops when sock present; ready file → HostProbe READY; warm pool stub + `GET /cvr/microd` |
| Phase E shared/dedicated + auto | **Done** — `shared_pool` (N agents/guest); dedicated 1:1 `mc-d-*`; `auto_policy` table (env/JSON); `resources` small/default/compute |
| Phase F promote + lifecycle | **Done** — `promote_to_microcell` (same pid); ordered quarantine; regime seal; child propagation; inflight classify; soft unit tests |

---

## 9. Immediate next engineering slice

**KVM Effective green on this host** — soft LAB + live Firecracker start/pause/resume/stop; REACH E3/T4 flipped off `[LAB]` for MicroCell.

Keep partner HAL `[LAB]`. Re-verify after VMM changes: `CONNECTOR_KVM_REQUIRED=1 make cvr-kvm-acceptance`.
