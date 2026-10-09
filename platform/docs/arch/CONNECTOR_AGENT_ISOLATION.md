# Connector Agent Isolation Architecture

**Status:** Architecture source of truth (product model)  
**Implementation plan:** [CONNECTOR_ISOLATION_IMPLEMENTATION_PLAN.md](CONNECTOR_ISOLATION_IMPLEMENTATION_PLAN.md)  
**Related:** [MICROVM_CHANNELS.md](MICROVM_CHANNELS.md) · [CONNECTOR_OPERATIONAL_SOFTWARE.md](CONNECTOR_OPERATIONAL_SOFTWARE.md) · [CONNECTOR_REACH_CHECKLIST.md](CONNECTOR_REACH_CHECKLIST.md) · [CONNECTOR_ARC.md](CONNECTOR_ARC.md) (agency plane above bodies) · [World cage (Linux/userspace slice)](../../../docs/WORLD_CAGE_AND_BROWSER.md)

## Thesis

Connector isolates **agents**, not merely processes. Three layers are required:

1. **Machine** — MicroCell (default backend: Firecracker/KVM)  
2. **Linux** — AgentCell (namespaces, cgroups, Landlock, seccomp, network mark)  
3. **Semantic** — identity, memory, grants, budgets, DNA, PATE/ActionBinding, evidence  

**Agent ≠ execution body.** The same `agent_pid` may move between AgentCell and MicroCell without becoming a new agent.

## Engineer surface

```yaml
agent:
  isolation: auto  # linux-cell | hardened-linux-cell | shared-microvm | dedicated-microvm
  isolation_risk: R2   # optional; drives auto table only — never grants authority
  resources: default   # small | default | compute
```

Profiles **V0–V4** compile intent → concrete boundaries. Hardened missing controls → **START_REFUSED**. Posture is always **Requested / Applied / Effective**.

- **V3 Shared MicroCell** — multiple AgentCells share one Firecracker guest (`CONNECTOR_MICROCELL_SHARED_MAX`).  
- **V4 Dedicated MicroCell** — one guest per agent (`mc-d-*`), never pooled.  
- **`isolation: auto`** — configurable risk→profile table (`CONNECTOR_ISOLATION_AUTO_POLICY_JSON`).  
- **Promote** — `POST /agents/:pid/isolation/promote` moves AgentCell → MicroCell **without** a new `agent_pid`.  
- **Quarantine order** — deny effects → classify inflight → cut grants → cut net → freeze cell → pause VMM → verify → propagate children.  
- **No auto-revival** — `QUARANTINED` / `STOPPED_BY_OPERATOR` require explicit operator/HITL.

## Default virtualization

Firecracker is the **default MicroVmBackend**, not the product UX. Engineers operate **MicroCells**; Connector owns VMM, jailer, guest kernel, rootfs, vsock, snapshots.

## Lifecycle

OS-grade: RUNNING · PAUSED · QUARANTINED · STOPPED · REAP · DESTROY — enforced on AgentCell and, when required, on the VMM. Quarantine is human-gated; no watchdog revival.

## Implementation

Follow the phased plan (A–F) in [CONNECTOR_ISOLATION_IMPLEMENTATION_PLAN.md](CONNECTOR_ISOLATION_IMPLEMENTATION_PLAN.md). Extend existing `membrane_posture`, DockLock, `platform/microvm`, and lifecycle gates — do not invent a parallel stack.

**Linux/userspace slice (shipped, not a MicroCell substitute):** world dials from `connector-platform` go through dest-pinned Landlock children and a default-DROP pore table; unmarked host processes can have vendor HTTPS DROPped except the LLM-cage mark. That is the path described in [WORLD_CAGE_AND_BROWSER.md](../../../docs/WORLD_CAGE_AND_BROWSER.md). Firecracker MicroCell remains the default *virtualization* backend in this architecture document — do not read the Landlock child as “MicroCell is on.”
