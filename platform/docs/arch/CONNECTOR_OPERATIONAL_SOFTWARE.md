# Connector Operational Software

**Thesis:** Like Linux, Connector is **operational** — syscalls (effects), cgroups (budgets), namespaces (memory), audit (proof) run on the live path, not only as documentation.

**Architecture record (printable):** [arch.pdf](arch.pdf) · source [arch.html](arch.html) — complete drawings, ~40 capability claims, engineer/agent use, honesty bounds, runbook, outcomes.  
**Next plane (target):** [CONNECTOR_ARC.md](CONNECTOR_ARC.md) — agency virtualization above L1/L2 bodies · [CONNECTOR_ARC_IMPLEMENTATION_PLAN.md](CONNECTOR_ARC_IMPLEMENTATION_PLAN.md) coding phases A–H.

## Live ops map

| Operation | Runtime path | Finalized capability |
|-----------|--------------|----------------------|
| Agent start | `assert_harden_ready_for_start` + CVR bind | §16 START_REFUSED |
| Talk | `ops_runtime::preflight` → PATE → BCR spend → recall | §13 · §17 · §6–7 |
| Tool / MCP | `preflight` → knowledge justify → DNA → governed_effect → PATE | §5 · §12–13 · §19 · A6 |
| CONP | membrane → governed_effect → PATE → DNA | A25 / S20 |
| Agent-loop tool | `admit_proposal` → same tool path | §10 |
| Workbench Admit | identity stack → DAL → PATE → ToolDispatch | Workbench journal |
| SpendCease | fence generation + void ctx_tok + reap | [SPEND_CEASE.md](SPEND_CEASE.md) |
| Expometer | `GET /agents/:pid/expometer` | Authority + world + LLM exposure |
| Action Trail | `/run/trail` UI + watch/activity compose | [CONNECTOR_PLAYGROUND_REACHED.md](../demo/CONNECTOR_PLAYGROUND_REACHED.md) |
| Recall | `memory_retrieval` + knowledge boundary + DIM radius | §5–9 |
| Spend | BCR reserve→commit (`spend_tokens`) | A12 / §17 |
| Operator pulse | `GET /operator/pulse` denials/spend/HITL/DIM | E6 / S26 |
| Operator stop | `POST /agents/:pid/operator-stop` regime/Φ + VMM stop | A27 |
| Poison | `POST /dim/:pid/poison` verification↑ | S27 |
| Proof | `/proof/export` + DNA log + MicroCell + `connectorctl worldline export` | §23–25 |

## CVR (Agent Isolation)

| Operation | Path |
|-----------|------|
| Isolation resolve | `cvr::resolve_isolation` · `PATCH /agents/:pid/isolation` |
| HostProbe / bundle | `GET /cvr/status` · `/substrate/status` → `cvr` |
| Start bind body | `cvr::bind_on_start` → AgentCell and/or **Firecracker MicroCell** |
| MicroCell VMM | Prefer **connector-microd** IPC; fallback `MicrovmHost` in-process (lab) |
| Boot READY | `connector-microd prepare/serve` → `/run/connector/microd.ready` |
| Pause / quarantine / stop | AgentCell freeze + **Firecracker pause/stop** (via microd when up) + egress cut |
| Frozen effects | `ops_runtime` preflight denies |
| Microd status | `GET /cvr/microd` · warm: `POST /cvr/microd/warm` |
| Shared MicroCell (V3) | `shared_pool::acquire_shared` — N AgentCells / guest (`CONNECTOR_MICROCELL_SHARED_MAX`) |
| Dedicated MicroCell (V4) | Always new `mc-d-*` guest — never pooled |
| `isolation: auto` | `auto_policy` table (R0→V1 … R3→V4); `CONNECTOR_ISOLATION_AUTO_POLICY_JSON` |
| Resources | `small` \| `default` \| `compute` via `agent_meta.resources` / `CONNECTOR_AGENT_RESOURCES` |
| Promote | `POST /agents/:pid/isolation/promote` `{target: shared\|dedicated}` — same `agent_pid` |
| Quarantine | Ordered deny→inflight→grants→net→freeze→VMM→verify→progeny; `QUARANTINE_FAILED` on miss |
| Regime | `QUARANTINED` / `STOPPED_BY_OPERATOR` never auto-revive |

Engineer intent: `auto` \| `linux-cell` \| `hardened-linux-cell` \| `shared-microvm` \| `dedicated-microvm`  
Default VMM backend: **Firecracker** (real InstanceStart when KVM + kernel + rootfs present; jailer required under harden).

```yaml
agent:
  isolation: auto                 # or shared-microvm / dedicated-microvm / …
  isolation_risk: R2              # drives auto table; never grants authority
  resources: default              # small | default | compute
```

See [CONNECTOR_AGENT_ISOLATION.md](CONNECTOR_AGENT_ISOLATION.md) · [CONNECTOR_ISOLATION_IMPLEMENTATION_PLAN.md](CONNECTOR_ISOLATION_IMPLEMENTATION_PLAN.md).

```bash
# Privileged supervisor (production path)
systemctl enable --now connector-microd.service
# Inspect: GET /api/v1/cvr/status → cvr.microd / host_probe.effective_state

# Asset pins (also via /etc/connector/microd.env)
export CONNECTOR_FIRECRACKER_BIN=/path/to/firecracker
export CONNECTOR_JAILER_BIN=/path/to/jailer          # required under harden
export CONNECTOR_MICROVM_KERNEL=/path/to/vmlinux
export CONNECTOR_MICROVM_ROOTFS=/path/to/rootfs.ext4
export CONNECTOR_MICROVM_STATE_DIR=/var/lib/connector/microvm/instances
export CONNECTOR_MICROD_SOCK=/run/connector/microd.sock
# optional lab override (never claim Effective without real assets):
# export CONNECTOR_MICROVM_HOST_AVAILABLE=1
```

```yaml
agent:
  isolation: dedicated-microvm   # or shared-microvm / auto with R3
```

Missing KVM/assets/jailer (when required) → **START_REFUSED**.

## Acceptance (Linux-level Effective gate)

```bash
make cvr-soft-acceptance          # always — LAB honesty / unit / refuse-start
make cvr-kvm-acceptance           # KVM host — writes Effective artifact when PASS
# CI: .github/workflows/cvr-kvm-acceptance.yml
# Effective claim: artifacts/cvr-acceptance/cvr-kvm-acceptance.json → effective_claim=true
```

## Enable real augmented env

```bash
export CONNECTOR_AUGMENTED_ENV=1
# membrane must be ready or start/Talk/tools return START_REFUSED / PolicyDenied
```

Inspect: `GET /api/v1/substrate/status` → `ops_runtime` + `harden_posture` + `cvr` + `escape_hatches` + `lab_banner`.

## Honesty

Playground remains soft. Operational harden refuses when Requested gates are unmet — it does not silently become lab. T4 microVM Effective requires host; otherwise `applied_truth: unavailable`.
