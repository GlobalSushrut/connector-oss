# LLM Tokenization Plane — kernel-path unbypassable

## Correct sandwich (SVF / §15)

```text
tokenize/seal (SEMANTICIZE) → residual redact protecting opaque spans
  → LLM → validate opaque egress → PATE Admit → expand_after_admit → CDP
```

Never redact-first wipe of tokenizable secrets. See [CONNECTOR_SVF.md](./CONNECTOR_SVF.md).

## Goal

One probabilistic LLM may power **100+ agents**. The broker lane is fail-closed
**like Linux kernel paths**: Landlock FS, cgroup/nsfs attribution, nft/eBPF egress,
microVM/vsock — plus per-agent seal/sandbox. Userspace L7 alone is **not** enough.

| Event | HTTP | Meaning |
|-------|------|---------|
| Normal talk/tools after approve | **200** | Live sandbox + Linux bind |
| Parameter / VAC / seal mismatch | **409** redo | Cannot skip |
| Quarantine / unusual / missing Linux bar | **499** | `sorry, you are not allowed — need human approval` |
| Human HITL approve / unquarantine | **200** resume | New epoch; old seals dead |

## Unbypassable = Linux + broker

`assert_llm_lane` calls `assert_sandbox_unbypassable`:

- Landlock fail-closed + FS allowlists  
- kerneld Active + nft/iptables **or** eBPF pins  
- measured microVM + vsock tickets when tools-in-microVM  
- per-agent **cgroup/nsfs** bind + egress mark  
- per-agent **broker sandbox slot** (identity · character · knowledge · generation)

Skipping the lane to avoid 409/499 → treated as bypass → 499 + quarantine.

## Per-agent sandbox

`llm_agent_sandbox` slot stores `linux_bind` + `egress_mark` so the same LLM
provider cannot conflate agents at the kernel-attributable layer.

## Per-agent isolation audit PDF (required)

System brief/report PDFs remain. **Each agent must also file:**

| Route | Artifact |
|-------|----------|
| `GET /agents/:pid/audit/pdf` | UTC-stamped isolation proof PDF |
| `GET /agents/:pid/audit/isolation` | Same packet as JSON |

Proof sections: **FS Landlock**, **iptables/nft/eBPF + SO_MARK**, **VM/vsock measured assets**, **cgroup/nsfs**, **tokenization broker** (generation, quarantine, 200/409/499).

## Env

| Var | Role |
|-----|------|
| `CONNECTOR_LLM_BROKER_UNBYPASSABLE=1` | Broker + pulls unbypassable bar |
| `CONNECTOR_SANDBOX_UNBYPASSABLE=1` | Master Linux bar |
| `CONNECTOR_KERNEL_ENFORCE=1` | Require Active + net cut |
| `CONNECTOR_CGROUP_REQUIRE=1` | Fail if cgroup bind fails |
| `CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED=1` | FS path |

## Honesty

- **Coded:** fail-closed gates, seals, slots, cgroup bind attempts, eBPF/nft probes.  
- **Host evidence still required** for military/court attach (pins loaded, Landlock ABI visible, measured microVM).  
- Not a claim that the LLM process runs *inside* the kernel — the claim is effects cannot leave Connector without the same class of Linux path checks used for other unbypassable bars.
