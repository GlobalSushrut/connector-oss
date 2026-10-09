# Effect Exclusivity Standard

Connector's security claim under hardened posture: **an agent cannot produce a consequential
effect except through the Connector effect mediator**.

## What this means

Every path to a side effect must converge on:

```text
agent intent → governed_effect → admission → Ring-1/QPR → broker policy → EFFECT
```

Alternate authority paths are **structurally closed** under
`CONNECTOR_EFFECT_EXCLUSIVITY=1` (production default). Effects refuse until each
path is closed:

| Path | How it is closed |
| --- | --- |
| Raw network / TCP / HTTP outside broker | L7 + MCP egress + Ring-1, and matrix cut **or** microVM/docker guest `--network none` / vsock-only |
| Ungoverned shell or subprocess | Isolation is not subprocess; shell/exec I/O only via microVM tool plane |
| In-process ToolDispatch/MCP | Isolation bar (microvm/docker_lab) + ZT handshake; no `CONNECTOR_ALLOW_IN_PROCESS_EFFECTS` |
| In-process world sockets (MCP/HAL/LLM/HTTP) | **Landlock child** + pore table default DROP; see [WORLD_CAGE_AND_BROWSER.md](../../../docs/WORLD_CAGE_AND_BROWSER.md) |
| Direct secret read from agent environment | Cage env strip + isolation membrane forbids API keys/tokens in guest `-e` |
| Ungoverned memory read/write | `governed_effect` + identity stack + Ring-1 |
| Agent-to-agent without grant | Inter-intelligence grant **or** explicit world address grant — remote A2A is not a side door |

`GET /api/v1/runtime/effect-exclusivity/status` → `alternate_paths` (`closed: true` per path).
`assert_effect_exclusivity_ready` fail-closes if any path is still open.

Break-glass (weakens claim): `CONNECTOR_ALLOW_IN_PROCESS_EFFECTS=1`, `CONNECTOR_ALLOW_GUEST_EGRESS=1`.

## Environment (production defaults)

| Variable | Purpose |
|----------|---------|
| `CONNECTOR_EFFECT_EXCLUSIVITY=1` | Master switch |
| `CONNECTOR_IIA_RING1=1` | Quantum required for effects |
| `CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED=1` | Refuse if Landlock ABI missing |
| `CONNECTOR_L7_EGRESS_PROXY=1` | App-layer egress allowlist |
| `CONNECTOR_MCP_EGRESS_ENFORCE=1` | MCP egress allowlist |
| `CONNECTOR_MATRIX_HW_ENFORCE=1` | Host matrix cut for intelligence marks |
| `CONNECTOR_ISOLATION_RUNTIME=docker_lab` or `microvm` | No in-process tool plane |

Break-glass (weakens claim):

- `CONNECTOR_ALLOW_IN_PROCESS_EFFECTS=1` — permits in-process ToolDispatch/MCP

## APIs

- `GET /api/v1/runtime/effect-exclusivity/status` — posture + honesty fields
- `POST /api/v1/runtime/effect-exclusivity/probe` — adversarial bypass probe
- `GET /api/v1/runtime/enforcement` — includes `effect_exclusivity` block

## Adversarial gate

```bash
platform/scripts/effect-exclusivity-adversarial.sh
```

Probes: direct HTTP, raw TCP, shell, subprocess, direct MCP, secret env, filesystem,
delegation, approval replay, manifest mutation, restart replay.

## Implementation map

| Module | Role |
|--------|------|
| `substrate/effect_exclusivity.rs` | Master gate + in-process deny + probe registry |
| `substrate/governed_effect.rs` | Unified admission for all effect classes |
| `kernel/docklock.rs` | Ring-1 quantum + cage env |
| `kernel/membrane_posture.rs` | Fail-closed when backends missing |
| `substrate/cage_security.rs` | Isolation grade + prodish subprocess deny |
| `services/tools.rs` | Tool dispatch exclusivity gates |
| `services/memory2.rs` | Memory read governed admission |
| `services/gateway.rs` | LLM path exclusivity ready gate |
| `kernel/landlock_child.rs` + `pore_worker.rs` | Dest-pinned world dials outside the parent PID |
| `kernel/llm_vendor_cut.rs` | Host DROP of vendor LLM IPs except cage SO_MARK |
| `kernel/browser_world.rs` | Granted-origin document explorer (not computer-use) |

## Remaining hardening (honest)

1. **Transparent egress** — **complete**: eBPF connect4 + nft NAT REDIRECT + `connector-egress-proxy` TLS terminate under Connector CA (ticket required)
2. **OS-level cage syscall tests** — Landlock ABI apply proven in host attach; deeper seccomp child proofs remain soak depth
3. **Exact-action approval binding** — cryptographic bind to principal + args + policy version (P3 mostly gated)
4. **Durable replay journal** — **solidified** (`begin_step_detailed`, abandon stale Pending, RG-09 light soak)

## Isolation membrane (done under distrust)

When `CONNECTOR_LLM_DISTRUST=1` or effect exclusivity is on, plugin-runtime:

- **docker_lab**: forces `--network none`, docker-grade `cap-drop ALL` / read-only / `ipc=none`, passes cage env via docker `-e` (not host process env), strips secrets/tokens from guest env
- **microvm**: forces vsock-only (no TAP), clears allowlists, never puts API keys on the guest cmdline

### Tools in microVM (incl. I/O)

`CONNECTOR_TOOLS_IN_MICROVM=1` (production default):

| Effect | Where it runs |
| --- | --- |
| Shell / filesystem / exec | **microVM guest only** — host path refused |
| Robotics / IoT / MQTT / Modbus / machine | **microVM channel** (`CONNECTOR_WORLD_CHANNEL_VIA_MICROVM=1`) |
| Remote MCP HTTPS | Host broker only if `CONNECTOR_ALLOW_HOST_MCP_BROKER=1` |
| WM memory syscalls | Connector kernel (not host FS) |

Strict (no host MCP broker): `CONNECTOR_TOOLS_IN_MICROVM_STRICT=1`.

APIs: `GET/POST /api/v1/runtime/microvm-tools/{status,invoke}` · CONP: `POST /api/v1/protocol/conp/command`

See `platform/docs/arch/MICROVM_CHANNELS.md`.

Break-glass: `CONNECTOR_ALLOW_GUEST_EGRESS=1`, `CONNECTOR_ALLOW_IN_PROCESS_EFFECTS=1`.

Receipts alone do not prevent bypass; physical path closure + adversarial tests do.

Operator recipe (pores, vendor cut, browser world): [docs/WORLD_CAGE_AND_BROWSER.md](../../../docs/WORLD_CAGE_AND_BROWSER.md).
