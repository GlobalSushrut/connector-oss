# Linux capabilities for host kernel enforcement (checklist §10.2)

When `connector-kerneld` loads **real** nftables + eBPF programs on the host, use **least privilege** service accounts.

| Capability | Why |
|------------|-----|
| `CAP_NET_ADMIN` | nftables rule load, netns moves, some cgroup socket matches |
| `CAP_BPF` | load/attach BPF programs, pin maps under bpffs |
| `CAP_SYS_ADMIN` | **Avoid** in steady state; only if your chosen attach path strictly requires it (prefer redesign) |
| `CAP_PERFMON` / `CAP_IPC_LOCK` | Usually **not** required for cgroup `connect4` allowlists |

**Pin layout (contract):** `/sys/fs/bpf/connector/<agent_or_profile>/…` — maps and links owned by `connector-kerneld` user, mode `0600` or `0660` + dedicated group.

The platform **stub** (`kernel_host` in `connector-platform`) does not load BPF itself; `connector-kerneld ebpf-load` does. Confirm Active with `apply_backend=bpf` only after bpffs pins exist (or break-glass `CONNECTOR_KERNEL_BPF_APPLIED`).
