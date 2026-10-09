# Connector kernel controls — scope and layering

This document satisfies checklist **§10.1** (correctness and scope): **where** each control lives so operators do not confuse per-agent quarantine with per-operation blocks or host policy.

| Control | Authority | What it blocks | Typical trigger |
|---------|-----------|----------------|-----------------|
| **Per-agent quarantine** | Platform `admission::check` step 1 (`agent_meta.quarantined` / `paused`) | **All** operations for that `agent_pid` | Injection/guard security path, operator pause |
| **Per-operation / scoped deny** | AAPI / policies / plugins (e.g. TraceTramp `operation_blocks`) | One **class** of work (route, tool family, tenant op key) | Policy change, incident response |
| **Per-decision hold / approval** | Guard pipeline + HITL flows | Specific transition until human/system approval | High-risk tool, compliance hold |
| **Host kernel attachment** | `kernel_host` + future `connector-kerneld` (`CONNECTOR_KERNEL_ENFORCE`) | **Raw egress** from governed workers (bypass proxy) | Prod hardening, CISO egress proof |

**Rule:** semantic decisions stay in Connector (`MemoryKernel`, `DualDispatcher`, admission, guard). **nft/eBPF** only enforces what maps cleanly to sockets and cgroups.

See also: `CONNECTOR_OS_AGENTIC_ENTROPY_FIREWALL_RESEARCH.md` §0 phases, `CONNECTOR_KERNEL_CAPS.md`, `CONNECTOR_KERNEL_RUNBOOK.md`.

**Outcome narrative (AI OS + orchestration in one cage):** [`AIOS_ADVANCED_CAGE_OUTCOME.md`](./AIOS_ADVANCED_CAGE_OUTCOME.md) — controlled / managed / proved, and what “impossible to bypass” means in scope.

**Kernel-first cage + plugin roles (TraceTramp vs WitnessCtl):** [`CONNECTOR_KERNEL_CAGE_AND_LEDGER.md`](./CONNECTOR_KERNEL_CAGE_AND_LEDGER.md).
