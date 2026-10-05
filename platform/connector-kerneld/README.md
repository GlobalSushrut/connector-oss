# connector-kerneld

Thin **host reconciler**: reads the Connector platform **`GET /api/v1/kernel/status`** contract and writes a **systemd unit drop-in** using **`IPAddressAllow=`** (default prod path aligned with `systemd.resource-control(5)`).

## Cage architecture & ledger (read this)

TraceTramp proves **ingress decisions**; WitnessCtl proves **wire / custody** depth; **this daemon** materializes **egress cage** from `policy_revision` so agents cannot cheaply bypass the app stack. Strategy, TraceTramp vs WitnessCtl split, DevGuard, and custom plugins: **[`../docs/arch/CONNECTOR_KERNEL_CAGE_AND_LEDGER.md`](../docs/arch/CONNECTOR_KERNEL_CAGE_AND_LEDGER.md)** (companion: **[`../docs/arch/AIOS_ADVANCED_CAGE_OUTCOME.md`](../docs/arch/AIOS_ADVANCED_CAGE_OUTCOME.md)**).  
**GRC artifact:** `GET /api/v1/kernel/cage-manifest` on Connector (same host as `GET /api/v1/kernel/status`) returns `ledger_contracts` + embedded kernel snapshot for review automation.

## Why systemd first

- **Declarative**, **restart-safe** when combined with unit drop-ins under `/run` or `/etc`.
- Fits **STIG-style** fleets (RHEL/Alma) without a large third-party IPS.
- **nftables / eBPF:** systemd remains the default allowlist path; eBPF is a real `cgroup/skb` mark-deny load via `ebpf-load` (bpffs pins under `/sys/fs/bpf/connector/`).

## Build

```bash
make -C platform/ebpf
cargo build --release --manifest-path platform/connector-kerneld/Cargo.toml
```

Install the binary to `/usr/bin/connector-kerneld` (packaging TBD). Set `CONNECTOR_EBPF_OBJ` if the `.bpf.o` is installed elsewhere.

## Environment

| Variable | Meaning |
|----------|---------|
| `CONNECTOR_PLATFORM_URL` | Platform base URL (default `http://127.0.0.1:9735`). Alias: `CONNECTOR_TEST_URL`. |
| `CONNECTOR_API_KEY` | Bearer token for platform. Alias: `CONNECTOR_TEST_API_KEY`. |
| `CONNECTOR_KERNELD_AGENT_PID` | Agent PID attached via `POST /api/v1/kernel/agents/:pid/attach`. |
| `CONNECTOR_KERNELD_DROPIN_PATH` | Output path for `watch` (e.g. under `your-worker.service.d/`). |
| `CONNECTOR_KERNELD_SYSTEMD_UNIT` | Optional: run `systemctl try-reload-or-restart` after each write. |
| `CONNECTOR_KERNELD_INTERVAL_SEC` | Poll interval for `watch` (default 30). |
| `CONNECTOR_LICENSE_ENFORCE` | When `1`/`true`/`yes`, if platform snapshot `license.time_valid` is **false**, materialize **`IPAddressDeny=any`** instead of hostname allowlists (egress fail-closed at systemd). Match the same env on **connector-platform** to deny admission when the license window has expired. |
| *(platform)* `CONNECTOR_KERNEL_ENFORCE` + flow lease map | When platform snapshot `flow_lease.enforcement_enabled` is **true** and `active_leases` is **0**, materialize **`IPAddressDeny=any`** until admission mints a flow lease. |
| `CONNECTOR_EBPF_OBJ` | Path to `connector_mark_deny.bpf.o`. |
| `CONNECTOR_EBPF_PIN_ROOT` | bpffs root (default `/sys/fs/bpf/connector`). |
| `CONNECTOR_EBPF_REQUIRE` | When `1`, fail closed if eBPF pins are missing. |

## Commands

```bash
# Debug: pretty-print kernel snapshot
CONNECTOR_PLATFORM_URL=… CONNECTOR_API_KEY=… \
  connector-kerneld print-snapshot

# One-shot drop-in to stdout
CONNECTOR_PLATFORM_URL=… CONNECTOR_API_KEY=… \
  connector-kerneld render-dropin --agent "$AGENT_PID"

# eBPF (CAP_BPF + CAP_NET_ADMIN; bpftool)
connector-kerneld ebpf-load --agent "$AGENT_PID" [--cgroup /sys/fs/cgroup/…]
connector-kerneld ebpf-status --agent "$AGENT_PID"
connector-kerneld ebpf-deny-mark --agent "$AGENT_PID" --mark $((0xCD000001))
connector-kerneld ebpf-unload --agent "$AGENT_PID"

# Write + periodic refresh (+ optional unit reload)
export CONNECTOR_KERNELD_DROPIN_PATH=/run/systemd/system/myworker.service.d/50-connector-ip.conf
export CONNECTOR_KERNELD_SYSTEMD_UNIT=myworker.service
connector-kerneld watch --agent "$AGENT_PID" --output "$CONNECTOR_KERNELD_DROPIN_PATH"
```

## Operator flow

1. Platform: `POST /api/v1/kernel/profiles` then `POST /api/v1/kernel/agents/:pid/attach`.
2. Ensure the **worker** runs in a **systemd service** with `IPAddressAllow=` / `IPAddressDeny=` policy enabled (see `CONNECTOR_KERNEL_RUNBOOK.md`).
3. Point **`CONNECTOR_KERNELD_DROPIN_PATH`** at `…/myworker.service.d/50-connector-ip.conf`, then `systemctl daemon-reload` once.
4. Run **`connector-kerneld watch`** (see `platform/connector-kerneld/systemd/connector-kerneld.service`).

## Caveats

- Resolves **`allow_hostnames`** via DNS on the host running this binary; ensure resolver trust and TTL expectations match your threat model.
- **`proxy_only`** profiles still emit IPs for listed hostnames only; default-route “full internet via proxy” is **not** captured by `IPAddressAllow=` alone — design profiles accordingly or use nft/CNI for default-deny + explicit proxy path.
