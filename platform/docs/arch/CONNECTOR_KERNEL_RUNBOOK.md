# Host kernel runbook — nft reload, systemd, rollback (checklist §10.3 / §10.5)

## Default prod stack (chosen)

1. **Systemd egress allowlist** — `IPAddressAllow=` / implied deny via `systemd.resource-control(5)` on the **worker unit** that runs the agent (cgroup before sockets still applies).  
2. **`connector-kerneld`** — `platform/connector-kerneld/`: polls `GET /api/v1/kernel/status`, resolves profile **`allow_hostnames`**, writes a **`.conf` drop-in** fragment, optionally `systemctl try-reload-or-restart` the worker.  
3. **nftables `NFTSet=`** — optional refill path for host-level rules; keep sets authoritative after `nft` reload (see below).

See `platform/connector-kerneld/README.md` and `systemd/connector-kerneld.service` for install variables (`CONNECTOR_PLATFORM_URL`, `CONNECTOR_API_KEY`, `CONNECTOR_KERNELD_AGENT_PID`, `CONNECTOR_KERNELD_DROPIN_PATH`).

## Startup order (cgroup before sockets)

1. Create or select **cgroup** / **systemd scope** for the agent worker.  
2. **Attach** BPF programs + populate maps (or join nft **cgroupsv2** set via `NFTSet=` / controller).  
3. **Only then** `exec` the worker binary that may open sockets.

Moving a task **after** sockets exist may leave sockets on the wrong cgroup — see kernel/nft discussions linked from the main research doc.

## nftables reload without losing dynamic sets

- Prefer **sets** (`type cgroupsv2`) populated by systemd `NFTSet=` or `connector-kerneld`, not hard-coded per-cgroup rules that embed numeric IDs.  
- After `nft flush ruleset` or package upgrade, **refill** sets: `systemctl daemon-reload` (per `systemd.resource-control(5)` `NFTSet=` notes) or controller equivalent.

## Rollback / kill switch

1. Set `CONNECTOR_KERNEL_ENFORCE=0` (or unset) and restart `connector-platform` — admission no longer requires host attachment.  
2. Stop `connector-kerneld`; detach BPF links; remove nft set members.  
3. Verify `GET /api/v1/runtime/enforcement` → `host_kernel.kernel_enforce_enabled: false`.

## SLO hints (checklist §10.5)

- Alert on rising `connector_kernel_host_admission_denied_total` with stable agent counts (misconfiguration).  
- Track `connector_kernel_host` snapshot `counters.last_apply_latency_us` after real daemon lands (p95 attach time).
