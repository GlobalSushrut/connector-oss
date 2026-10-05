# Connector OS packaging — Linux/POSIX production standard (honest gaps)

Connector aims for **neutral production packaging** like a POSIX daemon:
one binary name, one unit file, FHS paths, sd_notify, checksummed tarball, OCI image.
It does **not** claim Kubernetes HA or multi-region from packaging alone.

## Canonical artifacts

| Artifact | Path / command | Role |
|----------|----------------|------|
| Release tarball | `make package` → `dist/connector-os-<ver>-<arch>-linux.tar.gz` | Single-node install |
| Checksums | `dist/SHA256SUMS` | Integrity |
| systemd unit | `systemd/connector-platform.service` inside tarball | Type=notify + WatchdogSec |
| OCI image | `platform/deploy/Dockerfile.connector-platform` | Non-root, `/healthz` |
| CLI | `connectorctl` | start/status/doctor/support-bundle |

Binary name is always **`connector-platform`** (never `connector-node`).
Legacy `platform/release/package.sh` forwards to `scripts/package-connector-os.sh`.

## FHS layout (bare metal)

```
/usr/local/bin/connector-platform
/usr/local/bin/connectorctl
/etc/connector/env                 # secrets (mode 0600)
/etc/connector/connector.yaml      # optional config
/var/lib/connector/                # data_dir (persistent)
/var/lib/connector/ui/             # dashboard assets
/var/log/connector/                # if not journald-only
/etc/systemd/system/connector-platform.service
```

Install: extract tarball → `sudo ./install.sh` → edit `/etc/connector/env` → `systemctl enable --now connector-platform`.

## Machine truths (packaging)

| Claim | Truth |
|-------|--------|
| Type=notify | READY=1 only after HTTP router + PLATFORM_READY |
| WatchdogSec=60 | binary pings WATCHDOG=1 when NOTIFY_SOCKET set |
| Single replica Helm | RWO / local state — not HA |
| OCI HEALTHCHECK | `/healthz` liveness only; readiness is `/readyz` |
| Support bundle | `GET /api/v1/support/bundle` + `connectorctl support-bundle` (admin+, redacted) |
| MANIFEST.json `libc` | recorded at pack time (`glibc` / `musl` / …) — verify on target with `ldd` |

## Closed vs still lagging

**Closed for single-node POSIX packaging**

- Unified tarball + SHA256SUMS via `make package`
- systemd Type=notify + WatchdogSec wired from `PLATFORM_READY`
- FHS install helper (env-based config; no fake `--data-dir` argv)
- Production OCI Dockerfile (debian bookworm-slim, non-root)
- Support bundle API + CLI

**Still lagging (not packaging “done” for every OS)**

1. **Dashboard UI** — packaged by default when Trunk `dist/` exists; otherwise runtime uses compile-time embed (stub if dist missing at build). Set `CONNECTOR_PACKAGE_UI=0` for API-only tarballs.
2. **License server** — optional companion; not required for community/self-host free profiles.
3. **Cross-compile** — host arch only (no Darwin/Windows in canonical path).
4. **musl static** — default build is typically glibc; check `MANIFEST.json` / `ldd` before musl-only hosts.
5. **HA / mesh / multi-region** — separate gates; packaging explicitly sets `ha_claimable: false`.

## Operator day-2

```bash
connectorctl node doctor
connectorctl node support-bundle --out ./support.json
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9091/api/v1/support/bundle
```

Upgrade: stop unit → `connectorctl data upgrade --from-tarball … --apply` → start; keep `/var/lib/connector` unchanged.

Operator guide: [docs/SELFHOST_LINUX.md](../../docs/SELFHOST_LINUX.md).
CLI audit: [docs/CONNECTORCTL_COMMAND_AUDIT.md](../../docs/CONNECTORCTL_COMMAND_AUDIT.md).
