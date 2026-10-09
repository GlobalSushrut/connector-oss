# Self-host Connector on Linux (boring path)

One binary. One unit. One data directory. No HA claim from packaging.

## Install

```bash
make package
# → dist/connector-os-<ver>-<arch>-linux.tar.gz + SHA256SUMS

cd dist && sha256sum -c SHA256SUMS
tar -xzf connector-os-*-linux.tar.gz
cd connector-os-*/
sudo ./install.sh
# edit /etc/connector/env (mode 0600) — secrets only
sudo systemctl enable --now connector-platform
```

## Operate

```bash
systemctl status connector-platform
journalctl -u connector-platform -f
curl -fsS http://127.0.0.1:9091/healthz
curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9091/
connectorctl node doctor
connectorctl node support-bundle --out ./support.json
```

## Seven real backends

The base node can boot without every external controller. That is process
readiness, not a production backend claim. For the Linux/KVM reference stack,
follow
[`platform/deploy/seven-backends/linux/README.md`](../platform/deploy/seven-backends/linux/README.md),
then run:

```bash
connectorctl govern backends
connectorctl govern deploy-verify linux-kvm
```

The second command exits nonzero until Keycloak verifies a real OIDC/JWKS
token, SPIRE returns an SVID, OpenShell accepts a policy (OPA remains inside
OpenShell), Firecracker completes its lifecycle through microd, an OTLP batch
exports successfully, and cosign verifies the release manifest.

| Path | Role |
|------|------|
| `/usr/local/bin/connector-platform` | daemon |
| `/usr/local/bin/connectorctl` | operator CLI |
| `/etc/connector/env` | secrets |
| `/etc/connector/connector.yaml` | optional config (`CONNECTOR_CONFIG_FILE`) |
| `/var/lib/connector` | persistent state — keep across upgrades |
| `/` on :9091 | dashboard (filesystem UI or embed) |

## Upgrade (binaries only)

```bash
connectorctl data backup -o /var/backups/pre-upgrade.tar.gz
connectorctl node stop
connectorctl data upgrade --from-tarball /path/to/new.tar.gz --apply
connectorctl node start
connectorctl node doctor
```

Commercial license tiers: `connectorctl access license tiers` (not `data upgrade`).

## Truths

- Topology from this path: **sovereign single-node** (`ha_claimable: false` in package `MANIFEST.json`).
- systemd `Type=notify` + `WatchdogSec` — READY after `PLATFORM_READY`.
- License server is **optional**; do not use `platform/deploy/install.sh` unless you set `CONNECTOR_INSTALL_ALLOW_LICENSE_COUPLED=1`.
- OCI: `platform/deploy/Dockerfile.connector-platform` (same single-node honesty).
- CLI reference: [CONNECTORCTL_COMMAND_AUDIT.md](CONNECTORCTL_COMMAND_AUDIT.md).

Details: [platform/deploy/PACKAGING.md](../platform/deploy/PACKAGING.md), [PRODUCTION_UPGRADE.md](PRODUCTION_UPGRADE.md).
