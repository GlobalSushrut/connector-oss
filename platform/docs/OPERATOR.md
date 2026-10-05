# Operate Connector

Linux with KVM is the production install. Kubernetes remains a second deployment profile and is not what `product install` accepts. Connector configures Keycloak, SPIRE, OpenShell, Firecracker, the OpenTelemetry Collector, and cosign. Those projects stay upstream. Connector does not fork them, and none of them admits an action.

`READY` means the process is up and `connectorctl govern deploy-verify linux-kvm` has evidence for that backend. A finished install that still lacks evidence prints `CONNECTOR NOT PRODUCTION READY` and the blocker. That is the expected result until the seven operations have succeeded.

## Install

1. Copy `platform/deploy/seven-backends/linux/deployment.example.json`.
2. Replace every image with an `@sha256:` reference and every artifact, kernel, and rootfs with a path and a 64-character SHA-256.
3. Put TLS material for Keycloak in the `tls_dir` you named. Secrets in the spec are `file:` paths under `/var/lib/connector/deployment`. Connector generates a missing file with mode `0600`. It refuses an inline password.
4. Stage the digest-pinned upstream binaries yourself. Connector does not download `latest`.

```bash
connectorctl product install /etc/connector/deployment.json
connectorctl --yes product install /etc/connector/deployment.json
```

The first command prints the plan and changes nothing. The second runs as root: it checks `/dev/kvm`, installs only after the SHA-256 matches, writes SPIRE config, starts Keycloak and the collector, creates the realm and PKCE client, starts SPIRE and `connector-microd`, and enables a reconcile timer. It does not start `connector-platform` or the OpenShell gateway. The install step named deploy-verify does not probe. Run `connectorctl product status` after those two processes are up. Exit 0 on that status happens only when the live board says `CONNECTOR READY`.

## Create the first agent

Register through the API after the node is up:

```bash
curl -s -X POST "$CONNECTOR_API_URL/api/v1/agents" \
  -H "Authorization: Bearer $CONNECTOR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"rotation","namespace":"m/rotation","purpose":"rotate one credential","role":"writer"}'
```

The intelligence id comes from that registration. It is not the model name, the JWT subject, or the SPIFFE ID.

## Give it a contract

Contracts are compiled in Connector from the agent principal. The OpenShell projection is schema version 1. It is pushed only by `openshell policy set --wait` against a live gateway. Until that command exits 0, policy enforcement stays `NOT READY`.

## Run it

PATE is the only admission. OpenShell enforces the projection. Firecracker is the isolation tier when `connector-microd` is verified. Spend ceilings stop a generation that goes over budget.

## Inspect an effect

```bash
connectorctl govern explain <receipt-id>
```

Missing rows are `absent`. A three-id court signature appears only when explain has a verified operator subject, a fetched SPIFFE ID, and an intelligence id. The signature does not authorize.

## Cease it

```bash
connectorctl govern spend cease <agent-pid>
connectorctl govern cease-proof <agent-pid>
```

Cease bumps the generation, voids context, seals memory, and pauses a MicroCell when one is bound. Cease-proof does not call a model. Step 10 is present only when continuing the ceased generation would be `DENIED` / `stale_generation`.

## Prove the deployment

```bash
connectorctl product status
connectorctl govern deploy-verify linux-kvm
connectorctl product demo governed-agent
```

`product status` is the operator board. `deploy-verify` is the evidence verdict. `demo governed-agent` refuses while any spine step is still target. It does not register an agent and it does not call a model in order to print a success.

## Upgrade

```bash
connectorctl --yes product upgrade /etc/connector/deployment-next.json
connectorctl --yes product rollback
```

Upgrade stays on `linux-kvm` and OpenShell policy schema 1. The previous spec is saved as `desired.previous.json`. Rollback applies that file. Neither command marks the node ready by itself.

## Recover a failed node

`connector-product-reconcile.timer` runs every 30 seconds. If SPIRE, the agent, or microd is down, Connector restarts that unit at most three times, then stops. The row stays `NOT READY` until the real operation succeeds again. A previous OIDC login, SVID fetch, policy push, MicroCell lifecycle, OTLP batch, or cosign check does not keep a dead process `READY`.

```bash
connectorctl product diagnose
journalctl -u connector-spire-server -u connector-spire-agent -u connector-microd -n 80 --no-pager
```

## Start, stop, uninstall

```bash
connectorctl --yes product start
connectorctl --yes product stop
connectorctl --yes product restart
connectorctl --yes product uninstall
connectorctl --yes product uninstall purge
```

`uninstall` stops units and keeps `/var/lib/connector/deployment`. `purge` also removes volumes and that state directory.

## What you are not being certified for

This install does not produce a bank, PCI, SOC, or military certificate. `product compatibility` names the contracts Connector speaks. It is not a promise that every upstream release has been certified.
