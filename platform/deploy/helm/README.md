# Connector OS Helm charts

| Chart | Install |
|-------|---------|
| **connector** | `helm install connector ./connector` |
| **tracetramp** | `helm install tracetramp ./tracetramp` |
| **witnessctl** | `helm install witnessctl ./witnessctl` |

## Seven-backend functional gate

The Connector chart can mount the official SPIRE CSI Workload API socket and
the host `connector-microd` socket. Enabling `backendVerification` adds a
post-install/post-upgrade Job:

```bash
helm upgrade --install connector ./connector \
  -f ../seven-backends/kubernetes/connector-values.yaml
```

The Job runs `connectorctl govern deploy-verify kubernetes` and fails when any
of IAM, SPIRE, OpenShell/OPA, Firecracker, OpenTelemetry, or cosign lacks
operational evidence. It does not replace `/readyz`. See
[`../seven-backends/kubernetes/README.md`](../seven-backends/kubernetes/README.md).
The Kubernetes profile is not production-eligible while NVIDIA documents its
OpenShell Helm chart as experimental.

## TraceTramp (PostgreSQL-only default)

```bash
helm install tracetramp ./tracetramp \
  --set externalDatabase.host=postgresql.default.svc \
  --set redis.enabled=false \
  --set connector.baseUrl=http://connector:9091 \
  --set witness.handoffBaseUrl=http://witnessctl:7443
```

Management dashboard: port-forward `mgmt` (9742) → `GET /admin/dashboard`.

## WitnessCtl

```bash
helm install witnessctl ./witnessctl \
  --set connector.baseUrl=http://connector:9091 \
  --set custody.replicas[0]=http://witnessctl-node:7444
```

Offline verify: `witnessctl-verify ./evidence.witness --hmac-secret $SECRET`

## Lint (CI)

```bash
make helm-lint-smoke
```

Requires [Helm 3](https://helm.sh/docs/intro/install/). Bitnami subchart deps are linted with `--dependency-update` skipped when offline; `helm lint` validates templates only.
