# Seven backends on one Linux/KVM host

This is the production install path. Operators use Connector, not seven
separate consoles:

```bash
connectorctl product install deployment.json
connectorctl --yes product install deployment.json
connectorctl product status
```

Copy `deployment.example.json`, fill digest-pinned images and artifacts, and
pass `--yes` as root to apply. The installer checks KVM, verifies SHA-256
before it copies anything, writes SPIRE and service configuration, starts
Keycloak, the collector, SPIRE, and `connector-microd`, and then runs
deploy-verify. It does not download `latest` and it does not mark the node
READY. `connectorctl product status` is the board. `govern deploy-verify
linux-kvm` is the evidence verdict.

Job-oriented steps are in [OPERATOR.md](../../../docs/OPERATOR.md).

Connector operates:

1. Keycloak for operator OIDC.
2. SPIRE server and agent for workload X.509 SVIDs.
3. NVIDIA OpenShell for the execution boundary.
4. OPA/Rego inside OpenShell.
5. Firecracker+jailer through `connector-microd`.
6. OpenTelemetry Collector for OTLP.
7. Sigstore cosign for release-manifest verification.

PATE remains the only admission authority.

## Requirements

- Linux with KVM available to the service account.
- cgroup v2, nftables, systemd, Docker Compose or Podman Compose.
- Upstream `spire-server`, `spire-agent`, `openshell`, `firecracker`,
  `jailer`, and `cosign` binaries.
- Measured Firecracker kernel and rootfs paths and SHA-256 values.
- TLS certificates and a PostgreSQL volume.

Connector does not download an unpinned `latest` image. Copy
`images.env.example` to `images.env` and supply immutable image digests.

For host binaries, obtain released OpenShell, SPIRE, Firecracker+jailer,
cosign, and `connector-microd` artifacts through your approved supply-chain
channel. Set each `*_BIN`/`*_PACKAGE` and `*_SHA256` variable, then run
`install-host-upstreams.sh` as root. The installer verifies every digest before
installing anything and does not fetch from `main`.

## Bring up identity and telemetry

```bash
cp images.env.example images.env
# Fill every REQUIRED value. Do not commit this file.
set -a; . ./images.env; set +a
docker compose --env-file images.env -f compose.yaml up -d
```

Bootstrap the Keycloak realm/client with `bootstrap-keycloak.sh`. It reads the
admin and client secrets from the environment and never writes them into the
realm template.

Set these on `connector-platform.service`:

```text
CONNECTOR_SSO_CLIENT_ID=connector-platform
CONNECTOR_SSO_CLIENT_SECRET=<secret>
CONNECTOR_SSO_ISSUER=https://id.example/realms/connector
CONNECTOR_SSO_DISCOVERY_URL=https://id.example/realms/connector/.well-known/openid-configuration
CONNECTOR_SSO_AUTHORIZATION_URL=https://id.example/realms/connector/protocol/openid-connect/auth
CONNECTOR_SSO_TOKEN_URL=https://id.example/realms/connector/protocol/openid-connect/token
CONNECTOR_SSO_USERINFO_URL=https://id.example/realms/connector/protocol/openid-connect/userinfo
CONNECTOR_SSO_JWKS_URL=https://id.example/realms/connector/protocol/openid-connect/certs
SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent/sockets/api.sock
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317
CONNECTOR_OPENSHELL_SANDBOX=<sandbox-handle>
CONNECTOR_COSIGN_BLOB=<release-manifest>
CONNECTOR_COSIGN_SIGNATURE=<signature>
CONNECTOR_COSIGN_KEY=<verification-key>
```

The first successful Keycloak OIDC/JWKS login records IAM operational
evidence. A local JWT alone does not make this profile ready.

## Host enforcement

Configure SPIRE from the upstream release, register the Connector workload,
and expose its Workload API socket at `/run/spire/agent/sockets/api.sock`.
Connector only fetches the SVID; it does not issue one.

Install OpenShell from its signed upstream release, create a sandbox, and set
`CONNECTOR_OPENSHELL_SANDBOX`. Connector compiles `AgentContractV2` and calls
`openshell policy set ... --wait`. OPA readiness follows that successful
operation; Connector never invokes `opa eval`.

Install Firecracker and jailer from the same upstream release. Start
`connector-microd.service`, then run:

```bash
CONNECTOR_KVM_REQUIRED=1 bash platform/scripts/cvr-kvm-acceptance.sh
```

The backend becomes operational only after one real MicroCell completes
create/start, pause, and stop. Host probing alone is insufficient.

## Verdict

```bash
bash platform/deploy/seven-backends/linux/host-preflight.sh
CONNECTOR_BACKENDS_PROFILE=linux-kvm \
  bash platform/scripts/seven-backends-deployment-verify.sh
```

Exit `0` means all seven required operations have evidence. Exit `5` means
Connector refused the deployment claim and prints blockers. This is not a PCI,
bank, defense, or military certification.
