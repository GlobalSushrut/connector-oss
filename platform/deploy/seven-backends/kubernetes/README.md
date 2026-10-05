# Seven backends on Kubernetes

This installs real upstream controllers; Connector does not vendor them.

The functional gate is:

```bash
connectorctl govern deploy-verify kubernetes
```

`operational_ready` can become true after all seven operations succeed.
`production_eligible` remains false while NVIDIA labels the OpenShell
Kubernetes Helm chart experimental and “do not use it in production.”

## Required upstream releases

Set explicit released versions. Floating `latest`, `main`, and development
charts are refused by policy:

```bash
export KEYCLOAK_OPERATOR_VERSION=<released-version>
export SPIRE_CHART_VERSION=<released-version>
export OPENSHELL_CHART_VERSION=<released-version>
```

### Keycloak

Install the official Keycloak Operator, preferably through OLM with manual
upgrade approval. For a pinned kubectl installation:

```bash
kubectl create namespace keycloak
kubectl apply -k \
  "github.com/keycloak/keycloak-k8s-resources/kubernetes?ref=${KEYCLOAK_OPERATOR_VERSION}"
envsubst < keycloak.yaml.example | kubectl apply -f -
```

The example requires pre-created TLS, database username, and database password
Secrets. Bootstrap the `connector` realm and confidential PKCE client through
Keycloak administration without storing the client secret in git.

### SPIRE

Use the official SPIFFE hardened charts and production recommendations:

```bash
helm upgrade --install --create-namespace -n spire-mgmt spire-crds spire-crds \
  --repo https://spiffe.github.io/helm-charts-hardened/ \
  --version "$SPIRE_CHART_VERSION"
helm upgrade --install -n spire-mgmt spire spire \
  --repo https://spiffe.github.io/helm-charts-hardened/ \
  --version "$SPIRE_CHART_VERSION" \
  -f spire-values.yaml
```

The Connector chart mounts the CSI Workload API socket. A SPIFFE-shaped string
is not readiness; `spire-agent api fetch x509` must return an SVID.

### OpenShell and OPA

Install the required Agent Sandbox controller/CRDs first, then NVIDIA's
released OCI chart:

```bash
helm upgrade --install --create-namespace -n openshell openshell \
  oci://ghcr.io/nvidia/openshell/helm-chart \
  --version "$OPENSHELL_CHART_VERSION" \
  -f openshell-values.yaml
```

Use `combined` supervisor topology for full enforcement. OPA is inside
OpenShell. Connector never deploys a second OPA and never calls `opa eval`.

### Firecracker

Label and taint dedicated KVM nodes, run `connector-microd` as a privileged
host service/DaemonSet there, and expose only its Unix socket and verified
ready file to Connector. The Connector pod itself remains non-privileged.

The profile requires a real create/start, pause, and destroy sequence through
microd. `/dev/kvm` presence alone is not sufficient.

### Connector and functional gate

```bash
helm upgrade --install connector ../../helm/connector \
  -f connector-values.yaml
```

The post-install Job calls the authenticated deployment verifier and fails the
Helm release when operational evidence is incomplete. `/readyz` remains process
readiness and is not rewritten.

This deployment is not a bank, defense, military, PCI, or SOC certification.
