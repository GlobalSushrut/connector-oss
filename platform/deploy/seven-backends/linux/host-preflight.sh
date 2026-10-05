#!/usr/bin/env bash
set -euo pipefail

fail() { echo "[error] $*" >&2; exit 1; }
ok() { echo "[ok] $*"; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "missing upstream binary: $1"; }
need_env() { [[ -n "${!1:-}" ]] || fail "missing environment value: $1"; }

for cmd in curl openshell spire-agent firecracker jailer cosign python3; do
  need_cmd "$cmd"
done

[[ -r /dev/kvm && -w /dev/kvm ]] || fail "/dev/kvm is not usable by this account"
ok "/dev/kvm usable"

openshell version >/dev/null
openshell status >/dev/null
ok "OpenShell CLI reached its mTLS gateway"

need_env SPIFFE_ENDPOINT_SOCKET
spire-agent api fetch x509 -socketPath "$SPIFFE_ENDPOINT_SOCKET" \
  | awk '/SPIFFE ID:/ {found=1} END {exit(found ? 0 : 1)}' \
  || fail "SPIRE Workload API did not return a SPIFFE ID"
ok "SPIRE Workload API returned an X.509 SVID"

MICROD_READY="${CONNECTOR_MICROD_READY_FILE:-/run/connector/microd.ready}"
python3 - "$MICROD_READY" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    row = json.load(f)
if row.get("verified") is not True:
    raise SystemExit("microd ready file is not verified")
PY
ok "connector-microd reports verified assets"

need_env CONNECTOR_COSIGN_BLOB
need_env CONNECTOR_COSIGN_SIGNATURE
COSIGN=(cosign verify-blob --signature "$CONNECTOR_COSIGN_SIGNATURE")
if [[ -n "${CONNECTOR_COSIGN_KEY:-}" ]]; then
  COSIGN+=(--key "$CONNECTOR_COSIGN_KEY")
elif [[ -n "${CONNECTOR_COSIGN_CERTIFICATE:-}" ]]; then
  COSIGN+=(--certificate "$CONNECTOR_COSIGN_CERTIFICATE")
else
  fail "set CONNECTOR_COSIGN_KEY or CONNECTOR_COSIGN_CERTIFICATE"
fi
"${COSIGN[@]}" "$CONNECTOR_COSIGN_BLOB" >/dev/null
ok "cosign verified the release manifest"

need_env CONNECTOR_SSO_DISCOVERY_URL
curl --fail --silent --show-error "$CONNECTOR_SSO_DISCOVERY_URL" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["issuer"] and d["jwks_uri"]'
ok "Keycloak OIDC discovery returned issuer and jwks_uri"

OTEL_HEALTH_URL="${CONNECTOR_OTEL_HEALTH_URL:-http://127.0.0.1:13133/}"
curl --fail --silent --show-error "$OTEL_HEALTH_URL" >/dev/null
ok "OpenTelemetry Collector health endpoint ready"

echo "[honesty] preflight is not the verdict; perform a real OIDC login, OpenShell policy set,"
echo "[honesty] Firecracker lifecycle, and OTLP export, then run deploy-verify"
