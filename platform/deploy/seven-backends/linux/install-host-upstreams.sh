#!/usr/bin/env bash
# Install only operator-supplied, digest-pinned upstream artifacts.
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "[error] run as root" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

require() {
  [[ -n "${!1:-}" ]] || { echo "[error] required: $1" >&2; exit 2; }
}

verify() {
  local path="$1" expected="$2" actual
  [[ -f "$path" ]] || { echo "[error] missing artifact: $path" >&2; exit 2; }
  actual="$(sha256sum "$path" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || {
    echo "[error] SHA-256 mismatch: $path" >&2
    exit 2
  }
}

for name in OPENSHELL_PACKAGE OPENSHELL_PACKAGE_SHA256 \
  SPIRE_SERVER_BIN SPIRE_SERVER_SHA256 SPIRE_AGENT_BIN SPIRE_AGENT_SHA256 \
  FIRECRACKER_BIN FIRECRACKER_SHA256 JAILER_BIN JAILER_SHA256 \
  COSIGN_BIN COSIGN_SHA256 CONNECTOR_MICROD_BIN CONNECTOR_MICROD_SHA256
do
  require "$name"
done

verify "$OPENSHELL_PACKAGE" "$OPENSHELL_PACKAGE_SHA256"
verify "$SPIRE_SERVER_BIN" "$SPIRE_SERVER_SHA256"
verify "$SPIRE_AGENT_BIN" "$SPIRE_AGENT_SHA256"
verify "$FIRECRACKER_BIN" "$FIRECRACKER_SHA256"
verify "$JAILER_BIN" "$JAILER_SHA256"
verify "$COSIGN_BIN" "$COSIGN_SHA256"
verify "$CONNECTOR_MICROD_BIN" "$CONNECTOR_MICROD_SHA256"

case "$OPENSHELL_PACKAGE" in
  *.deb) dpkg -i "$OPENSHELL_PACKAGE" ;;
  *.rpm) rpm -Uvh "$OPENSHELL_PACKAGE" ;;
  *) echo "[error] OPENSHELL_PACKAGE must be a signed .deb or .rpm release package" >&2; exit 2 ;;
esac

install -m 0755 "$SPIRE_SERVER_BIN" /usr/local/bin/spire-server
install -m 0755 "$SPIRE_AGENT_BIN" /usr/local/bin/spire-agent
install -m 0755 "$FIRECRACKER_BIN" /usr/local/bin/firecracker
install -m 0755 "$JAILER_BIN" /usr/local/bin/jailer
install -m 0755 "$COSIGN_BIN" /usr/local/bin/cosign
install -m 0755 "$CONNECTOR_MICROD_BIN" /usr/bin/connector-microd

if ! id spire-server >/dev/null 2>&1; then
  useradd --system --home /var/lib/spire/server --shell /usr/sbin/nologin spire-server
fi

install -d -m 0750 /etc/connector/seven-backends/spire
install -d -o spire-server -g spire-server -m 0750 /var/lib/spire/server /run/spire/server
install -d -o root -g root -m 0750 /var/lib/spire/agent /run/spire/agent

install -m 0644 \
  "$ROOT/systemd/connector-spire-server.service" \
  /etc/systemd/system/connector-spire-server.service
install -m 0644 \
  "$ROOT/systemd/connector-spire-agent.service" \
  /etc/systemd/system/connector-spire-agent.service
install -m 0644 \
  "$ROOT/../../../connector-microd/systemd/connector-microd.service" \
  /etc/systemd/system/connector-microd.service

systemctl daemon-reload

cat <<'EOF'
[ok] digest-pinned host artifacts installed
[next] write reviewed SPIRE configs:
  /etc/connector/seven-backends/spire/server.conf
  /etc/connector/seven-backends/spire/agent.conf
[next] write /etc/connector/microd.env with measured kernel/rootfs paths and hashes
[next] enable services only after reviewing those files:
  systemctl enable --now connector-spire-server connector-spire-agent connector-microd
[next] run OpenShell gateway under the same service account as connector-platform,
       then run host-preflight.sh and connectorctl govern deploy-verify linux-kvm
EOF
