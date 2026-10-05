#!/usr/bin/env bash
# Install Connector OS from an extracted release tarball onto FHS paths (Linux).
# Run from the package root (directory containing bin/, systemd/, install.sh) as root.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "install-from-tarball: must run as root (or sudo ./install.sh)" >&2
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${CONNECTOR_INSTALL_DIR:-/usr/local/bin}"
DATA_DIR="${CONNECTOR_DATA_DIR:-/var/lib/connector}"
LOG_DIR="${CONNECTOR_LOG_DIR:-/var/log/connector}"
ETC_DIR="${CONNECTOR_ETC_DIR:-/etc/connector}"
SERVICE_USER="${CONNECTOR_SERVICE_USER:-connector}"

test -x "$HERE/bin/connector-platform" || { echo "missing bin/connector-platform" >&2; exit 1; }
test -x "$HERE/bin/connectorctl" || { echo "missing bin/connectorctl" >&2; exit 1; }
test -f "$HERE/systemd/connector-platform.service" || { echo "missing systemd unit" >&2; exit 1; }

if ! id "$SERVICE_USER" &>/dev/null; then
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin \
    --comment "Connector Platform" "$SERVICE_USER"
fi

mkdir -p "$DATA_DIR" "$LOG_DIR" "$ETC_DIR" "$INSTALL_DIR" "$DATA_DIR/ui"
install -m755 "$HERE/bin/connector-platform" "$INSTALL_DIR/connector-platform"
install -m755 "$HERE/bin/connectorctl" "$INSTALL_DIR/connectorctl"
install -m644 "$HERE/systemd/connector-platform.service" /etc/systemd/system/connector-platform.service

if [[ -f "$HERE/etc/connector.yaml.example" && ! -f "$ETC_DIR/connector.yaml.example" ]]; then
  install -m644 "$HERE/etc/connector.yaml.example" "$ETC_DIR/connector.yaml.example"
fi
if [[ -f "$HERE/etc/connector.yaml.example" && ! -f "$ETC_DIR/connector.yaml" ]]; then
  install -m640 "$HERE/etc/connector.yaml.example" "$ETC_DIR/connector.yaml"
  chown root:"$SERVICE_USER" "$ETC_DIR/connector.yaml"
fi
if [[ -d "$HERE/ui" ]]; then
  cp -a "$HERE/ui/." "$DATA_DIR/ui/"
fi

touch "$ETC_DIR/env"
chmod 600 "$ETC_DIR/env"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$LOG_DIR"
chown root:"$SERVICE_USER" "$ETC_DIR"
chmod 750 "$ETC_DIR"

systemctl daemon-reload
echo "Installed. Next:"
echo "  1. Edit $ETC_DIR/env (secrets) — never world-readable"
echo "  2. systemctl enable --now connector-platform"
echo "  3. curl -fsS http://127.0.0.1:9091/healthz"
echo "  4. connectorctl doctor"
echo "Topology: sovereign single-node (packaging does not enable HA)."
