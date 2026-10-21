#!/usr/bin/env bash
# Turn the prebuilt tarball into a Debian package and a Docker build context.
# Run from the repo after platform/release/package.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${CONNECTOR_PACKAGE_DIR:-$ROOT/dist}"
TAR="$OUT_DIR/connector-os-linux-x86_64.tar.gz"
SERVICE="$ROOT/platform/release/connector-platform.service"

if [[ ! -f "$TAR" ]]; then
  echo "distributions: missing $TAR" >&2
  exit 1
fi
if [[ ! -f "$SERVICE" ]]; then
  echo "distributions: missing $SERVICE" >&2
  exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/connector-dist.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

tar -xzf "$TAR" -C "$WORK"
PKG_ROOT="$(find "$WORK" -mindepth 1 -maxdepth 1 -type d -name 'connector-os-*' | head -1)"
test -n "$PKG_ROOT"
test -x "$PKG_ROOT/bin/connector-platform"
test -x "$PKG_ROOT/bin/connectorctl"

VERSION="$(tr -d '[:space:]' < "$PKG_ROOT/VERSION")"
DEB_STAGE="$WORK/deb/connector-os_${VERSION}_amd64"
mkdir -p \
  "$DEB_STAGE/DEBIAN" \
  "$DEB_STAGE/usr/bin" \
  "$DEB_STAGE/lib/systemd/system" \
  "$DEB_STAGE/usr/share/connector" \
  "$DEB_STAGE/usr/share/doc/connector-os"

install -m755 "$PKG_ROOT/bin/connector-platform" "$DEB_STAGE/usr/bin/connector-platform"
install -m755 "$PKG_ROOT/bin/connectorctl" "$DEB_STAGE/usr/bin/connectorctl"
install -m644 "$SERVICE" "$DEB_STAGE/lib/systemd/system/connector-platform.service"
install -m644 "$PKG_ROOT/etc/connector.yaml.example" "$DEB_STAGE/usr/share/connector/connector.yaml.example"
if [[ -d "$PKG_ROOT/ui" ]]; then
  mkdir -p "$DEB_STAGE/usr/share/connector/ui"
  cp -a "$PKG_ROOT/ui/." "$DEB_STAGE/usr/share/connector/ui/"
fi
install -m644 "$PKG_ROOT/README.txt" "$DEB_STAGE/usr/share/doc/connector-os/README.txt"

cat > "$DEB_STAGE/DEBIAN/control" <<EOF
Package: connector-os
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Connector <opensource@cnktros.com>
Depends: libc6 (>= 2.35), adduser
Homepage: https://github.com/GlobalSushrut/connector-oss
Description: Connector node
 Control plane for AI agents. Installs the node, connectorctl, and a systemd service.
EOF

cat > "$DEB_STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if ! getent passwd connector >/dev/null; then
  adduser --system --group --home /var/lib/connector --no-create-home connector
fi
mkdir -p /var/lib/connector /var/log/connector /etc/connector /usr/share/connector
if [ ! -f /etc/connector/connector.yaml ]; then
  cp /usr/share/connector/connector.yaml.example /etc/connector/connector.yaml
  chown root:connector /etc/connector/connector.yaml
  chmod 640 /etc/connector/connector.yaml
fi
chown -R connector:connector /var/lib/connector /var/log/connector
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl enable connector-platform.service || true
  systemctl restart connector-platform.service || true
fi
EOF

cat > "$DEB_STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop connector-platform.service || true
  systemctl disable connector-platform.service || true
fi
EOF
chmod 755 "$DEB_STAGE/DEBIAN/postinst" "$DEB_STAGE/DEBIAN/prerm"

DEB="$OUT_DIR/connector-os_amd64.deb"
dpkg-deb --root-owner-group --build "$DEB_STAGE" "$DEB"

IMAGE="$OUT_DIR/image"
rm -rf "$IMAGE"
mkdir -p "$IMAGE"
install -m755 "$PKG_ROOT/bin/connector-platform" "$IMAGE/connector-platform"
install -m755 "$PKG_ROOT/bin/connectorctl" "$IMAGE/connectorctl"
cp "$ROOT/platform/deploy/Dockerfile.release" "$IMAGE/Dockerfile"
cat > "$IMAGE/connector.yaml" <<'EOF'
version: 1
preset: local
connector:
  host: "0.0.0.0"
  port: 9091
EOF

echo "distributions: $DEB"
echo "distributions: image context $IMAGE"
