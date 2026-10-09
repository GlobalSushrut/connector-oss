#!/usr/bin/env bash
# Phase 1.7 — build release binaries and emit a single connector-os tarball.
#
# Usage (repo root):
#   bash scripts/package-connector-os.sh
#   CONNECTOR_PACKAGE_DIR=/tmp/out bash scripts/package-connector-os.sh
#   CONNECTOR_PACKAGE_NO_BUILD=1 bash scripts/package-connector-os.sh
#   CONNECTOR_PACKAGE_UI=1 bash scripts/package-connector-os.sh   # include dashboard dist if present
#
# Output: $CONNECTOR_PACKAGE_DIR/connector-os-<semver>-<cpu>-linux.tar.gz + SHA256SUMS
# Layout mirrors Linux/POSIX FHS install helper (install-from-tarball.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_DIR="$ROOT/platform/server"
MANIFEST="$SERVER_DIR/Cargo.toml"
OUT_DIR="${CONNECTOR_PACKAGE_DIR:-$ROOT/dist}"

if [[ ! -f "$MANIFEST" ]]; then
  echo "package-connector-os: missing $MANIFEST" >&2
  exit 1
fi

VERSION="$(
  cd "$SERVER_DIR" && cargo metadata --format-version 1 --no-deps 2>/dev/null \
    | python3 -c "import json,sys; m=json.load(sys.stdin); print(next(p['version'] for p in m['packages'] if p['name']=='connector-platform'))"
)"
if [[ -z "${VERSION:-}" || "$VERSION" == "" ]]; then
  echo "package-connector-os: could not read connector-platform version from cargo metadata" >&2
  exit 1
fi

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64) ARCH_TAG=x86_64-linux ;;
  aarch64 | arm64) ARCH_TAG=aarch64-linux ;;
  *) ARCH_TAG="${ARCH_RAW}-linux" ;;
esac

TAR_NAME="connector-os-${VERSION}-${ARCH_TAG}.tar.gz"
mkdir -p "$OUT_DIR"
OUT_PATH="$OUT_DIR/$TAR_NAME"

BIN_PLATFORM="$SERVER_DIR/target/release/connector-platform"
BIN_CTL="$SERVER_DIR/target/release/connectorctl"
# Prefer PLATFORM_CARGO_TARGET_DIR layout when used by Makefile
if [[ ! -x "$BIN_PLATFORM" && -x "$SERVER_DIR/.cargo-target/release/connector-platform" ]]; then
  BIN_PLATFORM="$SERVER_DIR/.cargo-target/release/connector-platform"
  BIN_CTL="$SERVER_DIR/.cargo-target/release/connectorctl"
fi

if [[ "${CONNECTOR_PACKAGE_NO_BUILD:-}" != "1" ]]; then
  echo "package-connector-os: cargo build --release (connector-platform + connectorctl) ..."
  (cd "$ROOT" && cargo build --manifest-path "$MANIFEST" --release --bin connector-platform --bin connectorctl)
fi

if [[ ! -x "$BIN_PLATFORM" || ! -x "$BIN_CTL" ]]; then
  echo "package-connector-os: missing release binaries (expected $BIN_PLATFORM and $BIN_CTL)" >&2
  exit 1
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/connector-os-pack.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

mkdir -p "$STAGE/bin" "$STAGE/systemd" "$STAGE/docs" "$STAGE/etc"
install -m755 "$BIN_PLATFORM" "$STAGE/bin/connector-platform"
install -m755 "$BIN_CTL" "$STAGE/bin/connectorctl"
install -m644 "$ROOT/connector.yaml.example" "$STAGE/etc/connector.yaml.example"
install -m644 "$ROOT/platform/deploy/systemd/connector-platform.service" "$STAGE/systemd/connector-platform.service"
install -m644 "$ROOT/platform/deploy/PACKAGING.md" "$STAGE/docs/PACKAGING.md"
install -m755 "$ROOT/platform/deploy/install-from-tarball.sh" "$STAGE/install.sh"
printf '%s\n' "$VERSION" > "$STAGE/VERSION"
LIBC="unknown"
if command -v ldd >/dev/null 2>&1; then
  if ldd "$BIN_PLATFORM" 2>/dev/null | grep -qi musl; then
    LIBC=musl
  elif ldd "$BIN_PLATFORM" 2>/dev/null | grep -qiE 'libc\.so|glibc'; then
    LIBC=glibc
  elif ! ldd "$BIN_PLATFORM" >/dev/null 2>&1; then
    LIBC=static-or-non-elf
  fi
fi

cat > "$STAGE/MANIFEST.json" <<EOF
{
  "schema": "connector.os.package.v1",
  "name": "connector-os",
  "version": "$VERSION",
  "arch": "$ARCH_TAG",
  "libc": "$LIBC",
  "binary": "connector-platform",
  "cli": "connectorctl",
  "port_default": 9091,
  "systemd_unit": "connector-platform.service",
  "topology": "sovereign_single_node",
  "ha_claimable": false,
  "honesty": "Packaging does not imply HA, mesh, or multi-region"
}
EOF

INCLUDE_UI=0
# Default: include UI when dist exists. Set CONNECTOR_PACKAGE_UI=0 for API-only packages.
if [[ "${CONNECTOR_PACKAGE_UI:-1}" != "0" ]]; then
  UI_DIST="$ROOT/platform/ui-leptos/dashboard/dist"
  if [[ ! -f "$UI_DIST/index.html" ]] && command -v trunk >/dev/null 2>&1; then
    echo "package-connector-os: building dashboard (trunk) ..."
    (cd "$ROOT/platform/ui-leptos/dashboard" && trunk build --release) || true
  fi
  if [[ -f "$UI_DIST/index.html" ]]; then
    mkdir -p "$STAGE/ui"
    cp -a "$UI_DIST/." "$STAGE/ui/"
    INCLUDE_UI=1
  else
    echo "package-connector-os: WARN — dashboard dist missing; binary embed/stub will serve UI" >&2
  fi
fi

cat > "$STAGE/README.txt" <<EOF
Connector OS — production node tarball
======================================
Contents:
  bin/connector-platform   node daemon (env / connector.yaml; no argv --port)
  bin/connectorctl         operator CLI
  systemd/connector-platform.service
  etc/connector.yaml.example
  install.sh               FHS install helper (root)
  docs/PACKAGING.md
  VERSION, MANIFEST.json
$([ "$INCLUDE_UI" = "1" ] && echo "  ui/                     dashboard assets" || echo "  (ui omitted — embed/stub at runtime; set CONNECTOR_PACKAGE_UI=0 to silence)")

Quick start (foreground, no root):
  ./bin/connectorctl node start --foreground

Systemd (root):
  sudo ./install.sh
  sudo systemctl enable --now connector-platform

Verify:
  curl -fsS http://127.0.0.1:9091/healthz
  curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9091/
  connectorctl node doctor
  connectorctl node support-bundle --out ./support.json

Never commit secrets. Topology is single-node until HA is separately proven.
EOF

# Flat names for tar members under package root dir
PKG_ROOT="connector-os-${VERSION}-${ARCH_TAG}"
mkdir -p "$STAGE/_root"
mv "$STAGE/bin" "$STAGE/systemd" "$STAGE/docs" "$STAGE/etc" \
   "$STAGE/VERSION" "$STAGE/MANIFEST.json" "$STAGE/README.txt" "$STAGE/install.sh" \
   "$STAGE/_root/"
if [[ "$INCLUDE_UI" = "1" ]]; then
  mv "$STAGE/ui" "$STAGE/_root/"
fi
mv "$STAGE/_root" "$STAGE/$PKG_ROOT"

echo "package-connector-os: writing $OUT_PATH ..."
tar -C "$STAGE" -czf "$OUT_PATH" "$PKG_ROOT"

need_files=(
  "$PKG_ROOT/bin/connector-platform"
  "$PKG_ROOT/bin/connectorctl"
  "$PKG_ROOT/systemd/connector-platform.service"
  "$PKG_ROOT/etc/connector.yaml.example"
  "$PKG_ROOT/install.sh"
  "$PKG_ROOT/docs/PACKAGING.md"
  "$PKG_ROOT/VERSION"
  "$PKG_ROOT/MANIFEST.json"
  "$PKG_ROOT/README.txt"
)
for n in "${need_files[@]}"; do
  if ! tar -tzf "$OUT_PATH" | grep -qx "$n"; then
    echo "package-connector-os: tarball missing member: $n" >&2
    exit 1
  fi
done

SUMS_PATH="$OUT_DIR/SHA256SUMS"
(
  cd "$OUT_DIR"
  sha256sum "$(basename "$OUT_PATH")" >"$(basename "$SUMS_PATH")"
)
echo "package-connector-os: OK — $OUT_PATH"
echo "package-connector-os: checksums — $SUMS_PATH"
echo "package-connector-os: ui_included=$INCLUDE_UI"
