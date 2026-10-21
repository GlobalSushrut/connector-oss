#!/usr/bin/env bash
# Build connector-platform and connectorctl, then write a Linux tarball.
#
# Output (CONNECTOR_PACKAGE_DIR, default: <repo>/dist):
#   connector-os-<version>-<commit>-<arch>-linux.tar.gz
#   connector-os-linux-<arch>.tar.gz          stable name for GitHub downloads
#   connector-os-linux-<arch>.tar.gz.sha256
#
# CONNECTOR_PACKAGE_NO_BUILD=1   pack binaries that are already built
# CONNECTOR_PACKAGE_UI=0         do not copy dashboard dist into the tarball
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_DIR="$ROOT/platform/server"
MANIFEST="$SERVER_DIR/Cargo.toml"
OUT_DIR="${CONNECTOR_PACKAGE_DIR:-$ROOT/dist}"
EXAMPLE="$ROOT/platform/release/connector.yaml.example"

if [[ ! -f "$MANIFEST" ]]; then
  echo "package: missing $MANIFEST" >&2
  exit 1
fi
if [[ ! -f "$EXAMPLE" ]]; then
  echo "package: missing $EXAMPLE" >&2
  exit 1
fi

VERSION="$(
  cd "$SERVER_DIR" && cargo metadata --format-version 1 --no-deps \
    | python3 -c "import json,sys; m=json.load(sys.stdin); print(next(p['version'] for p in m['packages'] if p['name']=='connector-platform'))"
)"
if [[ -z "${VERSION}" ]]; then
  echo "package: could not read connector-platform version" >&2
  exit 1
fi

COMMIT="unknown"
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
fi
SHORT="${COMMIT:0:12}"

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64) ARCH=x86_64 ;;
  aarch64 | arm64) ARCH=aarch64 ;;
  *) ARCH="$ARCH_RAW" ;;
esac
ARCH_TAG="${ARCH}-linux"
STABLE="connector-os-linux-${ARCH}.tar.gz"
VERSIONED="connector-os-${VERSION}-${SHORT}-${ARCH_TAG}.tar.gz"

mkdir -p "$OUT_DIR"

BIN_PLATFORM="${CARGO_TARGET_DIR:-$SERVER_DIR/target}/release/connector-platform"
BIN_CTL="${CARGO_TARGET_DIR:-$SERVER_DIR/target}/release/connectorctl"
if [[ ! -x "$BIN_PLATFORM" && -x "$SERVER_DIR/.cargo-target/release/connector-platform" ]]; then
  BIN_PLATFORM="$SERVER_DIR/.cargo-target/release/connector-platform"
  BIN_CTL="$SERVER_DIR/.cargo-target/release/connectorctl"
fi

if [[ "${CONNECTOR_PACKAGE_NO_BUILD:-}" != "1" ]]; then
  echo "package: cargo build --release (connector-platform + connectorctl)"
  (cd "$ROOT" && cargo build --manifest-path "$MANIFEST" --release --bin connector-platform --bin connectorctl)
fi

if [[ ! -x "$BIN_PLATFORM" || ! -x "$BIN_CTL" ]]; then
  echo "package: missing release binaries ($BIN_PLATFORM and $BIN_CTL)" >&2
  exit 1
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/connector-os-pack.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

PKG_ROOT="connector-os-${VERSION}-${SHORT}-${ARCH_TAG}"
DEST="$STAGE/$PKG_ROOT"
mkdir -p "$DEST/bin" "$DEST/systemd" "$DEST/docs" "$DEST/etc"
install -m755 "$BIN_PLATFORM" "$DEST/bin/connector-platform"
install -m755 "$BIN_CTL" "$DEST/bin/connectorctl"
install -m644 "$EXAMPLE" "$DEST/etc/connector.yaml.example"
install -m644 "$ROOT/platform/release/connector-platform.service" "$DEST/systemd/connector-platform.service"
install -m644 "$ROOT/platform/deploy/PACKAGING.md" "$DEST/docs/PACKAGING.md"
install -m755 "$ROOT/platform/deploy/install-from-tarball.sh" "$DEST/install.sh"
printf '%s\n' "$VERSION" > "$DEST/VERSION"
printf '%s\n' "$COMMIT" > "$DEST/COMMIT"

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

INCLUDE_UI=0
if [[ "${CONNECTOR_PACKAGE_UI:-1}" != "0" ]]; then
  UI_DIST="$ROOT/platform/ui-leptos/dashboard/dist"
  if [[ -f "$UI_DIST/index.html" ]]; then
    mkdir -p "$DEST/ui"
    cp -a "$UI_DIST/." "$DEST/ui/"
    INCLUDE_UI=1
  else
    echo "package: dashboard dist missing; the binary embed is used instead" >&2
  fi
fi

cat > "$DEST/MANIFEST.json" <<EOF
{
  "schema": "connector.os.package.v1",
  "name": "connector-os",
  "version": "$VERSION",
  "commit": "$COMMIT",
  "arch": "$ARCH_TAG",
  "libc": "$LIBC",
  "binary": "connector-platform",
  "cli": "connectorctl",
  "port_default": 9091,
  "ui_included": $([ "$INCLUDE_UI" = "1" ] && echo true || echo false),
  "systemd_unit": "connector-platform.service",
  "topology": "sovereign_single_node",
  "ha_claimable": false
}
EOF

cat > "$DEST/README.txt" <<EOF
Connector prebuilt node
=======================
version: $VERSION
commit:  $COMMIT

Run without installing system-wide:
  ./bin/connector-platform

Install for this user (no compiler):
  curl -fsSL https://raw.githubusercontent.com/GlobalSushrut/connector-oss/main/platform/release/install.sh | bash

Then open http://127.0.0.1:9091/
EOF

echo "package: writing $OUT_DIR/$VERSIONED"
tar -C "$STAGE" -czf "$OUT_DIR/$VERSIONED" "$PKG_ROOT"
cp -f "$OUT_DIR/$VERSIONED" "$OUT_DIR/$STABLE"
(
  cd "$OUT_DIR"
  sha256sum "$STABLE" > "${STABLE}.sha256"
)

# Read the listing once. Piping tar into grep -q trips pipefail: grep exits
# at the first hit and tar dies with SIGPIPE, which looks like a missing file.
members="$(tar -tzf "$OUT_DIR/$STABLE")"
for n in \
  "$PKG_ROOT/bin/connector-platform" \
  "$PKG_ROOT/bin/connectorctl" \
  "$PKG_ROOT/etc/connector.yaml.example" \
  "$PKG_ROOT/install.sh" \
  "$PKG_ROOT/VERSION" \
  "$PKG_ROOT/COMMIT" \
  "$PKG_ROOT/MANIFEST.json" \
  "$PKG_ROOT/README.txt"
do
  if ! grep -qxF -- "$n" <<<"$members"; then
    echo "package: tarball missing member: $n" >&2
    echo "package: archive listing:" >&2
    printf '%s\n' "$members" | head -40 >&2
    exit 1
  fi
done

echo "package: OK $OUT_DIR/$STABLE"
echo "package: checksum $OUT_DIR/${STABLE}.sha256"
echo "package: ui_included=$INCLUDE_UI commit=$SHORT"
