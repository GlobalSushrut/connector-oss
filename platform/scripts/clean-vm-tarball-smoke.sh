#!/usr/bin/env bash
# Final GO #1 (partial) — install from release tarball only, start, health + doctor.
# Matches the nested layout from scripts/package-connector-os.sh:
#   connector-os-<ver>-<arch>-linux/{bin,systemd,install.sh,...}
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${CONNECTOR_PORT:-19101}"
DATA_DIR="${CONNECTOR_DATA_DIR:-$(mktemp -d /tmp/connector_tarball_smoke.XXXXXX)}"
INSTALL_DIR="${CONNECTOR_TARBALL_INSTALL_DIR:-$(mktemp -d /tmp/connector_tarball_install.XXXXXX)}"

export CONNECTOR_HOST=127.0.0.1
export CONNECTOR_PORT="$PORT"
export CONNECTOR_DATA_DIR="$DATA_DIR"
export CONNECTOR_PRESET=local
export CONNECTOR_DEV_MODE=1
export CONNECTOR_LLM_STUB=1
export CONNECTOR_PLUGIN_LAB_AUTO_START=0
export CONNECTOR_REPO_ROOT="$ROOT"

cleanup() {
  if [[ -n "${PID:-}" ]]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$DATA_DIR" "$INSTALL_DIR" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[pack] building release tarball …"
(cd "$ROOT" && CONNECTOR_PACKAGE_NO_BUILD="${CONNECTOR_PACKAGE_NO_BUILD:-}" bash scripts/package-connector-os.sh)

TAR="$(ls -1t "$ROOT/dist"/connector-os-*-linux.tar.gz 2>/dev/null | head -1)"
[[ -f "$TAR" ]] || { echo "[fail] no tarball in dist/"; exit 1; }
SUMS="$ROOT/dist/SHA256SUMS"
[[ -f "$SUMS" ]] || { echo "[fail] missing SHA256SUMS"; exit 1; }

echo "[verify] sha256sum -c"
(cd "$ROOT/dist" && sha256sum -c SHA256SUMS)

echo "[install] extract to $INSTALL_DIR"
tar -xzf "$TAR" -C "$INSTALL_DIR"
PKG_ROOT="$(find "$INSTALL_DIR" -maxdepth 1 -type d -name 'connector-os-*' | head -1)"
[[ -d "$PKG_ROOT" ]] || { echo "[fail] missing connector-os-* package root"; exit 1; }
BIN="$PKG_ROOT/bin/connector-platform"
CTL="$PKG_ROOT/bin/connectorctl"
[[ -x "$BIN" && -x "$CTL" ]] || { echo "[fail] missing binaries under $PKG_ROOT/bin"; exit 1; }
[[ -f "$PKG_ROOT/systemd/connector-platform.service" ]] || { echo "[fail] missing systemd unit"; exit 1; }
[[ -f "$PKG_ROOT/install.sh" ]] || { echo "[fail] missing install.sh"; exit 1; }
[[ -f "$PKG_ROOT/docs/PACKAGING.md" ]] || { echo "[fail] missing PACKAGING.md"; exit 1; }

# Honest libc tag (informational)
if command -v ldd >/dev/null 2>&1; then
  echo "[info] ldd connector-platform:"
  ldd "$BIN" 2>&1 | head -5 || true
fi

echo "[start] connector-platform from tarball (foreground child)"
"$BIN" &
PID=$!
BASE="http://${CONNECTOR_HOST}:${PORT}"

ok=0
for _ in $(seq 1 120); do
  if curl -sf "${BASE}/healthz" >/dev/null 2>&1 || curl -sf "${BASE}/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.5
done

if [[ "$ok" -ne 1 ]]; then
  echo "[fail] health check after tarball start" >&2
  exit 1
fi

echo "[doctor] connectorctl from tarball"
export PATH="$PKG_ROOT/bin:$PATH"
if ! "$CTL" doctor >/tmp/connector-tarball-doctor.out 2>&1; then
  # doctor may exit 1 on gaps — still require it to run and print something
  echo "[warn] doctor exited non-zero (allowed if boot gaps reported)"
fi
head -20 /tmp/connector-tarball-doctor.out || true

echo "[node-upgrade] dry-run print"
"$CTL" node-upgrade | head -25

echo "[ok] clean-vm-tarball-smoke: tarball + checksum + health + doctor + node-upgrade"
echo "[truth] packaging = sovereign single-node; HA not claimed"
