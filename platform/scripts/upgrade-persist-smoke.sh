#!/usr/bin/env bash
# P0.1 — data_dir survives stop/start (simulates tarball N→N+1 without wiping data).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_ROOT="$ROOT/platform/server"
export CONNECTOR_REPO_ROOT="$ROOT"
DATA_DIR="${CONNECTOR_DATA_DIR:-$(mktemp -d /tmp/connector_upgrade.XXXXXX)}"
MARKER="$DATA_DIR/.upgrade_smoke_marker"
PORT="${CONNECTOR_PORT:-19094}"

export CONNECTOR_HOST=127.0.0.1
export CONNECTOR_PORT="$PORT"
export CONNECTOR_DATA_DIR="$DATA_DIR"
export CONNECTOR_PRESET=local
export CONNECTOR_DEV_MODE=1
export CONNECTOR_LLM_STUB=1
export CARGO_TARGET_DIR="$SERVER_ROOT/.cargo-target"

CTL="$CARGO_TARGET_DIR/debug/connectorctl"
BASE="http://${CONNECTOR_HOST}:${PORT}"

cleanup() {
  "$CTL" stop 2>/dev/null || true
  if [[ "$DATA_DIR" == /tmp/connector_upgrade.* ]]; then
    rm -rf "$DATA_DIR" || true
  fi
}
trap cleanup EXIT INT TERM

cd "$SERVER_ROOT"
cargo build -q --bin connector-platform --bin connectorctl

echo "marker-v1" >"$MARKER"
"$CTL" start

ok=0
for _ in $(seq 1 90); do
  if curl -sf "${BASE}/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.5
done
[[ "$ok" -eq 1 ]] || { echo "[fail] health timeout"; exit 124; }

"$CTL" stop
sleep 1
[[ -f "$MARKER" ]] || { echo "[fail] marker missing after stop"; exit 1; }

"$CTL" start
ok=0
for _ in $(seq 1 90); do
  if curl -sf "${BASE}/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.5
done
[[ "$ok" -eq 1 ]] || { echo "[fail] health timeout after restart"; exit 124; }

grep -q marker-v1 "$MARKER" || { echo "[fail] marker content changed"; exit 1; }
echo "[ok] upgrade-persist-smoke: data_dir intact across stop/start"
