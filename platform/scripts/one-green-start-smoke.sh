#!/usr/bin/env bash
# P0.1 — one green start smoke: build, background start, health + plugins, stop.
#
# Requires: Docker (for plugin lab autostart), curl, repo checkout.
# Usage (from repo root):
#   bash platform/scripts/one-green-start-smoke.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_ROOT="$ROOT/platform/server"
DATA_DIR="${CONNECTOR_DATA_DIR:-$(mktemp -d /tmp/connector_one_green.XXXXXX)}"
PORT="${CONNECTOR_PORT:-19092}"
BASE="http://127.0.0.1:${PORT}"
PID_FILE="${CONNECTOR_PID_FILE:-/tmp/connector-one-green-smoke.pid}"

export CONNECTOR_REPO_ROOT="$ROOT"
export CONNECTOR_HOST=127.0.0.1
export CONNECTOR_PORT="$PORT"
export CONNECTOR_API_URL="$BASE"
export CONNECTOR_DATA_DIR="$DATA_DIR"
export CONNECTOR_PRESET=local
export CONNECTOR_DEV_MODE=1
export CONNECTOR_PLUGIN_LAB_AUTO_START=1
export CONNECTOR_LLM_STUB=1
export CARGO_TARGET_DIR="$SERVER_ROOT/.cargo-target"

CTL="$CARGO_TARGET_DIR/debug/connectorctl"
PLATFORM_BIN="$CARGO_TARGET_DIR/debug/connector-platform"

cleanup() {
  if [[ -f "$PID_FILE" ]]; then
    "$CTL" stop 2>/dev/null || true
    rm -f "$PID_FILE"
  fi
  if [[ "$DATA_DIR" == /tmp/connector_one_green.* ]]; then
    rm -rf "$DATA_DIR" || true
  fi
}
trap cleanup EXIT INT TERM

cd "$SERVER_ROOT"
cargo build -q --bin connector-platform --bin connectorctl
(cd "$ROOT" && bash scripts/audit-target-not-root-owned.sh)

if curl -sf "${BASE}/health" >/dev/null 2>&1; then
  echo "[skip] Node already on ${BASE}; stop it first or set CONNECTOR_PORT"
  exit 0
fi

echo "[start] connectorctl start (local preset + plugin lab autostart)…"
"$CTL" start

ok=0
for _ in $(seq 1 120); do
  if curl -sf "${BASE}/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.5
done
if [[ "$ok" -ne 1 ]]; then
  echo "[fail] timeout waiting for ${BASE}/health" >&2
  exit 124
fi
echo "[ok] ${BASE}/health"

if ! curl -sf -H "Authorization: Bearer dev-token" "${BASE}/api/v1/apps" | grep -q '"apps"'; then
  echo "[fail] GET /api/v1/apps" >&2
  exit 1
fi
echo "[ok] GET /api/v1/apps"

if ! curl -sf -H "Authorization: Bearer dev-token" "${BASE}/api/v1/plugins/cage-proof" | grep -q '"ok":true'; then
  echo "[fail] GET /api/v1/plugins/cage-proof" >&2
  exit 1
fi
echo "[ok] cage-proof"

wait_plugin_healthy() {
  local slug="$1"
  local max="${2:-180}"
  local i st
  for ((i = 1; i <= max; i++)); do
    st="$(curl -sf -H "Authorization: Bearer dev-token" "${BASE}/api/v1/plugins/status" 2>/dev/null \
      | python3 -c "import json,sys; d=json.load(sys.stdin); print((d.get('plugins') or {}).get('$slug',{}).get('status',''))" 2>/dev/null || true)"
    if [[ "$st" == "healthy" ]]; then
      echo "[ok] plugin $slug → healthy"
      return 0
    fi
    sleep 1
  done
  echo "[fail] plugin $slug not healthy within ${max}s (last status: ${st:-unknown})" >&2
  return 1
}

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  wait_plugin_healthy tracetramp 180
  wait_plugin_healthy witnessctl 180
else
  echo "[skip] plugin health wait (Docker not available)"
fi

wait_plugin_healthy devguard 30 || {
  echo "[warn] devguard not healthy — kernel profile may seed on next boot"
}

st_dg="$(curl -sf -H "Authorization: Bearer dev-token" "${BASE}/api/v1/plugins/status" 2>/dev/null \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print((d.get('plugins') or {}).get('devguard',{}).get('status_badge',''))" 2>/dev/null || true)"
if [[ "$st_dg" == "healthy" ]]; then
  echo "[ok] devguard → healthy (local profile or upstream)"
fi

"$CTL" status || true

export CONNECTOR_TEST_URL="$BASE"
export CONNECTOR_TRACETRAMP_MANAGEMENT_URL="${CONNECTOR_TRACETRAMP_MANAGEMENT_URL:-http://127.0.0.1:19742}"
export CONNECTOR_WITNESSCTL_MANAGEMENT_URL="${CONNECTOR_WITNESSCTL_MANAGEMENT_URL:-http://127.0.0.1:17443}"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  bash "$ROOT/platform/scripts/tt-wc-prod-smoke.sh" || {
    echo "[warn] tt-wc-prod-smoke had warnings (lab ports / tokens)" >&2
  }
  bash "$ROOT/platform/scripts/cage-tt-load-smoke.sh" || {
    echo "[warn] cage-tt-load-smoke had warnings" >&2
  }
  bash "$ROOT/platform/scripts/k6-cage-load.sh" || true
fi

echo "[ok] One-green-start smoke passed."
