#!/usr/bin/env bash
# P1.3 — hardened production dogfood: strict JWT, no dev/open auth, microVM preset.
#
# Usage (repo root):
#   bash platform/scripts/prod-dogfood-smoke.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_ROOT="$ROOT/platform/server"
PORT="${CONNECTOR_PORT:-19093}"
# Always use a fresh temp dir unless PROD_DOGFOOD_DATA_DIR is set (ignore inherited CONNECTOR_DATA_DIR).
DATA_DIR="${PROD_DOGFOOD_DATA_DIR:-$(mktemp -d /tmp/connector_prod_dogfood.XXXXXX)}"

export CONNECTOR_HOST=127.0.0.1
export CONNECTOR_PORT="$PORT"
export CONNECTOR_DATA_DIR="$DATA_DIR"
export CONNECTOR_PRESET=production
export CONNECTOR_DEFENSE_STRICT=1
export CONNECTOR_ENV=production
export CONNECTOR_JWT_SECRET="${CONNECTOR_JWT_SECRET:-ci-prod-dogfood-jwt-secret-min-32-bytes}"
export CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD="${CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD:-admin}"
# Production preset requires non-lab secrets. Dogfood generates ephemeral values.
export CONNECTOR_AUDIT_HMAC_KEY="${CONNECTOR_AUDIT_HMAC_KEY:-$(openssl rand -hex 32)}"
export CONNECTOR_CFNI_SECRET="${CONNECTOR_CFNI_SECRET:-ci-prod-dogfood-cfni-secret-min-32b}"
export CONNECTOR_CAGE_CAP_SECRET="${CONNECTOR_CAGE_CAP_SECRET:-ci-prod-dogfood-cage-cap-secret-32}"
# Dogfood hosts rarely have Firecracker; allow subprocess isolation with explicit break-glass.
export CONNECTOR_ALLOW_SUBPROCESS_ISOLATION="${CONNECTOR_ALLOW_SUBPROCESS_ISOLATION:-1}"
export CONNECTOR_LLM_STUB=1
export CONNECTOR_LLM_STUB_ALLOW_IN_PROD="${CONNECTOR_LLM_STUB_ALLOW_IN_PROD:-1}"
export CONNECTOR_PROTOCOL_PORT=0
export CONNECTOR_UI_RPC_PORT=0
export CONNECTOR_PROD_DOGFOOD=1
unset CONNECTOR_DEV_MODE CONNECTOR_ULTIMATE_FREE CONNECTOR_OPEN_AUTH CONNECTOR_FREE_TIER_OPEN_AUTH

export CONNECTOR_TEST_URL="http://${CONNECTOR_HOST}:${PORT}"
export CARGO_TARGET_DIR="$SERVER_ROOT/.cargo-target"

SERVER_PID=""
cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ "$DATA_DIR" == /tmp/connector_prod_dogfood.* ]]; then
    rm -rf "$DATA_DIR" || true
  fi
}
trap cleanup EXIT INT TERM

cd "$SERVER_ROOT"
cargo build -q --bin connector-platform
PLATFORM_BIN="$CARGO_TARGET_DIR/debug/connector-platform"

"$PLATFORM_BIN" &
SERVER_PID="$!"

ok=0
for _ in $(seq 1 120); do
  if curl -sf "${CONNECTOR_TEST_URL}/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.25
done
if [[ "$ok" -ne 1 ]]; then
  echo "[fail] timeout waiting for ${CONNECTOR_TEST_URL}/health" >&2
  exit 124
fi

code="$(curl -s -o /dev/null -w "%{http_code}" "${CONNECTOR_TEST_URL}/api/v1/agents")"
if [[ "$code" != "401" ]]; then
  echo "[fail] GET /api/v1/agents without auth expected 401, got $code" >&2
  exit 1
fi
echo "[ok] unauthenticated /api/v1/agents → 401"

CONNECTOR_PROD_DOGFOOD=1 cargo test --test prod_dogfood_http -- --test-threads=1
echo "[ok] prod-dogfood-smoke passed."
