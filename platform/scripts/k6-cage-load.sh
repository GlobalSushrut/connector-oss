#!/usr/bin/env bash
# k6 cage load test (plan Phase 2). Skips gracefully when k6 is not installed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT}/platform/k6/cage-load-test.js"

if ! command -v k6 >/dev/null 2>&1; then
  echo "[skip] k6 not installed — install from https://grafana.com/docs/k6/latest/set-up/install-k6/"
  echo "[hint] bash platform/scripts/cage-tt-load-smoke.sh for bash-based load probe"
  exit 0
fi

BASE="${CONNECTOR_TEST_URL:-http://127.0.0.1:9091}"
if ! curl -sf "${BASE%/}/health" >/dev/null 2>&1; then
  echo "[skip] no Connector on ${BASE} (start node or set CONNECTOR_TEST_URL)"
  exit 0
fi

echo "== k6 cage-load @ ${BASE} =="
export CONNECTOR_TEST_URL="${BASE}"
export CONNECTOR_DEV_TOKEN="${CONNECTOR_DEV_TOKEN:-dev-token}"
export K6_VUS="${K6_VUS:-25}"
export K6_DURATION="${K6_DURATION:-45s}"

k6 run "$SCRIPT"
echo "[ok] k6 cage-load finished"
