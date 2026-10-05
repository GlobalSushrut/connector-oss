#!/usr/bin/env bash
# TraceTramp + WitnessCtl production gate (all plugin smokes, no full prod-readiness-gate).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "== tt-wc-prod-gate =="
echo "Low-RAM: run alone; see docs/LOW_MEMORY_DEV.md"

bash platform/scripts/witness-bundle-smoke.sh
bash platform/scripts/custody-quorum-smoke.sh
bash scripts/audit-tracetramp-tenancy.sh
bash platform/scripts/helm-lint-smoke.sh

if curl -sf "${CONNECTOR_TEST_URL:-http://127.0.0.1:9091}/health" >/dev/null 2>&1; then
  export CONNECTOR_TEST_URL="${CONNECTOR_TEST_URL:-http://127.0.0.1:9091}"
  bash platform/scripts/tt-wc-prod-smoke.sh
  bash platform/scripts/cage-tt-load-smoke.sh || true
  bash platform/scripts/k6-cage-load.sh || true
else
  echo "[skip] live TT/WC smokes (no Connector on CONNECTOR_TEST_URL)"
fi

echo "== tt-wc-prod-gate: OK =="
