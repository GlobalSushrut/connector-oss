#!/usr/bin/env bash
# IIA P10.9 — court gate aggregates T19–T24 (single node).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FAIL=0
export CONNECTOR_IIA_KEEP_NODE=1
export CONNECTOR_IIA_PORT="${CONNECTOR_IIA_PORT:-18190}"
export CONNECTOR_IIA_SUFFIX="court_$(date +%s)"
export CONNECTOR_IIA_DATA_DIR="${CONNECTOR_IIA_DATA_DIR:-$ROOT/.iia-court-data-$$}"
# Fresh node for court run (avoids agent_limit from prior soaks).
fuser -k "${CONNECTOR_IIA_PORT}/tcp" 2>/dev/null || true
sleep 1

# Shared court node registers many agents — raise Dev cap (default is 3).
export CONNECTOR_DEV_AGENT_CAP="${CONNECTOR_DEV_AGENT_CAP:-32}"

echo "== IIA court gate =="
bash "$ROOT/platform/scripts/iia-p0-gate.sh" || FAIL=1

for g in iia-n4-gate iia-qpr-gate docklock-bypass-adversarial matrix-isolation-gate iia-continuity-gate iia-forensics-gate agent-identity-envelope-gate; do
  echo "-- $g --"
  if ! bash "$ROOT/platform/scripts/${g}.sh"; then
    FAIL=1
  fi
done

# Stop shared node if we started it
if [[ -n "${CONNECTOR_IIA_PID:-}" ]]; then
  kill "$CONNECTOR_IIA_PID" 2>/dev/null || true
fi

if [[ "$FAIL" -ne 0 ]]; then
  echo "== iia-court-gate: FAIL ==" >&2
  exit 1
fi

date -u +%Y-%m-%dT%H:%M:%SZ >"$ROOT/platform/scripts/.iia-court-gate.ok"
echo "== iia-court-gate: PASS =="
