#!/usr/bin/env bash
# IIA P10.2 — two principals, same model, distinct cnktr:agent:* (T19).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OK_FILE="$ROOT/platform/scripts/.iia-p0-gate.ok"
PORT="${CONNECTOR_IIA_PORT:-18190}"
BASE="http://127.0.0.1:${PORT}"
DATA="${CONNECTOR_IIA_DATA_DIR:-$ROOT/.iia-p0-data}"
BIN="${CONNECTOR_BIN:-$ROOT/platform/server/.cargo-target-umesh/debug/connector-platform}"
PID="${CONNECTOR_IIA_PID:-}"
SUFFIX="${CONNECTOR_IIA_SUFFIX:-$(date +%s)}"

started_here=0
cleanup() {
  [[ "${CONNECTOR_IIA_KEEP_NODE:-0}" == "1" ]] && return 0
  [[ "$started_here" == "1" && -n "$PID" ]] && kill "$PID" 2>/dev/null || true
}
trap cleanup EXIT

if [[ ! -x "$BIN" ]]; then
  echo "[fail] build connector-platform first (make platform-build)" >&2
  exit 1
fi

if ! curl -sf "$BASE/health" >/dev/null 2>&1; then
  rm -rf "$DATA"
  mkdir -p "$DATA"
  env -u CONNECTOR_OPEN_AUTH \
    CONNECTOR_PRESET=local CONNECTOR_DEV_MODE=1 CONNECTOR_LLM_STUB=1 \
    CONNECTOR_IIA_RING1=1 \
    CONNECTOR_DEV_AGENT_CAP="${CONNECTOR_DEV_AGENT_CAP:-32}" \
    CONNECTOR_HOST=127.0.0.1 CONNECTOR_PORT="$PORT" CONNECTOR_DATA_DIR="$DATA" \
    "$BIN" >"$DATA/node.log" 2>&1 &
  PID=$!
  started_here=1
  for _ in $(seq 1 60); do
    curl -sf "$BASE/health" >/dev/null 2>&1 && break
    sleep 1
  done
fi
curl -sf "$BASE/health" >/dev/null || { echo "[fail] node did not start"; exit 1; }

AUTH="Authorization: Bearer dev-smoke"
reg() {
  curl -sf -X POST "$BASE/api/v1/agents" \
    -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"name\":\"$1\",\"model\":\"shared-llm\",\"role\":\"writer\"}"
}

A="$(reg "agent_dev_${SUFFIX}")"
B="$(reg "agent_fin_${SUFFIX}")"
PID_A="$(echo "$A" | jq -r '.pid')"
PID_B="$(echo "$B" | jq -r '.pid')"
PR_A="$(echo "$A" | jq -r '.principal_id')"
PR_B="$(echo "$B" | jq -r '.principal_id')"

[[ "$PR_A" != "$PR_B" && "$PR_A" != "null" && "$PR_B" != "null" ]] || {
  echo "[fail] distinct principal_id required: $PR_A vs $PR_B" >&2
  echo "$A" >&2
  echo "$B" >&2
  exit 1
}

SELF_A="$(curl -sf "$BASE/api/v1/runtime/self?agent_pid=$PID_A" -H "$AUTH")"
SELF_B="$(curl -sf "$BASE/api/v1/runtime/self?agent_pid=$PID_B" -H "$AUTH")"
echo "$SELF_A" | jq -e '.ok == true' >/dev/null
echo "$SELF_B" | jq -e '.ok == true' >/dev/null

date -u +%Y-%m-%dT%H:%M:%SZ >"$OK_FILE"
{
  echo "T19=PASS principal_a=$PR_A principal_b=$PR_B"
  echo "AGENT_A=$PID_A"
  echo "AGENT_B=$PID_B"
} | tee -a "$OK_FILE"
echo "== iia-p0-gate: PASS =="
