#!/usr/bin/env bash
# CDMI — matrix isolation: continuity break revokes quanta + cuts egress (P10.6.2).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OK_FILE="$ROOT/platform/scripts/.matrix-isolation-gate.ok"
PORT="${CONNECTOR_IIA_PORT:-18190}"
BASE="http://127.0.0.1:${PORT}"
AUTH="Authorization: Bearer dev-smoke"

curl -sf "$BASE/health" >/dev/null || bash "$ROOT/platform/scripts/iia-p0-gate.sh"

# shellcheck disable=SC1090
source <(grep -E '^AGENT_' "$ROOT/platform/scripts/.iia-p0-gate.ok" | sed 's/^/export /')
PID="${AGENT_A:?missing AGENT_A}"

# Fresh agent for isolation test (avoid prior continuity break on AGENT_B).
REG="$(curl -sf -X POST "$BASE/api/v1/agents" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"name\":\"matrix-isolation-test\",\"model\":\"shared-llm\",\"role\":\"writer\"}")"
ISO_PID="$(echo "$REG" | jq -r '.pid')"

curl -sf -X POST "$BASE/api/v1/runtime/continuity/evaluate?agent_pid=$ISO_PID" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"runtime_hash":"tampered-binary","model_ref":"evil-substitute"}' \
  | jq -e '.continuity.state == "broken"' >/dev/null

MATRIX="$(curl -sf "$BASE/api/v1/runtime/matrix?agent_pid=$ISO_PID" -H "$AUTH")"
echo "$MATRIX" | jq -e '.matrix.egress_isolated == true' >/dev/null
echo "$MATRIX" | jq -e '.matrix.cdmi_posture == "egress_isolated"' >/dev/null

MEM_CODE="$(curl -s -o /tmp/matrix-mem.json -w '%{http_code}' -X POST "$BASE/api/v1/memory/write" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$ISO_PID\",\"content\":\"should be blocked by matrix isolation\"}")"
if [[ "$MEM_CODE" != "403" && "$MEM_CODE" != "401" ]]; then
  echo "[fail] isolated agent memory write expected 403, got $MEM_CODE" >&2
  cat /tmp/matrix-mem.json >&2 || true
  exit 1
fi

# Gateway raw tools without CPO must fail under Ring-1.
TOOLS_CODE="$(curl -s -o /tmp/matrix-tools.json -w '%{http_code}' -X POST "$BASE/v1/chat/completions" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"model\":\"gpt-test\",\"agent_pid\":\"$PID\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"tools\":[{\"type\":\"function\",\"function\":{\"name\":\"exec\",\"parameters\":{}}}]}" )"
if [[ "$TOOLS_CODE" != "403" && "$TOOLS_CODE" != "401" ]]; then
  echo "[fail] raw gateway tools without CPO expected 403, got $TOOLS_CODE" >&2
  cat /tmp/matrix-tools.json >&2 || true
  exit 1
fi

date -u +%Y-%m-%dT%H:%M:%SZ >"$OK_FILE"
echo "T25=PASS matrix_egress_isolated" >>"$OK_FILE"
echo "T26=PASS gateway_tools_n4_intercept" >>"$OK_FILE"
echo "== matrix-isolation-gate: PASS =="
