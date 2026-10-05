#!/usr/bin/env bash
# IIA P10.6 — continuity break stops new quanta (T23).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OK_FILE="$ROOT/platform/scripts/.iia-continuity-gate.ok"
PORT="${CONNECTOR_IIA_PORT:-18190}"
BASE="http://127.0.0.1:${PORT}"
AUTH="Authorization: Bearer dev-smoke"

curl -sf "$BASE/health" >/dev/null || bash "$ROOT/platform/scripts/docklock-bypass-adversarial.sh"

# shellcheck disable=SC1090
source <(grep -E '^AGENT_' "$ROOT/platform/scripts/.iia-p0-gate.ok" | sed 's/^/export /')
PID="${AGENT_B:?missing AGENT_B}"

curl -sf -X POST "$BASE/api/v1/runtime/continuity/evaluate?agent_pid=$PID" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"runtime_hash":"tampered","model_ref":"evil"}' | jq -e '.continuity.state == "broken"' >/dev/null

curl -sf -X POST "$BASE/api/v1/n4/hello" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID\",\"model_ref\":\"gpt\",\"provider\":\"lab\"}" >/dev/null
CPO="$(curl -sf -X POST "$BASE/api/v1/n4/cognize" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID\",\"proposed_action\":\"read\",\"proposed_target\":\"/workspace/x\"}")"
CPO_ID="$(echo "$CPO" | jq -r '.cpo.cpo_id')"
DENY="$(curl -sf -X POST "$BASE/api/v1/qpr/intent" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID\",\"cpo_id\":\"$CPO_ID\"}" || echo '{}')"
echo "$DENY" | jq -e '.denial_reason == "continuity_broken" or .error == "qpr_denied"' >/dev/null

curl -sf "$BASE/api/v1/runtime/hardware" -H "$AUTH" | jq -e '.execution_reality.attestation_tier != null' >/dev/null

date -u +%Y-%m-%dT%H:%M:%SZ >"$OK_FILE"
echo "T23=PASS" >>"$OK_FILE"
echo "== iia-continuity-gate: PASS =="
