#!/usr/bin/env bash
# IIA P10.3 — N4 handshake + CPO, no raw execution (T20).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OK_FILE="$ROOT/platform/scripts/.iia-n4-gate.ok"
PORT="${CONNECTOR_IIA_PORT:-18190}"
BASE="http://127.0.0.1:${PORT}"
AUTH="Authorization: Bearer dev-smoke"
SUFFIX="${CONNECTOR_IIA_SUFFIX:-n4_$(date +%s)}"

curl -sf "$BASE/health" >/dev/null || bash "$ROOT/platform/scripts/iia-p0-gate.sh"

# shellcheck disable=SC1090
source <(grep -E '^AGENT_' "$ROOT/platform/scripts/.iia-p0-gate.ok" | sed 's/^/export /')
PID="${AGENT_A:?missing AGENT_A from iia-p0-gate}"

curl -sf -X POST "$BASE/api/v1/n4/hello" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID\",\"model_ref\":\"gpt-test\",\"provider\":\"openai-compat\"}" \
  | jq -e '.ok == true' >/dev/null

CPO="$(curl -sf -X POST "$BASE/api/v1/n4/cognize" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID\",\"proposed_action\":\"read_file\",\"proposed_target\":\"/workspace/a.txt\"}")"
echo "$CPO" | jq -e '.cpo.non_authoritative == true' >/dev/null

# Unqualified model rejected
DENY="$(curl -sf -X POST "$BASE/api/v1/n4/hello" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID\",\"model_ref\":\"\",\"provider\":\"\"}" || true)"
echo "$DENY" | jq -e '.error == "n4_handshake_denied"' >/dev/null 2>&1 || {
  echo "[fail] expected n4_handshake_denied for empty model" >&2
  exit 1
}

date -u +%Y-%m-%dT%H:%M:%SZ >"$OK_FILE"
echo "T20=PASS" >>"$OK_FILE"
echo "== iia-n4-gate: PASS =="
