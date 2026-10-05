#!/usr/bin/env bash
# Zero-trust handshake adversarial gate — LLM/external forged tickets must DENY.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OK_FILE="$ROOT/platform/scripts/.zt-handshake-adversarial.ok"
PORT="${CONNECTOR_IIA_PORT:-18190}"
BASE="http://127.0.0.1:${PORT}"
AUTH="Authorization: Bearer dev-smoke"

curl -sf "$BASE/health" >/dev/null || bash "$ROOT/platform/scripts/iia-p0-gate.sh"

# shellcheck disable=SC1090
source <(grep -E '^AGENT_' "$ROOT/platform/scripts/.iia-p0-gate.ok" | sed 's/^/export /')
PID="${AGENT_A:?missing AGENT_A}"

STATUS="$(curl -sf "$BASE/api/v1/runtime/zt-handshake/status" -H "$AUTH")"
echo "$STATUS" | jq -e '.ok == true' >/dev/null || {
  echo "[fail] zt-handshake status unavailable" >&2
  exit 1
}

ENFORCED="$(echo "$STATUS" | jq -r '.zt_handshake.enforced // false')"

curl -sf -X POST "$BASE/api/v1/runtime/zt-handshake/establish" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID\",\"bridge_id\":\"default\",\"tool_name\":\"search_docs\"}" \
  | jq -e '.ok == true and .llm_holds_session_key == false' >/dev/null

if [[ "$ENFORCED" == "true" ]]; then
  for KIND in llm_direct_tool external_agent forged_ticket replay_ticket mutated_manifest; do
    RESP="$(curl -sf -X POST "$BASE/api/v1/runtime/zt-handshake/probe" -H "$AUTH" -H "Content-Type: application/json" \
      -d "{\"agent_pid\":\"$PID\",\"bypass_kind\":\"$KIND\"}")"
    echo "$RESP" | jq -e '.zt_handshake_bypass_denied == true' >/dev/null || {
      echo "[fail] handshake probe $KIND expected deny" >&2
      echo "$RESP" >&2
      exit 1
    }
  done
fi

printf 'T24=PASS zt_handshake\n' >"$OK_FILE"
echo "== zt-handshake-adversarial: PASS =="
