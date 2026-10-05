#!/usr/bin/env bash
# IIA P10.5 — DockLock Ring-1 bypass probe (must deny without quantum).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OK_FILE="$ROOT/platform/scripts/.docklock-bypass-adversarial.ok"
PORT="${CONNECTOR_IIA_PORT:-18190}"
BASE="http://127.0.0.1:${PORT}"
AUTH="Authorization: Bearer dev-smoke"
QH="X-Connector-Execution-Quantum"

curl -sf "$BASE/health" >/dev/null || bash "$ROOT/platform/scripts/iia-p0-gate.sh"

# shellcheck disable=SC1090
source <(grep -E '^AGENT_' "$ROOT/platform/scripts/.iia-p0-gate.ok" | sed 's/^/export /')
PID="${AGENT_A:?missing AGENT_A}"

STATUS="$(curl -sf "$BASE/api/v1/runtime/docklock/status" -H "$AUTH")"
echo "$STATUS" | jq -e '.docklock.ring1_enforce == true' >/dev/null || {
  echo "[fail] CONNECTOR_IIA_RING1=1 required on node" >&2
  exit 1
}

for KIND in shell sdk_bypass raw_network memory_bypass tool_bypass mcp_bypass debug_bypass; do
  curl -sf -X POST "$BASE/api/v1/runtime/docklock/probe" -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"agent_pid\":\"$PID\",\"bypass_kind\":\"$KIND\"}" \
    | jq -e '.docklock_bypass_denied == true' >/dev/null
done

# Live HTTP bypass: memory write without quantum must fail closed.
MEM_CODE="$(curl -s -o /tmp/ii-ring1-mem.json -w '%{http_code}' -X POST "$BASE/api/v1/memory/write" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID\",\"content\":\"adversarial memory probe\",\"session_id\":\"adversarial\"}")"
if [[ "$MEM_CODE" != "403" && "$MEM_CODE" != "401" ]]; then
  echo "[fail] memory/write without quantum expected 403, got $MEM_CODE" >&2
  cat /tmp/ii-ring1-mem.json >&2 || true
  exit 1
fi

# Mint quantum and prove replay is denied (single-use).
bash "$ROOT/platform/scripts/iia-qpr-gate.sh" >/dev/null
source <(grep -E '^AGENT_' "$ROOT/platform/scripts/.iia-p0-gate.ok" | sed 's/^/export /')
PID_B="${AGENT_B:?}"
curl -sf -X POST "$BASE/api/v1/n4/hello" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID_B\",\"model_ref\":\"gpt-test\",\"provider\":\"lab\"}" >/dev/null
CPO="$(curl -sf -X POST "$BASE/api/v1/n4/cognize" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID_B\",\"proposed_action\":\"read\",\"proposed_target\":\"/workspace/doc.txt\"}")"
CPO_ID="$(echo "$CPO" | jq -r '.cpo.cpo_id')"
Q="$(curl -sf -X POST "$BASE/api/v1/qpr/intent" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID_B\",\"cpo_id\":\"$CPO_ID\"}")"
QID="$(echo "$Q" | jq -r '.execution_quantum.quantum_id')"

curl -sf -X POST "$BASE/api/v1/n4/hello" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID_B\",\"model_ref\":\"gpt-test\",\"provider\":\"lab\"}" >/dev/null
curl -sf -X POST "$BASE/v1/chat/completions" -H "$AUTH" -H "Content-Type: application/json" -H "$QH: $QID" \
  -d "{\"model\":\"gpt-test\",\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}],\"agent_pid\":\"$PID_B\"}" >/dev/null || true

REPLAY_CODE="$(curl -s -o /tmp/ii-ring1-replay.json -w '%{http_code}' -X POST "$BASE/v1/chat/completions" \
  -H "$AUTH" -H "Content-Type: application/json" -H "$QH: $QID" \
  -d "{\"model\":\"gpt-test\",\"messages\":[{\"role\":\"user\",\"content\":\"replay\"}],\"agent_pid\":\"$PID_B\"}")"
if [[ "$REPLAY_CODE" != "403" && "$REPLAY_CODE" != "401" && "$REPLAY_CODE" != "429" ]]; then
  echo "[fail] quantum replay expected deny, got $REPLAY_CODE" >&2
  cat /tmp/ii-ring1-replay.json >&2 || true
  exit 1
fi

date -u +%Y-%m-%dT%H:%M:%SZ >"$OK_FILE"
echo "T22=PASS ring1_bypass_denied" >>"$OK_FILE"
echo "T22b=PASS memory_without_quantum_denied" >>"$OK_FILE"
echo "T22c=PASS quantum_replay_denied" >>"$OK_FILE"
echo "== docklock-bypass-adversarial: PASS =="
