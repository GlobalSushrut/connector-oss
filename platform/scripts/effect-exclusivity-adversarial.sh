#!/usr/bin/env bash
# Effect exclusivity adversarial gate — alternate authority paths must DENY under hardened posture.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OK_FILE="$ROOT/platform/scripts/.effect-exclusivity-adversarial.ok"
PORT="${CONNECTOR_IIA_PORT:-18190}"
BASE="http://127.0.0.1:${PORT}"
AUTH="Authorization: Bearer dev-smoke"

curl -sf "$BASE/health" >/dev/null || bash "$ROOT/platform/scripts/iia-p0-gate.sh"

# shellcheck disable=SC1090
source <(grep -E '^AGENT_' "$ROOT/platform/scripts/.iia-p0-gate.ok" | sed 's/^/export /')
PID="${AGENT_A:?missing AGENT_A}"

STATUS="$(curl -sf "$BASE/api/v1/runtime/effect-exclusivity/status" -H "$AUTH")"
echo "$STATUS" | jq -e '.ok == true' >/dev/null || {
  echo "[fail] effect-exclusivity status unavailable" >&2
  exit 1
}

ENFORCED="$(echo "$STATUS" | jq -r '.effect_exclusivity.effect_exclusivity_enforced // false')"
if [[ "$ENFORCED" != "true" ]]; then
  echo "[warn] CONNECTOR_EFFECT_EXCLUSIVITY not on — probes are informational only" >&2
fi

PROBES=(
  direct_http
  raw_tcp
  shell_curl
  plugin_subprocess
  direct_mcp
  read_injected_secret
  write_outside_tree
  delegate_unauthorized
  reuse_old_approval
  mutate_approved_tool
  restart_replay
)

for KIND in "${PROBES[@]}"; do
  RESP="$(curl -sf -X POST "$BASE/api/v1/runtime/effect-exclusivity/probe" -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"agent_pid\":\"$PID\",\"bypass_kind\":\"$KIND\"}" || true)"
  if [[ "$ENFORCED" == "true" ]]; then
    echo "$RESP" | jq -e '.effect_exclusivity_bypass_denied == true' >/dev/null || {
      echo "[fail] bypass probe $KIND expected deny" >&2
      echo "$RESP" >&2
      exit 1
    }
  fi
done

# Memory read without quantum must fail when Ring-1 on.
RING1="$(curl -sf "$BASE/api/v1/runtime/docklock/status" -H "$AUTH" | jq -r '.docklock.ring1_enforce // false')"
if [[ "$RING1" == "true" ]]; then
  RECALL_CODE="$(curl -s -o /tmp/ii-excl-recall.json -w '%{http_code}' \
    "$BASE/api/v1/memory/recall2/test-ns?limit=1" \
    -H "$AUTH" -H "x-connector-agent-pid: $PID")"
  if [[ "$RECALL_CODE" != "403" && "$RECALL_CODE" != "401" ]]; then
    echo "[fail] memory recall without quantum expected deny, got $RECALL_CODE" >&2
    cat /tmp/ii-excl-recall.json >&2 || true
    exit 1
  fi
fi

printf 'T23=PASS effect_exclusivity_probes\n' >"$OK_FILE"
echo "== effect-exclusivity-adversarial: PASS =="
