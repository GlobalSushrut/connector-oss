#!/usr/bin/env bash
# IIA P10.7 — export + receipt chain structure (T24 partial — full Ed25519 offline in connector-trust tests).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OK_FILE="$ROOT/platform/scripts/.iia-forensics-gate.ok"
PORT="${CONNECTOR_IIA_PORT:-18190}"
BASE="http://127.0.0.1:${PORT}"
AUTH="Authorization: Bearer dev-smoke"

curl -sf "$BASE/health" >/dev/null || bash "$ROOT/platform/scripts/iia-continuity-gate.sh"

# shellcheck disable=SC1090
source <(grep -E '^AGENT_' "$ROOT/platform/scripts/.iia-p0-gate.ok" | sed 's/^/export /')
PID="${AGENT_A:?missing AGENT_A}"

curl -sf -X POST "$BASE/api/v1/n4/hello" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID\",\"model_ref\":\"gpt\",\"provider\":\"lab\"}" >/dev/null
CPO="$(curl -sf -X POST "$BASE/api/v1/n4/cognize" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID\",\"proposed_action\":\"read\",\"proposed_target\":\"/workspace/x\"}")"
CPO_ID="$(echo "$CPO" | jq -r '.cpo.cpo_id')"
curl -sf -X POST "$BASE/api/v1/qpr/intent" -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"$PID\",\"cpo_id\":\"$CPO_ID\"}" >/dev/null

EXP="$(curl -sf "$BASE/api/v1/runtime/export?agent_pid=$PID" -H "$AUTH")"
echo "$EXP" | jq -e '.signing_tier == "ed25519_court"' >/dev/null
echo "$EXP" | jq -e '.receipts | length >= 1' >/dev/null
TMP="$ROOT/.iia-export-verify-$$.json"
echo "$EXP" >"$TMP"
(cd "$ROOT/oss/connector/crates/connector-trust" && cargo test --quiet -p connector-trust iia::) || {
  echo "[fail] connector-trust IIA tests" >&2
  rm -f "$TMP"
  exit 1
}
CTL="${CONNECTOR_CTL:-$ROOT/platform/server/.cargo-target-umesh/debug/connectorctl}"
if [[ ! -x "$CTL" ]]; then
  echo "[fail] connectorctl not built — run: make platform-build" >&2
  rm -f "$TMP"
  exit 1
fi
"$CTL" iia verify-export --file "$TMP" || {
  echo "[fail] verify-export" >&2
  rm -f "$TMP"
  exit 1
}
rm -f "$TMP"

date -u +%Y-%m-%dT%H:%M:%SZ >"$OK_FILE"
echo "T24=PASS export_structure" >>"$OK_FILE"
echo "== iia-forensics-gate: PASS =="
