#!/usr/bin/env bash
# P10.10 — Agent identity envelope: distinct who_am_i, namespace isolation, forensic package (T25–T28).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OK_FILE="$ROOT/platform/scripts/.agent-identity-envelope-gate.ok"
PORT="${CONNECTOR_IIA_PORT:-18191}"
BASE="http://127.0.0.1:${PORT}"
DATA="${CONNECTOR_AGENT_ID_DATA:-$ROOT/.agent-identity-envelope-data}"
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

if [[ "${CONNECTOR_IIA_KEEP_NODE:-0}" == "1" ]] && curl -sf --max-time 2 "$BASE/health" >/dev/null 2>&1; then
  : # reuse court/shared node
else
  fuser -k "${PORT}/tcp" 2>/dev/null || true
  sleep 1
  if curl -sf --max-time 2 "$BASE/health" >/dev/null 2>&1; then
    fuser -k "${PORT}/tcp" 2>/dev/null || true
    sleep 1
  fi
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
  for _ in $(seq 1 90); do
    curl -sf --max-time 2 "$BASE/health" >/dev/null 2>&1 && break
    sleep 1
  done
fi
curl -sf --max-time 2 "$BASE/health" >/dev/null || {
  echo "[fail] node did not start — see $DATA/node.log" >&2
  exit 1
}

AUTH="Authorization: Bearer dev-smoke"

reg() {
  local name="$1" acume="$2"
  curl -sf --max-time 30 -X POST "$BASE/api/v1/agents" \
    -H "$AUTH" -H "Content-Type: application/json" \
    -d "{\"name\":\"$name\",\"model\":\"shared-llm\",\"purpose\":\"$acume\",\"knowledge_base_id\":\"kb:$name\"}"
}

A="$(reg "finance_${SUFFIX}" "FINANCE_AGENT_ACUME")"
B="$(reg "soc_${SUFFIX}" "SOC_ANALYST_ACUME")"
PID_A="$(echo "$A" | jq -r '.pid')"
PID_B="$(echo "$B" | jq -r '.pid')"

[[ "$PID_A" != "null" && -n "$PID_A" && "$PID_B" != "null" && -n "$PID_B" ]] || {
  echo "[fail] agent register failed: A=$A B=$B" >&2
  exit 1
}

SELF_A="$(curl -sf --max-time 15 "$BASE/api/v1/runtime/self?agent_pid=$PID_A" -H "$AUTH")"
SELF_B="$(curl -sf --max-time 15 "$BASE/api/v1/runtime/self?agent_pid=$PID_B" -H "$AUTH")"
WHO_A="$(echo "$SELF_A" | jq -r '.who_am_i_authoritative // empty')"
WHO_B="$(echo "$SELF_B" | jq -r '.who_am_i_authoritative // empty')"

echo "$WHO_A" | grep -q "FINANCE_AGENT_ACUME" || {
  echo "[fail] Agent A who_am_i missing acume" >&2
  exit 1
}
echo "$WHO_B" | grep -q "SOC_ANALYST_ACUME" || {
  echo "[fail] Agent B who_am_i missing acume" >&2
  exit 1
}
[[ "$WHO_A" != "$WHO_B" ]] || {
  echo "[fail] who_am_i must differ between agents" >&2
  exit 1
}
echo "$WHO_A" | grep -q "/m/finance_${SUFFIX}" || {
  echo "[fail] Agent A who_am_i missing private namespace" >&2
  exit 1
}
echo "$WHO_B" | grep -q "kb:soc_${SUFFIX}\|Knowledge base: /k/soc_${SUFFIX}" || {
  echo "[fail] Agent B who_am_i missing distinct KB" >&2
  exit 1
}

ENV_A="$(curl -sf --max-time 15 "$BASE/api/v1/agents/$PID_A/identity-envelope" -H "$AUTH")"
echo "$ENV_A" | jq -e '.ok == true and .envelope.namespace_scope.isolation_enforced == true' >/dev/null

FORENSIC="$(curl -sf --max-time 15 "$BASE/api/v1/agents/$PID_A/forensic/universal" -H "$AUTH")"
echo "$FORENSIC" | jq -e '.ok == true and .count >= 1' >/dev/null
echo "$FORENSIC" | jq -e '.schema == "connector.forensic.universal_envelope.v2"' >/dev/null

NS_B="m/soc_${SUFFIX}"
NS_B_ENC="$(printf '%s' "$NS_B" | jq -sRr @uri)"
RECALL_CODE="$(curl -sS --max-time 15 -o /tmp/agent-id-recall.json -w '%{http_code}' \
  "$BASE/api/v1/memory/recall2/${NS_B_ENC}" -H "$AUTH" -H "X-Connector-Agent-Pid: $PID_A" || true)"
RECALL_BODY="$(cat /tmp/agent-id-recall.json 2>/dev/null || true)"
echo "$RECALL_BODY" | jq -e '.error == "namespace_isolation_denied"' >/dev/null || {
  echo "[fail] cross-agent recall expected namespace_isolation_denied (http=$RECALL_CODE): $RECALL_BODY" >&2
  exit 1
}

# Phase D — compliance contract + rollups + package
CC_A="$(curl -sf --max-time 15 "$BASE/api/v1/agents/$PID_A/compliance-contract" -H "$AUTH")"
echo "$CC_A" | jq -e '.ok == true and .contract.isolation_enforced == true and (.contract.signature != null)' >/dev/null || {
  echo "[fail] compliance contract missing/unsigned for A: $CC_A" >&2
  exit 1
}
CC_B="$(curl -sf --max-time 15 "$BASE/api/v1/agents/$PID_B/compliance-contract" -H "$AUTH")"
DIG_A="$(echo "$CC_A" | jq -r '.contract.compliance_contract_digest_sha256')"
DIG_B="$(echo "$CC_B" | jq -r '.contract.compliance_contract_digest_sha256')"
[[ -n "$DIG_A" && -n "$DIG_B" && "$DIG_A" != "$DIG_B" ]] || {
  echo "[fail] distinct A/B compliance contract digests required" >&2
  exit 1
}

ROLLUPS="$(curl -sf --max-time 15 "$BASE/api/v1/forensics/rollups/$PID_A" -H "$AUTH")"
echo "$ROLLUPS" | jq -e '.ok == true and .count >= 1' >/dev/null || {
  echo "[fail] expected forensic rollups for A: $ROLLUPS" >&2
  exit 1
}
CROSS_DENY="$(echo "$ROLLUPS" | jq '[.rollups[].memory_trace.cross_agent_attempts_denied] | add // 0')"
[[ "$CROSS_DENY" -ge 1 ]] || {
  echo "[fail] expected cross_agent_attempts_denied >= 1 after recall deny; got $CROSS_DENY" >&2
  exit 1
}

CHAIN="$(curl -sf --max-time 15 "$BASE/api/v1/forensics/chain?agent_pid=$PID_A" -H "$AUTH")"
echo "$CHAIN" | jq -e '.ok == true and .join_count >= 1' >/dev/null || {
  echo "[fail] correlation chain empty: $CHAIN" >&2
  exit 1
}

PKG="$(curl -sf --max-time 20 "$BASE/api/v1/forensics/package?agent_pid=$PID_A" -H "$AUTH")"
echo "$PKG" | jq -e '.ok == true and .manifest.signature != null and .manifest.package_root_sha256 != null and .compliance_contract != null' >/dev/null || {
  echo "[fail] forensic package incomplete: $PKG" >&2
  exit 1
}
echo "$PKG" | jq -e '.control_matrix.score >= 0 and (.control_matrix.controls | length) >= 4' >/dev/null || {
  echo "[fail] control_matrix missing from package" >&2
  exit 1
}

# WitnessCtl join (session hint from activation)
WC_SID="$(echo "$CC_A" | jq -r '.contract.witnessctl_session_id // empty')"
if [[ -n "$WC_SID" ]]; then
  WC_ENC="$(printf '%s' "$WC_SID" | jq -sRr @uri)"
  JOIN="$(curl -sf --max-time 15 "$BASE/api/v1/forensics/witnessctl-join?session_id=${WC_ENC}" -H "$AUTH")"
  echo "$JOIN" | jq -e '.ok == true and (.join.agents | length) >= 1' >/dev/null || {
    echo "[fail] witnessctl-join empty for session $WC_SID: $JOIN" >&2
    exit 1
  }
fi

STATUS="$(curl -sf --max-time 15 "$BASE/api/v1/forensics/status" -H "$AUTH")"
echo "$STATUS" | jq -e '.iia.compliance_contracts >= 1 and .iia.rollup_buckets >= 1' >/dev/null || {
  echo "[fail] forensics status missing live IIA counts: $STATUS" >&2
  exit 1
}

date -u +%Y-%m-%dT%H:%M:%SZ >"$OK_FILE"
{
  echo "T25=PASS distinct_who_am_i"
  echo "T26=PASS namespace_isolation_403"
  echo "T27=PASS compliance_contract_distinct"
  echo "T28=PASS forensic_rollup_package"
  echo "AGENT_A=$PID_A"
  echo "AGENT_B=$PID_B"
  echo "CONTRACT_DIGEST_A=$DIG_A"
  echo "PACKAGE_ROOT=$(echo "$PKG" | jq -r '.manifest.package_root_sha256')"
} | tee -a "$OK_FILE"
echo "== agent-identity-envelope-gate: PASS =="
