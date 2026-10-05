#!/usr/bin/env bash
# P2.2 — LLM fallback + cost-cap settings smoke (curl field presence).
#
# Skips with exit 0 when the platform server is not reachable (laptop-friendly).
#
# Usage (from repo root):
#   bash platform/scripts/llm-fallback-cap-smoke.sh
#   CONNECTOR_API_URL=http://127.0.0.1:8080 bash platform/scripts/llm-fallback-cap-smoke.sh

set -euo pipefail

BASE="${CONNECTOR_API_URL:-http://127.0.0.1:8080}"
BASE="${BASE%/}"
AUTH="${CONNECTOR_SMOKE_TOKEN:-dev-token}"
HDR=(-H "Authorization: Bearer ${AUTH}" -H "Accept: application/json")

if ! curl -sf --max-time 2 "${BASE}/health" >/dev/null 2>&1; then
  echo "[skip] server down at ${BASE}/health — start connector-platform to exercise LLM fallback/cap settings"
  exit 0
fi

fail() {
  echo "[fail] $*" >&2
  exit 1
}

echo "[probe] ${BASE}/api/v1/settings/llms/fallback-cap"
body="$(curl -sf --max-time 10 "${HDR[@]}" "${BASE}/api/v1/settings/llms/fallback-cap")" \
  || fail "GET /api/v1/settings/llms/fallback-cap"

echo "$body" | grep -q '"ok"' || fail "fallback-cap missing ok"
echo "$body" | grep -q '"fallback"' || fail "fallback-cap missing fallback"
echo "$body" | grep -q '"cost_cap"' || fail "fallback-cap missing cost_cap"
echo "$body" | grep -q '"provider_configured\|env_provider\|router_wired"' \
  || fail "fallback-cap missing fallback contract fields"
echo "$body" | grep -q '"guardrails\|hard_stop\|monthly_budget"' \
  || fail "fallback-cap missing cost_cap/guardrails fields"
echo "[ok] fallback-cap fields present"

echo "[probe] ${BASE}/api/v1/settings/llms/guardrails"
gbody="$(curl -sf --max-time 10 "${HDR[@]}" "${BASE}/api/v1/settings/llms/guardrails")" \
  || fail "GET /api/v1/settings/llms/guardrails"
echo "$gbody" | grep -q '"guardrails"' || fail "guardrails missing guardrails object"
echo "$gbody" | grep -q '"fallback"' || fail "guardrails missing fallback block"
echo "[ok] guardrails + fallback present"

echo "[probe] ${BASE}/api/v1/settings/llms/routing-rules"
rbody="$(curl -sf --max-time 10 "${HDR[@]}" "${BASE}/api/v1/settings/llms/routing-rules")" \
  || fail "GET /api/v1/settings/llms/routing-rules"
echo "$rbody" | grep -q 'cost_cap' || fail "routing-rules missing cost_cap trigger"
echo "[ok] routing-rules lists cost_cap trigger"

echo "[ok] llm-fallback-cap-smoke"
