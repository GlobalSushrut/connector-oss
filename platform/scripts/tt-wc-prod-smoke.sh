#!/usr/bin/env bash
# TraceTramp + WitnessCtl production probes (plan Phase 1 / Connector integration).
set -euo pipefail

BASE="${CONNECTOR_TEST_URL:-http://127.0.0.1:9091}"
BASE="${BASE%/}"
TOKEN="${CONNECTOR_DEV_TOKEN:-dev-token}"
AUTH="Authorization: Bearer ${TOKEN}"

TT_MGMT="${CONNECTOR_TRACETRAMP_MANAGEMENT_URL:-${TRACETRAMP_MANAGEMENT_URL:-http://127.0.0.1:19742}}"
TT_MGMT="${TT_MGMT%/}"
TT_TOKEN="${CONNECTOR_TRACETRAMP_ADMIN_TOKEN:-${TRACETRAMP_ADMIN_TOKEN:-}}"
WC_MGMT="${CONNECTOR_WITNESSCTL_MANAGEMENT_URL:-${WITNESSCTL_MANAGEMENT_URL:-http://127.0.0.1:17443}}"
WC_MGMT="${WC_MGMT%/}"
WC_TOKEN="${CONNECTOR_WITNESSCTL_ADMIN_TOKEN:-${WITNESSCTL_ADMIN_TOKEN:-}}"

fail=0
warn=0

curl_json() {
  curl -sf -H "$AUTH" -H "Content-Type: application/json" "$@"
}

echo "== tt-wc-prod-smoke @ ${BASE} =="

# Connector aggregate status
PS="$(curl_json "${BASE}/api/v1/plugins/status" 2>/dev/null || true)"
if [[ -z "$PS" ]]; then
  echo "[fail] GET /api/v1/plugins/status" >&2
  fail=1
else
  echo "[ok] plugins/status"
  echo "$PS" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for k in ('tracetramp','witnessctl'):
    p=(d.get('plugins') or {}).get(k,{})
    print(f'  {k}: badge={p.get(\"status_badge\",\"?\")} upstream={p.get(\"upstream_reachable\")}')"
fi

# TraceTramp management
if [[ -n "$TT_TOKEN" ]]; then
  if curl -sf -H "Authorization: Bearer ${TT_TOKEN}" "${TT_MGMT}/health" >/dev/null; then
    echo "[ok] TraceTramp management /health @ ${TT_MGMT}"
  else
    echo "[fail] TraceTramp management /health" >&2
    fail=1
  fi
  if curl -sf -H "Authorization: Bearer ${TT_TOKEN}" "${TT_MGMT}/admin/stats" | grep -q active_calls; then
    echo "[ok] TraceTramp /admin/stats"
  else
    echo "[warn] TraceTramp /admin/stats" >&2
    warn=1
  fi
  if curl -sf "${TT_MGMT}/admin/dashboard" | grep -qi tracetramp; then
    echo "[ok] TraceTramp /admin/dashboard"
  else
    echo "[warn] TraceTramp /admin/dashboard (no token required)" >&2
    warn=1
  fi
  TT_DATA="${CONNECTOR_TRACETRAMP_DATA_URL:-${TRACETRAMP_DATA_URL:-http://127.0.0.1:19741}}"
  TT_DATA="${TT_DATA%/}"
  if curl -sf "${TT_DATA}/ready" 2>/dev/null | grep -q '"ready"'; then
    echo "[ok] TraceTramp data plane /ready @ ${TT_DATA}"
  else
    echo "[warn] TraceTramp /ready @ ${TT_DATA}" >&2
    warn=1
  fi
else
  echo "[skip] TraceTramp management (no admin token)"
fi

# WitnessCtl management
if [[ -n "$WC_TOKEN" ]]; then
  if curl -sf -H "Authorization: Bearer ${WC_TOKEN}" "${WC_MGMT}/health" >/dev/null 2>&1 || \
     curl -sf -H "Authorization: Bearer ${WC_TOKEN}" "${WC_MGMT}/api/v1/health" >/dev/null 2>&1; then
    echo "[ok] WitnessCtl management health @ ${WC_MGMT}"
  else
    echo "[warn] WitnessCtl management health not 2xx" >&2
    warn=1
  fi
  if curl -sf "${WC_MGMT}/admin/dashboard" 2>/dev/null | grep -qi witnessctl; then
    echo "[ok] WitnessCtl /admin/dashboard"
  else
    echo "[warn] WitnessCtl /admin/dashboard" >&2
    warn=1
  fi
else
  echo "[skip] WitnessCtl management (no admin token)"
fi

# Connector proxy routes (when configured)
if curl_json "${BASE}/api/v1/plugins/tracetramp/stats" 2>/dev/null | grep -q .; then
  echo "[ok] Connector tracetramp stats proxy"
else
  echo "[warn] Connector tracetramp stats proxy" >&2
  warn=1
fi

HANDOFF_SECRET="${TRACETRAMP_WITNESS_HANDOFF_SECRET:-${WITNESSCTL_TRACETRAMP_HANDOFF_SECRET:-}}"
if [[ -n "$HANDOFF_SECRET" && -n "$WC_MGMT" ]]; then
  CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${WC_MGMT}/api/v1/integrations/tracetramp/handoff" \
    -H "Content-Type: application/json" \
    -H "X-WitnessCtl-Tracetramp-Handoff-Secret: ${HANDOFF_SECRET}" \
    -d '{"trace_id":"smoke-tt-wc","request_id":"smoke-req","tenant_id":"smoke","event":"prod_smoke"}' || echo 000)"
  if [[ "$CODE" == "200" || "$CODE" == "201" || "$CODE" == "204" ]]; then
    echo "[ok] WitnessCtl tracetramp handoff ingest (HTTP ${CODE})"
  else
    echo "[warn] handoff ingest HTTP ${CODE} (check secrets and WC URL)" >&2
    warn=1
  fi
else
  echo "[skip] handoff ingest (secret or WC URL unset)"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "== tt-wc-prod-smoke: FAILED ==" >&2
  exit 1
fi
echo "== tt-wc-prod-smoke: OK (warnings=${warn}) =="
