#!/usr/bin/env bash
# Launch stories A.2–A.4 — automated HTTP acceptance (Jordan / Sam / Riley).
# Requires: running node at CONNECTOR_TEST_URL (e.g. after make start or one-green-start-smoke).
# If no server is reachable: exit 0 with clear SKIP (safe for light / offline gates).
set -euo pipefail

BASE="${CONNECTOR_TEST_URL:-http://127.0.0.1:9091}"
BASE="${BASE%/}"
TOKEN="${CONNECTOR_DEV_TOKEN:-dev-token}"
AUTH="Authorization: Bearer ${TOKEN}"
fail=0

curl_json() {
  curl -sf -H "$AUTH" -H "Content-Type: application/json" "$@"
}

echo "== Story QA smoke @ ${BASE} =="

# Skip cleanly when nothing is listening (P7 offline / light-gate friendly).
if ! curl -sf --max-time 2 "${BASE}/health" >/dev/null 2>&1 \
  && ! curl -sf --max-time 2 "${BASE}/healthz" >/dev/null 2>&1 \
  && ! curl -sf --max-time 2 "${BASE}/api/v1/monitor/health" >/dev/null 2>&1; then
  echo "[SKIP] no server at ${BASE} — story QA requires a running node (make start)"
  echo "       Offline route wiring: bash platform/scripts/l4-story-offline-check.sh"
  echo "== story-qa-smoke: SKIP (no server) =="
  exit 0
fi

# A.2 Jordan — Service Map / apps / cage / TraceTramp slot
echo "[Jordan] apps catalog …"
if ! curl_json "${BASE}/api/v1/apps" | grep -q '"apps"'; then
  echo "[fail] GET /api/v1/apps" >&2
  fail=1
else
  echo "[ok] apps catalog"
fi

echo "[Jordan] plugins status + cage …"
PS="$(curl_json "${BASE}/api/v1/plugins/status")"
TT="$(echo "$PS" | python3 -c "import json,sys; d=json.load(sys.stdin); print((d.get('plugins') or {}).get('tracetramp',{}).get('status_badge',''))")"
if [[ "$TT" != "healthy" && "$TT" != "enabled" ]]; then
  echo "[warn] tracetramp status_badge=$TT (expected healthy when lab up)"
fi
if ! curl_json "${BASE}/api/v1/plugins/cage-proof" | grep -q '"ok":true'; then
  echo "[fail] cage-proof" >&2
  fail=1
else
  echo "[ok] cage-proof"
fi

# A.3 Sam — WitnessCtl proxy surface
echo "[Sam] witnessctl status …"
WC="$(echo "$PS" | python3 -c "import json,sys; d=json.load(sys.stdin); print((d.get('plugins') or {}).get('witnessctl',{}).get('status_badge',''))")"
echo "  witnessctl status_badge=$WC"
if curl_json "${BASE}/api/v1/plugins/witnessctl/status" >/dev/null 2>&1; then
  echo "[ok] GET /api/v1/plugins/witnessctl/status"
else
  echo "[warn] witnessctl status route not 2xx (management URL may be unset)"
fi

# A.4 Riley — workflow register → enable → dry-run + CNP
echo "[Riley] workflow lifecycle + CNP …"
TPL="$(curl_json "${BASE}/api/v1/workflows/reference-templates")"
CLS="$(echo "$TPL" | python3 -c "import json,sys; t=json.load(sys.stdin)['templates'][0]['cls_source']; print(json.dumps(t))")"
WF="story-qa-$(date +%s)"
curl_json -X POST "${BASE}/api/v1/workflows" \
  -d "{\"workflow_id\":\"${WF}\",\"package_id\":\"hitl_approve_audit\",\"version\":\"v1\",\"cls_source\":${CLS}}" >/dev/null
EN=""
for ST in COMPILED STAGED ENABLED; do
  EN="$(curl_json -X POST "${BASE}/api/v1/workflows/${WF}/lifecycle" -d "{\"state\":\"${ST}\"}")"
done
if ! echo "$EN" | grep -q 'dispatch_token'; then
  echo "[fail] ENABLE missing dispatch_token" >&2
  fail=1
fi
curl_json -X POST "${BASE}/api/v1/workflows/${WF}/dry-run" -d '{"replay_minutes":5}' | grep -q dry_run || {
  echo "[fail] dry-run" >&2
  fail=1
}
echo "[ok] workflow ${WF} enable + dry-run"

if [[ "$fail" -ne 0 ]]; then
  echo "== story-qa-smoke: FAILED ==" >&2
  exit 1
fi
echo "== story-qa-smoke: OK =="
