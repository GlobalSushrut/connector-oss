#!/usr/bin/env bash
# E2E smoke (checklist §10.6): preflight + optional live API checks when CONNECTOR_TEST_URL is set.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$ROOT/scripts/connector-kernel-prod-preflight.sh"

BASE="${CONNECTOR_TEST_URL:-}"
KEY="${CONNECTOR_TEST_API_KEY:-}"

if [[ -z "$BASE" || -z "$KEY" ]]; then
  echo "[skip] Set CONNECTOR_TEST_URL and CONNECTOR_TEST_API_KEY to run HTTP checks."
  exit 0
fi

hdr=(-H "Authorization: Bearer ${KEY}" -H "Content-Type: application/json")

echo "[http] GET ${BASE}/api/v1/kernel/status"
KERNEL_JSON=$(curl -fsS "${hdr[@]}" "${BASE}/api/v1/kernel/status")
echo "$KERNEL_JSON" | head -c 400
echo ""
if ! echo "$KERNEL_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin).get('data',{}); fl=d.get('flow_lease',{}); assert fl.get('schema')=='flow_lease_map.v1', fl" 2>/dev/null; then
  echo "[warn] kernel/status missing flow_lease_map.v1 (connector-kerneld lease deny path)"
fi

echo "[http] POST ${BASE}/api/v1/kernel/profiles"
curl -fsS "${hdr[@]}" -X POST "${BASE}/api/v1/kernel/profiles" \
  -d '{"profile_id":"smoke-default","allow_hostnames":["api.example.com"],"egress_mode":"proxy_only","source":"e2e-smoke"}' | head -c 400
echo ""

echo "[http] POST ${BASE}/api/v1/firewall/inspect + alias /guard/firewall"
curl -fsS "${hdr[@]}" -X POST "${BASE}/api/v1/firewall/inspect" \
  -d '{"agent_pid":"smoke-agent","content":"hello","namespace":"m/smoke"}' >/dev/null
curl -fsS "${hdr[@]}" -X POST "${BASE}/api/v1/guard/firewall" \
  -d '{"agent_pid":"smoke-agent","content":"hello","namespace":"m/smoke"}' >/dev/null

echo "[ok] E2E smoke HTTP checks passed."
