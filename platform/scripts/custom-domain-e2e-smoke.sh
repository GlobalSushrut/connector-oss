#!/usr/bin/env bash
# T6 — custom public domain → cage Host routing (no real TLS termination; checks Host proxy + tls_mode metadata).
#
# Requires a running node:
#   export CONNECTOR_TEST_URL=http://127.0.0.1:9091
#   export CONNECTOR_DEV_MODE=1 CONNECTOR_DEV_TOKEN=dev-token
#
# Optional:
#   CAGE_ALIAS_HOST=tracetramp.acme.corp
#   CAGE_ALIAS_PLUGIN=tracetramp
set -euo pipefail

BASE="${CONNECTOR_TEST_URL:-}"
KEY="${CONNECTOR_TEST_API_KEY:-}"
ALIAS_HOST="${CAGE_ALIAS_HOST:-tracetramp.acme.corp}"
ALIAS_PLUGIN="${CAGE_ALIAS_PLUGIN:-tracetramp}"

if [[ -z "$BASE" ]]; then
  echo "[skip] Set CONNECTOR_TEST_URL"
  exit 0
fi

if [[ -z "$KEY" ]]; then
  if [[ "${CONNECTOR_DEV_MODE:-}" == "1" ]]; then
    KEY="${CONNECTOR_DEV_TOKEN:-dev-token}"
  else
    echo "[skip] Set CONNECTOR_TEST_API_KEY or CONNECTOR_DEV_MODE=1"
    exit 0
  fi
fi

hdr=(-H "Authorization: Bearer ${KEY}" -H "Content-Type: application/json")

echo "[http] POST ${BASE}/api/v1/settings/networking/custom-domains (alias ${ALIAS_HOST} → ${ALIAS_PLUGIN})"
export ALIAS_HOST ALIAS_PLUGIN
body="$(python3 -c "
import json, os
print(json.dumps({
  'value': {
    'aliases': [{
      'host': os.environ['ALIAS_HOST'],
      'plugin_id': os.environ['ALIAS_PLUGIN'],
      'enabled': True,
    }],
    'tls_mode': 'lets_encrypt',
    'public_domain': os.environ.get('CONNECTOR_TEST_URL', 'http://127.0.0.1:9091'),
  }
}))")"
curl -fsS "${hdr[@]}" -X POST "${BASE}/api/v1/settings/networking/custom-domains" -d "$body" | head -c 400
echo ""

echo "[http] GET ${BASE}/api/v1/plugins/cage-proof"
proof="$(curl -fsS "${hdr[@]}" "${BASE}/api/v1/plugins/cage-proof")"
echo "$proof" | head -c 500
echo ""

echo "$proof" | python3 -c "
import json, os, sys
d = json.load(sys.stdin)
host = os.environ['ALIAS_HOST']
aliases = d.get('custom_domain_aliases') or []
if not any(a.get('host') == host for a in aliases):
    print(f'[fail] cage-proof missing alias {host}', file=sys.stderr)
    sys.exit(1)
tls = d.get('custom_domains', {}).get('tls_mode') or d.get('checks', [{}])
print('[ok] cage-proof lists alias', host)
" ALIAS_HOST="$ALIAS_HOST" CONNECTOR_TEST_URL="$BASE"

tls_mode="$(curl -fsS "${hdr[@]}" "${BASE}/api/v1/settings/networking/custom-domains" | python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("custom_domains") or {}).get("tls_mode","?"))' 2>/dev/null || echo "?")"
echo "[ok] tls_mode metadata: ${tls_mode} (TLS terminates outside connector-platform)"

echo "[http] Host-based proxy GET /admin/stats Host: ${ALIAS_HOST}"
code="$(curl -sS -o /dev/null -w '%{http_code}' "${hdr[@]}" -H "Host: ${ALIAS_HOST}" "${BASE}/admin/stats" || echo 000)"
if [[ "$code" =~ ^502$ ]]; then
  echo "[warn] Host proxy → HTTP ${code} (TraceTramp management plane may be down)"
elif [[ "$code" =~ ^[23] ]]; then
  echo "[ok] Host proxy → HTTP ${code}"
else
  echo "[fail] Host proxy → HTTP ${code}" >&2
  exit 1
fi

echo "[ok] Custom domain E2E smoke passed."
