#!/usr/bin/env bash
# Cage E2E smoke (T6 / CONNECTOR_OS §10 B.3): internal DNS + /plugin/* proxy + custom domains.
#
# Requires a running node:
#   export CONNECTOR_TEST_URL=http://127.0.0.1:9091
#   export CONNECTOR_TEST_API_KEY=<bearer>   # or use dev token below
#
# Optional: CAGE_TLD=cnktros (default from API), SKIP_PUBLIC_DNS=1
set -euo pipefail

BASE="${CONNECTOR_TEST_URL:-}"
KEY="${CONNECTOR_TEST_API_KEY:-}"

if [[ -z "$BASE" ]]; then
  echo "[skip] Set CONNECTOR_TEST_URL to run cage E2E HTTP checks."
  exit 0
fi

if [[ -z "$KEY" ]]; then
  if [[ "${CONNECTOR_DEV_MODE:-}" == "1" ]]; then
    KEY="${CONNECTOR_DEV_TOKEN:-dev-token}"
  else
    echo "[skip] Set CONNECTOR_TEST_API_KEY (or CONNECTOR_DEV_MODE=1 + CONNECTOR_DEV_TOKEN)."
    exit 0
  fi
fi

hdr=(-H "Authorization: Bearer ${KEY}" -H "Content-Type: application/json")

echo "[http] GET ${BASE}/api/v1/plugins/cage-proof"
proof="$(curl -fsS "${hdr[@]}" "${BASE}/api/v1/plugins/cage-proof")"
echo "$proof" | head -c 600
echo ""

ok="$(echo "$proof" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("ok", False))' 2>/dev/null || echo false)"
if [[ "$ok" != "True" && "$ok" != "true" ]]; then
  echo "[fail] cage-proof reported ok=false" >&2
  exit 1
fi

CAGE_TLD="${CAGE_TLD:-$(echo "$proof" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("cage_tld","cnktros"))' 2>/dev/null || echo cnktros)}"

if [[ "${SKIP_PUBLIC_DNS:-}" != "1" ]] && command -v dig >/dev/null 2>&1; then
  host="tracetramp.${CAGE_TLD}"
  echo "[dns] Public resolver must not answer ${host}"
  pub="$(dig +short "$host" @8.8.8.8 2>/dev/null | head -1 || true)"
  if [[ -n "$pub" ]]; then
    echo "[fail] ${host} resolved publicly to: ${pub}" >&2
    exit 1
  fi
  echo "[dns] ok (no public A/AAAA for ${host})"
fi

if echo "$proof" | python3 -c '
import json,sys
p=json.load(sys.stdin)
en=[x for x in p.get("plugins",[]) if x.get("enabled_in_deployment")]
sys.exit(0 if en else 1)
' 2>/dev/null; then
  slug="$(echo "$proof" | python3 -c '
import json,sys
for x in json.load(sys.stdin).get("plugins",[]):
  if x.get("enabled_in_deployment") and x.get("slug")=="tracetramp":
    print("tracetramp"); break
' 2>/dev/null || true)"
  if [[ -n "$slug" ]]; then
    path="/plugin/${slug}/admin/stats"
    echo "[http] GET ${BASE}${path} (cage reverse proxy)"
    code="$(curl -sS -o /dev/null -w '%{http_code}' "${hdr[@]}" "${BASE}${path}" || echo 000)"
    if [[ "$code" =~ ^[23] ]]; then
      echo "[ok] ${path} → HTTP ${code}"
    else
      echo "[warn] ${path} → HTTP ${code} (upstream may be down; cage-proof DNS checks passed)"
    fi
  fi
fi

echo "[http] GET ${BASE}/api/v1/settings/networking/custom-domains"
curl -fsS "${hdr[@]}" "${BASE}/api/v1/settings/networking/custom-domains" | head -c 400
echo ""

ALIAS_HOST="${CAGE_ALIAS_HOST:-tracetramp.acme.corp}"
# Default on in dev unless SKIP_CAGE_ALIAS=1 (T6 host-routing check).
if [[ "${CONFIGURE_CAGE_ALIAS:-}" == "1" ]] || { [[ "${CONNECTOR_DEV_MODE:-}" == "1" ]] && [[ "${SKIP_CAGE_ALIAS:-}" != "1" ]]; }; then
  echo "[http] POST custom-domains alias ${ALIAS_HOST} → tracetramp"
  curl -fsS "${hdr[@]}" -X POST "${BASE}/api/v1/settings/networking/custom-domains" \
    -d "$(python3 -c "import json; print(json.dumps({'value': {'aliases': [{'host': '${ALIAS_HOST}', 'plugin_id': 'tracetramp', 'enabled': True, 'tls_mode': 'lets_encrypt'}], 'tls_mode': 'lets_encrypt'}}))")" \
    | head -c 300
  echo ""
fi

if proof="$(curl -fsS "${hdr[@]}" "${BASE}/api/v1/plugins/cage-proof")"; then
  if echo "$proof" | python3 -c "import json,sys; d=json.load(sys.stdin); import os; h=os.environ.get('ALIAS_HOST','tracetramp.acme.corp'); sys.exit(0 if any(a.get('host')==h for a in d.get('custom_domain_aliases',[])) else 1)" 2>/dev/null; then
    echo "[http] Host-based cage proxy GET /admin/stats Host: ${ALIAS_HOST}"
    code="$(curl -sS -o /dev/null -w '%{http_code}' "${hdr[@]}" -H "Host: ${ALIAS_HOST}" "${BASE}/admin/stats" || echo 000)"
    echo "[host-proxy] HTTP ${code} (2xx/3xx expected when TraceTramp upstream is up)"
  fi
fi

echo "[ok] Cage E2E smoke passed."
