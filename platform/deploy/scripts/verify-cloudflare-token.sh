#!/usr/bin/env bash
# Verify CLOUDFLARE_API_TOKEN from platform/deploy/.env (never commit .env).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${CONNECTOR_DEPLOY_ENV:-$ROOT/.env}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
fi

: "${CLOUDFLARE_API_TOKEN:?Set CLOUDFLARE_API_TOKEN in $ENV_FILE (copy from .env.example)}"

API="https://api.cloudflare.com/client/v4"
auth=(-H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" -H "Content-Type: application/json")

echo "== Cloudflare token verify =="

echo -n "[1] Token valid … "
verify="$(curl -sf "${API}/user/tokens/verify" "${auth[@]}")"
echo "$verify" | python3 -c "import json,sys; d=json.load(sys.stdin); print('OK' if d.get('success') else 'FAIL'); sys.exit(0 if d.get('success') else 1)"

echo "[2] Zones (cnktros.com) …"
zones="$(curl -sf "${API}/zones?name=cnktros.com" "${auth[@]}")"
ZONE_ID="$(echo "$zones" | python3 -c "
import json, sys
d = json.load(sys.stdin)
if not d.get('success'):
    print('FAIL:', d.get('errors'), file=sys.stderr); sys.exit(1)
r = d.get('result') or []
if not r:
    print('FAIL: cnktros.com zone not visible to this token', file=sys.stderr); sys.exit(1)
z = r[0]
print(f\"  zone_id={z['id']}  name={z['name']}  status={z['status']}\", file=sys.stderr)
print(z['id'])
")"

if [[ -n "${CLOUDFLARE_ZONE_ID:-}" && "${CLOUDFLARE_ZONE_ID}" != "your_zone_id_here" && "$CLOUDFLARE_ZONE_ID" != "$ZONE_ID" ]]; then
  echo "  warn: CLOUDFLARE_ZONE_ID in .env does not match API ($CLOUDFLARE_ZONE_ID vs $ZONE_ID)"
fi

check() {
  local name="$1" path="$2"
  echo -n "[$name] … "
  resp="$(curl -sS "${API}/zones/${ZONE_ID}${path}" "${auth[@]}" 2>/dev/null || echo '{"success":false}')"
  echo "$resp" | python3 -c "
import json, sys
d = json.load(sys.stdin)
if d.get('success'):
    print('OK')
else:
    errs = d.get('errors') or []
    msg = errs[0].get('message', 'unknown') if errs else json.dumps(d)[:120]
    code = errs[0].get('code', '') if errs else ''
    print(f'FAIL ({code}) {msg}')
    sys.exit(0)
"
}

# Prefer zone id from .env when it matches API discovery
if [[ -n "${CLOUDFLARE_ZONE_ID:-}" && "${CLOUDFLARE_ZONE_ID}" != "your_zone_id_here" ]]; then
  ZONE_ID="$CLOUDFLARE_ZONE_ID"
fi

check "3 DNS records" "/dns_records?per_page=5"
check "4 SSL certs (SSL and Certificates)" "/ssl/certificate_packs?per_page=1"
check "4b Zone TLS mode (/settings/ssl)" "/settings/ssl"
check "5 Firewall rules (legacy)" "/firewall/rules?per_page=1"
check "6 WAF packages" "/firewall/waf/packages?per_page=1"

echo ""
echo "== Summary =="
echo "  Core deploy (DNS, WAF, firewall, SSL certs): [1][2][3][4][5][6] should be OK"
echo "  [4b] /settings/ssl needs «Zone Settings: Read» (separate from SSL and Certificates)"
echo "  Set Full (strict) + HSTS in dashboard, or add Zone Settings Read to the token"
echo ""
echo "== Done. CLOUDFLARE_ZONE_ID=$ZONE_ID =="
echo "Wrangler: export CLOUDFLARE_API_TOKEN=... && wrangler whoami"
