#!/usr/bin/env bash
# Create/update cnktros.com DNS for control plane (throttled; one record at a time).
#
# Usage:
#   bash cloudflare-dns.sh              # all Fly records, 4s apart
#   DNS_RECORD=api bash cloudflare-dns.sh   # single record only
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${CONNECTOR_DEPLOY_ENV:-$ROOT/.env}"
[[ -f "$ENV_FILE" ]] && { set -a; source "$ENV_FILE"; set +a; }

: "${CLOUDFLARE_API_TOKEN:?}"
: "${CLOUDFLARE_ZONE_ID:?}"

LICENSE_HOST="${LICENSE_FLY_HOST:-connector-license.fly.dev}"
PLAYGROUND_HOST="${PLAYGROUND_FLY_HOST:-connector-playground.fly.dev}"
VERCEL_CNAME="${VERCEL_CNAME_TARGET:-cname.vercel-dns.com}"
CF_PROXY_FLY="${CF_PROXY_FLY:-false}"
CF_PROXY_ADMIN="${CF_PROXY_ADMIN:-false}"
CF_SLEEP_SECS="${CF_SLEEP_SECS:-5}"

API="https://api.cloudflare.com/client/v4"
auth=(-H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" -H "Content-Type: application/json")

cf_wait() {
  local secs="${1:-$CF_SLEEP_SECS}"
  echo "[cloudflare-dns] waiting ${secs}s (rate-limit backoff)…"
  sleep "$secs"
}

upsert_cname() {
  local name="$1" target="$2" proxied="${3:-true}"
  local fqdn="${name}.cnktros.com"
  echo "[cloudflare-dns] ${fqdn} → ${target} (proxied=${proxied})"

  local existing
  existing="$(curl -sS "${API}/zones/${CLOUDFLARE_ZONE_ID}/dns_records?type=CNAME&name=${fqdn}" "${auth[@]}")"
  local success
  success="$(echo "$existing" | python3 -c "import json,sys; d=json.load(sys.stdin); print('yes' if d.get('success') else 'no')")"
  if [[ "$success" != "yes" ]]; then
    echo "$existing" | python3 -c "import json,sys; d=json.load(sys.stdin); print('  list error:', d.get('errors'))"
    return 1
  fi

  local id
  id="$(echo "$existing" | python3 -c "import json,sys; r=json.load(sys.stdin).get('result') or []; print(r[0]['id'] if r else '')")"
  local proxied_py="True"
  [[ "$proxied" == "false" ]] && proxied_py="False"
  local body
  body="$(python3 -c "import json; print(json.dumps({'type':'CNAME','name':'$name','content':'$target','proxied':$proxied_py,'ttl':1}))")"

  local resp
  if [[ -n "$id" ]]; then
    resp="$(curl -sS -X PATCH "${API}/zones/${CLOUDFLARE_ZONE_ID}/dns_records/${id}" "${auth[@]}" -d "$body")"
    action="updated"
  else
    resp="$(curl -sS -X POST "${API}/zones/${CLOUDFLARE_ZONE_ID}/dns_records" "${auth[@]}" -d "$body")"
    action="created"
  fi
  echo "$resp" | python3 -c "
import json,sys
d=json.load(sys.stdin)
ok=d.get('success')
print('  ', '$action', '$name', ok)
if not ok:
    for e in d.get('errors') or []:
        print('  error:', e.get('code'), e.get('message', e))
    sys.exit(1)
r=(d.get('result') or {})
if r:
    print('  id=', r.get('id',''), 'proxied=', r.get('proxied'))
"
}

apply_record() {
  case "$1" in
    api)    upsert_cname "api" "$LICENSE_HOST" "$CF_PROXY_FLY" ;;
    portal) upsert_cname "portal" "$LICENSE_HOST" "$CF_PROXY_FLY" ;;
    admin)  upsert_cname "admin" "$LICENSE_HOST" "$CF_PROXY_ADMIN" ;;
    try)    upsert_cname "try" "$PLAYGROUND_HOST" "$CF_PROXY_FLY" ;;
    *) echo "Unknown DNS_RECORD=$1 (use api|portal|admin|try)" >&2; return 1 ;;
  esac
}

echo "== cloudflare-dns =="
echo -n "[preflight] token verify … "
if ! curl -sf "${API}/user/tokens/verify" "${auth[@]}" | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin).get('success') else 1)"; then
  echo "FAIL — invalid CLOUDFLARE_API_TOKEN" >&2
  exit 1
fi
echo "OK"
echo -n "[preflight] zone access … "
zone_check="$(curl -sS "${API}/zones/${CLOUDFLARE_ZONE_ID}" "${auth[@]}")"
if ! echo "$zone_check" | python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get('success') else 1)"; then
  echo "FAIL" >&2
  echo "$zone_check" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for e in d.get('errors') or []:
    c=e.get('code','')
    m=e.get('message','')
    print(' ', c, m)
    if c == 9109:
        print()
        print('  Fix: Cloudflare → My Profile → API Tokens → edit token')
        print('  Remove «IP Address Filtering» OR add your current public IP.')
        print('  Or set DNS manually: platform/deploy/CLOUDFLARE_DNS_FIX.md')
" >&2
  exit 1
fi
echo "OK"
cf_wait 2

if [[ -n "${DNS_RECORD:-}" ]]; then
  apply_record "$DNS_RECORD"
else
  for rec in api portal admin try; do
    apply_record "$rec"
    cf_wait
  done
  echo "  (cnktros.com / www → ${VERCEL_CNAME} — set in dashboard for Vercel marketing)"
fi
echo "== done =="
