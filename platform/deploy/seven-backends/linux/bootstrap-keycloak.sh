#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${1:-$ROOT/images.env}"
[[ -f "$ENV_FILE" ]] || { echo "[error] missing $ENV_FILE" >&2; exit 2; }

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

for name in KEYCLOAK_ADMIN KEYCLOAK_ADMIN_PASSWORD CONNECTOR_SSO_CLIENT_ID \
  CONNECTOR_SSO_CLIENT_SECRET CONNECTOR_SSO_REDIRECT_URI
do
  [[ -n "${!name:-}" ]] || { echo "[error] $name is required" >&2; exit 2; }
done

DC=(docker compose --env-file "$ENV_FILE" -f "$ROOT/compose.yaml")
KCADM=(/opt/keycloak/bin/kcadm.sh)

"${DC[@]}" exec -T keycloak "${KCADM[@]}" config credentials \
  --server http://127.0.0.1:8080 \
  --realm master \
  --user "$KEYCLOAK_ADMIN" \
  --password "$KEYCLOAK_ADMIN_PASSWORD" >/dev/null

if ! "${DC[@]}" exec -T keycloak "${KCADM[@]}" get realms/connector >/dev/null 2>&1; then
  "${DC[@]}" exec -T keycloak "${KCADM[@]}" create realms \
    -s realm=connector \
    -s enabled=true \
    -s registrationAllowed=false \
    -s resetPasswordAllowed=true >/dev/null
fi

CLIENT_UUID="$("${DC[@]}" exec -T keycloak "${KCADM[@]}" get clients \
  -r connector -q "clientId=$CONNECTOR_SSO_CLIENT_ID" --fields id \
  | tr -d '\r' | awk -F'"' '/"id"/ {print $4; exit}')"

if [[ -z "$CLIENT_UUID" ]]; then
  "${DC[@]}" exec -T keycloak "${KCADM[@]}" create clients -r connector \
    -s "clientId=$CONNECTOR_SSO_CLIENT_ID" \
    -s enabled=true \
    -s publicClient=false \
    -s clientAuthenticatorType=client-secret \
    -s standardFlowEnabled=true \
    -s directAccessGrantsEnabled=false \
    -s "secret=$CONNECTOR_SSO_CLIENT_SECRET" \
    -s "redirectUris=[\"$CONNECTOR_SSO_REDIRECT_URI\"]" \
    -s 'attributes."pkce.code.challenge.method"=S256' >/dev/null
else
  "${DC[@]}" exec -T keycloak "${KCADM[@]}" update "clients/$CLIENT_UUID" -r connector \
    -s enabled=true \
    -s publicClient=false \
    -s standardFlowEnabled=true \
    -s directAccessGrantsEnabled=false \
    -s "secret=$CONNECTOR_SSO_CLIENT_SECRET" \
    -s "redirectUris=[\"$CONNECTOR_SSO_REDIRECT_URI\"]" \
    -s 'attributes."pkce.code.challenge.method"=S256' >/dev/null
fi

for role in connector-operator connector-admin; do
  if ! "${DC[@]}" exec -T keycloak "${KCADM[@]}" get "roles/$role" -r connector >/dev/null 2>&1; then
    "${DC[@]}" exec -T keycloak "${KCADM[@]}" create roles -r connector \
      -s "name=$role" >/dev/null
  fi
done

echo "[ok] Keycloak realm 'connector' and confidential PKCE client are configured"
echo "[honesty] no login is marked ready until Connector verifies a real JWKS-signed ID token"
