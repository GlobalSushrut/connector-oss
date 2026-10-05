#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${1:-$ROOT/images.env}"

[[ -f "$ENV_FILE" ]] || {
  echo "[error] missing $ENV_FILE; copy images.env.example and fill it" >&2
  exit 2
}

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

require() {
  local name="$1"
  [[ -n "${!name:-}" ]] || {
    echo "[error] required value is empty: $name" >&2
    exit 2
  }
}

for name in POSTGRES_IMAGE KEYCLOAK_IMAGE OTEL_COLLECTOR_IMAGE \
  KEYCLOAK_DB_PASSWORD KEYCLOAK_ADMIN KEYCLOAK_ADMIN_PASSWORD \
  KEYCLOAK_HOSTNAME KEYCLOAK_TLS_DIR \
  CONNECTOR_SSO_CLIENT_ID CONNECTOR_SSO_CLIENT_SECRET CONNECTOR_SSO_REDIRECT_URI
do
  require "$name"
done

for name in POSTGRES_IMAGE KEYCLOAK_IMAGE OTEL_COLLECTOR_IMAGE; do
  [[ "${!name}" == *@sha256:* ]] || {
    echo "[error] $name must be pinned by digest, got '${!name}'" >&2
    exit 2
  }
done

docker compose --env-file "$ENV_FILE" -f "$ROOT/compose.yaml" up -d
echo "[ok] Keycloak, PostgreSQL, and OpenTelemetry Collector launched from digest-pinned images"
echo "[next] $ROOT/bootstrap-keycloak.sh $ENV_FILE"
