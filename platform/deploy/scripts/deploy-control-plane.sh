#!/usr/bin/env bash
# Connector OS control-plane deploy: Neon + Fly + Cloudflare (+ UI build).
# Usage: bash platform/deploy/scripts/deploy-control-plane.sh [init|secrets|ui|license|playground|dns|all]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${DEPLOY_DIR}/../.." && pwd)"
ENV_FILE="${CONNECTOR_DEPLOY_ENV:-$DEPLOY_DIR/.env}"

export PATH="${HOME}/.fly/bin:${HOME}/.nvm/versions/node/v24.15.0/bin:/usr/bin:/bin:${PATH:-}"

info() { echo "[deploy] $*"; }
die() { echo "[deploy] ERROR: $*" >&2; exit 1; }

load_env() {
  [[ -f "$ENV_FILE" ]] || die "Missing $ENV_FILE — copy from .env.example"
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
}

ensure_admin_key() {
  if [[ -z "${CONNECTOR_LICENSE_ADMIN_KEY:-}" || "${CONNECTOR_LICENSE_ADMIN_KEY}" == change-me* ]]; then
    local hex
    hex="$(openssl rand -hex 24)"
    CONNECTOR_LICENSE_ADMIN_KEY="sk_admin_${hex}"
    echo "CONNECTOR_LICENSE_ADMIN_KEY=${CONNECTOR_LICENSE_ADMIN_KEY}" >> "$ENV_FILE"
    info "Generated CONNECTOR_LICENSE_ADMIN_KEY in .env (paste into admin UI login)"
  fi
}

neon_database_url() {
  if [[ -n "${DATABASE_URL:-}" ]]; then
    echo "$DATABASE_URL"
    return
  fi
  local pid="${NEON_PROJECT_ID:-late-water-00019648}"
  neonctl connection-string --project-id "$pid" --branch main --database-name "${NEON_DATABASE:-neondb}" \
    --role-name "${NEON_ROLE:-neondb_owner}" --pooled 2>/dev/null | tail -1
}

cmd_init() {
  bash "${SCRIPT_DIR}/fly-deploy.sh" init
}

cmd_ui() {
  info "Building portal + admin WASM (trunk)…"
  command -v trunk >/dev/null || die "Install trunk: cargo install trunk"
  make -C "${REPO_ROOT}/platform/ui-leptos" build-www build-admin
}

cmd_secrets() {
  load_env
  ensure_admin_key
  local db_url
  db_url="$(neon_database_url)"
  [[ -n "$db_url" ]] || die "DATABASE_URL unset and neonctl failed"

  info "Setting Fly secrets on connector-license (not printing values)…"
  fly secrets set -a connector-license \
    DATABASE_URL="$db_url" \
    CONNECTOR_LICENSE_ADMIN_KEY="${CONNECTOR_LICENSE_ADMIN_KEY}" \
    CONNECTOR_PORTAL_JWT_SECRET="${CONNECTOR_PORTAL_JWT_SECRET:-$(openssl rand -hex 32)}" \
    CONNECTOR_RPC_SECRET="${CONNECTOR_RPC_SECRET:-$(openssl rand -hex 32)}" \
    CONNECTOR_PUBLIC_URL="${CONNECTOR_PUBLIC_URL:-https://portal.cnktros.com}" \
    CONNECTOR_CORS_ORIGINS="${CONNECTOR_CORS_ORIGINS:-https://portal.cnktros.com,https://admin.cnktros.com,https://api.cnktros.com,https://cnktros.com,https://www.cnktros.com}" \
    CONNECTOR_FROM_EMAIL="${CONNECTOR_FROM_EMAIL:-noreply@cnktros.com}" \
    ${STRIPE_SECRET_KEY:+STRIPE_SECRET_KEY="$STRIPE_SECRET_KEY"} \
    ${STRIPE_WEBHOOK_SECRET:+STRIPE_WEBHOOK_SECRET="$STRIPE_WEBHOOK_SECRET"} \
    ${SENDGRID_API_KEY:+SENDGRID_API_KEY="$SENDGRID_API_KEY"}

  fly secrets set -a connector-playground \
    CONNECTOR_LICENSE_SERVER="https://api.cnktros.com" \
    CONNECTOR_PUBLIC_URL="${PLAYGROUND_PUBLIC_URL:-https://try.cnktros.com}" \
    CONNECTOR_PLAYGROUND=1
  info "Secrets set."
}

cmd_license() { cmd_ui; bash "${SCRIPT_DIR}/fly-deploy.sh" license; }
cmd_playground() { bash "${SCRIPT_DIR}/fly-deploy.sh" playground; }
cmd_dns() { bash "${SCRIPT_DIR}/cloudflare-dns.sh"; }
cmd_marketing() { bash "${SCRIPT_DIR}/deploy-marketing-vercel.sh"; }

cmd_all() {
  cmd_init
  cmd_secrets
  cmd_license
  cmd_playground
  cmd_dns
  info "Next: fly certs add api.cnktros.com portal.cnktros.com -a connector-license"
  info "Next: fly certs add try.cnktros.com -a connector-playground"
  info "Admin UI: https://admin.cnktros.com/admin — key: sk_admin_<first32 of CONNECTOR_LICENSE_ADMIN_KEY>"
}

case "${1:-all}" in
  init) cmd_init ;;
  secrets) cmd_secrets ;;
  ui) cmd_ui ;;
  license) cmd_license ;;
  playground) cmd_playground ;;
  dns) cmd_dns ;;
  marketing) cmd_marketing ;;
  all) cmd_all ;;
  *)
    echo "Usage: $0 {init|secrets|ui|license|playground|dns|marketing|all}"
    exit 1
    ;;
esac
