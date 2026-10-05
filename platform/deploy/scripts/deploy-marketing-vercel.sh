#!/usr/bin/env bash
# Deploy cnktros.com marketing site to Vercel.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
WEB="${REPO_ROOT}/platform/docs/landing-page/web"
ENV_FILE="${CONNECTOR_DEPLOY_ENV:-${SCRIPT_DIR}/../.env}"

export PATH="${HOME}/.nvm/versions/node/v24.15.0/bin:${PATH:-}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
fi

command -v vercel >/dev/null || { echo "Install: npm i -g vercel" >&2; exit 1; }

cd "$WEB"
export VITE_PORTAL_BASE_URL="${VITE_PORTAL_BASE_URL:-https://portal.cnktros.com}"
export VITE_PLAYGROUND_BASE_URL="${VITE_PLAYGROUND_BASE_URL:-https://try.cnktros.com}"
export VITE_API_BASE_URL="${VITE_API_BASE_URL:-https://api.cnktros.com}"

echo "[marketing] Building…"
npm ci
npm run build

echo "[marketing] Deploying to Vercel (production)…"
vercel deploy --prod --yes

echo "[marketing] Set these in Vercel → Project → Environment Variables (Production):"
echo "  VITE_PORTAL_BASE_URL=${VITE_PORTAL_BASE_URL}"
echo "  VITE_PLAYGROUND_BASE_URL=${VITE_PLAYGROUND_BASE_URL}"
echo "  VITE_API_BASE_URL=${VITE_API_BASE_URL}"
