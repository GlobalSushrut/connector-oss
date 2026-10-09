#!/usr/bin/env bash
# Single entrypoint for the premium TraceTramp + advanced lab stack (CONNECTOR_OS_ROADMAP.md §0.6).
# Requires DeepSeek credentials in advanced-lab/.env (see advanced-lab/.env.example).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${LAB_ENV_FILE:-$ROOT/advanced-lab/.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing env file: $ENV_FILE" >&2
  echo "  cp advanced-lab/.env.example advanced-lab/.env  # then set DEEPSEEK_API_KEY" >&2
  echo "Or: LAB_ENV_FILE=/path/to/.env $0 ..." >&2
  exit 1
fi

cd "$ROOT"
exec docker compose \
  --env-file "$ENV_FILE" \
  -f "$ROOT/lab/docker-compose.premium-lab.yml" \
  -f "$ROOT/lab/advanced.yml" \
  "$@"
