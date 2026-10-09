#!/usr/bin/env bash
# One-shot playground deploy (Talk identity-stack fix + AACR).
# Run this in a normal host terminal — the agent sandbox has no Docker socket
# and cannot reach api.fly.io.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -w "${HOME}/.fly" ]]; then
  echo "ERROR: ${HOME}/.fly is not writable (often owned by root)."
  echo "Fix:  sudo chown -R \"\$USER:\$USER\" ~/.fly"
  exit 1
fi

command -v docker >/dev/null || { echo "ERROR: docker required"; exit 1; }
command -v flyctl >/dev/null || { echo "ERROR: flyctl required"; exit 1; }

if ! flyctl auth whoami >/dev/null 2>&1; then
  echo "Fly auth missing — opening login…"
  flyctl auth login
fi

echo "Deploying connector-playground…"
exec ./scripts/build-and-deploy.sh
