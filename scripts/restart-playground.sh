#!/usr/bin/env bash
# Fast recovery when try.cnktros.com shows 503 (platform not listening on :8080).
set -euo pipefail
APP="connector-playground"
MID="${1:-d895907a61d6e8}"
export HOME="${HOME:-/home/umesh}"
export PATH="${HOME}/.fly/bin:${PATH}"
command -v flyctl >/dev/null || { echo "flyctl required"; exit 1; }
echo "Restarting ${APP} machine ${MID}…"
flyctl machines restart "$MID" -a "$APP" --force
echo "Waiting 75s for supervisord + connector-platform…"
sleep 75
flyctl checks list -a "$APP" || true
curl -sS -o /dev/null -w "health=%{http_code}\n" --max-time 30 "https://try.cnktros.com/health" || true
curl -sS -o /dev/null -w "trial=%{http_code}\n" --max-time 30 "https://try.cnktros.com/trial" || true
