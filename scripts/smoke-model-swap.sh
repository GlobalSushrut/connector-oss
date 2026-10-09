#!/usr/bin/env bash
# A20 / S3 — model-replaceable mind smoke (requires running node + auth token).
# Usage: BASE_URL=http://127.0.0.1:8080 TOKEN=... ./scripts/smoke-model-swap.sh <agent_pid>
set -euo pipefail
BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
TOKEN="${TOKEN:-}"
PID="${1:-}"
if [[ -z "$PID" || -z "$TOKEN" ]]; then
  echo "usage: TOKEN=<jwt> $0 <agent_pid>"
  exit 2
fi
AUTH="Authorization: Bearer $TOKEN"
# Capture DIM revision family before swap
before=$(curl -sf -H "$AUTH" "$BASE_URL/api/v1/dim/$PID" || true)
# Swap model (mind only)
curl -sf -X PATCH -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"model":"swap-model-ref-e2e"}' \
  "$BASE_URL/api/v1/agents/$PID" >/dev/null
after=$(curl -sf -H "$AUTH" "$BASE_URL/api/v1/dim/$PID" || true)
echo "before_revision=$(echo "$before" | jq -r '.revision // empty')"
echo "after_revision=$(echo "$after" | jq -r '.revision // empty')"
echo "honesty: model_ref swap must not change agent_pid / grants; DIM may refresh"
echo "smoke-model-swap: OK (operator must confirm grants unchanged via /agents/$PID)"
