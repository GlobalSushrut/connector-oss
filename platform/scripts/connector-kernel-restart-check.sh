#!/usr/bin/env bash
# Checklist §10.3: optional process/container restart then re-verify kernel API contract.
# In-memory platform stub loses attachments across restart — use for wiring/CI until state is persisted.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$ROOT/scripts/connector-kernel-prod-preflight.sh"

BASE="${CONNECTOR_TEST_URL:-}"
KEY="${CONNECTOR_TEST_API_KEY:-}"
AGENT="${CONNECTOR_TEST_AGENT_PID:-smoke-restart-agent}"
PROFILE="${CONNECTOR_TEST_KERNEL_PROFILE:-smoke-restart-profile}"

if [[ -z "$BASE" || -z "$KEY" ]]; then
  echo "[skip] Set CONNECTOR_TEST_URL and CONNECTOR_TEST_API_KEY."
  exit 0
fi

hdr=(-H "Authorization: Bearer ${KEY}" -H "Content-Type: application/json")

echo "[http] upsert profile + attach ${AGENT}"
curl -fsS "${hdr[@]}" -X POST "${BASE}/api/v1/kernel/profiles" \
  -d "{\"profile_id\":\"${PROFILE}\",\"allow_hostnames\":[\"api.example.com\"],\"egress_mode\":\"proxy_only\",\"source\":\"restart-check\"}" >/dev/null
curl -fsS "${hdr[@]}" -X POST "${BASE}/api/v1/kernel/agents/${AGENT}/attach" \
  -d "{\"profile_id\":\"${PROFILE}\"}" >/dev/null
curl -fsS "${hdr[@]}" "${BASE}/api/v1/kernel/agents/${AGENT}/status" | head -c 500
echo ""

if [[ -n "${CONNECTOR_KERNEL_RESTART_CMD:-}" ]]; then
  echo "[restart] Running: ${CONNECTOR_KERNEL_RESTART_CMD}"
  eval "${CONNECTOR_KERNEL_RESTART_CMD}"
  sleep "${CONNECTOR_KERNEL_RESTART_WAIT_SEC:-5}"
  echo "[http] GET status after restart"
  code="$(curl -sS -o /tmp/ck_restart_body.json -w '%{http_code}' "${hdr[@]}" "${BASE}/api/v1/kernel/agents/${AGENT}/status" || true)"
  echo "HTTP ${code}"
  head -c 600 /tmp/ck_restart_body.json || true
  echo ""
  if [[ "${CONNECTOR_KERNEL_RESTART_EXPECT_PERSISTENT:-0}" == "1" ]]; then
    if [[ "${code}" != "200" ]]; then
      echo "[fail] Expected 200 after restart (CONNECTOR_KERNEL_RESTART_EXPECT_PERSISTENT=1)."
      exit 1
    fi
    if ! grep -q '"host_apply_state":"active"' /tmp/ck_restart_body.json 2>/dev/null; then
      echo "[fail] Expected active attachment in JSON."
      exit 1
    fi
  else
    echo "[info] CONNECTOR_KERNEL_RESTART_EXPECT_PERSISTENT unset/0 — not failing on 404 (stub has no cross-restart state)."
  fi
else
  echo "[skip] Set CONNECTOR_KERNEL_RESTART_CMD to exercise real restart (e.g. docker compose restart platform)."
fi

echo "[ok] restart-check script finished."
