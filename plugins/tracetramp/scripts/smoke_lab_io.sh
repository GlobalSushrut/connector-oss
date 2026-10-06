#!/usr/bin/env bash
# Smoke I/O for TraceTramp premium lab (host ports from docker-compose.yml).
# Prereq: from this repo directory run: docker compose up -d
#   cd plugins/tracetramp && docker compose up -d
set -euo pipefail

DATA_URL="${TRACETRAMP_DATA_URL:-http://127.0.0.1:19741}"
MGMT_URL="${TRACETRAMP_MGMT_URL:-http://127.0.0.1:19742}"
# Default matches lab/advanced.yml (TraceTramp overlay for premium lab).
ADMIN_TOKEN="${TRACETRAMP_ADMIN_TOKEN:-lab_admin_token_static}"

hdr_auth=(-H "Authorization: Bearer ${ADMIN_TOKEN}")

echo "== TraceTramp lab smoke (data=${DATA_URL} mgmt=${MGMT_URL}) =="

echo "-> GET ${DATA_URL}/health"
curl -fsS "${DATA_URL}/health" | head -c 400; echo; echo

echo "-> GET ${MGMT_URL}/health"
curl -fsS "${MGMT_URL}/health" | head -c 400; echo; echo

echo "-> GET ${MGMT_URL}/admin/stats (admin bearer)"
curl -fsS "${hdr_auth[@]}" "${MGMT_URL}/admin/stats" | head -c 600; echo; echo

echo "-> GET ${MGMT_URL}/admin/tenants (admin bearer)"
curl -fsS "${hdr_auth[@]}" "${MGMT_URL}/admin/tenants" | head -c 600; echo; echo

echo "-> GET ${MGMT_URL}/admin/policies (admin bearer)"
curl -fsS "${hdr_auth[@]}" "${MGMT_URL}/admin/policies" | head -c 600; echo; echo

echo "-> GET ${DATA_URL}/v1/models (data plane; may be unauthenticated in lab)"
curl -fsS "${DATA_URL}/v1/models" | head -c 500; echo; echo

CONNECTOR_URL="${CONNECTOR_OSS_URL:-http://127.0.0.1:19735}"
echo "-> GET ${CONNECTOR_URL}/health (lab Connector OSS from compose)"
curl -fsS "${CONNECTOR_URL}/health" | head -c 300; echo; echo

echo "OK — TraceTramp data + management planes responded."

echo ""
echo "Leptos operator UI (connector-platform):"
echo "  export CONNECTOR_TRACETRAMP_MANAGEMENT_URL=${MGMT_URL}"
echo "  export CONNECTOR_TRACETRAMP_ADMIN_TOKEN=\${TRACETRAMP_ADMIN_TOKEN:-lab_admin_token_static}"
echo "  cd platform/server && CONNECTOR_PRESET=local CONNECTOR_LLM_STUB=1 cargo run --bin connector-platform"
echo "  Open http://localhost:9091/plugins/tracetramp (default CONNECTOR_PORT=9091 from repo Makefile)"
