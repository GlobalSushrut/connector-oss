#!/usr/bin/env bash
# Ordered E2E checks for a recorded walkthrough: health → host smoke → OpenFang → in-compose DeepSeek smoke.
# Prereq: stack up with advanced lab extend, e.g. from repo root:
#   cd plugins/tracetramp && COMPOSE_PROFILES=lab docker compose \
#     --env-file ../../advanced-lab/.env -f docker-compose.yml -f ../../lab/advanced.yml up -d
set -euo pipefail

export TRACETRAMP_ADMIN_TOKEN="${TRACETRAMP_ADMIN_TOKEN:-lab_admin_token_static}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== 1) TraceTramp data + management health ==="
curl -fsS http://127.0.0.1:19741/health | head -c 200; echo; echo
curl -fsS http://127.0.0.1:19742/health | head -c 200; echo; echo

echo "=== 2) WitnessCtl + Connector health ==="
curl -fsS http://127.0.0.1:17443/health | head -c 200; echo; echo
curl -fsS http://127.0.0.1:19735/health | head -c 200; echo; echo

echo "=== 3) OpenFang lab agent service ==="
curl -fsS http://127.0.0.1:14200/health | head -c 200; echo; echo
curl -fsS http://127.0.0.1:14200/agents | head -c 400; echo; echo

echo "=== 4) One-shot researcher run (real TraceTramp → DeepSeek via compose env) ==="
curl -fsS -X POST http://127.0.0.1:14200/run/researcher \
  -H "Content-Type: application/json" \
  -d '{"tag":"e2e-video","messages":[{"role":"user","content":"Say hello in one short sentence for a connectivity test."}]}' | head -c 1200; echo; echo

echo "=== 5) Host smoke (admin stats, tenants, policies, models, connector) ==="
bash "${SCRIPT_DIR}/smoke_lab_io.sh"

echo "=== 6) In-compose lab_runner.smoke (Witness proxy + DeepSeek + correlation) ==="
cd "${ROOT_DIR}"
COMPOSE_PROFILES=lab docker compose --env-file ../../advanced-lab/.env \
  -f docker-compose.yml -f ../../lab/advanced.yml \
  run --rm lab-runner python -m lab_runner.smoke

echo "=== E2E video script finished OK ==="
