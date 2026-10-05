#!/usr/bin/env bash
# Start Postgres + Redis + OSS Connector + TraceTramp + WitnessCtl (same stack as lab/docker-compose.premium-lab.yml;
# images build from lab/Dockerfile.* — see lab/README.md).
# Then point connector-platform at the management planes with the env vars printed below.
#
# DevGuard is not containerized here: on your laptop run `devguard status-api` and set
# CONNECTOR_DEVGUARD_MANAGEMENT_URL on the platform to that bind address.
#
# Usage:
#   ./platform/scripts/plugins-dev-stack-up.sh
# Optional: ./platform/scripts/plugins-dev-stack-up.sh down

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LAB="$ROOT/lab"

cmd="${1:-up}"
if [[ "$cmd" == "down" ]]; then
  cd "$LAB"
  docker compose -f docker-compose.premium-lab.yml down
  exit 0
fi

cd "$LAB"
docker compose -f docker-compose.premium-lab.yml up -d --build postgres redis connector tracetramp witnessctl

echo ""
echo "=== Plugin data plane is up (TraceTramp + WitnessCtl + DB + Redis) ==="
echo "Set these on connector-platform before or when you start the UI binary:"
echo "  export CONNECTOR_TRACETRAMP_MANAGEMENT_URL=http://127.0.0.1:19742"
echo "  export CONNECTOR_TRACETRAMP_ADMIN_TOKEN=lab_tracetramp_admin_token_change_me"
echo "  (must match TRACETRAMP_ADMIN_TOKEN in lab/docker-compose.premium-lab.yml — default added for lab)"
echo "  export CONNECTOR_WITNESSCTL_MANAGEMENT_URL=http://127.0.0.1:17443"
echo "  export CONNECTOR_WITNESSCTL_ADMIN_TOKEN=\"\${WITNESSCTL_ADMIN_TOKEN:-from witnessctl env}\""
echo "  export CONNECTOR_DEVGUARD_MANAGEMENT_URL=http://127.0.0.1:<devguard-status-api-port>"
echo ""
echo "Dashboard: DevGuard → Setup tab saves single-machine profile via POST /api/v1/plugins/devguard/local-profile"
