# Source from repo root:  source advanced-lab/scripts/lab-tui-env.sh
# Host ports match lab/docker-compose.premium-lab.yml (+ lab/advanced.yml overlay secrets).
# TraceTramp TUI talks to TT admin/gateway on localhost; WitnessCtl TUI reads Postgres directly.

export TRACETRAMP_DATA_PLANE_BASE_URL="${TRACETRAMP_DATA_PLANE_BASE_URL:-http://127.0.0.1:19741}"
export TRACETRAMP_MANAGEMENT_PLANE_PORT="${TRACETRAMP_MANAGEMENT_PLANE_PORT:-19742}"
export TRACETRAMP_DATABASE_URL="${TRACETRAMP_DATABASE_URL:-postgres://postgres:postgres@127.0.0.1:15432/tracetramp}"
export TRACETRAMP_REDIS_URL="${TRACETRAMP_REDIS_URL:-redis://127.0.0.1:16379}"
export TRACETRAMP_CONNECTOR_BASE_URL="${TRACETRAMP_CONNECTOR_BASE_URL:-http://127.0.0.1:19735}"
export TRACETRAMP_CONNECTOR_API_KEY="${TRACETRAMP_CONNECTOR_API_KEY:-lab_dev_connector_key_change_me}"
export CONNECTOR_KEY="${CONNECTOR_KEY:-$TRACETRAMP_CONNECTOR_API_KEY}"
export TRACETRAMP_JWT_SECRET="${TRACETRAMP_JWT_SECRET:-lab_jwt_secret_change_me}"
# Management plane (/admin/*) requires the admin bearer — not the Connector API key (401 otherwise).
export TRACETRAMP_ADMIN_TOKEN="${TRACETRAMP_ADMIN_TOKEN:-lab_admin_token_static}"

export WITNESSCTL_DATABASE_URL="${WITNESSCTL_DATABASE_URL:-postgres://postgres:postgres@127.0.0.1:15432/witnessctl}"
export WITNESSCTL_REDIS_URL="${WITNESSCTL_REDIS_URL:-redis://127.0.0.1:16379}"
export CONNECTOR_BASE_URL="${CONNECTOR_BASE_URL:-http://127.0.0.1:19735}"
export CONNECTOR_API_KEY="${CONNECTOR_API_KEY:-lab_dev_connector_key_change_me}"
export WITNESSCTL_HMAC_SECRET="${WITNESSCTL_HMAC_SECRET:-lab_hmac_secret_premium_2026}"
export WITNESSCTL_REQUESTED_AGENTS="${WITNESSCTL_REQUESTED_AGENTS:-3}"
export WITNESSCTL_ADMIN_TOKEN="${WITNESSCTL_ADMIN_TOKEN:-lab_admin_token_static}"
