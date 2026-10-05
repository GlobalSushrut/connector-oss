#!/usr/bin/env bash
# Start connector-platform in dev mode, wait for health, run Suite E (enterprise_beta_gate).
#
# Usage (from repo root):
#   ./platform/scripts/ci_beta_gate.sh
#
# Env (optional):
#   CONNECTOR_PORT / BETA_GATE_PORT — API listen port (default 19091)
#   CONNECTOR_DATA_DIR — persistent data dir (default: mktemp under /tmp)
#   BETA_GATE_DATA_DIR — override data dir for this script only (ignores CONNECTOR_DATA_DIR)
#   CONNECTOR_HOST — bind address (default 127.0.0.1)
#   RUST_LOG — tracing level for the server process
#
# Exports for the test binary:
#   CONNECTOR_TEST_URL — base URL including port (no trailing slash)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_ROOT="$ROOT/platform/server"
PORT="${CONNECTOR_PORT:-${BETA_GATE_PORT:-19091}}"
# Always use a fresh temp dir unless BETA_GATE_DATA_DIR is set explicitly (ignore inherited CONNECTOR_DATA_DIR).
DATA_DIR="${BETA_GATE_DATA_DIR:-$(mktemp -d /tmp/connector_beta_gate.XXXXXX)}"

export CONNECTOR_HOST="${CONNECTOR_HOST:-127.0.0.1}"
export CONNECTOR_PORT="$PORT"
export CONNECTOR_DATA_DIR="$DATA_DIR"
export CONNECTOR_ENV="${CONNECTOR_ENV:-development}"
export CONNECTOR_DEV_MODE="${CONNECTOR_DEV_MODE:-1}"
export CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD="${CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD:-admin}"
# Avoid auxiliary bind conflicts in shared CI runners / dev machines.
export CONNECTOR_PROTOCOL_PORT="${CONNECTOR_PROTOCOL_PORT:-0}"
export CONNECTOR_UI_RPC_PORT="${CONNECTOR_UI_RPC_PORT:-0}"
export RUST_LOG="${RUST_LOG:-warn}"

BASE="http://${CONNECTOR_HOST}:${PORT}"
export CONNECTOR_TEST_URL="$BASE"

SERVER_PID=""
stop_server() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}

rm_tmp_data() {
  if [[ "$DATA_DIR" == /tmp/connector_beta_gate.* ]]; then
    rm -rf "$DATA_DIR" || true
  fi
}

finish() {
  stop_server
  rm_tmp_data
}

trap 'finish; exit 130' INT TERM

cd "$SERVER_ROOT"
_target="${CARGO_TARGET_DIR:-.cargo-target}"
if [[ "$_target" != /* ]]; then
  export CARGO_TARGET_DIR="$SERVER_ROOT/$_target"
else
  export CARGO_TARGET_DIR="$_target"
fi
PLATFORM_BIN="$CARGO_TARGET_DIR/debug/connector-platform"
cargo build --bin connector-platform --bin connectorctl --quiet
cargo test --bin connector-platform router_build_tests --quiet
cargo test --bin connector-platform middleware::tenant::tests --quiet
(cd "$ROOT" && bash scripts/audit-target-not-root-owned.sh)
"$PLATFORM_BIN" &
SERVER_PID="$!"

ok=0
for _ in $(seq 1 120); do
  if curl -sf "${BASE}/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.25
done

if [[ "$ok" -ne 1 ]]; then
  echo "ci_beta_gate: timeout waiting for GET ${BASE}/health" >&2
  finish
  exit 124
fi

set +e
CONNECTOR_DEV_MODE=1 CONNECTOR_DEV_TOKEN="${CONNECTOR_DEV_TOKEN:-dev-token}" \
  SKIP_PUBLIC_DNS=1 bash "$ROOT/platform/scripts/cage-e2e-smoke.sh"
CAGE_EC=$?

CONNECTOR_DEV_MODE=1 CONNECTOR_DEV_TOKEN="${CONNECTOR_DEV_TOKEN:-dev-token}" \
  bash "$ROOT/platform/scripts/custom-domain-e2e-smoke.sh"
CUSTOM_DOMAIN_EC=$?

CONNECTOR_DEV_MODE=1 CONNECTOR_DEV_TOKEN="${CONNECTOR_DEV_TOKEN:-dev-token}" CONNECTOR_TEST_URL="$BASE" \
  cargo test --test enterprise_beta_gate -- --test-threads=1
BETA_EC=$?

CONNECTOR_DEV_MODE=1 CONNECTOR_DEV_TOKEN="${CONNECTOR_DEV_TOKEN:-dev-token}" CONNECTOR_TEST_URL="$BASE" \
  cargo test --test trust_adversarial_http -- --test-threads=1
TRUST_HTTP_EC=$?

CONNECTOR_DURABILITY_PORT="${CONNECTOR_DURABILITY_PORT:-$((PORT + 1))}" \
  env -u CONNECTOR_DATA_DIR bash "$ROOT/platform/server/scripts/durability-kill-soak.sh"
DURABILITY_EC=$?

CONNECTOR_DEV_MODE=1 CONNECTOR_DEV_TOKEN="${CONNECTOR_DEV_TOKEN:-dev-token}" CONNECTOR_SOAK_ITERATIONS="${CONNECTOR_SOAK_ITERATIONS:-20}" CONNECTOR_TEST_URL="$BASE" \
  cargo test --test enterprise_soak -- --test-threads=1
SOAK_EC=$?

# Workflow + RBAC smokes require single-tenant (no X-Tenant-ID) — run before MT restart.
CONNECTOR_DEV_MODE=1 CONNECTOR_DEV_TOKEN="${CONNECTOR_DEV_TOKEN:-dev-token}" CONNECTOR_TEST_URL="$BASE" \
  cargo test --test workflows_http -- --test-threads=1
WF_EC=$?

CONNECTOR_DEV_MODE=1 CONNECTOR_DEV_TOKEN="${CONNECTOR_DEV_TOKEN:-dev-token}" CONNECTOR_TEST_URL="$BASE" \
  cargo test --test apps_http -- --test-threads=1
APPS_EC=$?

CONNECTOR_DEV_MODE=1 CONNECTOR_DEV_TOKEN="${CONNECTOR_DEV_TOKEN:-dev-token}" CONNECTOR_TEST_URL="$BASE" \
  cargo test --test rbac_http -- --test-threads=1
RBAC_EC=$?

# Dream ops: two-charter DI regression (grant → fabric COMPLETED → lifecycle).
CONNECTOR_DEV_MODE=1 CONNECTOR_DEV_TOKEN="${CONNECTOR_DEV_TOKEN:-dev-token}" \
  CONNECTOR_API_URL="$BASE" CONNECTOR_API_KEY="${CONNECTOR_DEV_TOKEN:-dev-token}" \
  "$CARGO_TARGET_DIR/debug/connectorctl" iia smoke
IIA_SMOKE_EC=$?

# Ultimate Free: production env, no CONNECTOR_DEV_MODE, no login required.
stop_server
unset CONNECTOR_DEV_MODE
export CONNECTOR_ENV=production
export CONNECTOR_ULTIMATE_FREE=1
"$PLATFORM_BIN" &
SERVER_PID="$!"
ok=0
for _ in $(seq 1 120); do
  if curl -sf "${BASE}/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.25
done
if [[ "$ok" -ne 1 ]]; then
  echo "ci_beta_gate: timeout waiting for ultimate-free health" >&2
  finish
  exit 124
fi

set +e
CONNECTOR_ULTIMATE_FREE=1 CONNECTOR_TEST_URL="$BASE" \
  cargo test --test open_auth_http -- --test-threads=1
OPEN_AUTH_EC=$?
set -e

# T7: restart with multi-tenant enabled for HTTP isolation tests.
stop_server
unset CONNECTOR_ULTIMATE_FREE
unset CONNECTOR_DEV_MODE
export CONNECTOR_DEFENSE_STRICT=1
export CONNECTOR_ENV=production
export CONNECTOR_MULTI_TENANT=1
export CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD="${CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD:-admin}"
"$PLATFORM_BIN" &
SERVER_PID="$!"
ok=0
for _ in $(seq 1 120); do
  if curl -sf "${BASE}/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.25
done
if [[ "$ok" -ne 1 ]]; then
  echo "ci_beta_gate: timeout waiting for multi-tenant health" >&2
  finish
  exit 124
fi

set +e
CONNECTOR_MULTI_TENANT=1 CONNECTOR_DEFENSE_STRICT=1 \
  CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD="${CONNECTOR_BOOTSTRAP_SUPERADMIN_PASSWORD:-admin}" \
  CONNECTOR_TEST_URL="$BASE" \
  cargo test --test multi_tenant_http -- --test-threads=1
MT_EC=$?
set -e

finish
if [[ "$CAGE_EC" -ne 0 ]]; then
  echo "ci_beta_gate: cage-e2e-smoke failed (exit $CAGE_EC)" >&2
  exit "$CAGE_EC"
fi
if [[ "$CUSTOM_DOMAIN_EC" -ne 0 ]]; then
  echo "ci_beta_gate: custom-domain-e2e-smoke failed (exit $CUSTOM_DOMAIN_EC)" >&2
  exit "$CUSTOM_DOMAIN_EC"
fi
if [[ "$BETA_EC" -ne 0 ]]; then
  exit "$BETA_EC"
fi
if [[ "$TRUST_HTTP_EC" -ne 0 ]]; then
  echo "ci_beta_gate: trust_adversarial_http failed (exit $TRUST_HTTP_EC)" >&2
  exit "$TRUST_HTTP_EC"
fi
if [[ "$DURABILITY_EC" -ne 0 ]]; then
  echo "ci_beta_gate: durability-kill-soak failed (exit $DURABILITY_EC)" >&2
  exit "$DURABILITY_EC"
fi
if [[ "$SOAK_EC" -ne 0 ]]; then
  echo "ci_beta_gate: enterprise_soak failed (exit $SOAK_EC)" >&2
  exit "$SOAK_EC"
fi
if [[ "$MT_EC" -ne 0 ]]; then
  exit "$MT_EC"
fi
if [[ "$RBAC_EC" -ne 0 ]]; then
  exit "$RBAC_EC"
fi
if [[ "$WF_EC" -ne 0 ]]; then
  exit "$WF_EC"
fi
if [[ "$APPS_EC" -ne 0 ]]; then
  echo "ci_beta_gate: apps_http failed (exit $APPS_EC)" >&2
  exit "$APPS_EC"
fi
if [[ "${IIA_SMOKE_EC:-0}" -ne 0 ]]; then
  echo "ci_beta_gate: connectorctl iia smoke failed (exit $IIA_SMOKE_EC)" >&2
  exit "$IIA_SMOKE_EC"
fi
if [[ "$OPEN_AUTH_EC" -ne 0 ]]; then
  echo "ci_beta_gate: open_auth_http failed (exit $OPEN_AUTH_EC)" >&2
  exit "$OPEN_AUTH_EC"
fi
exit 0
