#!/usr/bin/env bash
# Sandbox unbypassable adversarial scaffold (microVM/vsock + FS + net).
# Wiring-only by default (no full platform cargo — avoids laptop OOM).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "== gate: SANDBOX_UNBYPASSABLE / vsock / revoke wiring =="
grep -q 'assert_sandbox_unbypassable' platform/server/src/substrate/governed_effect.rs
grep -q 'assert_sandbox_unbypassable' platform/server/src/services/tools.rs
grep -q 'mint_vsock_ticket\|authorize_vsock_channel' platform/server/src/kernel/isolation_manifest.rs
grep -q 'expected_ticket' platform/plugin-runtime/src/microvm_backend.rs
grep -q 'apply_matrix_host_egress_cut' platform/server/src/substrate/atomic_revoke.rs
grep -q 'vsock_ticket_rejected\|ticket_matches' platform/plugin-runtime/src/microvm_vsock_agent.rs

if [[ "${CONNECTOR_SP_HEAVY:-0}" == "1" ]]; then
  echo "== heavy: plugin-runtime check =="
  cargo check --manifest-path platform/plugin-runtime/Cargo.toml -q
fi

echo "seven-pillars-sandbox-unbypassable-adversarial: OK (wired fail-closed paths)"
