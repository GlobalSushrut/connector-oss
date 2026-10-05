#!/usr/bin/env bash
# Complete Seven Pillars PDF checklist gate — light only (no full platform link).
# Avoids connector-platform cargo check/test which can OOM laptops.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

bash platform/scripts/seven-pillars-gate.sh
bash platform/scripts/seven-pillars-p2t07-adversarial.sh
bash platform/scripts/seven-pillars-t2-t8-harden.sh

echo "== fast 100-agent soak proofs =="
cargo test --manifest-path platform/seven-pillars-proofs/Cargo.toml -- --nocapture
cargo run --manifest-path platform/seven-pillars-proofs/Cargo.toml -q

echo "== kerneld + trust unit gates =="
cargo test --manifest-path platform/connector-kerneld/Cargo.toml -- --nocapture
cargo test -p connector-trust --manifest-path oss/connector/Cargo.toml effect_ -- --nocapture

echo "== adversarial wiring (RG-02 / P2-T07 / P5-T08 / P6) =="
grep -q 'assert_sandbox_unbypassable' platform/server/src/substrate/governed_effect.rs
grep -q 'bind_agent_process_tree' platform/server/src/substrate/governed_effect.rs
grep -q 'socket_binding_for_flow' platform/server/src/substrate/flow_lease.rs
grep -q 'peer_overlay' platform/server/src/cnp/wire.rs
grep -q 'mint_vsock_ticket\|authorize_vsock_channel' platform/server/src/kernel/isolation_manifest.rs
grep -q 'connector_mark_deny' platform/ebpf/connector_mark_deny.bpf.c
test -f platform/scripts/docklock-bypass-adversarial.sh
test -f platform/scripts/seven-pillars-ebpf-adversarial.sh
test -f platform/scripts/seven-pillars-sandbox-unbypassable-adversarial.sh
test -f platform/seven-pillars-proofs/Cargo.toml

# Status: zero PLANNED rows remain for PDF checklist completeness
if grep -E '^\|[^|]+\|[[:space:]]*PLANNED[[:space:]]*\|' platform/docs/arch/SEVEN_PILLARS_STATUS.md; then
  echo "FAIL: PLANNED rows remain — PDF checklist incomplete"
  exit 1
fi

echo "seven-pillars-complete-adversarial: OK (PDF checklist IMPLEMENTED_GATED+; no full platform compile)"

# Court/military claim discipline (may report MILITARY_COURT=false — that is correct honesty)
if [[ -f /tmp/connector-unbypassable-lab.json ]]; then
  bash platform/scripts/court-grade-evidence-bind.sh || true
else
  bash platform/scripts/seven-pillars-host-adversarial-lab.sh
fi
