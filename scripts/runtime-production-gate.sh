#!/usr/bin/env bash
# Mechanical gate for Connector Talk/Effect runtime contracts (INV-01…20).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/platform/server"

echo "== runtime invariant + foundation unit tests =="
cargo test --bin connector-platform runtime_invariants -- --nocapture
cargo test --bin connector-platform turn_envelope -- --nocapture
cargo test --bin connector-platform session_owner -- --nocapture
cargo test --bin connector-platform workload_bulkhead -- --nocapture
cargo test --bin connector-platform generation_mismatch -- --nocapture
cargo test --bin connector-platform workbench_order_binds -- --nocapture
cargo test --bin connector-platform governed_stream -- --nocapture
cargo test --bin connector-platform talk_turn_pipeline -- --nocapture
cargo test --bin connector-platform reconcile_unknown -- --nocapture

echo "== source contracts present =="
need=(
  src/substrate/turn_envelope.rs
  src/substrate/agent_runtime_snapshot.rs
  src/substrate/talk_turn_pipeline.rs
  src/substrate/governed_stream_gate.rs
  src/substrate/authority_evidence.rs
  src/substrate/runtime_invariants.rs
  src/substrate/effect_intent.rs
  src/concurrency/session_owner.rs
  src/concurrency/workload_bulkhead.rs
)
for f in "${need[@]}"; do
  [[ -f "$f" ]] || { echo "MISSING $f"; exit 1; }
done

if rg -n "playground_kernel_chip_reply|kernel_identity short-circuit" \
  src/services/gateway.rs src/services/workbench.rs 2>/dev/null; then
  echo "FAIL: chip short-circuit markers still present"
  exit 1
fi

echo "OK: runtime production gate passed"
