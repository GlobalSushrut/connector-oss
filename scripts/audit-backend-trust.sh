#!/usr/bin/env bash
# Backend trust gates (no UI) — run in CI and before B-EXIT.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== Backend trust: no fake verified in platform services =="
if rg -q 'verified:\s*true|"verified":\s*true' platform/server/src/services/ 2>/dev/null; then
  echo "FAIL: platform/server/src/services must not emit verified:true without recompute"
  rg 'verified:\s*true|"verified":\s*true' platform/server/src/services/ || true
  exit 1
fi
echo "OK"

echo "== connector-trust unit tests =="
cargo test -q --manifest-path oss/connector/crates/connector-trust/Cargo.toml

echo "== trust_foundation_adversarial =="
cargo test -q --manifest-path platform/server/Cargo.toml --test trust_foundation_adversarial

echo "== admission_matrix =="
bash scripts/audit-admission-matrix.sh

echo "== substrate durability unit tests =="
cargo test -q --manifest-path platform/server/Cargo.toml --bin connector-platform handoff_pending_max
cargo test -q --manifest-path platform/server/Cargo.toml --bin connector-platform lease_ttl_has_sane_default

echo "== connector-kerneld flow lease =="
cargo test -q --manifest-path platform/connector-kerneld/Cargo.toml

echo "Backend trust audit passed."
