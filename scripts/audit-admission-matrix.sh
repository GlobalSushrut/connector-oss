#!/usr/bin/env bash
# Admission matrix CI gate — critical effect handlers must call admission.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== Admission matrix: critical handler wiring =="
cargo test -q --manifest-path platform/server/Cargo.toml admission_matrix::tests

echo "== Admission matrix: wired route minimum =="
WIRED=$(rg -c 'WIRED_EFFECT_ROUTES' platform/server/src/substrate/admission_matrix.rs | head -1 || true)
if [[ -z "$WIRED" ]]; then
  echo "FAIL: admission_matrix.rs missing WIRED_EFFECT_ROUTES"
  exit 1
fi

echo "== route admission inventory (wired effect paths) =="
python3 scripts/audit-route-admission-inventory.py

echo "Admission matrix audit passed."
