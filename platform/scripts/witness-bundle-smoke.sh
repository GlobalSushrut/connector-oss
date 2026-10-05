#!/usr/bin/env bash
# Offline WitnessCtl bundle verify (plan Phase 1 — .witness + witnessctl-verify).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WC_DIR="${ROOT}/plugins/witnessctl"

echo "== witness-bundle-smoke =="

cd "$WC_DIR"
cargo test -p witnessctl --test witness_bundle_smoke --quiet
echo "[ok] witness_bundle_offline_roundtrip (write .witness + load + verify)"

cargo test -p witnessctl receipt::tests::test_verify_bundle_value_ok_and_tamper --quiet
echo "[ok] receipt tamper detection unit tests"

cargo build -q --bin witnessctl-verify
echo "[ok] witnessctl-verify binary built"

echo "== witness-bundle-smoke: OK =="
