#!/usr/bin/env bash
# S21–S23 — RGO harden suite (compile-time unit tests via cargo).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/platform/server"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-.cargo-target-umesh}"
cargo test -p connector-platform --bin connector-platform harden_suite_r0_r1_r3 --offline -- --nocapture
echo "harden-rgo-suite: PASSED"
