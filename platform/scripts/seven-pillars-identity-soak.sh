#!/usr/bin/env bash
# Identity isolation soak (Seven Pillars P1-T08 / RG-08).
# Default: fast in-process 100-agent proof (no platform binary).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "seven-pillars identity soak: fast proofs"
cargo test --manifest-path platform/seven-pillars-proofs/Cargo.toml -- --nocapture
cargo run --manifest-path platform/seven-pillars-proofs/Cargo.toml -q
bash "$ROOT/platform/scripts/seven-pillars-gate.sh"
echo "seven-pillars identity soak: OK"
