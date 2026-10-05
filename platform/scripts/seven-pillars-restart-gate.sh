#!/usr/bin/env bash
# Restart / no-dupe effect gate scaffold (Seven Pillars RG-09).
# Verifies mission journal helpers and exclusivity adversarial scripts exist;
# live kill-mid-mission proof is operator-run against a real node.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "seven-pillars restart gate: checking artifacts"
test -f "$ROOT/platform/server/src/kernel/mission_journal.rs"
test -f "$ROOT/platform/server/src/substrate/atomic_revoke.rs"
test -f "$ROOT/platform/server/src/kernel/effect_authz.rs"
test -f "$ROOT/platform/scripts/effect-exclusivity-adversarial.sh"
test -f "$ROOT/platform/scripts/zt-handshake-adversarial.sh"
bash "$ROOT/platform/scripts/seven-pillars-gate.sh"
echo "seven-pillars restart gate: OK (artifact + status discipline)"
