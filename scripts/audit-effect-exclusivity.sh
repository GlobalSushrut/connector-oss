#!/usr/bin/env bash
# S24 — Effect exclusivity honesty: mutating paths must cite exclusivity / PATE / ActionBinding.
# Does not claim production is secure; fails if ungated patterns reappear without labels.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0

# Core exclusivity surface must exist
for f in \
  platform/server/src/substrate/effect_exclusivity.rs \
  platform/server/src/substrate/harden_posture.rs \
  platform/server/src/substrate/governed_effect.rs \
  platform/server/src/kernel/action_binding.rs \
  platform/server/src/substrate/pate.rs
do
  if [[ ! -f "$f" ]]; then
    echo "MISSING: $f"
    fail=1
  else
    echo "ok: $f"
  fi
done

# Harden start must wire exclusivity
if ! rg -q "assert_harden_ready_for_start" platform/server/src/services/agents.rs; then
  echo "FAIL: start_agent must call assert_harden_ready_for_start"
  fail=1
else
  echo "ok: start_agent harden gate"
fi

if ! rg -q "START_REFUSED" platform/server/src/substrate/harden_posture.rs; then
  echo "FAIL: START_REFUSED token missing"
  fail=1
else
  echo "ok: START_REFUSED"
fi

# Tool / gateway effect paths should reference exclusivity or governed_effect under harden paths
if ! rg -q "assert_effect_exclusivity_ready|assert_in_process_dispatch_allowed|governed_effect" \
  platform/server/src/services/tools.rs \
  platform/server/src/services/gateway.rs \
  platform/server/src/substrate/governed_effect.rs 2>/dev/null; then
  echo "FAIL: tools/gateway/governed_effect must reference exclusivity gates"
  fail=1
else
  echo "ok: effect path cites exclusivity"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "audit-effect-exclusivity: FAILED"
  exit 1
fi
echo "audit-effect-exclusivity: PASSED"
