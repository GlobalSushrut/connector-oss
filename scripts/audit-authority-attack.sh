#!/usr/bin/env bash
# A28 / S10 — authority-attack: DIM/Knot/KECS must not appear as Allow sources.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0

# RegulationAction must stay authority-neutral
if ! rg -q "is_authority_neutral" platform/server/src/substrate/dim/state.rs; then
  echo "FAIL: is_authority_neutral missing"
  fail=1
else
  echo "ok: is_authority_neutral"
fi

if ! rg -q "authority_attack_high_scores_do_not_authorize" platform/server/src/substrate/dim/state.rs; then
  echo "FAIL: authority-attack unit test missing"
  fail=1
else
  echo "ok: authority-attack test present"
fi

# DIM regulate must never claim Allow
if rg -n 'AutonomyVerdict::Allow|"Allow"|authority.*"granted"' platform/server/src/substrate/dim/regulate.rs 2>/dev/null; then
  echo "FAIL: dim/regulate appears to grant authority"
  fail=1
else
  echo "ok: dim regulate has no Allow grant"
fi

# Knot belief field honesty
if ! rg -q "never admits|never authoriz" platform/server/src/substrate/knot_belief_field.rs; then
  echo "FAIL: knot_belief_field missing never-authorize honesty"
  fail=1
else
  echo "ok: knot never-authorize"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "audit-authority-attack: FAILED"
  exit 1
fi
echo "audit-authority-attack: PASSED"
