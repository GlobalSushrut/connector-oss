#!/usr/bin/env bash
# Product promise + final outcomes honesty gate (S28).
# Fails if SoT docs missing, anti-claims appear as guarantees, or code surfaces vanish.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0
check() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "MISSING: $path"
    fail=1
  else
    echo "ok: $path"
  fi
}

check platform/docs/arch/CONNECTOR_PRODUCT_PROMISE.md
check platform/docs/arch/CONNECTOR_FINAL_OUTCOMES.md
check platform/docs/arch/CONNECTOR_CAPABILITY_STANDARD.md
check platform/docs/arch/CONNECTOR_REACH_CHECKLIST.md
check platform/docs/arch/AAPI_BEHAVIOR_RUNTIME.md
check platform/docs/arch/DYNAMIC_INTELLIGENCE_MANIFOLD.md
check platform/server/src/substrate/proof_export.rs
check platform/server/src/substrate/aapi_effect_field.rs
check platform/server/src/substrate/knot_belief_field.rs
check platform/server/src/substrate/dim/wake.rs

# Parent standard must state engineer envelope principle
if ! grep -qi 'engineer chooses the operating envelope' \
  platform/docs/arch/CONNECTOR_CAPABILITY_STANDARD.md; then
  echo "FAIL: CAPABILITY_STANDARD missing engineer-envelope principle"
  fail=1
else
  echo "ok: capability standard envelope principle"
fi

# Promise must state non-guarantee of absolute security
if ! grep -qi '100% secure\|absolute.security\|do not guarantee' \
  platform/docs/arch/CONNECTOR_PRODUCT_PROMISE.md; then
  echo "FAIL: PRODUCT_PROMISE must explicitly reject absolute-security guarantee"
  fail=1
else
  echo "ok: product promise rejects absolute security"
fi

# Anti-claims section must exist in outcomes
if ! grep -q 'Anti-claims' platform/docs/arch/CONNECTOR_FINAL_OUTCOMES.md; then
  echo "FAIL: FINAL_OUTCOMES missing Anti-claims"
  fail=1
else
  echo "ok: anti-claims present"
fi

# Five invariants present in standard
if ! grep -q 'No Self-Authorization\|No self-authorization' \
  platform/docs/arch/CONNECTOR_CAPABILITY_STANDARD.md; then
  echo "FAIL: CAPABILITY_STANDARD missing No Self-Authorization invariant"
  fail=1
else
  echo "ok: no-self-authorization invariant"
fi

# Must not market soft-fail as production membrane in promise
if grep -qiE 'soft-fail[[:space:]]+(is|=)[[:space:]]+production|makes agents 100% secure|guarantee[[:space:]]+100%[[:space:]]+secure' \
  platform/docs/arch/CONNECTOR_PRODUCT_PROMISE.md; then
  echo "FAIL: PRODUCT_PROMISE appears to claim soft-fail == production or 100% secure"
  fail=1
else
  echo "ok: no false absolute-security marketing"
fi

# Code symbols for E5 / A12 / A28
for sym in export_for_agent product_posture_json bcr_reserve evaluate_wake is_authority_neutral; do
  if ! rg -q "$sym" platform/server/src/substrate; then
    echo "FAIL: missing symbol $sym under substrate/"
    fail=1
  else
    echo "ok: symbol $sym"
  fi
done

# Anti-claims: product/marketing paths must not claim certified / compliant AI / 100% secure
# Docs that *reject* those claims are allowed; blog GRC education is out of product surface.
ANTI_CLAIM_PATHS=(
  platform/docs/arch
  CHANGELOG.md
)
ANTI_PATTERNS='makes agents 100% secure|guarantee[[:space:]]+100%[[:space:]]+secure|certified AI agent|AI certified|Connector is compliant|compliant AI platform'
for path in "${ANTI_CLAIM_PATHS[@]}"; do
  if [[ -e "$path" ]]; then
    hits=$(rg -n -i -e "$ANTI_PATTERNS" "$path" 2>/dev/null \
      | rg -v -i 'anti-claim|do not|must not|never|reject|not a claim|does_not_guarantee|not guarantee|not “100%|not "100%|outside absolute' \
      || true)
    if [[ -n "$hits" ]]; then
      echo "$hits"
      echo "FAIL: anti-claim marketing language found under $path"
      fail=1
    else
      echo "ok: no forbidden anti-claim marketing under $path"
    fi
  fi
done

# Escape hatch inventory must exist (E8)
if ! rg -q 'escape_hatches' platform/server/src/substrate; then
  echo "FAIL: missing escape_hatches module"
  fail=1
else
  echo "ok: escape_hatches symbol"
fi

# Operational spine
for sym in preflight_agent_effect spend_tokens mint_require_and_log; do
  if ! rg -q "$sym" platform/server/src; then
    echo "FAIL: missing operational symbol $sym"
    fail=1
  else
    echo "ok: symbol $sym"
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo "audit-product-promise: FAILED"
  exit 1
fi
echo "audit-product-promise: PASSED"
