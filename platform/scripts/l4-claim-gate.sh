#!/usr/bin/env bash
# L4 claim gate — engineering path toward marketable +2 / L4.
# Laptop-safe CORE + optional heavy steps.
#
#   make l4-claim-gate
#   L4_HEAVY=1 make l4-claim-gate   # also clean-vm-tarball + story-qa if server up
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FAIL=0

echo "== L4 claim gate =="

echo "-- final-reach-light-gate --"
if ! bash platform/scripts/final-reach-light-gate.sh; then
  echo "[FAIL] light gate" >&2
  FAIL=1
fi

# Docs required for Final GO (no platform-test — OOM on ≤16 GiB)
for doc in docs/FINAL_GO_RUNBOOK.md docs/TRUST_DOMAIN_BACKUP.md docs/SIGNED_RELEASE.md docs/STORY_QA_RUNBOOK.md; do
  if [[ -f "$doc" ]]; then
    echo "[ok] $doc"
  else
    echo "[FAIL] missing $doc" >&2
    FAIL=1
  fi
done

if [[ "${L4_HEAVY:-0}" == "1" ]]; then
  echo "-- HEAVY path (≥32 GiB / CI): section10 + custody + clean-vm + story-qa --"
  echo "WARNING: section10 runs platform-test (monolith) — do not on ≤16 GiB laptops"
  bash platform/scripts/section10-automated-smoke.sh || FAIL=1
  bash platform/scripts/custody-quorum-smoke.sh || true
  bash platform/scripts/clean-vm-tarball-smoke.sh || FAIL=1
  if curl -sf --max-time 2 "${CONNECTOR_TEST_URL:-http://127.0.0.1:8080}/health" >/dev/null; then
    bash platform/scripts/story-qa-smoke.sh || FAIL=1
  else
    echo "[SKIP] story-qa (no server)"
  fi
  if [[ -f dist/SHA256SUMS ]]; then
    bash scripts/verify-release-artifacts.sh || FAIL=1
  else
    echo "[WARN] no dist/ — run make package"
  fi
else
  echo "[note] Laptop path only. For full L4 eng: L4_HEAVY=1 make l4-claim-gate (on ≥32 GiB)"
  echo "       then make prod-readiness-gate + FINAL_GO_RUNBOOK clean VM"
fi

if [[ "$FAIL" -ne 0 ]]; then
  echo "== L4 claim gate: FAIL ==" >&2
  exit 1
fi

echo "== L4 claim gate: ENGINEERING PASS =="
echo "Market L4 still needs human Final GO (docs/FINAL_GO_RUNBOOK.md):"
echo "  1) signed tarball on clean VM + prod secrets + doctor"
echo "  2) Stories A–D / story-qa with server"
echo "  3) make prod-readiness-gate on ≥32 GiB / CI"
echo "  4) Sign PRODUCTION_READINESS_CHECKLIST Final GO #6/#7b"
touch platform/scripts/.l4-claim-gate.last
date -u +%Y-%m-%dT%H:%M:%SZ >platform/scripts/.l4-claim-gate.last
