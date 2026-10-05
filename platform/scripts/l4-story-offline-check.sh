#!/usr/bin/env bash
# P7 / T7 partial — validate Story QA routes exist in router.rs without a running server.
# Full Jordan/Sam/Riley HTTP acceptance remains: make story-qa-smoke (server required).
#
# Usage (repo root):
#   bash platform/scripts/l4-story-offline-check.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROUTER="$ROOT/platform/server/src/router.rs"

if [[ ! -f "$ROUTER" ]]; then
  echo "[FAIL] missing $ROUTER" >&2
  exit 1
fi

search() {
  if command -v rg >/dev/null 2>&1; then
    rg -n --fixed-strings "$1" "$ROUTER" >/dev/null
  else
    grep -nF "$1" "$ROUTER" >/dev/null
  fi
}

REQUIRED=(
  '"/apps"'
  '"/plugins/cage-proof"'
  '"/plugins/witnessctl/status"'
  '"/workflows/reference-templates"'
  '"/workflows/:id/lifecycle"'
  '"/workflows/:id/dry-run"'
)

echo "== l4-story-offline-check (Story QA routes in router.rs) =="
fail=0
for pat in "${REQUIRED[@]}"; do
  if search "$pat"; then
    echo "[ok] route $pat"
  else
    echo "[fail] missing route $pat in router.rs" >&2
    fail=1
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo "== l4-story-offline-check: FAIL ==" >&2
  exit 1
fi

echo "== l4-story-offline-check: OK (T7 partial — routes wired; full story-qa-smoke needs server) =="
exit 0
