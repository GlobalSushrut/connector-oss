#!/usr/bin/env bash
# Build the dashboard with cargo-leptos WASM code splitting.
#
# Usage:
#   ./scripts/build-leptos.sh playground   → manifest-backed dist/playground/
#   ./scripts/build-leptos.sh self-deploy  → dashboard/dist/
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE="${1:-playground}"

if [ "$PROFILE" = "playground" ]; then
  exec python3 "$ROOT/scripts/build_release.py" --profile playground
fi

STAGE="$ROOT/dist/.leptos-stage-self"
bash "$ROOT/scripts/build-leptos-core.sh" "$PROFILE" "$STAGE"

OUT="$ROOT/dist"
mkdir -p "$OUT"
rsync -a --delete "$STAGE/" "$OUT/"
echo "==> Built $PROFILE → $OUT"
