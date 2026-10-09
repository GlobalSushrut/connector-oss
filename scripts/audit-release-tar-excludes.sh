#!/usr/bin/env bash
# Phase 0.7.7 / CONNECTOR_OS_ROADMAP §2D.6 — release tarball must omit GTM/npm-only trees.
# Single source of truth: scripts/release-tar-excludes.txt (extend when `make package` / Phase 5 ships a full-tree archive).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXCLUDES_FILE="$ROOT/scripts/release-tar-excludes.txt"

want=(
  "ppt"
  "platform/gtm-presentation"
  "platform/docs/landing-page/web"
  "platform/docs/connector-youtube-deck"
)

if [[ ! -f "$EXCLUDES_FILE" ]]; then
  echo "audit-release-tar-excludes: missing $EXCLUDES_FILE" >&2
  exit 1
fi

filtered() { grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$EXCLUDES_FILE"; }

for p in "${want[@]}"; do
  if ! filtered | grep -Fxq "$p"; then
    echo "audit-release-tar-excludes: scripts/release-tar-excludes.txt must list exactly (one path per line): $p" >&2
    exit 1
  fi
done

# These trees are npm-only; a stray Cargo.toml would pull them into ad-hoc cargo workspaces.
for p in "${want[@]}"; do
  if [[ -f "$ROOT/$p/Cargo.toml" ]]; then
    echo "audit-release-tar-excludes: unexpected $p/Cargo.toml — keep GTM trees out of the Rust workspace (§2D.6)" >&2
    exit 1
  fi
done

echo "audit-release-tar-excludes: OK"
