#!/usr/bin/env bash
# Phase 0.1 — fail if anything under platform/server/target is owned by root (uid 0).
# Run after `cargo build`/`cargo test` in CI or locally. Fix: chown -R "$USER:$USER" platform/server/target
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0
for TARGET in "$ROOT/platform/server/target" "$ROOT/platform/server/.cargo-target"; do
  if [[ ! -d "$TARGET" ]]; then
    continue
  fi
  if find "$TARGET" -user root 2>/dev/null | head -n 1 | grep -q .; then
    echo "audit-target-not-root-owned: found root-owned files under $TARGET" >&2
    echo "  Fix (local): chown -R \"\${USER:-\$LOGNAME}:\${USER:-\$LOGNAME}\" $(basename "$(dirname "$TARGET")")/$(basename "$TARGET")" >&2
    fail=1
  fi
done
if [[ "$fail" -ne 0 ]]; then
  echo "  Never run cargo as root in this repo. Prefer: make platform-build (uses .cargo-target)." >&2
  exit 1
fi

echo "audit-target-not-root-owned: OK"
