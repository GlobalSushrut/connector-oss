#!/usr/bin/env bash
# P6.11 — property / soak hooks (laptop-safe).
# Runs connector-trust tests, notes SGKE unit path, lists docs/SOAK_EVIDENCE.md.
# Exit 0 on pass. Does NOT run cargo test -p connector-platform --bin by default
# (see docs/LOW_MEMORY_DEV.md). Set PROPERTY_SOAK_RUN_SGKE=1 to opt in.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "== property-soak-hooks (P6.11) =="
echo "ROOT=$ROOT"

# ── connector-trust ──────────────────────────────────────────────────────────
echo
echo "== cargo test -p connector-trust (oss/connector) =="
(
  cd "$ROOT/oss/connector"
  CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" cargo test -p connector-trust -- --test-threads=1
)
echo "[ok] connector-trust"

# ── SGKE unit tests (path known; bin-local) ──────────────────────────────────
echo
SGKE_SRC="platform/server/src/substrate/sgke_gate.rs"
if [[ -f "$SGKE_SRC" ]] && grep -q '#\[test\]' "$SGKE_SRC"; then
  echo "[path] SGKE unit tests: $SGKE_SRC"
  if [[ "${PROPERTY_SOAK_RUN_SGKE:-0}" == "1" ]]; then
    echo "== cargo test -p connector-platform --bin connector-platform sgke (opt-in) =="
    CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" cargo test -p connector-platform --bin connector-platform sgke -- --test-threads=1
    echo "[ok] sgke (platform bin)"
  else
    echo "[skip] SGKE bin-local tests (set PROPERTY_SOAK_RUN_SGKE=1 to run; laptop rule: no default platform --bin)"
  fi
else
  echo "[warn] SGKE test path not found: $SGKE_SRC" >&2
fi

# ── SOAK_EVIDENCE index ──────────────────────────────────────────────────────
echo
SOAK_DOC="docs/SOAK_EVIDENCE.md"
if [[ -f "$SOAK_DOC" ]]; then
  echo "== $SOAK_DOC =="
  # List make targets / table rows (evidence index)
  grep -E '^\| `make |^\| `platform/|^\| `docs/|^## ' "$SOAK_DOC" | head -n 80 || true
  echo "[ok] listed $SOAK_DOC"
else
  echo "[fail] missing $SOAK_DOC" >&2
  exit 1
fi

echo
echo "== property-soak-hooks: OK =="
exit 0
