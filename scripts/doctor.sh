#!/usr/bin/env bash
# Phase 0.5 — local sanity: target ownership, default port, kernel build, dashboard dist age.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${CONNECTOR_PORT:-9091}"
fail=0

echo "== Connector doctor (repo root: $ROOT) =="

if [[ -d platform/server/target ]] || [[ -d platform/server/.cargo-target ]]; then
  if ! "$ROOT/scripts/audit-target-not-root-owned.sh"; then
    fail=1
  fi
else
  echo "[ok] no platform/server/target or .cargo-target yet (first build)"
fi

if command -v ss >/dev/null 2>&1; then
  if ss -tlnH "sport = :$PORT" 2>/dev/null | grep -q .; then
    echo "[warn] something is listening on TCP $PORT (CONNECTOR_PORT)"
  else
    echo "[ok] TCP $PORT not in use (ss)"
  fi
elif command -v lsof >/dev/null 2>&1; then
  if lsof -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "[warn] something is listening on TCP $PORT (lsof)"
  else
    echo "[ok] TCP $PORT not in use (lsof)"
  fi
else
  echo "[skip] neither ss nor lsof — port $PORT not checked"
fi

echo "[..] cargo check (platform/server) ..."
if ! cargo check --manifest-path platform/server/Cargo.toml -q; then
  echo "[fail] cargo check — run without -q or set RUST_BACKTRACE=1 for details"
  fail=1
else
  echo "[ok] cargo check"
fi

src_probe="$ROOT/platform/ui-leptos/dashboard/src/lib.rs"
dist_probe="$ROOT/platform/ui-leptos/dashboard/dist/index.html"
if [[ -f "$dist_probe" ]]; then
  if [[ -f "$src_probe" ]] && [[ "$src_probe" -nt "$dist_probe" ]]; then
    echo "[warn] dashboard src looks newer than dist/index.html — rebuild dashboard (see platform/ui-leptos/Makefile)"
  else
    echo "[ok] dashboard dist present ($dist_probe)"
  fi
else
  echo "[warn] no $dist_probe — embedded UI build may be missing until you run the Leptos/trunk build"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "== doctor: FAILED =="
  exit 1
fi
echo "== doctor: OK =="
