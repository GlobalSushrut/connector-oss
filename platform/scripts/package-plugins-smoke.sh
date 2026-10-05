#!/usr/bin/env bash
# Build + verify TraceTramp and WitnessCtl release tarballs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "== package-plugins-smoke =="

if [[ "${CONNECTOR_SKIP_PLUGIN_PACKAGE_BUILD:-}" == "1" ]]; then
  CONNECTOR_PACKAGE_NO_BUILD=1 bash scripts/package-tracetramp.sh
  CONNECTOR_PACKAGE_NO_BUILD=1 bash scripts/package-witnessctl.sh
else
  bash scripts/package-tracetramp.sh
  bash scripts/package-witnessctl.sh
fi

TT="$(ls -1 dist/tracetramp-*-linux.tar.gz 2>/dev/null | head -1)"
WC="$(ls -1 dist/witnessctl-*-linux.tar.gz 2>/dev/null | head -1)"
[[ -n "$TT" ]] || { echo "[fail] tracetramp tarball missing" >&2; exit 1; }
[[ -n "$WC" ]] || { echo "[fail] witnessctl tarball missing" >&2; exit 1; }

# pipefail + grep -q: tar gets SIGPIPE; list members first.
tt_members="$(tar -tzf "$TT")"
wc_members="$(tar -tzf "$WC")"
echo "$tt_members" | grep -qE '(^|/)bin/tracetramp$' || { echo "[fail] TT tarball layout" >&2; exit 1; }
echo "$wc_members" | grep -qE '(^|/)bin/witnessctl-verify$' || { echo "[fail] WC tarball layout" >&2; exit 1; }

echo "[ok] $TT"
echo "[ok] $WC"
echo "== package-plugins-smoke: OK =="
