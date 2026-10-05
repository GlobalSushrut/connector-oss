#!/usr/bin/env bash
# Lightweight cage + TraceTramp load probe (plan Phase 2 — not full k6).
# Requires running Connector node; TraceTramp upstream optional (warn if down).
set -euo pipefail

BASE="${CONNECTOR_TEST_URL:-http://127.0.0.1:9091}"
BASE="${BASE%/}"
TOKEN="${CONNECTOR_DEV_TOKEN:-dev-token}"
AUTH="Authorization: Bearer ${TOKEN}"
CONCURRENCY="${CAGE_LOAD_CONCURRENCY:-32}"
REQUESTS="${CAGE_LOAD_REQUESTS:-128}"
CAGE_SHA="${CAGE_LOAD_SHA:-deadbeef0123456789abcdef0123456789abcdef01}"

fail=0

echo "== cage-tt-load-smoke @ ${BASE} (requests=${REQUESTS} concurrency=${CONCURRENCY}) =="

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

run_batch() {
  local path="$1"
  local ok=0 failc=0
  local i=0
  while [[ "$i" -lt "$REQUESTS" ]]; do
    local batch=0
    while [[ "$batch" -lt "$CONCURRENCY" && "$i" -lt "$REQUESTS" ]]; do
      (
        code="$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" "${BASE}${path}" 2>/dev/null || echo 000)"
        if [[ "$code" =~ ^[23] ]]; then
          echo ok >>"$tmpdir/r"
        else
          echo "fail:${code}" >>"$tmpdir/r"
        fi
      ) &
      batch=$((batch + 1))
      i=$((i + 1))
    done
    wait
  done
  ok="$(grep -c '^ok$' "$tmpdir/r" 2>/dev/null || echo 0)"
  failc="$(grep -c '^fail:' "$tmpdir/r" 2>/dev/null || echo 0)"
  rm -f "$tmpdir/r"
  echo "  ${path}: ok=${ok} fail=${failc}"
  if [[ "$failc" -gt 0 ]]; then
    return 1
  fi
  return 0
}

# Cage-proof (fast, no upstream)
: >"$tmpdir/r" 2>/dev/null || true
if ! run_batch "/api/v1/plugins/cage-proof"; then
  echo "[fail] cage-proof load" >&2
  fail=1
else
  echo "[ok] cage-proof load"
fi

# TraceTramp cage health via connector proxy (needs TT up)
: >"$tmpdir/r" 2>/dev/null || true
if run_batch "/plugin/tracetramp/cage/${CAGE_SHA}/health"; then
  echo "[ok] /plugin/tracetramp/cage/…/health load"
else
  echo "[warn] cage health load had failures (TraceTramp lab may be down)" >&2
fi

# Invalid cage address must not 2xx
bad_code="$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH" \
  "${BASE}/plugin/tracetramp/cage/not-hex!/health" 2>/dev/null || echo 000)"
if [[ "$bad_code" =~ ^4 ]]; then
  echo "[ok] invalid cage address rejected (HTTP ${bad_code})"
else
  echo "[warn] invalid cage address returned HTTP ${bad_code} (expected 4xx)" >&2
fi

if [[ "$fail" -ne 0 ]]; then
  echo "== cage-tt-load-smoke: FAILED ==" >&2
  exit 1
fi
echo "== cage-tt-load-smoke: OK =="
