#!/usr/bin/env bash
# WitnessCtl custody quorum verification (plan Phase 2 / FINAL_REACH P8.6).
#
# Honesty contract (documented here + custody_status JSON):
#   honesty_strip: local_only | partial | quorum_met
#   court_export_ready: true ONLY when verify_quorum → QuorumMet
#   Never market "court-grade" until quorum_met + independent recompute.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WC="${ROOT}/plugins/witnessctl"

echo "== custody-quorum-smoke =="
echo "[doc] court_export_ready requires quorum_met (verify_quorum QuorumResult::QuorumMet)"
echo "[doc] UI strip enums: local_only | partial | quorum_met (never court-grade before quorum)"

cd "$WC"
cargo test -p witnessctl --lib custody_node --quiet
echo "[ok] custody_node quorum + honesty_strip unit tests"

cargo build -q --bin witnessctl-node
echo "[ok] witnessctl-node binary built"

# Optional: local replicate round-trip when server env set
if [[ -n "${WITNESSCTL_CUSTODY_NODE_PORT:-}" ]]; then
  PORT="${WITNESSCTL_CUSTODY_NODE_PORT}"
  SECRET="${WITNESSCTL_CUSTODY_NODE_SECRET:-${WITNESSCTL_HMAC_SECRET:-custody-smoke-secret}}"
  export WITNESSCTL_CUSTODY_NODE_SECRET="$SECRET"
  export WITNESSCTL_HMAC_SECRET="$SECRET"
  NODE_BIN="$WC/target/debug/witnessctl-node"
  "$NODE_BIN" &
  NP=$!
  sleep 1
  CODE="$(curl -s -o /tmp/wc-repl.json -w '%{http_code}' -X POST "http://127.0.0.1:${PORT}/api/v1/custody/replicate" \
    -H "X-WitnessCtl-Custody-Secret: ${SECRET}" \
    -H "Content-Type: application/json" \
    -d '{"session_id":"00000000-0000-0000-0000-000000000001","payload_hash":"smokehash"}' || echo 000)"
  kill "$NP" 2>/dev/null || true
  if [[ "$CODE" =~ ^2 ]]; then
    echo "[ok] custody replicate HTTP ${CODE}"
  else
    echo "[warn] custody replicate HTTP ${CODE}" >&2
  fi
else
  echo "[skip] live replicate (set WITNESSCTL_CUSTODY_NODE_PORT to exercise)"
fi

echo "== custody-quorum-smoke: OK =="
echo "[note] Multi-node N-of-M with distinct keys remains open (P8.6 Backend soak)."
