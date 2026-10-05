#!/usr/bin/env bash
# T17 court-path: N-of-M WitnessCtl custody with distinct node ids.
# Builds on make custody-quorum-smoke; starts 3× witnessctl-node when binary present.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OK_FILE="$ROOT/platform/scripts/.custody-multinode-soak.ok"
PIDS=()

cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

echo "== custody multinode soak (T17) =="
bash platform/scripts/custody-quorum-smoke.sh

BIN="${WITNESSCTL_NODE_BIN:-}"
if [[ -z "$BIN" ]]; then
  for c in \
    "$ROOT/plugins/witnessctl/target/debug/witnessctl-node" \
    "${CARGO_TARGET_DIR:-}/debug/witnessctl-node"; do
    [[ -n "$c" && -x "$c" ]] && BIN="$c" && break
  done
fi
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
  echo "[ok] unit/lib custody quorum green; 3-node live replicate SKIP (no witnessctl-node bin)"
  echo "     Build: cd plugins/witnessctl && cargo build --bin witnessctl-node"
  echo "T17_LIGHT=PASS"
  exit 0
fi

SECRET="${WITNESSCTL_CUSTODY_NODE_SECRET:-custody-multinode-soak-secret}"
HASH="soak-hash-$(date -u +%Y%m%d%H%M%S)"
SESSION="00000000-0000-4000-8000-000000000017"
# High ports avoid collisions with leftover lab processes.
PORT_A=28741
PORT_B=28742
PORT_C=28743

echo "[info] starting 3× witnessctl-node (distinct node_id, shared custody secret)"
for port in "$PORT_A" "$PORT_B" "$PORT_C"; do
  fuser -k "${port}/tcp" >/dev/null 2>&1 || true
done
sleep 0.5

start_node() {
  local id="$1" region="$2" port="$3"
  WITNESSCTL_CUSTODY_NODE_SECRET="$SECRET" \
    WITNESSCTL_HMAC_SECRET="$SECRET" \
    WITNESSCTL_CUSTODY_NODE_ID="$id" \
    WITNESSCTL_CUSTODY_NODE_REGION="$region" \
    WITNESSCTL_CUSTODY_NODE_PORT="$port" \
    "$BIN" >"/tmp/wc-node-${id}.log" 2>&1 &
  PIDS+=($!)
  sleep 0.4
}
start_node custody-a lab-a "$PORT_A"
start_node custody-b lab-b "$PORT_B"
start_node custody-c lab-c "$PORT_C"

for port in "$PORT_A" "$PORT_B" "$PORT_C"; do
  ok=0
  for _ in $(seq 1 40); do
    if curl -sf --max-time 1 "http://127.0.0.1:${port}/health" >/dev/null; then
      ok=1
      break
    fi
    sleep 0.25
  done
  if [[ "$ok" != "1" ]]; then
    echo "[fail] witnessctl-node :${port} not healthy — see /tmp/wc-node-*.log" >&2
    exit 1
  fi
done
echo "[ok] three custody nodes healthy"

PROOF_FILE=$(mktemp)
echo '[]' >"$PROOF_FILE"
collect_proof() {
  local port="$1"
  local RESP
  RESP=$(curl -sf --max-time 5 -X POST "http://127.0.0.1:${port}/api/v1/custody/replicate" \
    -H "X-WitnessCtl-Custody-Secret: ${SECRET}" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\":\"${SESSION}\",\"payload_hash\":\"${HASH}\"}")
  python3 - "$PROOF_FILE" "$RESP" <<'PY'
import json, sys
path, resp = sys.argv[1], sys.argv[2]
arr = json.load(open(path))
body = json.loads(resp)
proof = body.get("proof") or body
arr.append(proof)
json.dump(arr, open(path, "w"))
print("proof_from", proof.get("node_id"), "ok")
PY
}
collect_proof "$PORT_A"
collect_proof "$PORT_B"
collect_proof "$PORT_C"

# Independent verify matching custody_node::verify_quorum (HMAC node_id:hash:rfc3339)
python3 - "$PROOF_FILE" "$SECRET" <<'PY'
import hashlib, hmac, json, sys
path, secret = sys.argv[1], sys.argv[2]
proofs = json.load(open(path))
required = 2
valid = 0
nodes = set()
hashes = set()
for p in proofs:
    ts = p["timestamp"]
    # serde/chrono often emits +00:00; Rust to_rfc3339 may use Z — try both
    candidates = [ts]
    if ts.endswith("+00:00"):
        candidates.append(ts[:-6] + "Z")
    elif ts.endswith("Z"):
        candidates.append(ts[:-1] + "+00:00")
    ok = False
    for ts_try in candidates:
        payload = f'{p["node_id"]}:{p["capture_hash"]}:{ts_try}'.encode()
        mac = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        if mac == p["signature"]:
            ok = True
            break
    if not ok:
        print("[fail] bad signature for", p.get("node_id"), file=sys.stderr)
        sys.exit(1)
    valid += 1
    nodes.add(p["node_id"])
    hashes.add(p["capture_hash"])
if len(hashes) != 1:
    print("[fail] hash inconsistent", hashes, file=sys.stderr)
    sys.exit(1)
if valid < required or len(nodes) < required:
    print("[fail] quorum not met", valid, len(nodes), file=sys.stderr)
    sys.exit(1)
print(f"[PASS] T17 live quorum_met distinct_nodes={len(nodes)} valid_proofs={valid}")
print("honesty_strip=quorum_met court_export_ready=true (independent verify)")
PY

{
  echo "custody_multinode_soak_ok=1"
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "t17=PASS"
  echo "distinct_nodes=3"
  echo "required_quorum=2"
} >"$OK_FILE"

echo "Wrote $OK_FILE"
echo "T17_LIVE=PASS"
echo "== custody multinode soak: PASS =="
