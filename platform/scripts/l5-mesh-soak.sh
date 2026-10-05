#!/usr/bin/env bash
# L5 mesh soak — T13 (peers + mesh reachability) + T15 (cross-cell channel).
# Prefer lab VMs / CI. Optional: start two local nodes if CONNECTOR_BIN is set.
#
# Usage:
#   # Nodes already up:
#   NODE_A=http://127.0.0.1:18080 NODE_B=http://127.0.0.1:18081 \
#     CONNECTOR_MESH_CHANNEL_SECRET=mesh-soak-secret-32chars!! \
#     bash platform/scripts/l5-mesh-soak.sh
#
#   # Auto-start two bins (dev preset):
#   CONNECTOR_BIN=./platform/server/.cargo-target/debug/connector-platform \
#     bash platform/scripts/l5-mesh-soak.sh --start-local
#
# On PASS: writes platform/scripts/.l5-mesh-soak.ok and prints env to claim mesh_fabric.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OK_FILE="$ROOT/platform/scripts/.l5-mesh-soak.ok"
SECRET="${CONNECTOR_MESH_CHANNEL_SECRET:-mesh-soak-secret-32chars!!}"
AUTH="${CONNECTOR_SMOKE_TOKEN:-}"
START_LOCAL=0
CLAIM_FABRIC=0
for a in "$@"; do
  [[ "$a" == "--start-local" ]] && START_LOCAL=1
  [[ "$a" == "--claim-fabric" ]] && CLAIM_FABRIC=1
done

NODE_A="${NODE_A:-http://127.0.0.1:18080}"
NODE_B="${NODE_B:-http://127.0.0.1:18081}"
PIDS=()

cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

hdr() {
  if [[ -n "$AUTH" ]]; then echo -n "-H" "Authorization: Bearer $AUTH"; fi
}

resolve_connector_bin() {
  local candidates=(
    "${CONNECTOR_BIN:-}"
    "${PLATFORM_BIN:-}"
    "$ROOT/platform/server/.cargo-target-umesh/debug/connector-platform"
    "$ROOT/platform/server/.cargo-target/debug/connector-platform"
    "${CARGO_TARGET_DIR:-}/debug/connector-platform"
    "$ROOT/platform/server/target/debug/connector-platform"
  )
  local c
  for c in "${candidates[@]}"; do
    [[ -n "$c" && -x "$c" ]] || continue
    # Prefer builds that include mesh ping (post T13 recursion fix).
    if command -v rg >/dev/null 2>&1; then
      if rg -a -q 'runtime_mesh_ping' "$c" 2>/dev/null; then
        echo "$c"
        return 0
      fi
    else
      echo "$c"
      return 0
    fi
  done
  # Fall back to first executable even if string check unavailable.
  for c in "${candidates[@]}"; do
    if [[ -n "$c" && -x "$c" ]]; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

start_local_pair() {
  local bin
  bin="$(resolve_connector_bin || true)"
  if [[ -z "$bin" || ! -x "$bin" ]]; then
    echo "[fail] CONNECTOR_BIN not set or not executable — build connector-platform first" >&2
    echo "       Prefer: cd platform/server && CARGO_TARGET_DIR=.cargo-target-umesh cargo build -p connector-platform --bin connector-platform" >&2
    exit 1
  fi
  echo "[info] CONNECTOR_BIN=$bin"
  local da="$ROOT/.mesh-soak-data-a" db="$ROOT/.mesh-soak-data-b"
  rm -rf "$da" "$db"
  mkdir -p "$da" "$db"
  echo "[info] starting node A :18080 and B :18081"
  # Bind loopback only — open-auth on 0.0.0.0 is refused. Dev-mode auth bypass (Bearer any).
  # Stagger protocol GW / UI-RPC ports so two nodes do not collide.
  env -u CONNECTOR_AIRGAP -u CONNECTOR_OPEN_AUTH \
    CONNECTOR_PRESET=local CONNECTOR_DEV_MODE=1 CONNECTOR_LLM_STUB=1 \
    CONNECTOR_HOST=127.0.0.1 CONNECTOR_PORT=18080 CONNECTOR_DATA_DIR="$da" \
    CONNECTOR_CELL_ID=cell_a CONNECTOR_CELL_REGION=lab-a \
    CONNECTOR_HA_PEER_URLS=http://127.0.0.1:18081 \
    CONNECTOR_MESH_CHANNEL_SECRET="$SECRET" \
    CONNECTOR_PROTOCOL_PORT=19092 CONNECTOR_UI_RPC_PORT=19093 \
    CONNECTOR_AIRGAP=false \
    "$bin" >"$da/node.log" 2>&1 &
  PIDS+=($!)
  env -u CONNECTOR_AIRGAP -u CONNECTOR_OPEN_AUTH \
    CONNECTOR_PRESET=local CONNECTOR_DEV_MODE=1 CONNECTOR_LLM_STUB=1 \
    CONNECTOR_HOST=127.0.0.1 CONNECTOR_PORT=18081 CONNECTOR_DATA_DIR="$db" \
    CONNECTOR_CELL_ID=cell_b CONNECTOR_CELL_REGION=lab-b \
    CONNECTOR_HA_PEER_URLS=http://127.0.0.1:18080 \
    CONNECTOR_MESH_CHANNEL_SECRET="$SECRET" \
    CONNECTOR_PROTOCOL_PORT=19192 CONNECTOR_UI_RPC_PORT=19193 \
    CONNECTOR_AIRGAP=false \
    "$bin" >"$db/node.log" 2>&1 &
  PIDS+=($!)
  for i in $(seq 1 60); do
    if curl -sf --max-time 1 "$NODE_A/health" >/dev/null \
      && curl -sf --max-time 1 "$NODE_B/health" >/dev/null; then
      echo "[ok] both nodes healthy"
      return 0
    fi
    sleep 1
  done
  echo "[fail] nodes did not become healthy — see $da/node.log $db/node.log" >&2
  exit 1
}

if [[ "$START_LOCAL" == "1" ]]; then
  start_local_pair
fi

echo "== L5 mesh soak =="
echo "NODE_A=$NODE_A NODE_B=$NODE_B"

if ! curl -sf --max-time 3 "$NODE_A/health" >/dev/null; then
  echo "[skip] NODE_A not up — start two nodes or pass --start-local" >&2
  exit 0
fi
if ! curl -sf --max-time 3 "$NODE_B/health" >/dev/null; then
  echo "[fail] NODE_B not up at $NODE_B" >&2
  exit 1
fi

# T13 — peer mesh reachability
MA=$(curl -sf --max-time 5 "$NODE_A/api/v1/runtime/mesh")
MB=$(curl -sf --max-time 5 "$NODE_B/api/v1/runtime/mesh")
PA=$(echo "$MA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('peers_seen',0))" 2>/dev/null || echo 0)
PB=$(echo "$MB" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('peers_seen',0))" 2>/dev/null || echo 0)
echo "[T13] peers_seen A=$PA B=$PB"
if [[ "${PA:-0}" -lt 2 || "${PB:-0}" -lt 2 ]]; then
  echo "[fail] T13: expected peers_seen≥2 on both (configure CONNECTOR_HA_PEER_URLS)" >&2
  exit 1
fi
echo "[PASS] T13 peer mesh reachability"

# T15 — cross-cell channel
SEND=$(curl -sf --max-time 10 -X POST "$NODE_A/api/v1/runtime/mesh/channel/send" \
  -H 'content-type: application/json' \
  -d "{\"peer_url\":\"$NODE_B\",\"payload\":{\"effect\":\"l5_soak\",\"n\":1},\"fni_flow_id\":\"soak-t15\"}" \
  || true)
if ! echo "$SEND" | grep -q '"delivered"[[:space:]]*:[[:space:]]*true'; then
  echo "[fail] T15 send failed: $SEND" >&2
  echo "       Ensure CONNECTOR_MESH_CHANNEL_SECRET matches on both nodes." >&2
  exit 1
fi
INBOX=$(curl -sf --max-time 5 "$NODE_B/api/v1/runtime/mesh/channel/inbox" || true)
if ! echo "$INBOX" | grep -q 'l5_soak\|cnp_mesh_channel\|cell_a\|from_cell'; then
  # count >= 1 is enough
  CNT=$(echo "$INBOX" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('count',0))" 2>/dev/null || echo 0)
  if [[ "${CNT:-0}" -lt 1 ]]; then
    echo "[fail] T15 inbox empty on B: $INBOX" >&2
    exit 1
  fi
fi
echo "[PASS] T15 cross-cell channel"

# T18 honesty without claim env
FA=$(echo "$MA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('mesh_fabric',True))" 2>/dev/null || echo true)
if [[ "$FA" == "True" || "$FA" == "true" ]]; then
  # Only OK if operator already claimed
  if [[ "${CONNECTOR_MESH_FABRIC:-}" == "1" ]]; then
    echo "[ok] mesh_fabric true (CONNECTOR_MESH_FABRIC=1)"
  else
    echo "[fail] T18: mesh_fabric true without CONNECTOR_MESH_FABRIC=1" >&2
    exit 1
  fi
else
  echo "[PASS] T18 honesty (mesh_fabric false until claim env)"
fi

claim_fabric_local() {
  echo "[info] --claim-fabric: restarting pair with CONNECTOR_MESH_FABRIC=1"
  cleanup
  PIDS=()
  # Ensure old soak nodes are gone — otherwise curl can hit pre-claim PIDs (mesh_fabric=false).
  for port in 18080 18081 19092 19093 19192 19193; do
    fuser -k "${port}/tcp" >/dev/null 2>&1 || true
  done
  for _ in $(seq 1 40); do
    if ! curl -sf --max-time 0.3 "$NODE_A/health" >/dev/null \
      && ! curl -sf --max-time 0.3 "$NODE_B/health" >/dev/null; then
      break
    fi
    sleep 0.25
  done
  sleep 0.5
  local bin
  bin="$(resolve_connector_bin || true)"
  [[ -n "$bin" && -x "$bin" ]] || { echo "[fail] no CONNECTOR_BIN for fabric claim" >&2; exit 1; }
  local da="$ROOT/.mesh-soak-data-a" db="$ROOT/.mesh-soak-data-b"
  rm -rf "$da" "$db"
  mkdir -p "$da" "$db"
  env -u CONNECTOR_AIRGAP -u CONNECTOR_OPEN_AUTH \
    CONNECTOR_PRESET=local CONNECTOR_DEV_MODE=1 CONNECTOR_LLM_STUB=1 \
    CONNECTOR_HOST=127.0.0.1 CONNECTOR_PORT=18080 CONNECTOR_DATA_DIR="$da" \
    CONNECTOR_CELL_ID=cell_a CONNECTOR_CELL_REGION=lab-a \
    CONNECTOR_HA_PEER_URLS=http://127.0.0.1:18081 \
    CONNECTOR_MESH_CHANNEL_SECRET="$SECRET" \
    CONNECTOR_MESH_FABRIC=1 \
    CONNECTOR_PROTOCOL_PORT=19092 CONNECTOR_UI_RPC_PORT=19093 \
    CONNECTOR_AIRGAP=false \
    "$bin" >"$da/node.log" 2>&1 &
  PIDS+=($!)
  env -u CONNECTOR_AIRGAP -u CONNECTOR_OPEN_AUTH \
    CONNECTOR_PRESET=local CONNECTOR_DEV_MODE=1 CONNECTOR_LLM_STUB=1 \
    CONNECTOR_HOST=127.0.0.1 CONNECTOR_PORT=18081 CONNECTOR_DATA_DIR="$db" \
    CONNECTOR_CELL_ID=cell_b CONNECTOR_CELL_REGION=lab-b \
    CONNECTOR_HA_PEER_URLS=http://127.0.0.1:18080 \
    CONNECTOR_MESH_CHANNEL_SECRET="$SECRET" \
    CONNECTOR_MESH_FABRIC=1 \
    CONNECTOR_PROTOCOL_PORT=19192 CONNECTOR_UI_RPC_PORT=19193 \
    CONNECTOR_AIRGAP=false \
    "$bin" >"$db/node.log" 2>&1 &
  PIDS+=($!)
  for i in $(seq 1 60); do
    if curl -sf --max-time 1 "$NODE_A/health" >/dev/null \
      && curl -sf --max-time 1 "$NODE_B/health" >/dev/null; then
      break
    fi
    sleep 1
  done
  local FA FB
  FA=""; FB=""
  for _ in $(seq 1 10); do
    FA=$(curl -sf --max-time 5 "$NODE_A/api/v1/runtime/mesh" \
      | python3 -c "import sys,json; d=json.load(sys.stdin); m=d.get('membership') or {}; print(d.get('mesh_fabric'), d.get('product_sot'), d.get('peers_seen'), m.get('mesh_fabric_env'))")
    FB=$(curl -sf --max-time 5 "$NODE_B/api/v1/runtime/mesh" \
      | python3 -c "import sys,json; d=json.load(sys.stdin); m=d.get('membership') or {}; print(d.get('mesh_fabric'), d.get('product_sot'), d.get('peers_seen'), m.get('mesh_fabric_env'))")
    echo "[claim] A: $FA"
    echo "[claim] B: $FB"
    if python3 - <<PY
fa = """$FA""".split()
fb = """$FB""".split()
def ok(parts):
    return len(parts) >= 3 and parts[0].lower() == "true" and parts[1] == "cell_mesh" and int(float(parts[2])) >= 2
raise SystemExit(0 if ok(fa) and ok(fb) else 1)
PY
    then
      echo "[PASS] fabric claim (mesh_fabric + product_sot=cell_mesh, peers_seen≥2)"
      return 0
    fi
    sleep 0.5
  done
  echo "[fail] fabric claim A: $FA B: $FB" >&2
  exit 1
}

{
  echo "l5_mesh_soak_ok=1"
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "node_a=$NODE_A"
  echo "node_b=$NODE_B"
  echo "t13=PASS"
  echo "t15=PASS"
} >"$OK_FILE"

if [[ "$CLAIM_FABRIC" == "1" && "$START_LOCAL" == "1" ]]; then
  claim_fabric_local
  {
    echo "l5_mesh_soak_ok=1"
    echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "node_a=$NODE_A"
    echo "node_b=$NODE_B"
    echo "t13=PASS"
    echo "t15=PASS"
    echo "fabric_claim=PASS"
  } >"$OK_FILE"
elif [[ "$CLAIM_FABRIC" == "1" ]]; then
  echo "[warn] --claim-fabric requires --start-local (skipped)" >&2
fi

echo
echo "== L5 mesh soak: PASS =="
echo "Wrote $OK_FILE"
if [[ "$CLAIM_FABRIC" != "1" ]]; then
  echo "To claim fabric on both nodes (after this soak), restart with:"
  echo "  export CONNECTOR_MESH_FABRIC=1"
  echo "  export CONNECTOR_MESH_CHANNEL_SECRET=$SECRET"
  echo "  # keep CONNECTOR_HA_PEER_URLS pointing at peers"
  echo "  # or re-run: bash platform/scripts/l5-mesh-soak.sh --start-local --claim-fabric"
  echo "Then GET /api/v1/runtime/mesh → mesh_fabric:true, product_sot:cell_mesh, peers_seen≥2"
fi
