#!/usr/bin/env bash
# CNP L5 static 1-hop smoke — two cells, forward via CONNECTOR_CNP_PEERS.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/.cargo-target-umesh/debug/connector-platform"
BASE_DIR="${CONNECTOR_SMOKE_BASE:-/tmp/connector-cnp-l5-smoke-$$}"
# Avoid stale listeners on fixed dev ports.
PORT_BASE=$((19000 + ($$ % 400) * 2))
PORT_A="${CONNECTOR_SMOKE_PORT_A:-$PORT_BASE}"
PORT_B="${CONNECTOR_SMOKE_PORT_B:-$((PORT_BASE + 1))}"
CNP_A="${CONNECTOR_CNP_BIND_A:-127.0.0.1:$((9410 + ($$ % 400) * 2))}"
CNP_B="${CONNECTOR_CNP_BIND_B:-127.0.0.1:$((9410 + ($$ % 400) * 2 + 1))}"
CELL_A="${CONNECTOR_CELL_A:-cell_a}"
CELL_B="${CONNECTOR_CELL_B:-cell_b}"
DATA_A="$BASE_DIR/a"
DATA_B="$BASE_DIR/b"
LOG_A="$DATA_A/platform.log"
LOG_B="$DATA_B/platform.log"
PID_A="$DATA_A/platform.pid"
PID_B="$DATA_B/platform.pid"

cleanup() {
  for pf in "$PID_A" "$PID_B"; do
    if [[ -f "$pf" ]]; then
      kill "$(cat "$pf")" 2>/dev/null || true
      rm -f "$pf"
    fi
  done
}
trap cleanup EXIT

mkdir -p "$DATA_A" "$DATA_B"

if [[ ! -x "$BIN" ]] || [[ "${CONNECTOR_SMOKE_REBUILD:-}" == "1" ]]; then
  echo "[build] connector-platform missing or rebuild requested — building"
  CARGO_TARGET_DIR="$ROOT/.cargo-target-umesh" \
    cargo build --manifest-path "$ROOT/platform/server/Cargo.toml" --bin connector-platform
elif find "$ROOT/platform/server/src/cnp" -name '*.rs' -newer "$BIN" -print -quit 2>/dev/null | grep -q .; then
  echo "[build] CNP sources newer than binary — rebuilding"
  CARGO_TARGET_DIR="$ROOT/.cargo-target-umesh" \
    cargo build --manifest-path "$ROOT/platform/server/Cargo.toml" --bin connector-platform
fi

wait_healthy() {
  local name="$1" port="$2" log="$3"
  for i in $(seq 1 120); do
    if curl -sf --connect-timeout 1 --max-time 2 "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      return 0
    fi
    if (( i % 10 == 0 )); then
      echo "[wait] $name :$port (${i}/120)..."
      tail -3 "$log" 2>/dev/null || true
    fi
    sleep 0.5
  done
  return 1
}

start_cell() {
  local data_dir="$1" port="$2" cnp_bind="$3" cell_id="$4" peers="$5" log="$6" pidfile="$7"
  CONNECTOR_ENV=development \
  CONNECTOR_DEV_MODE=1 \
  CONNECTOR_HOST=127.0.0.1 \
  CONNECTOR_PORT="$port" \
  CONNECTOR_DATA_DIR="$data_dir" \
  CONNECTOR_CELL_ID="$cell_id" \
  CONNECTOR_CNP_BIND="$cnp_bind" \
  CONNECTOR_CNP_PEERS="$peers" \
  CONNECTOR_HA_PEER_URLS="" \
  CONNECTOR_FEDERATION_PEERS="" \
  CONNECTOR_MESH_PEERS="" \
  CONNECTOR_MESH_FABRIC=0 \
  CONNECTOR_MESH_FABRIC=0 \
  CONNECTOR_LLM_STUB=1 \
  "$BIN" >"$log" 2>&1 &
  echo $! >"$pidfile"
}

echo "[info] L5 smoke ports HTTP $PORT_A/$PORT_B CNP $CNP_A / $CNP_B"

# B first so A's peer map resolves immediately.
start_cell "$DATA_B" "$PORT_B" "$CNP_B" "$CELL_B" "${CELL_A}=${CNP_A}" "$LOG_B" "$PID_B"
start_cell "$DATA_A" "$PORT_A" "$CNP_A" "$CELL_A" "${CELL_B}=${CNP_B}" "$LOG_A" "$PID_A"

wait_healthy cell_b "$PORT_B" "$LOG_B" || { echo "[fail] cell_b unhealthy"; tail -40 "$LOG_B" || true; exit 1; }
wait_healthy cell_a "$PORT_A" "$LOG_A" || { echo "[fail] cell_a unhealthy"; tail -40 "$LOG_A" || true; exit 1; }
echo "[ok] two platforms healthy (:$PORT_A / :$PORT_B)"

WIRE_A=$(curl -sf --max-time 5 "http://127.0.0.1:${PORT_A}/api/v1/cnp/wire")
echo "$WIRE_A" | rg -q '"l5_static_live"[[:space:]]*:[[:space:]]*true' \
  || echo "$WIRE_A" | rg -q '"cnp_l5_mode"[[:space:]]*:[[:space:]]*"static_1hop"' || {
  echo "[fail] cell_a L5 not live: $WIRE_A"
  exit 1
}
echo "[ok] cell_a L5 static routes live"

BASE_A="http://127.0.0.1:${PORT_A}/api/v1"
BASE_B="http://127.0.0.1:${PORT_B}/api/v1"

SEND=$(curl -sf --max-time 5 -X POST "$BASE_A/cnp/send" \
  -H 'Content-Type: application/json' \
  -d "{\"dest_cell\":\"$CELL_B\",\"text\":\"l5-hop-smoke\",\"agent_pid\":\"smoke-agent\"}")
echo "$SEND" | rg -q '"ok"[[:space:]]*:[[:space:]]*true' || {
  echo "[fail] cell_a cnp/send to cell_b: $SEND"
  exit 1
}
echo "[ok] cell_a forwarded to cell_b"

sleep 0.5
INBOX_B=$(curl -sf --max-time 5 "$BASE_B/cnp/inbox")
echo "$INBOX_B" | rg -q 'l5-hop-smoke' || {
  echo "[fail] cell_b inbox missing forwarded message: $INBOX_B"
  tail -30 "$LOG_A" || true
  tail -30 "$LOG_B" || true
  exit 1
}
echo "[ok] cell_b inbox received forwarded message"

# Inbound forward: TCP frame arrives at A with to=cell_b.
python3 - <<PY
import json, socket, struct

host, port = "$CNP_A".rsplit(":", 1)
port = int(port)
body = json.dumps({
    "from": "tcp-l5",
    "to": "$CELL_B",
    "kind": "cognitive",
    "payload": {"text": "l5-inbound-forward"},
    "ts_ms": 2,
}).encode()
frame = b"CNP1" + struct.pack(">I", len(body)) + body
s = socket.create_connection((host, port), timeout=3)
s.sendall(frame)
resp = s.recv(64)
s.close()
if not resp.startswith(b"FWD:"):
    raise SystemExit(f"[fail] expected FWD response, got {resp!r}")
print("[ok] cell_a inbound forward ack:", resp.decode().strip())
PY

sleep 0.5
INBOX_B2=$(curl -sf --max-time 5 "$BASE_B/cnp/inbox")
echo "$INBOX_B2" | rg -q 'l5-inbound-forward' || {
  echo "[fail] inbound forward did not land on cell_b: $INBOX_B2"
  exit 1
}
echo "[ok] inbound TCP forward landed on cell_b"

echo "[pass] cnp-l5-smoke: static 1-hop routing is live"
