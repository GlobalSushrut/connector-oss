#!/usr/bin/env bash
# CNP L2 TCP frame smoke — proves bytes move on CONNECTOR_CNP_BIND.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/.cargo-target-umesh/debug/connector-platform"
PORT="${CONNECTOR_SMOKE_PORT:-19092}"
CNP_BIND="${CONNECTOR_CNP_BIND:-127.0.0.1:9410}"
DATA_DIR="${CONNECTOR_DATA_DIR:-/tmp/connector-cnp-smoke-$$}"
CELL_ID="${CONNECTOR_CELL_ID:-cell_smoke_local}"
LOG="$DATA_DIR/platform.log"
PIDFILE="$DATA_DIR/platform.pid"

cleanup() {
  if [[ -f "$PIDFILE" ]]; then
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE"
  fi
}
trap cleanup EXIT

mkdir -p "$DATA_DIR"

if [[ ! -x "$BIN" ]]; then
  echo "[build] connector-platform missing — run cargo build first"
  exit 1
fi

export CONNECTOR_ENV=development
export CONNECTOR_DEV_MODE=1
export CONNECTOR_HOST=127.0.0.1
export CONNECTOR_PORT="$PORT"
export CONNECTOR_DATA_DIR="$DATA_DIR"
export CONNECTOR_CELL_ID="$CELL_ID"
export CONNECTOR_CNP_BIND="$CNP_BIND"

"$BIN" >"$LOG" 2>&1 &
echo $! >"$PIDFILE"

BASE="http://127.0.0.1:${PORT}/api/v1"
for i in $(seq 1 60); do
  if curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null || {
  echo "[fail] platform did not become healthy"
  tail -40 "$LOG" || true
  exit 1
}

echo "[ok] platform healthy on :$PORT"

WIRE=$(curl -sf "$BASE/cnp/wire")
echo "$WIRE" | rg -q '"listening"[[:space:]]*:[[:space:]]*true' || {
  echo "[fail] CNP wire not listening: $WIRE"
  exit 1
}
echo "[ok] CNP listener on $CNP_BIND"

SEND=$(curl -sf -X POST "$BASE/cnp/send" \
  -H 'Content-Type: application/json' \
  -d "{\"dest_cell\":\"$CELL_ID\",\"text\":\"smoke-hello-l2\",\"agent_pid\":\"smoke-agent\"}")
echo "$SEND" | rg -q '"ok"[[:space:]]*:[[:space:]]*true' || {
  echo "[fail] cnp/send: $SEND"
  exit 1
}
echo "[ok] cnp/send local delivery"

INBOX=$(curl -sf "$BASE/cnp/inbox")
echo "$INBOX" | rg -q 'smoke-hello-l2' || {
  echo "[fail] inbox missing payload: $INBOX"
  exit 1
}
echo "[ok] cnp/inbox contains sent message"

# Raw TCP frame (CNP1 + len + JSON)
python3 - <<PY
import json, socket, struct, sys

host, port = "$CNP_BIND".rsplit(":", 1)
port = int(port)
body = json.dumps({
    "from": "tcp-smoke",
    "to": "$CELL_ID",
    "kind": "cognitive",
    "payload": {"text": "raw-tcp-frame"},
    "ts_ms": 1,
}).encode()
frame = b"CNP1" + struct.pack(">I", len(body)) + body
s = socket.create_connection((host, port), timeout=3)
s.sendall(frame)
s.close()
print("[ok] raw TCP frame sent")
PY

sleep 0.3
INBOX2=$(curl -sf "$BASE/cnp/inbox")
echo "$INBOX2" | rg -q 'raw-tcp-frame' || {
  echo "[fail] TCP frame not in inbox: $INBOX2"
  exit 1
}
echo "[ok] raw TCP frame landed in inbox"

echo "[pass] cnp-l2-smoke: L2 transport is live (HTTP + TCP)"
