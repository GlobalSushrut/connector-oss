#!/usr/bin/env bash
# SIGKILL durability soak — write-through MemWrite survives kill -9 (I-03 verify).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SERVER_ROOT="$ROOT/platform/server"
PORT="${CONNECTOR_DURABILITY_PORT:-19101}"
# Never reuse beta-gate / parent CONNECTOR_DATA_DIR — avoids redb lock while another server is up.
DATA_DIR="${CONNECTOR_DURABILITY_DATA_DIR:-$(mktemp -d /tmp/connector_durability.XXXXXX)}"

export CONNECTOR_HOST="${CONNECTOR_HOST:-127.0.0.1}"
export CONNECTOR_PORT="$PORT"
export CONNECTOR_DATA_DIR="$DATA_DIR"
export CONNECTOR_ENV="${CONNECTOR_ENV:-development}"
export CONNECTOR_DEV_MODE="${CONNECTOR_DEV_MODE:-1}"
export CONNECTOR_MEMWRITE_SYNC_FLUSH=1
export CONNECTOR_PROTOCOL_PORT="${CONNECTOR_PROTOCOL_PORT:-0}"
export CONNECTOR_UI_RPC_PORT="${CONNECTOR_UI_RPC_PORT:-0}"
export RUST_LOG="${RUST_LOG:-warn}"

BASE="http://${CONNECTOR_HOST}:${PORT}"
MARKER="durability-kill-marker-$(date +%s)"
NS="ns:durability-kill"
RECALL_NS="m/ns:durability-kill"

SERVER_PID=""
cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ "$DATA_DIR" == /tmp/connector_durability.* ]]; then
    rm -rf "$DATA_DIR" || true
  fi
}
trap cleanup EXIT INT TERM

cd "$SERVER_ROOT"
_target="${CARGO_TARGET_DIR:-.cargo-target}"
if [[ "$_target" != /* ]]; then
  export CARGO_TARGET_DIR="$SERVER_ROOT/$_target"
else
  export CARGO_TARGET_DIR="$_target"
fi
PLATFORM_BIN="$CARGO_TARGET_DIR/debug/connector-platform"
cargo build --bin connector-platform --quiet

start_server() {
  "$PLATFORM_BIN" &
  SERVER_PID="$!"
  for _ in $(seq 1 120); do
    if curl -sf "${BASE}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "durability-kill-soak: timeout waiting for health" >&2
  return 124
}

echo "== durability kill soak: boot =="
start_server

echo "== register agent + write marker =="
AGENT_JSON=$(curl -sf -X POST "${BASE}/api/v1/agents" \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Durability Agent\",\"namespace\":\"${NS}\",\"role\":\"writer\",\"model\":\"gpt-4o-mini\",\"token_budget\":10000}")
AGENT=$(echo "$AGENT_JSON" | python3 -c "import json,sys; b=json.load(sys.stdin); print(b.get('pid') or b.get('agent_pid') or '')")
RECALL_NS=$(echo "$AGENT_JSON" | python3 -c "import json,sys; b=json.load(sys.stdin); print(b.get('namespace') or '${RECALL_NS}')")
if [[ -z "$AGENT" ]]; then
  echo "durability-kill-soak: agent registration failed: $AGENT_JSON" >&2
  exit 1
fi

WRITE_JSON=$(curl -sf -X POST "${BASE}/api/v1/memory/write" \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d "{\"agent_pid\":\"${AGENT}\",\"content\":\"${MARKER}\",\"user\":\"durability\",\"pipeline\":\"kill-soak\",\"namespace\":\"${NS}\"}")
echo "$WRITE_JSON" | python3 -c "import json,sys; b=json.load(sys.stdin); assert b.get('ok') is True, b"

echo "== SIGKILL platform (pid ${SERVER_PID}) =="
kill -9 "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
sleep 1

echo "== restart and recall =="
start_server

ENC_NS=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${RECALL_NS}', safe=''))")
RECALL=$(curl -sf "${BASE}/api/v1/memory/recall/${ENC_NS}" -H "Authorization: Bearer dev-token")
echo "$RECALL" | python3 -c "import json,sys; b=json.load(sys.stdin); s=json.dumps(b); assert '${MARKER}' in s, 'marker missing after kill: '+s[:500]"

echo "durability kill soak passed (marker survived SIGKILL + restart)"
