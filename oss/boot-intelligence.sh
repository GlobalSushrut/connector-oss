#!/usr/bin/env bash
# Start the three internal intelligence processes Connector calls.
# This script does not start the seven backends and does not change deploy-verify.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$HERE/../platform/server" ]]; then
  ROOT="$(cd "$HERE/.." && pwd)"
elif [[ -d "$HERE/platform/server" ]]; then
  ROOT="$HERE"
else
  echo "platform/server was not found" >&2
  exit 2
fi
WORK="${CONNECTOR_OSS_WORK:-/tmp/connector-oss}"
PIN_DIR="$ROOT/platform/deploy/intelligence-backends/linux"
mkdir -p "$WORK/intelligence/letta" "$WORK/intelligence/litellm"
chmod 0700 "$WORK" "$WORK/intelligence"

pin_of() {
  awk 'NF && $1 !~ /^#/ { print; exit }' "$1"
}

already_running() {
  docker ps --filter "ancestor=$1" --format '{{.ID}}' | grep -q .
}

cat > "$WORK/intelligence/litellm/config.yaml" <<'EOF'
model_list: []
litellm_settings:
  drop_params: true
general_settings:
  disable_spend_logs: true
EOF
chmod 0644 "$WORK/intelligence/litellm/config.yaml"

BRAIN="$(pin_of "$PIN_DIR/letta.pin")"
BROKER="$(pin_of "$PIN_DIR/litellm.pin")"
ORCH="$(pin_of "$PIN_DIR/langflow.pin")"

if [[ "$BRAIN" == *@sha256:* ]] && ! already_running "$BRAIN"; then
  docker rm -f connector-intelligence-brain >/dev/null 2>&1 || true
  docker run -d --name connector-intelligence-brain \
    --restart no --security-opt no-new-privileges:true \
    -p "127.0.0.1:${CONNECTOR_INTELLIGENCE_BRAIN_PORT:-18283}:8283" \
    -v "$WORK/intelligence/letta:/root/.letta" \
    "$BRAIN" >/dev/null || true
fi

if [[ "$BROKER" == *@sha256:* ]] && ! already_running "$BROKER"; then
  docker rm -f connector-intelligence-broker >/dev/null 2>&1 || true
  docker run -d --name connector-intelligence-broker \
    --restart no --security-opt no-new-privileges:true \
    -p "127.0.0.1:${CONNECTOR_INTELLIGENCE_BROKER_PORT:-14011}:4000" \
    -v "$WORK/intelligence/litellm/config.yaml:/app/config.yaml:ro" \
    "$BROKER" --config /app/config.yaml --port 4000 >/dev/null || true
fi

if [[ "$ORCH" == *@sha256:* ]] && ! already_running "$ORCH"; then
  docker rm -f connector-intelligence-orchestrate >/dev/null 2>&1 || true
  docker run -d --name connector-intelligence-orchestrate \
    --restart no --security-opt no-new-privileges:true \
    -p "127.0.0.1:${CONNECTOR_INTELLIGENCE_ORCHESTRATE_PORT:-17860}:7860" \
    "$ORCH" >/dev/null || true
fi

echo "Intelligence processes are separate from the seven backends."
echo "Status is GET /api/v1/runtime/intelligence on the Connector port."
echo "ready is true only when each pinned image is a running docker ancestor."
