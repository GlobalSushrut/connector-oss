#!/usr/bin/env bash
# Boot Connector as one application: API and operator UI.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$HERE/platform/server" ]]; then
  ROOT="$HERE"
elif [[ -d "$HERE/../platform/server" ]]; then
  ROOT="$(cd "$HERE/.." && pwd)"
else
  echo "platform/server was not found" >&2
  exit 2
fi

WORK="${CONNECTOR_OSS_WORK:-/tmp/connector-oss}"
UI_DIR="$ROOT/platform/ui-leptos/dashboard/dist"
PORT="${CONNECTOR_PORT:-9091}"

find_platform_bin() {
  if [[ -n "${CONNECTOR_PLATFORM_BIN:-}" && -x "${CONNECTOR_PLATFORM_BIN}" ]]; then
    printf '%s\n' "$CONNECTOR_PLATFORM_BIN"
    return 0
  fi
  local candidate
  for candidate in \
    "$ROOT/platform/server/.cargo-target-umesh/debug/connector-platform" \
    "$ROOT/platform/server/.cargo-target-umesh/release/connector-platform" \
    "$ROOT/platform/server/target/debug/connector-platform" \
    "$ROOT/platform/server/target/release/connector-platform"
  do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

ensure_platform() {
  if BIN="$(find_platform_bin)"; then
    return 0
  fi
  echo "Building connector-platform. The first build downloads crates and can take several minutes."
  cargo build --manifest-path "$ROOT/platform/server/Cargo.toml" --bin connector-platform
  BIN="$ROOT/platform/server/target/debug/connector-platform"
  [[ -x "$BIN" ]]
}

ensure_ui() {
  if [[ -f "$UI_DIR/index.html" ]]; then
    return 0
  fi
  if ! command -v trunk >/dev/null 2>&1 || ! command -v npx >/dev/null 2>&1; then
    echo "The operator UI is not built. Install the UI tools, then run ./up.sh again:" >&2
    echo "  rustup target add wasm32-unknown-unknown && cargo install trunk" >&2
    echo "Node is required because the UI build runs npx tailwindcss." >&2
    exit 2
  fi
  echo "Building the operator UI."
  if command -v rustup >/dev/null 2>&1; then
    rustup target add wasm32-unknown-unknown
  fi
  (
    unset NO_COLOR
    cd "$ROOT/platform/ui-leptos/dashboard"
    trunk build --release
  )
  [[ -f "$UI_DIR/index.html" ]]
}

mkdir -p "$WORK/data" "$WORK/bin"

if [[ -z "${CONNECTOR_BOOT_SKIP:-}" ]]; then
  "$HERE/boot-backends.sh"
  if [[ -f "$WORK/platform.pid" ]]; then
    kill "$(cat "$WORK/platform.pid")" 2>/dev/null || true
  fi
  for _ in $(seq 1 20); do
    curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1 || break
    sleep 0.5
  done
fi

ensure_ui
ensure_platform

if [[ -f "$WORK/backend.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "$WORK/backend.env"
  set +a
fi
export PATH="$WORK/bin:${PATH}"

setsid env \
  PATH="$PATH" \
  CONNECTOR_ENV=development \
  CONNECTOR_HOST=127.0.0.1 \
  CONNECTOR_PORT="$PORT" \
  CONNECTOR_DATA_DIR="$WORK/data" \
  CONNECTOR_UI_DIR="$UI_DIR" \
  ${SPIFFE_ENDPOINT_SOCKET:+SPIFFE_ENDPOINT_SOCKET="$SPIFFE_ENDPOINT_SOCKET"} \
  ${CONNECTOR_SPIRE_AGENT_BIN:+CONNECTOR_SPIRE_AGENT_BIN="$CONNECTOR_SPIRE_AGENT_BIN"} \
  ${OTEL_EXPORTER_OTLP_ENDPOINT:+OTEL_EXPORTER_OTLP_ENDPOINT="$OTEL_EXPORTER_OTLP_ENDPOINT"} \
  ${CONNECTOR_COSIGN_BIN:+CONNECTOR_COSIGN_BIN="$CONNECTOR_COSIGN_BIN"} \
  ${CONNECTOR_COSIGN_BLOB:+CONNECTOR_COSIGN_BLOB="$CONNECTOR_COSIGN_BLOB"} \
  ${CONNECTOR_COSIGN_SIGNATURE:+CONNECTOR_COSIGN_SIGNATURE="$CONNECTOR_COSIGN_SIGNATURE"} \
  ${CONNECTOR_COSIGN_KEY:+CONNECTOR_COSIGN_KEY="$CONNECTOR_COSIGN_KEY"} \
  ${CONNECTOR_JWT_SECRET:+CONNECTOR_JWT_SECRET="$CONNECTOR_JWT_SECRET"} \
  "$BIN" >"$WORK/platform.log" 2>&1 < /dev/null &
echo $! >"$WORK/platform.pid"

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1 \
    && curl -fsS "http://127.0.0.1:${PORT}/" | grep -q '<html'; then
    echo "Connector is up."
    echo "Open http://127.0.0.1:${PORT}/"
    echo "Development login accepts Authorization: Bearer dev-token"
    exit 0
  fi
  sleep 1
done

echo "Connector did not become ready. Log: $WORK/platform.log" >&2
tail -n 40 "$WORK/platform.log" >&2 || true
exit 1
