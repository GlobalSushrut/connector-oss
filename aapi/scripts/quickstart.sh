#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p /tmp/aapi

echo "Building..."
cargo build

echo "Starting gateway (http://127.0.0.1:8080)..."
# Run gateway in background and ensure it is cleaned up on exit
cargo run --bin aapi -- serve --host 127.0.0.1 --port 8080 &
GATEWAY_PID=$!
trap 'kill "${GATEWAY_PID}" >/dev/null 2>&1 || true' EXIT

# Give the server a moment to come up
sleep 1

echo "Installing Python SDK (editable)..."
python -m pip install -U pip >/dev/null
python -m pip install -e "${ROOT_DIR}/sdks/python" >/dev/null

echo "Running Python example..."
python "${ROOT_DIR}/sdks/python/examples/basic_usage.py"

echo "Done."
