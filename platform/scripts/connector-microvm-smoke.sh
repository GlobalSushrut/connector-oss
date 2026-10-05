#!/usr/bin/env bash
set -euo pipefail

echo "[microvm-smoke] validating vendored manifests"
make microvm-vendor-check

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAUNCHER="${ROOT}/platform/plugin-runtime/assets/connector-microvm-wsl-launch.py"
test -f "${LAUNCHER}"
echo "[microvm-smoke] WSL launcher present: ${LAUNCHER}"
if command -v python3 >/dev/null 2>&1; then
  python3 -m py_compile "${LAUNCHER}"
  echo "[microvm-smoke] WSL launcher py_compile ok"
fi

echo "[microvm-smoke] building connector-microvm"
(
  cd platform/microvm
  cargo test
)

echo "[microvm-smoke] building connector-plugin-runtime"
(
  cd platform/plugin-runtime
  cargo test
)

echo "[microvm-smoke] building connector-vm-agent"
(
  cd platform/connector-vm-agent
  cargo test
)

echo "[microvm-smoke] done"
