#!/usr/bin/env bash
# R4 — two-agent Distributed Intelligence smoke gate.
# Requires a running platform (CONNECTOR_API_URL) and connectorctl on PATH or built.
#
# Usage (from repo root, platform already up):
#   bash platform/scripts/iia-two-agent-smoke.sh
#
# Or build + invoke:
#   cargo build -p connector-platform --bin connectorctl
#   CONNECTOR_API_URL=http://127.0.0.1:9091 ./platform/scripts/iia-two-agent-smoke.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_ROOT="$ROOT/platform/server"
export CONNECTOR_API_URL="${CONNECTOR_API_URL:-http://127.0.0.1:9091}"

CTL="${CONNECTORCTL:-}"
if [[ -z "$CTL" ]]; then
  if command -v connectorctl >/dev/null 2>&1; then
    CTL="$(command -v connectorctl)"
  elif [[ -x "$SERVER_ROOT/.cargo-target/debug/connectorctl" ]]; then
    CTL="$SERVER_ROOT/.cargo-target/debug/connectorctl"
  elif [[ -x "$ROOT/target/debug/connectorctl" ]]; then
    CTL="$ROOT/target/debug/connectorctl"
  else
    echo "building connectorctl…"
    cargo build --manifest-path "$SERVER_ROOT/Cargo.toml" --bin connectorctl
    if [[ -x "$SERVER_ROOT/.cargo-target/debug/connectorctl" ]]; then
      CTL="$SERVER_ROOT/.cargo-target/debug/connectorctl"
    else
      CTL="$ROOT/target/debug/connectorctl"
    fi
  fi
fi

exec "$CTL" iia smoke
