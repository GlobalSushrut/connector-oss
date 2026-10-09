#!/bin/bash
DG="/tmp/cursor-sandbox-cache/5abf50820e2eb3cac5a00bc226ef8d1c/cargo-target/debug/deps/devguard-b0b35022f3698903"
CONFIG="devguard.yaml"
CMD="$1"

if [ -z "$CMD" ]; then
  echo "[DevGuard] DENY: missing command payload" >&2
  exit 2
fi
if [ ! -f "$CONFIG" ]; then
  echo "[DevGuard] DENY: policy is unavailable" >&2
  exit 2
fi
if ! result=$("$DG" check exec "$CMD" --config "$CONFIG" 2>&1); then
  echo "[DevGuard] CLAUDE EXEC BLOCKED: $CMD"
  echo "  $result"
  exit 2
fi
exit 0
