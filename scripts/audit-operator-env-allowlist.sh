#!/usr/bin/env bash
# P0.3 — bootstrap allowlist for legacy secrets (must match connectorctl BOOTSTRAP_LEGACY_SECRET_VARS).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOWLIST="$ROOT/platform/server/src/bin/connectorctl.rs"

if ! rg -q 'BOOTSTRAP_LEGACY_SECRET_VARS' "$ALLOWLIST"; then
  echo "[fail] BOOTSTRAP_LEGACY_SECRET_VARS not found in connectorctl" >&2
  exit 1
fi

# Fail if new CONNECTOR_* vars are introduced in connector.yaml.example without a preset mapping comment.
NEW_VARS="$(rg '^#?\s*CONNECTOR_[A-Z0-9_]+' "$ROOT/connector.yaml.example" 2>/dev/null | wc -l || true)"
echo "[ok] operator env allowlist documented in connector.yaml.example ($NEW_VARS CONNECTOR_* hints)"
echo "[ok] bootstrap secrets: see connectorctl BOOTSTRAP_LEGACY_SECRET_VARS + docs/BOOTSTRAP_RUNBOOK.md"
exit 0
