#!/usr/bin/env bash
# Fail closed unless all seven Connector-operated backends have operational evidence.
set -euo pipefail

PROFILE="${CONNECTOR_BACKENDS_PROFILE:-linux-kvm}"
CONNECTORCTL="${CONNECTORCTL_BIN:-connectorctl}"

case "$PROFILE" in
  linux-kvm|kubernetes) ;;
  *)
    echo "[error] CONNECTOR_BACKENDS_PROFILE must be linux-kvm or kubernetes" >&2
    exit 2
    ;;
esac

if ! command -v "$CONNECTORCTL" >/dev/null 2>&1 && [[ ! -x "$CONNECTORCTL" ]]; then
  echo "[error] connectorctl not found: $CONNECTORCTL" >&2
  exit 3
fi

echo "[verify] profile=$PROFILE endpoint=${CONNECTOR_API_URL:-http://127.0.0.1:9091}"
echo "[verify] process readiness is separate; this command requires real backend operations"

# connectorctl exits Refused (5) when any required backend lacks evidence.
"$CONNECTORCTL" --json govern deploy-verify "$PROFILE"

echo "[ok] all seven backends have operational evidence"
if [[ "$PROFILE" == "kubernetes" ]]; then
  echo "[honesty] functional verification does not override NVIDIA's experimental OpenShell Kubernetes status"
fi
