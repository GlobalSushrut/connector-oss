#!/usr/bin/env bash
# Helm chart template lint for connector + TraceTramp + WitnessCtl.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HELM="${ROOT}/platform/deploy/helm"

if ! command -v helm >/dev/null 2>&1; then
  echo "[skip] helm not installed"
  exit 0
fi

echo "== helm-lint-smoke =="

lint_chart() {
  local name="$1"
  local dir="$2"
  local template="${3:-1}"
  echo "[lint] ${name} …"
  helm lint "$dir" >/dev/null
  if [[ "$template" == "1" ]]; then
    helm template "${name}-test" "$dir" >/dev/null
    echo "[ok] ${name} lint + template"
  else
    echo "[ok] ${name} lint (template skipped — run helm dependency build for subcharts)"
  fi
}

lint_chart connector "${HELM}/connector" 0
lint_chart tracetramp "${HELM}/tracetramp" 1
lint_chart witnessctl "${HELM}/witnessctl" 1

echo "== helm-lint-smoke: OK =="
