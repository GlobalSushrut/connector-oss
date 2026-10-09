#!/usr/bin/env bash
# Fail CI if Phase 0.7 removal targets reappear (CONNECTOR_OS_ROADMAP.md §2D).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0
for f in \
  advanced-lab/docker-compose.extend.yml \
  deploy/docker-compose.yml \
  oss/docker-compose.yml \
  platform/deploy/docker-compose.yml \
  platform/deploy/docker-compose.observability.yml \
  platform/deploy/docker-compose.prod.yml \
  oss/Dockerfile \
  plugins/tracetramp/Dockerfile \
  plugins/witnessctl/Dockerfile \
  platform/deploy/Dockerfile \
  advanced-lab/agents/Dockerfile \
  advanced-lab/runner/Dockerfile \
  advanced-lab/openfang/Dockerfile \
  advanced-lab/lab-llm/Dockerfile \
  plugins/tracetramp/monitoring/prometheus.yml \
  platform/deploy/prometheus.yml
do
  if [[ -e "$f" ]]; then
    echo "audit-removed-paths: forbidden path exists: $f" >&2
    fail=1
  fi
done

for d in plugins/tracetramp/k8s plugins/tracetramp/monitoring platform/deploy/prometheus deploy/grafana; do
  if [[ -d "$d" ]]; then
    echo "audit-removed-paths: forbidden directory exists: $d" >&2
    fail=1
  fi
done

# On-disk files named exactly "Dockerfile" (not lab/Dockerfile.*) anywhere except under lab/ are forbidden.
while IFS= read -r -d '' f; do
  f="${f#./}"
  case "$f" in
    lab/*) ;;
    *)
      echo "audit-removed-paths: unexpected Dockerfile: $f" >&2
      fail=1
      ;;
  esac
done < <(find "$ROOT" -name Dockerfile \
  -not -path '*/.git/*' \
  -not -path '*/target/*' \
  -not -path '*/node_modules/*' \
  -print0 2>/dev/null)

# docker-compose*.yml / .yaml on disk — only under lab/ (Phase 1.6).
while IFS= read -r -d '' f; do
  f="${f#$ROOT/}"
  case "$f" in
    lab/*) ;;
    *)
      echo "audit-removed-paths: unexpected compose file: $f" >&2
      fail=1
      ;;
  esac
done < <(find "$ROOT" \( -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' \) \
  -not -path '*/.git/*' \
  -not -path '*/target/*' \
  -not -path '*/node_modules/*' \
  -print0 2>/dev/null)

if [[ "$fail" -ne 0 ]]; then
  echo "audit-removed-paths: FAILED — see CONNECTOR_OS_ROADMAP.md §2D." >&2
  exit 1
fi

echo "audit-removed-paths: OK"
