#!/usr/bin/env bash
# Automatable subset of CONNECTOR_OS_ROADMAP.md §10 (no UI video / TLS terminator).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
fail=0

note() { echo "[ok] $*"; }
warn() { echo "[warn] $*" >&2; }
fail_item() { echo "[fail] $*" >&2; fail=1; }

echo "== section10-automated-smoke =="

make doctor || fail_item "make doctor"
make platform-test || fail_item "make platform-test"

for s in audit-removed-paths audit-release-tar-excludes audit-target-not-root-owned \
  audit-plugin-cage-hosts audit-operator-env-allowlist audit-secrets-in-repo; do
  bash "scripts/${s}.sh" || fail_item "$s"
done
note "repo hygiene audits"

bash platform/scripts/tt-wc-prod-gate.sh || fail_item "tt-wc-prod-gate"
bash platform/scripts/upgrade-persist-smoke.sh || fail_item "upgrade-persist"
bash platform/scripts/prod-dogfood-smoke.sh || fail_item "prod-dogfood"

if [[ "${CONNECTOR_SKIP_PLUGIN_PACKAGE:-}" != "1" ]]; then
  bash platform/scripts/package-plugins-smoke.sh || fail_item "package-plugins-smoke"
else
  warn "CONNECTOR_SKIP_PLUGIN_PACKAGE=1"
fi

TPL_COUNT="$(find platform/server/resources/workflow_templates -name '*.ccl' 2>/dev/null | wc -l | tr -d ' ')"
if [[ "${TPL_COUNT:-0}" -ge 3 ]]; then
  note "reference CLS templates: $TPL_COUNT"
else
  warn "fewer than 3 reference CLS templates ($TPL_COUNT)"
fi

# P1.4 — sovereign-node docs present (backup + node-upgrade path)
for doc in docs/TRUST_DOMAIN_BACKUP.md docs/PRODUCTION_UPGRADE.md; do
  if [[ -f "$doc" ]]; then
    note "doc present: $doc"
  else
    fail_item "missing required doc: $doc"
  fi
done

if command -v dig >/dev/null 2>&1; then
  if dig +short tracetramp.cnktros @8.8.8.8 2>/dev/null | grep -q .; then
    fail_item "tracetramp.cnktros resolves publicly"
  else
    note "cnktros not on public DNS"
  fi
fi

if curl -sf "${CONNECTOR_TEST_URL:-http://127.0.0.1:9091}/health" >/dev/null 2>&1; then
  CONNECTOR_TEST_URL="${CONNECTOR_TEST_URL:-http://127.0.0.1:9091}" bash platform/scripts/story-qa-smoke.sh || fail_item "story-qa"
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    bash platform/scripts/one-green-start-smoke.sh || warn "one-green-start (non-fatal)"
  fi
else
  warn "live story/one-green skipped (no server)"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "== section10-automated-smoke: FAILED ==" >&2
  exit 1
fi
echo "== section10-automated-smoke: OK (automated §10 subset) =="
echo "Manual still required: dashboard-only config, LLM fallback UI, TLS E2E, lab video, §10 sign-off"
