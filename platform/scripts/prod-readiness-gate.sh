#!/usr/bin/env bash
# Master gate for PRODUCTION_READINESS_CHECKLIST.md automatable items.
# Manual story QA, lab video, and CNP execution fabric remain operator sign-off.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "== prod-readiness-gate =="
echo "Low-RAM: run alone; see docs/LOW_MEMORY_DEV.md (.cargo/config.toml jobs=4)"

make doctor
make platform-test

bash scripts/audit-removed-paths.sh
bash scripts/audit-release-tar-excludes.sh
bash scripts/audit-target-not-root-owned.sh
bash scripts/audit-plugin-cage-hosts.sh
bash scripts/audit-operator-env-allowlist.sh
bash scripts/audit-secrets-in-repo.sh

cargo test --manifest-path platform/supervisor/Cargo.toml --quiet
bash platform/scripts/witness-bundle-smoke.sh
bash platform/scripts/custody-quorum-smoke.sh
bash scripts/audit-tracetramp-tenancy.sh
bash platform/scripts/helm-lint-smoke.sh
bash platform/scripts/tt-wc-prod-gate.sh

if [[ "${CONNECTOR_SKIP_PLUGIN_PACKAGE:-1}" != "1" ]]; then
  bash platform/scripts/package-plugins-smoke.sh
else
  echo "[skip] package-plugins-smoke (CONNECTOR_SKIP_PLUGIN_PACKAGE=1)"
fi

make ci-beta-gate

if curl -sf "${CONNECTOR_TEST_URL:-http://127.0.0.1:9091}/health" >/dev/null 2>&1; then
  CONNECTOR_TEST_URL="${CONNECTOR_TEST_URL:-http://127.0.0.1:9091}" bash platform/scripts/story-qa-smoke.sh
else
  echo "[skip] story-qa-smoke (no server on CONNECTOR_TEST_URL)"
fi
bash platform/scripts/upgrade-persist-smoke.sh
bash platform/scripts/prod-dogfood-smoke.sh

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  bash platform/scripts/one-green-start-smoke.sh
else
  echo "[skip] one-green-start-smoke (Docker not available)"
fi

if [[ "${CONNECTOR_SKIP_TARBALL_SMOKE:-}" != "1" ]]; then
  bash platform/scripts/clean-vm-tarball-smoke.sh
else
  echo "[skip] clean-vm-tarball-smoke (CONNECTOR_SKIP_TARBALL_SMOKE=1)"
fi

if command -v dig >/dev/null 2>&1; then
  if dig +short tracetramp.cnktros @8.8.8.8 2>/dev/null | grep -q .; then
    echo "[warn] public DNS resolved tracetramp.cnktros (expected NXDOMAIN outside node)" >&2
    exit 1
  fi
  echo "[ok] dig tracetramp.cnktros does not resolve via public resolver"
else
  echo "[skip] dig not installed — public DNS cage check skipped"
fi

echo "== prod-readiness-gate: OK (automated) =="
echo "Manual: Jordan/Sam/Riley stories, lab video, CNP execution (see docs/KNOWN_LIMITATIONS.md)"
