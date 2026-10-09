#!/usr/bin/env bash
# Static tenancy isolation audit for TraceTramp (plan Phase 2).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TT="${ROOT}/plugins/tracetramp/src"
fail=0

echo "== audit-tracetramp-tenancy =="

if ! rg -q 'tenancy::tenant_redis_config_key' "${TT}/storage.rs"; then
  echo "[fail] storage.rs must use tenancy::tenant_redis_config_key" >&2
  fail=1
else
  echo "[ok] redis tenant config keys scoped"
fi

if rg -n 'format!\("tenant:config:\{\}"' "${TT}" --glob '!tenancy.rs' 2>/dev/null | grep -q .; then
  echo "[fail] found unscoped tenant:config key outside tenancy.rs" >&2
  fail=1
else
  echo "[ok] no duplicate tenant:config key builders outside tenancy.rs"
fi

if ! rg -q 'validate_cage_sha_address' "${TT}/gateway.rs"; then
  echo "[fail] cage must validate sha addresses" >&2
  fail=1
else
  echo "[ok] cage sha validation present"
fi

if ! test -f "${TT}/tenancy.rs"; then
  echo "[fail] missing tenancy.rs" >&2
  fail=1
else
  echo "[ok] tenancy.rs module exists"
fi

cd "${ROOT}/plugins/tracetramp"
if ! cargo test --test tenancy_isolation --quiet 2>/dev/null; then
  echo "[fail] tenancy_isolation tests" >&2
  fail=1
else
  echo "[ok] tenancy_isolation cargo tests"
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
echo "== audit-tracetramp-tenancy: OK =="
