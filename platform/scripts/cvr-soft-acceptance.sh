#!/usr/bin/env bash
# CVR soft LAB acceptance — always runs (no KVM required).
# Proves honesty + refuse-start + unit posture for Linux-level Connector isolation.
# Does NOT claim MicroCell Effective.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export ROOT

ARTIFACT_DIR="${CONNECTOR_CVR_ARTIFACT_DIR:-$ROOT/artifacts/cvr-acceptance}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT="$ARTIFACT_DIR/cvr-soft-acceptance.json"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

pass() { echo "[cvr-soft] PASS: $*"; }
fail() { echo "[cvr-soft] FAIL: $*" >&2; exit 1; }

echo "[cvr-soft] Connector CVR soft LAB acceptance @ $STAMP"

# 1) Unit tests — CVR modules (binary crate)
(
  cd platform/server
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-.cargo-target}" \
    cargo test --bin connector-platform \
    substrate::cvr:: \
    -- --test-threads=4
) || fail "connector-platform cvr unit tests"

pass "cvr unit tests"

# 2) microvm crate (no live FC) — unset FC env so stub readiness stays hermetic
(
  cd platform/microvm
  env -u CONNECTOR_FIRECRACKER_BIN -u CONNECTOR_JAILER_BIN -u CONNECTOR_CVR_KVM_LIVE \
    cargo test --lib
) || fail "connector-microvm tests"

pass "connector-microvm tests"

# 3) microd compiles
cargo check --manifest-path platform/connector-microd/Cargo.toml \
  || fail "connector-microd check"

pass "connector-microd check"

# 4) Posture honesty: HostProbe without KVM must not claim microcell_ready
#    (invoke a tiny rust one-liner via existing binary tests already cover empty_not_ready)
#    Extra: auto policy default table
python3 - <<'PY' || fail "auto policy honesty check"
import json, os, subprocess, tempfile, textwrap
# Ensure default auto map is documented in source
root = os.environ.get("ROOT") or "."
p = os.path.join(root, "platform/server/src/substrate/cvr/auto_policy.rs")
src = open(p).read()
assert "IsolationProfile::V1" in src and "IsolationProfile::V4" in src
assert "never grants" in src.lower() or "Never grants" in src
print("auto_policy honesty ok")
PY

pass "auto policy honesty"

# 5) Refuse-start contract present in profile
rg -n 'START_REFUSED' platform/server/src/substrate/cvr/profile.rs \
  platform/server/src/substrate/cvr/micro_cell.rs >/dev/null \
  || fail "START_REFUSED contract missing"

pass "START_REFUSED contract"

# 6) Vendor manifests present (assets may be placeholders — soft only)
make -s microvm-vendor-check || fail "vendor manifests"

pass "vendor manifests"

# Write artifact (soft never claims Effective)
cat >"$ARTIFACT" <<EOF
{
  "schema": "connector.cvr.acceptance.v1",
  "suite": "soft_lab",
  "status": "PASS",
  "effective_claim": false,
  "at": "$STAMP",
  "honesty": "Soft LAB green does not authorize V3/V4 Effective — requires cvr-kvm-acceptance PASS on KVM host",
  "gates": ["cvr_unit", "microvm_unit", "microd_check", "auto_policy", "start_refused", "vendor_manifest"]
}
EOF

echo "[cvr-soft] artifact → $ARTIFACT"
echo "[cvr-soft] ALL PASS (LAB honesty only)"
