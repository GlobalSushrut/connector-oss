#!/usr/bin/env bash
# eBPF adversarial / acceptance scaffold (Seven Pillars P2-T05).
# Proves object builds, status probe works, and load fails closed without CAP_BPF
# or succeeds when privileges + bpffs are available.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "== build BPF object =="
make -C platform/ebpf all verify

echo "== build connector-kerneld =="
cargo build --manifest-path platform/connector-kerneld/Cargo.toml -q

BIN=platform/connector-kerneld/target/debug/connector-kerneld
# workspace may put target elsewhere
if [[ ! -x "$BIN" ]]; then
  BIN=$(find platform/connector-kerneld target -name connector-kerneld -type f 2>/dev/null | head -1 || true)
fi
if [[ -z "${BIN:-}" || ! -x "$BIN" ]]; then
  # cargo default target dir
  BIN=$(ls -1 target/debug/connector-kerneld 2>/dev/null || ls -1 /tmp/cursor-sandbox-cache/*/cargo-target/debug/connector-kerneld 2>/dev/null | head -1 || true)
fi
test -n "${BIN:-}" && test -x "$BIN"

export CONNECTOR_EBPF_OBJ="$ROOT/platform/ebpf/connector_mark_deny.bpf.o"
echo "== ebpf-status (pre-load) =="
"$BIN" ebpf-status --agent test-agent || true

echo "== ebpf-load (may fail without CAP_BPF — that is OK for gated) =="
set +e
"$BIN" ebpf-load --agent test-agent
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "LOAD_OK"
  "$BIN" ebpf-status --agent test-agent | tee /tmp/ebpf-status.json
  grep -q '"ebpf_loaded": true' /tmp/ebpf-status.json
  MARK=$((0xCD000001))
  "$BIN" ebpf-deny-mark --agent test-agent --mark "$MARK" --deny true
  "$BIN" ebpf-unload --agent test-agent || true
  echo "seven-pillars-ebpf-adversarial: OK (loaded + map update)"
else
  echo "LOAD_DENIED_OR_FAILED rc=$rc (expected without CAP_BPF / bpffs)"
  # Under REQUIRE, status must fail closed
  export CONNECTOR_EBPF_REQUIRE=1
  set +e
  "$BIN" ebpf-status --agent test-agent
  src=$?
  set -e
  test "$src" -ne 0
  echo "seven-pillars-ebpf-adversarial: OK (fail-closed without privileges)"
fi
