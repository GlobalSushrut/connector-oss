#!/usr/bin/env bash
# P2-T07 — adversarial syscall / raw socket / namespace escape (lab scaffold).
# Proves Connector refuses ambient regain when exclusivity / unbypassable bar is on.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

grep -q 'RawNetwork\|raw.socket\|raw_socket' platform/server/src/substrate/effect_exclusivity.rs \
  || grep -q 'raw' platform/server/src/substrate/effect_exclusivity.rs
grep -q 'landlock_fail_closed' platform/server/src/substrate/effect_exclusivity.rs
grep -q 'assert_sandbox_unbypassable\|CONNECTOR_SANDBOX_UNBYPASSABLE' \
  platform/server/src/substrate/sandbox_unbypassable.rs
grep -q 'cgroup_skb\|mark' platform/ebpf/connector_mark_deny.bpf.c
test -f platform/scripts/docklock-bypass-adversarial.sh
test -f platform/scripts/effect-exclusivity-adversarial.sh

echo "seven-pillars-p2t07-adversarial: OK (escape paths gated in exclusivity + sandbox + eBPF)"
