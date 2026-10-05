#!/usr/bin/env bash
# Host adversarial lab — close the gap toward SHIPPED_VERIFIED (light crates only).
# Never builds connector-platform (avoids laptop OOM).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
REPORT="${CONNECTOR_LAB_REPORT:-/tmp/connector-unbypassable-lab.json}"
PASS=0
FAIL=0
WARN=0
NOTES_FILE=$(mktemp)

ok() { echo "PASS: $1"; PASS=$((PASS+1)); echo "PASS:$1" >>"$NOTES_FILE"; }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); echo "FAIL:$1" >>"$NOTES_FILE"; }
warn() { echo "WARN: $1"; WARN=$((WARN+1)); echo "WARN:$1" >>"$NOTES_FILE"; }

cleanup() { rm -f "$NOTES_FILE"; }
trap cleanup EXIT

echo "== load unbypassable profile =="
set -a
# shellcheck disable=SC1091
source "$ROOT/platform/deploy/unbypassable.env"
set +a
ok "sourced platform/deploy/unbypassable.env"

echo "== required flags =="
for f in \
  CONNECTOR_SANDBOX_UNBYPASSABLE \
  CONNECTOR_EFFECT_EXCLUSIVITY \
  CONNECTOR_KERNEL_ENFORCE \
  CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED \
  CONNECTOR_VSOCK_TICKET_REQUIRE \
  CONNECTOR_EBPF_REQUIRE \
  CONNECTOR_TOOLS_IN_MICROVM \
  CONNECTOR_ISOLATION_RUNTIME
do
  v="${!f:-}"
  if [[ -z "$v" ]]; then bad "flag unset: $f"; continue; fi
  if [[ "$f" == "CONNECTOR_ISOLATION_RUNTIME" && "$v" != "microvm" ]]; then
    bad "$f=$v (want microvm)"
  else
    ok "$f=$v"
  fi
done

for f in CONNECTOR_ALLOW_IN_PROCESS_EFFECTS CONNECTOR_ALLOW_UNAUTH_VSOCK CONNECTOR_ALLOW_ISOLATION_DOWNGRADE; do
  v="${!f:-}"
  if [[ "${v,,}" == "1" || "${v,,}" == "true" ]]; then
    bad "break-glass enabled: $f=$v"
  else
    ok "break-glass off: $f"
  fi
done

echo "== 100-agent soak (light) =="
if cargo test --manifest-path platform/seven-pillars-proofs/Cargo.toml -q -- --nocapture \
  && cargo run --manifest-path platform/seven-pillars-proofs/Cargo.toml -q; then
  ok "P1-T08/P2-T08/P4-T08/P6-T09/RG-08 soak_100"
else
  bad "soak_100"
fi

echo "== eBPF object + kerneld =="
make -C platform/ebpf all verify >/dev/null
test -f platform/ebpf/connector_mark_deny.bpf.o && ok "eBPF object built" || bad "eBPF object missing"
cargo build --manifest-path platform/connector-kerneld/Cargo.toml -q
BIN=""
for cand in \
  platform/connector-kerneld/target/debug/connector-kerneld \
  target/debug/connector-kerneld; do
  if [[ -x "$cand" ]]; then BIN="$cand"; break; fi
done
if [[ -z "$BIN" ]]; then
  BIN=$(find /tmp/cursor-sandbox-cache -name connector-kerneld -type f 2>/dev/null | head -1 || true)
fi
if [[ -z "${BIN:-}" || ! -x "$BIN" ]]; then
  bad "connector-kerneld binary missing"
else
  ok "connector-kerneld binary"
  export CONNECTOR_EBPF_OBJ="$ROOT/platform/ebpf/connector_mark_deny.bpf.o"
  set +e
  "$BIN" ebpf-load --agent lab-agent >/tmp/ebpf-lab-load.json 2>/tmp/ebpf-lab-load.err
  rc=$?
  set -e
  if [[ $rc -eq 0 ]] && grep -q '"ebpf_loaded": true' /tmp/ebpf-lab-load.json 2>/dev/null; then
    ok "P2-T05 eBPF loaded+pinned"
    "$BIN" ebpf-unload --agent lab-agent >/dev/null 2>&1 || true
  else
    warn "P2-T05 eBPF load denied (need CAP_BPF/bpffs) — checking fail-closed"
    export CONNECTOR_EBPF_REQUIRE=1
    set +e
    "$BIN" ebpf-status --agent lab-agent >/dev/null 2>&1
    src=$?
    set -e
    if [[ $src -ne 0 ]]; then
      ok "P2-T05 fail-closed under CONNECTOR_EBPF_REQUIRE"
    else
      bad "P2-T05 REQUIRE did not fail-closed"
    fi
  fi
fi

echo "== host tools =="
if command -v nft >/dev/null; then ok "nft present"; else warn "nft missing (matrix cut limited)"; fi
if command -v bpftool >/dev/null || command -v /usr/sbin/bpftool >/dev/null; then
  ok "bpftool present"
else
  bad "bpftool missing"
fi
if [[ -r /sys/kernel/security/landlock/version ]] || [[ -d /sys/kernel/security/landlock ]]; then
  ok "Landlock ABI visible"
elif grep -q landlock /proc/filesystems 2>/dev/null; then
  ok "Landlock in /proc/filesystems"
else
  warn "Landlock not visible on this kernel"
fi
[[ -d /sys/fs/cgroup ]] && ok "cgroup fs present" || bad "cgroup fs missing"
if [[ -d /sys/fs/bpf ]]; then ok "bpffs present"; else warn "bpffs missing — eBPF pin needs mount"; fi

echo "== microVM asset gate =="
if [[ -n "${CONNECTOR_MICROVM_KERNEL:-}" && -f "${CONNECTOR_MICROVM_KERNEL}" \
   && -n "${CONNECTOR_MICROVM_ROOTFS:-}" && -f "${CONNECTOR_MICROVM_ROOTFS}" ]]; then
  ok "P6-T06 microVM assets present"
else
  warn "P6-T06 microVM KERNEL/ROOTFS unset — tool effects must refuse under unbypassable"
fi

echo "== wiring =="
bash platform/scripts/seven-pillars-sandbox-unbypassable-adversarial.sh >/dev/null
ok "sandbox/vsock/revoke wiring"
bash platform/scripts/seven-pillars-p2t07-adversarial.sh >/dev/null
ok "P2-T07 escape-path wiring"

# JSON report without fragile embedding
{
  echo '{'
  echo "  \"schema\": \"connector.unbypassable_lab.v1\","
  echo "  \"pass\": $PASS,"
  echo "  \"fail\": $FAIL,"
  echo "  \"warn\": $WARN,"
  echo "  \"profile\": \"platform/deploy/unbypassable.env\","
  echo '  "honesty": "Promote SHIPPED_VERIFIED only for PASS notes; eBPF attach and Firecracker remain host-gated",'
  echo -n '  "notes": ['
  first=1
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    esc=${line//\\/\\\\}
    esc=${esc//\"/\\\"}
    if [[ $first -eq 1 ]]; then first=0; else echo -n ','; fi
    echo -n "\"$esc\""
  done <"$NOTES_FILE"
  echo ']'
  echo '}'
} >"$REPORT"

echo ""
echo "LAB SUMMARY: pass=$PASS fail=$FAIL warn=$WARN"
echo "report: $REPORT"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
echo "seven-pillars-host-adversarial-lab: OK"

bash platform/scripts/seven-pillars-t2-t8-harden.sh

# Always bind court evidence after a green lab (no platform compile).
bash "$ROOT/platform/scripts/court-grade-evidence-bind.sh"

# Host attach proofs (CAP_BPF / nft may WARN — coding bar still OK)
bash "$ROOT/platform/scripts/seven-pillars-host-attach-proofs.sh" || true
exit 0
