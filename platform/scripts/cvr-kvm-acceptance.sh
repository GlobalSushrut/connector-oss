#!/usr/bin/env bash
# CVR KVM acceptance — Firecracker MicroCell live path (Linux-level Effective gate).
#
# Exit codes:
#   0  PASS or LAB_SKIP (honest skip when KVM/assets absent and not required)
#   1  FAIL (required path failed)
#
# Env:
#   CONNECTOR_KVM_REQUIRED=1     — no skip; missing KVM/assets → FAIL
#   CONNECTOR_FIRECRACKER_BIN    — path to firecracker
#   CONNECTOR_JAILER_BIN         — optional jailer
#   CONNECTOR_MICROVM_KERNEL     — vmlinux
#   CONNECTOR_MICROVM_ROOTFS     — rootfs.ext4 / .img
#   CONNECTOR_FETCH_FIRECRACKER=1 — download pinned FC binary when missing
#   CONNECTOR_CVR_ARTIFACT_DIR   — artifact output dir
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export ROOT

ARTIFACT_DIR="${CONNECTOR_CVR_ARTIFACT_DIR:-$ROOT/artifacts/cvr-acceptance}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT="$ARTIFACT_DIR/cvr-kvm-acceptance.json"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REQUIRED="${CONNECTOR_KVM_REQUIRED:-0}"
FC_VERSION="${CONNECTOR_FIRECRACKER_VERSION:-v1.9.1}"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) FC_ARCH="x86_64" ;;
  aarch64|arm64) FC_ARCH="aarch64" ;;
  *) FC_ARCH="$ARCH" ;;
esac

log() { echo "[cvr-kvm] $*"; }
write_artifact() {
  local status="$1" claim="$2" detail="$3"
  cat >"$ARTIFACT" <<EOF
{
  "schema": "connector.cvr.acceptance.v1",
  "suite": "kvm_firecracker",
  "status": "$status",
  "effective_claim": $claim,
  "at": "$STAMP",
  "arch": "$FC_ARCH",
  "detail": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$detail"),
  "honesty": "V3/V4 Effective only when status=PASS and effective_claim=true on a real KVM host",
  "required": $([[ "$REQUIRED" == "1" ]] && echo true || echo false)
}
EOF
  log "artifact → $ARTIFACT ($status)"
}

skip_or_fail() {
  local why="$1"
  if [[ "$REQUIRED" == "1" || "$REQUIRED" == "true" ]]; then
    write_artifact "FAIL" false "$why"
    log "FAIL (required): $why"
    exit 1
  fi
  write_artifact "LAB_SKIP" false "$why"
  log "LAB_SKIP: $why"
  exit 0
}

log "Connector CVR KVM acceptance @ $STAMP (required=$REQUIRED)"

# --- HostProbe: KVM ---
if [[ ! -e /dev/kvm ]]; then
  skip_or_fail "/dev/kvm missing"
fi
if ! (exec 3<>/dev/kvm) 2>/dev/null; then
  skip_or_fail "/dev/kvm not usable (permission)"
fi
log "KVM usable"

# --- Resolve Firecracker binary ---
FC_BIN="${CONNECTOR_FIRECRACKER_BIN:-}"
if [[ -z "$FC_BIN" || ! -x "$FC_BIN" ]]; then
  for c in \
    "/usr/lib/connector/vmm/firecracker" \
    "/var/lib/connector/microvm/vmm/firecracker" \
    "vendor/firecracker/linux/${FC_ARCH}/firecracker" \
    "$(command -v firecracker 2>/dev/null || true)"
  do
    if [[ -n "$c" && -x "$c" ]]; then FC_BIN="$c"; break; fi
  done
fi

if [[ -z "$FC_BIN" || ! -x "$FC_BIN" ]]; then
  if [[ "${CONNECTOR_FETCH_FIRECRACKER:-0}" == "1" ]]; then
    DEST_DIR="$ROOT/vendor/firecracker/linux/${FC_ARCH}"
    mkdir -p "$DEST_DIR"
    URL="https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-${FC_ARCH}.tgz"
    log "fetching Firecracker ${FC_VERSION} from $URL"
    TMP="$(mktemp -d)"
    if [[ "$FC_ARCH" != "x86_64" && -z "${CONNECTOR_FIRECRACKER_SHA256:-}" ]]; then
      echo "[error] pin CONNECTOR_FIRECRACKER_SHA256 for $FC_ARCH before fetching" >&2
      skip_or_fail "no published checksum pin for $FC_ARCH"
    fi
    EXPECTED_SHA="${CONNECTOR_FIRECRACKER_SHA256:-88d89221063ee4021b539a4fea4567642f4eecfb5d52eec04cd3390833f7f3de}"
    if curl -fsSL "$URL" -o "$TMP/fc.tgz"; then
      echo "$EXPECTED_SHA  $TMP/fc.tgz" | sha256sum -c - || {
        rm -rf "$TMP"
        skip_or_fail "Firecracker tarball SHA-256 mismatch"
      }
      tar -xzf "$TMP/fc.tgz" -C "$TMP"
      FOUND="$(find "$TMP" -type f \( -name firecracker -o -name 'firecracker-*' \) ! -name '*.tgz' | head -1)"
      if [[ -n "$FOUND" ]]; then
        cp "$FOUND" "$DEST_DIR/firecracker"
        chmod +x "$DEST_DIR/firecracker"
        FC_BIN="$DEST_DIR/firecracker"
        JAILER_SRC="$(find "$TMP" -type f \( -name jailer -o -name 'jailer-*' \) | head -1 || true)"
        if [[ -n "${JAILER_SRC:-}" ]]; then
          cp "$JAILER_SRC" "$DEST_DIR/jailer"
          chmod +x "$DEST_DIR/jailer"
          export CONNECTOR_JAILER_BIN="${CONNECTOR_JAILER_BIN:-$DEST_DIR/jailer}"
        fi
      fi
    fi
    rm -rf "$TMP"
  fi
fi

if [[ -z "${FC_BIN:-}" || ! -x "$FC_BIN" ]]; then
  skip_or_fail "firecracker binary missing (set CONNECTOR_FIRECRACKER_BIN or CONNECTOR_FETCH_FIRECRACKER=1)"
fi
FC_BIN="$(realpath "$FC_BIN")"
export CONNECTOR_FIRECRACKER_BIN="$FC_BIN"
log "firecracker=$FC_BIN"

# --- Resolve kernel + rootfs ---
KERNEL="${CONNECTOR_MICROVM_KERNEL:-}"
ROOTFS="${CONNECTOR_MICROVM_ROOTFS:-}"
if [[ -z "$KERNEL" || ! -f "$KERNEL" ]]; then
  for c in \
    "/var/lib/connector/microvm/kernels/connector-vmlinux" \
    "vendor/microvm/linux/${FC_ARCH}/vmlinux" \
    "vendor/microvm/linux/${FC_ARCH}/vmlinux.bin" \
    "platform/lab/microvm-assets/vmlinux" \
    "platform/lab/microvm-assets/vmlinux.lab"
  do
    if [[ -f "$c" ]]; then KERNEL="$c"; break; fi
  done
fi
if [[ -z "$ROOTFS" || ! -f "$ROOTFS" ]]; then
  for c in \
    "/var/lib/connector/microvm/images/connector-cell.img" \
    "vendor/microvm/linux/${FC_ARCH}/rootfs.ext4" \
    "vendor/microvm/linux/${FC_ARCH}/bionic.rootfs.ext4" \
    "platform/lab/microvm-assets/rootfs.ext4" \
    "platform/lab/microvm-assets/rootfs.lab.ext4"
  do
    if [[ -f "$c" ]]; then ROOTFS="$c"; break; fi
  done
fi

if [[ "${CONNECTOR_FETCH_FIRECRACKER:-0}" == "1" ]]; then
  ASSET_DIR="$ROOT/vendor/microvm/linux/${FC_ARCH}"
  mkdir -p "$ASSET_DIR"
  # Firecracker v1.9 CI guest. Proves KVM start/pause/stop. Not a Connector production rootfs.
  if [[ -z "${KERNEL:-}" || ! -f "${KERNEL:-}" ]]; then
    curl -fsSL -o "$ASSET_DIR/vmlinux" \
      "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.9/${FC_ARCH}/vmlinux-5.10.225"
    KERNEL="$ASSET_DIR/vmlinux"
  fi
  if [[ -z "${ROOTFS:-}" || ! -f "${ROOTFS:-}" ]]; then
    curl -fsSL -o "$ASSET_DIR/rootfs.ext4" \
      "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.9/${FC_ARCH}/ubuntu-22.04.ext4"
    ROOTFS="$ASSET_DIR/rootfs.ext4"
  fi
fi

if [[ -z "${KERNEL:-}" || ! -f "$KERNEL" || -z "${ROOTFS:-}" || ! -f "$ROOTFS" ]]; then
  skip_or_fail "guest kernel/rootfs missing (pin CONNECTOR_MICROVM_KERNEL + CONNECTOR_MICROVM_ROOTFS)"
fi
KERNEL="$(realpath "$KERNEL")"
ROOTFS="$(realpath "$ROOTFS")"
export CONNECTOR_MICROVM_KERNEL="$KERNEL"
export CONNECTOR_MICROVM_ROOTFS="$ROOTFS"
log "kernel=$KERNEL"
log "rootfs=$ROOTFS"

# --- Soft prerequisites must still pass ---
bash platform/scripts/cvr-soft-acceptance.sh || {
  write_artifact "FAIL" false "soft acceptance failed under kvm job"
  exit 1
}

# --- Live MicrovmHost start/pause/resume/stop via ignored test ---
export CONNECTOR_CVR_KVM_LIVE=1
STATE_DIR="${CONNECTOR_MICROVM_STATE_DIR:-/tmp/cvr-mc}"
mkdir -p "$STATE_DIR"
export CONNECTOR_MICROVM_STATE_DIR="$STATE_DIR"

log "running connector-microvm kvm_live ignored test"
(
  cd platform/microvm
  cargo test --features "" kvm_live_start_pause_stop -- --ignored --nocapture
) || {
  write_artifact "FAIL" false "kvm_live_start_pause_stop failed"
  exit 1
}

# --- microd probe (optional binary path) ---
if cargo build --manifest-path platform/connector-microd/Cargo.toml -q 2>/dev/null; then
  MICROD_BIN="$(find platform/connector-microd/target -type f -name connector-microd 2>/dev/null | head -1 || true)"
  if [[ -n "${MICROD_BIN:-}" && -x "$MICROD_BIN" ]]; then
    log "microd probe"
    # Probe may exit 2 if not fully verified in weird layouts — still record
    set +e
    "$MICROD_BIN" probe >"$ARTIFACT_DIR/microd-probe.json" 2>"$ARTIFACT_DIR/microd-probe.err"
    MP=$?
    set -e
    log "microd probe exit=$MP"
  fi
fi

write_artifact "PASS" true "KVM+/dev/kvm + firecracker + kernel + rootfs + start/pause/resume/stop green"
log "ALL PASS — V3/V4 Effective claim authorized by this artifact"
exit 0
